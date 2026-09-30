"""`ir --confidential` and `ir confidential …` — the confidential lane.

    ir --confidential [--model kimi-k2.6] [claude flags]   verify an enclave, pin it, launch
    ir confidential show                                   re-print the last session's panel
    ir confidential card [--svg PATH]                      export the last session's panel as an SVG card
    ir confidential models                                 which models can run confidentially

How a session runs: a per-session endpoint on 127.0.0.1 translates each Claude Code request,
seals it to the pinned enclave's key, hands the ciphertext to the carrier, opens the enclave's
reply on this device and hands Claude Code the plaintext. The endpoint dies with the session.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import signal
import socket
import sys
from pathlib import Path

DEFAULT_MODEL = "kimi-k2.6"

# PROBANT runs its own default. Measured 2026-09-30, per-model eligibility on this device:
#   kimi-k2.6  12 instances → 1 eligible      kimi-k3            4 → 3
#   glm-5.2     4 → 3                          glm-5.1           18 → 2
#   deepseek-v4-flash 4 → 4
# The k2.6 fleet had grown to 12 while 11 were refused HERE (7 for an enclave build InferRoute has not
# recorded, 7 for an e2e key the hardware quote does not commit to). A pool of one is why sessions kept
# reporting "the AI machine couldn't be reached": the pinned instance cycles out and there is no
# alternative. The other fleets were healthy throughout, so this was never a carrier outage.
PROBANT_MODEL = "kimi-k3"

# Tried in order when a session cannot get an eligible instance on the model asked for. Ordering is
# capability first, cheapest last — Probant is low-volume, so availability is worth more than price here.
#
# TWO LINES THIS MUST NOT CROSS. It never leaves the CONFIDENTIAL lane: falling back to the plain lane
# would send a client's disclosure to a machine nobody attested, which is the one thing the product
# exists to prevent. And it is never silent — the model that actually answered is announced, because a
# record whose reader assumes the preferred model ran is a record that misleads.
FALLBACK_MODELS = ("kimi-k3", "kimi-k2.6", "glm-5.2", "glm-5.1", "deepseek-v4-flash")


# ── competing provider routes ─────────────────────────────────────────────────────────────────────
# Found by the supply audit 2026-09-12 (A2), confirmed independently, and left SHIPPED and unfixed
# pending a design call. `env = os.environ.copy()` passed the parent environment through untouched, and
# Claude Code's own precedence makes CLAUDE_CODE_USE_BEDROCK=1 (or Vertex, or Mantle) beat the
# ANTHROPIC_BASE_URL we point at the local sealed proxy. Measured on this machine: with the var set,
# Claude Code IGNORED the base URL, resolved real AWS credentials and enumerated the Bedrock deployment.
#
# WHY IT IS WORSE THAN A FAILED CHECK: the session never touches the enclave while the panel renders
# every check green and "plaintext that left this device: 0 bytes". Every one of those checks is TRUE.
# A failure refuses; this displays success. And the lane is confidential BY DEFAULT since 0.9.0, so the
# user never opted in to the risk.
#
# STRIPPING THE CHILD ENV IS NOT ENOUGH: `/setup-bedrock` and `/setup-vertex` write these into
# ~/.claude/settings.json's env block, and Claude Code applies its own settings to itself, so a child-env
# strip cannot reach the wizard population — the most exposed. `--settings` is precedence 2 and beats a
# level-5 user settings file. Measured 2026-09-12: "0", "" and "false" are all falsy to Claude Code for
# these flags, so a falsy override there genuinely takes the Anthropic path.
PROVIDER_ROUTE_VARS = (
    "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_MANTLE",
    "ANTHROPIC_BEDROCK_BASE_URL", "ANTHROPIC_VERTEX_BASE_URL", "ANTHROPIC_MANTLE_BASE_URL",
    "CLAUDE_CODE_SKIP_BEDROCK_AUTH", "CLAUDE_CODE_SKIP_VERTEX_AUTH",
)


def strip_provider_route(env: dict) -> list[str]:
    """Remove competing provider routes from the child env; return the names that were set.

    Returning the names is the point: a user who deliberately configured Bedrock is TOLD the sealed lane
    overrode it, rather than silently getting something other than what they asked for. Silent denial and
    silent bypass are both failures to say what happened.
    """
    found = [k for k in PROVIDER_ROUTE_VARS if env.get(k, "").strip()]
    for k in PROVIDER_ROUTE_VARS:
        env.pop(k, None)
    return found


def force_provider_route_falsy(status_args: list[str], passthrough: list[str]) -> None:
    """Pin every provider route falsy in a `--settings` layer, so a settings FILE cannot re-enable one.

    This must not ride on the status-line settings, which back off when IR_NO_STATUSLINE is set or the
    user already has a statusLine of their own. A security override that is skipped because someone
    customised their status bar is not an override. So: merge into whichever --settings layer exists, and
    create one when none does.
    """
    import json
    falsy = {k: "0" for k in PROVIDER_ROUTE_VARS}

    def _merge(blob: str):
        """The merged JSON, or None when the caller's value cannot be parsed — never a rewrite of it."""
        try:
            doc = json.loads(blob) if blob.strip() else {}
        except (ValueError, TypeError):
            return None
        if not isinstance(doc, dict):
            return None
        envb = doc.get("env")
        doc["env"] = {**(envb if isinstance(envb, dict) else {}), **falsy}
        return json.dumps(doc)

    # FAILING TO PARSE MUST NOT MEAN FAILING TO OVERRIDE. The first version returned early on malformed
    # input, so a caller's broken --settings silently disabled the neutralisation entirely — a fail-OPEN,
    # caught by the test below. Unparseable input is left untouched and we add our own layer instead; a
    # later --settings wins for the keys it sets, and ours is the last one appended.
    for args in (status_args, passthrough):
        if "--settings" in args:
            i = args.index("--settings")
            if i + 1 < len(args):
                merged = _merge(args[i + 1])
                if merged is not None:
                    args[i + 1] = merged
                    return
                break                         # malformed: leave it alone, fall through to our own layer
    status_args.extend(["--settings", json.dumps({"env": falsy})])


# ── choosing a model that will STAY available, before paying for an attestation ────────────────────
# Henry, 2026-09-30: the fallback must "first choose the model that has the strongest chances to stay
# available", not discover a dead fleet by failing on it. The old loop tried the preferred model and
# learned it was unusable only after a full attestation — the slow part of a session open.
#
# TWO SIGNALS, because neither is enough alone:
#   LIVE   `instances(fleet)` needs no attestation and shows which instances are offering nonces RIGHT
#          NOW. It cannot see which will pass this device's checks.
#   YIELD  how many instances of that fleet HAVE passed our checks historically, read from our own
#          receipts. On 2026-09-30 this separated kimi-k2.6 (0.20) from kimi-k3 (0.88) — exactly the
#          distinction a live probe is blind to, because all 12 of k2.6's instances were offering
#          nonces and 11 of them failed verification here.
# expected usable = live x yield. A fleet with many instances and a terrible yield scores below a small
# healthy one, which is the judgement a human would make from the same two numbers.
# WINDOW PER MODEL, NOT PER RECEIPT. The first version read the last 40 receipts whatever model they
# were for. kimi-k2.6 has 487 receipts here and glm-5.2 has 382, so a rarely used model was crowded out
# of the window entirely and scored on one point or none: glm-5.1 was read as 0.11 from a SINGLE
# observation, and called the worst of five, when its four measurements ever run 0.24, 0.31, 0.31, 0.11.
# Henry asked "measures 0.11 at what?", which is the question that found it.
_YIELD_PER_MODEL = 10          # observations of THIS model, newest first
_YIELD_SCAN = 400              # receipts to walk looking for them; enough to reach a rare model
# Shrinkage toward "fine" so a thin history cannot condemn a fleet. Expressed as pseudo-instances that
# all verified: with one bad observation of 2/18 a fleet scores 0.27 rather than 0.11, and with a long
# history the prior washes out. A fleet is demoted on evidence, not on having been used rarely.
_PRIOR_INSTANCES = 4.0


def fleet_yield(model_short: str) -> tuple[float, int]:
    """(expected fraction of a fleet's instances that will verify here, observations used).

    Counted over INSTANCES rather than as a mean of ratios, so a 12-instance observation weighs more
    than a 3-instance one — they are not equally informative about a fleet's state.
    """
    import json as _json
    from pathlib import Path as _P
    d = _P.home() / ".inferroute" / "confidential" / "receipts"
    try:
        files = sorted(d.glob("*.json"))[-_YIELD_SCAN:]
    except OSError:
        return 1.0, 0
    elig = inst = n = 0
    for f in reversed(files):                       # newest first, stop as soon as we have enough
        if n >= _YIELD_PER_MODEL:
            break
        try:
            r = _json.loads(f.read_text())
        except (OSError, ValueError):
            continue
        if r.get("model_short") != model_short:
            continue
        fl = r.get("fleet") or {}
        i, e = fl.get("instances"), fl.get("eligible")
        if isinstance(i, int) and i > 0 and isinstance(e, int):
            elig += e; inst += i; n += 1
    if not n:
        return 1.0, 0                               # unseen gets the benefit of the doubt, as before
    return (elig + _PRIOR_INSTANCES) / (inst + _PRIOR_INSTANCES), n


def _yield_counts(model_short: str) -> tuple[float, float]:
    """(eligible, instances) over the same per-model window fleet_yield uses, WITHOUT the prior. The
    interval folds the prior in itself; taking it from the shrunk ratio would apply it twice."""
    import json as _json
    from pathlib import Path as _P
    d = _P.home() / ".inferroute" / "confidential" / "receipts"
    try:
        files = sorted(d.glob("*.json"))[-_YIELD_SCAN:]
    except OSError:
        return 0.0, 0.0
    elig = inst = n = 0
    for f in reversed(files):
        if n >= _YIELD_PER_MODEL:
            break
        try:
            r = _json.loads(f.read_text())
        except (OSError, ValueError):
            continue
        if r.get("model_short") != model_short:
            continue
        fl = r.get("fleet") or {}
        i, e = fl.get("instances"), fl.get("eligible")
        if isinstance(i, int) and i > 0 and isinstance(e, int):
            elig += e; inst += i; n += 1
    return float(elig), float(inst)


# VERIFIABLE IS NOT THE SAME AS WORKING, and fleet_yield only measures the first.
#
# Measured on glm-5.2, 2026-09-30, as its request failure rate climbed through the day:
#
#   12:07   31% of requests failed     fleet eligible/instances 3/3
#   12:36   63% failed                 3/3
#   13:50   95% failed                 3/3
#   16:20   76% failed                 3/3
#
# Every instance verified at every point. A chooser scoring `live x yield` rates that fleet PERFECT at
# the moment it is answering one request in twenty. Henry asked for the model with "the strongest
# chances to stay available"; verifiability is a precondition for availability, not a measure of it.
#
# Counted over the same per-model window as the yield, with shrinkage toward "fine" so a fleet is
# demoted on evidence rather than on being new.
#
# CAVEAT, to be narrowed once receipts carry kinds: `errors` includes our own seal failures, which are
# this device's fault and not the fleet's. They are rare and would affect every fleet alike, so they
# cannot flip an ordering on their own — but once `errors_seal_failed` has accumulated in real receipts
# this should subtract it.
_PRIOR_REQUESTS = 8.0


def fleet_success(model_short: str) -> tuple[float, int]:
    """(expected fraction of requests that will succeed on this fleet, requests observed)."""
    import json as _json
    from pathlib import Path as _P
    d = _P.home() / ".inferroute" / "confidential" / "receipts"
    try:
        files = sorted(d.glob("*.json"))[-_YIELD_SCAN:]
    except OSError:
        return 1.0, 0
    reqs = errs = n = 0
    for f in reversed(files):
        if n >= _YIELD_PER_MODEL:
            break
        try:
            r = _json.loads(f.read_text())
        except (OSError, ValueError):
            continue
        if r.get("model_short") != model_short:
            continue
        c = r.get("counters") or {}
        # errors_fleet counts ONLY failures attributable to this fleet. `errors` also holds our own bugs
        # (a malformed request, a seal failure), the account's billing state (402), and relay outages —
        # each of which would demote whichever fleet happened to be selected. Older receipts predate the
        # split and carry only the total; using it for them is wrong in the safe direction (it can only
        # understate a fleet), and they age out of the window.
        q = c.get("requests")
        e = c.get("errors_fleet", c.get("errors"))
        if isinstance(q, int) and q > 0 and isinstance(e, int):
            reqs += q
            errs += min(e, q)            # an error per request at most; a retry can count twice
            n += 1
    if not reqs:
        return 1.0, 0
    return (reqs - errs + _PRIOR_REQUESTS) / (reqs + _PRIOR_REQUESTS), reqs


def fleet_yield_interval(model_short: str, *, hint_ratio=None, hint_samples=None) -> tuple[float, float]:
    """A Wilson score interval (95%) for a fleet's yield, so an ORDERING can be refused when the evidence
    does not support it.

    Henry's question "measures 0.11 at what?" corrected a ranking built on one observation. The director
    session then made the sharper point: even after the fix, glm-5.1 at ~0.30 (n=3) against kimi-k2.6 at
    0.22 (n=10) is two numbers whose intervals overlap almost completely. A correction that had to be
    issued because a single observation moved the ordering is the strongest argument that the ordering
    should not come from a handful of receipts at all.

    So the point estimate decides nothing on its own. Two fleets whose intervals OVERLAP are treated as
    tied, and a tie is broken by the user's stated preference — never by a difference the samples cannot
    distinguish. With no counts at all the interval is (0, 1): unknown, distinguishes nothing, preference
    stands. That is also why the server hint is worth carrying `samples`.
    """
    if hint_ratio is not None and hint_samples:
        k, n = float(hint_ratio) * float(hint_samples), float(hint_samples)
    else:
        y, obs = fleet_yield(model_short)
        if not obs:
            return 0.0, 1.0                       # no history: the widest possible interval, so it ties
        k, n = _yield_counts(model_short)
    k, n = k + _PRIOR_INSTANCES, n + _PRIOR_INSTANCES
    if n <= 0:
        return 0.0, 1.0
    z = 1.96
    ph = k / n
    denom = 1.0 + z * z / n
    centre = (ph + z * z / (2 * n)) / denom
    half = (z / denom) * ((ph * (1 - ph) / n + z * z / (4 * n * n)) ** 0.5)
    return max(0.0, centre - half), min(1.0, centre + half)


async def server_fleet_health(transport) -> dict:
    """The operator's own view of which fleets are currently usable, keyed by fleet id.

    THIS BELONGS ON THE SERVER AND THE LOCAL VERSION IS A FALLBACK, not the other way round (Henry,
    2026-09-30: "put on server side what should be there rather than on the client"). `fleet_yield`
    below learns the same statistic from THIS device's receipts, which has two faults the server does
    not: a new client has no history at all, so the very first session gets no benefit from any of this;
    and one client's sample is tiny — ours was n=1 and n=2 for two of five models. The operator sees
    every session across every client, so its number is both fresh and real.

    IT IS A HINT, AND NOTHING RESTS ON IT. The client still attests whatever it chooses and records what
    it attested; a wrong or hostile hint costs one wasted attestation and the next candidate is tried.
    That is why consuming it does not move any trust to the server: it steers, it does not vouch.

    Absent endpoint, error, or nonsense shape: {} — and selection falls back to local history.
    """
    try:
        got = await transport.fleet_health()
    except Exception:                                    # noqa: BLE001 — absent or broken: fall back quietly
        return {}
    fleets = (got or {}).get("fleets")
    return fleets if isinstance(fleets, dict) else {}


async def probe_fleet(transport, fleet_id: str) -> int:
    """Instances offering a nonce right now. No attestation, so this is cheap enough to run before
    choosing. A probe that fails returns -1 (unknown) rather than 0 — "we could not ask" must not read
    as "there is nothing there", or one flaky listing would rule out a healthy fleet."""
    try:
        e2 = await transport.instances(fleet_id)
    except Exception:                                    # noqa: BLE001
        return -1
    return sum(1 for i in (e2.get("instances") or [])
               if i.get("e2e_pubkey") and (i.get("nonces") or []))


async def health_ordered(order: list[str], catalog: list, transport, console=None,
                         server_health: dict | None = None) -> list[str]:
    """`order` re-ranked by expected usable instances, preference preserved where health allows.

    Probing stops at the first candidate that looks healthy, so the common case costs ONE extra listing
    call and the preferred model still wins. Only when the preferred fleet looks thin do we pay to look
    further — which is the case that used to cost a failed attestation instead.

    A fleet whose probe FAILED keeps its place rather than being demoted: not being able to ask is not
    evidence of ill health, and demoting on it would make one flaky listing permanent.
    """
    scored: list[tuple[str, float, float, float]] = []     # (short, expected, lo, hi)
    for short in order:
        ref = next((m for m in catalog if str(m.get("name", "")).endswith(short) or m.get("name") == short), None)
        fleet = (ref or {}).get("fleet_id")
        if not fleet:
            continue
        live = await probe_fleet(transport, fleet)
        # Server first, this device's own history second. A new client has no history, which is exactly
        # the case the server number exists to cover.
        hint = (server_health or {}).get(fleet) or {}
        ratio = hint.get("eligible_ratio")
        use_hint = isinstance(ratio, (int, float)) and 0.0 <= ratio <= 1.0
        y = float(ratio) if use_hint else fleet_yield(short)[0]
        lo, hi = fleet_yield_interval(
            short,
            hint_ratio=ratio if use_hint else None,
            hint_samples=hint.get("samples") if use_hint else None)
        if live < 0:
            # COULD NOT ASK. The old sentinel was exactly 1.0, which SATISFIES the `expected >= 1.0` gate
            # below — so one flaky instances() listing on the preferred model silently returned "looks
            # fine" without looking, and `best[1] < 1.0` was false so nothing was printed either. Keep its
            # place without declaring it healthy: just under the gate, widest interval, ties with
            # everything, preference decides.
            scored.append((short, 1.0 - 1e-9, 0.0, 1.0))
            continue
        # Two different things have to be true for a fleet to be usable: its instances must VERIFY here,
        # and requests to it must SUCCEED. fleet_yield answers only the first, and on 2026-09-30 glm-5.2
        # held a perfect 3/3 yield while failing 95% of requests — rated best exactly when it was worst.
        succ, _reqs = fleet_success(short)
        expected = live * y * succ
        # The interval is the yield's, scaled by the success point estimate. That understates the
        # uncertainty in `succ` itself and so is slightly too confident; it is still far better than
        # scoring a fleet as if the second question did not exist. Widening it properly means an
        # interval on a product of two rates, which is worth doing when this has run for a while.
        scored.append((short, expected, live * lo * succ, live * hi * succ))
        if expected >= 1.0 and short == order[0]:
            return order                              # the preferred model looks fine; spend nothing more
        if expected >= 1.0:
            break                                     # good enough, and higher-preference ones were not
    if not scored:
        return order
    # A DIFFERENCE MUST BE SUPPORTED BEFORE IT IS ACTED ON. Rank by the point estimate, then widen the
    # winner to everything its interval OVERLAPS: those fleets are not distinguishable by the evidence we
    # have, so among them the user's stated preference decides, not a gap inside the noise.
    #
    # This is the director session's argument, and my own correction is the evidence for it. glm-5.1 at
    # ~0.30 (n=3) sits at [0.19, 0.43] and kimi-k2.6 at 0.22 (n=10) at [0.16, 0.29] — overlapping, so
    # ordering one above the other is reading a difference the samples cannot support. kimi-k3 at
    # [0.70, 0.91] against that same [0.16, 0.29] does NOT overlap, and that reorder is real.
    top = max(scored, key=lambda t: t[1])
    tied = [t for t in scored if t[3] >= top[2] and t[2] <= top[3]]      # intervals intersect
    rank = {short: i for i, short in enumerate(order)}
    best = min(tied, key=lambda t: rank.get(t[0], len(order)))           # preference breaks the tie
    if best[1] < 1.0 and console is not None:
        console.print("[grey58]no sealed model fleet looks comfortably available right now; "
                      f"trying {best[0]} first, then the rest.[/]")
    rest = [m for m in order if m != best[0]]
    return [best[0]] + rest


def _console():
    from rich.console import Console
    return Console()


def _need_extra():
    try:
        import cryptography  # noqa: F401
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
        from inferroute_local.confidential import e2ee
        e2ee.backend()
    except Exception as e:
        sys.stderr.write(f"\n  The confidential lane needs extra packages ({e}).\n"
                         "  Fix: pip install 'inferroute[confidential]'\n\n")
        sys.exit(2)


def _resolve_model(short: str | None):
    from . import models as models_mod
    short = short or DEFAULT_MODEL
    alias = models_mod.get(short)
    from . import lane as lane_mod
    if alias is None or not lane_mod.enclave_backed(short):
        tee = [a.short for a in models_mod.all_aliases() if lane_mod.enclave_backed(a.short)]
        sys.stderr.write(f"\n  `{short}` cannot run confidentially. Models that can: {', '.join(tee) or '(none in catalog)'}\n\n")
        sys.exit(2)
    return alias


def _resolve_model_quietly(short: str):
    """A fallback candidate that is not in the catalog, or not enclave-backed, is SKIPPED rather than fatal:
    _resolve_model exits the process, which is right for what the user asked for and wrong for a guess."""
    from . import models as models_mod
    from . import lane as lane_mod
    alias = models_mod.get(short)
    return alias if alias is not None and lane_mod.enclave_backed(short) else None


def _interactive(passthrough: list[str]) -> bool:
    """A human at a terminal (not `-p`/`--print`, not a pipe): the picker and the pause apply."""
    return sys.stdin.isatty() and sys.stdout.isatty() and not any(a in ("-p", "--print") or a.startswith("--print=") for a in passthrough)


async def _pause(prompt: str, timeout: float = 20.0) -> None:
    """Wait for Enter or `timeout` seconds, whichever first; never blocks a non-tty."""
    import select
    sys.stdout.write(f"\033[90m  {prompt}\033[0m ")
    sys.stdout.flush()
    loop = asyncio.get_running_loop()

    def _wait() -> None:
        r, _, _ = select.select([sys.stdin], [], [], timeout)
        if r:
            try:
                sys.stdin.readline()
            except Exception:
                pass
    await loop.run_in_executor(None, _wait)
    sys.stdout.write("\n")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _lane_price(alias, economy: bool) -> dict:
    """USD per 1M tokens from the catalog for this model and lane ({input, cached, output})."""
    from . import models as models_mod
    row = next((m for m in models_mod._rows() if m.get("short") == alias.short), None) or {}
    return dict((row.get("economy") if economy else row.get("standard")) or {})


async def _open_session(alias, session_id: str, http, console, *, continuity: bool = False):
    """`continuity`: open the side lane instead of a single session — several verified sessions, one
    conversation, with a standby warmed in the background so a fleet going bad never reaches the user.

    Set ONLY by Probant, where live availability is what the product is for. Every other caller gets
    exactly the single-session path it got before, byte for byte: the branch below is the only place
    this differs, and `IR_NO_MODEL_FALLBACK=1` turns it off even there."""
    from inferroute_local.confidential.session import ConfidentialSession
    from inferroute_local.confidential.transport import RelayUnavailable, make_transport
    from . import config as cfg
    creds = cfg.load()
    try:
        transport = make_transport(http, api_url=creds.api_url, api_key=creds.api_key, session_id=session_id)
    except ValueError as e:
        console.print(f"[red]{e}[/]")
        sys.exit(2)
    import httpx
    with console.status(f"[bold]resolving {alias.ref_key} on the confidential lane…", spinner="dots"):
        try:
            catalog = await transport.models()
        except RelayUnavailable as e:
            console.print(f"[red]{e}[/]\n[grey58]Nothing was sent.[/]")
            sys.exit(3)
        except httpx.HTTPStatusError as e:
            body = (e.response.text or "")[:200].replace("\n", " ")
            import re
            body = re.sub(r"https?://\S+", "<url>", body)
            code = e.response.status_code
            hint = ("your InferRoute key was refused — run `ir login`" if code in (401, 403)
                    else "try again in a minute")
            console.print(f"[red]the carrier answered {code} while listing confidential models[/]"
                          f"\n[grey58]{transport.name} · {body}[/]\n[grey58]Nothing was sent; {hint}.[/]")
            sys.exit(3)
        except httpx.HTTPError as e:
            console.print(f"[red]cannot reach the carrier ({type(e).__name__})[/]\n[grey58]Nothing was sent.[/]")
            sys.exit(3)
    economy = os.environ.get("IR_LANE", "").strip().lower() in ("economy", "economy-loop")
    # The model asked for, then the fallbacks, without repeating it. Only reached when a fleet cannot give
    # this device an eligible instance — a carrier or credential failure has already exited above, because
    # trying four models against a refused key would just print the same error four times.
    order = [alias.short] + [m for m in FALLBACK_MODELS if m != alias.short]
    if os.environ.get("IR_NO_MODEL_FALLBACK") == "1":
        order = [alias.short]
    else:
        # PROACTIVE: look before attesting. The old loop learned a fleet was unusable by paying a full
        # attestation against it — the slow part of an open — and only then moved on.
        #
        # SKIPPED FOR THE CONTINUITY LANE, which does its own looking with a better instrument and then
        # re-sorts this output by capability anyway, using it only as a tie-break. Running both meant
        # two probe rounds across every fleet on the critical path of every launch, and discarding the
        # first one's conclusion.
        if not continuity:
            try:
                order = await health_ordered(order, catalog, transport, console,
                                             server_health=await server_fleet_health(transport))
            except Exception:                         # noqa: BLE001 — a failed probe must never block a launch
                pass
    if continuity and os.environ.get("IR_NO_MODEL_FALLBACK") != "1":
        lane = await _open_continuity(order, alias, catalog, session_id, transport, http,
                                      economy, console)
        if lane is not None:
            return lane, lane.receipt
        # Falls through to the single-session path below. A side lane that cannot open must never be
        # worse than not having one, so it degrades to exactly what a caller would have had anyway.

    tried: list[str] = []
    for short in order:
        cand = alias if short == alias.short else _resolve_model_quietly(short)
        if cand is None:
            continue
        fleet_id = next((m.get("fleet_id") for m in catalog if m.get("name") == cand.ref_key), None)
        if not fleet_id:
            tried.append(f"{short} (not offered)")
            continue
        session = ConfidentialSession(session_id=session_id, model_short=cand.short, upstream_model=cand.ref_key,
                                      fleet_id=fleet_id, transport=transport, http=http,
                                      price=_lane_price(cand, economy), economy=economy)
        status = console.status(f"[bold]verifying the enclave from this device… ({cand.short})", spinner="dots")
        status.start()
        try:
            receipt = await session.open(progress=lambda s: status.update(f"[bold]{s}"))
        except Exception as e:      # session.open() refuses on expected failures; a bug shows the same way
            from inferroute_local.confidential.session import public_reason
            tried.append(f"{short} ({public_reason(e)})")
            continue
        finally:
            status.stop()
        if short != alias.short:
            # NEVER silent: the reader must know which model answered, and why it was not the first choice.
            console.print(f"[yellow]{alias.short} had no machine this device accepts, so this session runs "
                          f"{cand.short}[/]\n[grey58]still the confidential lane — a verified enclave, "
                          f"never the plain one. Tried: {', '.join(tried)}.[/]")
        return session, receipt
    console.print("[red]no confidential model could give this device a verified machine[/]"
                  f"\n[grey58]tried {', '.join(tried) or '(none)'}[/]\n[grey58]Nothing was sent.[/]")
    sys.exit(3)


async def _open_continuity(order, alias, catalog, session_id, transport, http, economy, console):
    """Build the continuity lane over the candidates the catalog actually offers."""
    from inferroute_local.confidential import availability as av
    from inferroute_local.confidential import continuity as cont
    from inferroute_local.confidential.session import ConfidentialSession

    cands = []
    for short in order:
        cand = alias if short == alias.short else _resolve_model_quietly(short)
        if cand is None:
            continue
        fleet_id = next((m.get("fleet_id") for m in catalog if m.get("name") == cand.ref_key), None)
        if not fleet_id:
            continue
        meta = next((m for m in catalog if m.get("name") == cand.ref_key), {}) or {}
        cands.append(cont.Candidate(
            fleet_id=fleet_id, model_short=cand.short, upstream_model=cand.ref_key,
            # The relay publishes only {fleet_ref, fleet_id, name} today, so this is usually 0 and every
            # standby is treated as context-compatible. Stated as a gap rather than hidden as a default;
            # it becomes a real guard the moment /confidential/models carries the field.
            context_length=int(meta.get("context_length") or 0), meta=meta))
    if not cands:
        return None

    beliefs = av.Beliefs()
    beliefs.load() or beliefs.backfit()          # what this device already knows, decayed to now

    async def opener(c):
        s = ConfidentialSession(session_id=f"{session_id}:{c.model_short}", model_short=c.model_short,
                                upstream_model=c.upstream_model, fleet_id=c.fleet_id,
                                transport=transport, http=http,
                                price=_lane_price(_resolve_model_quietly(c.model_short) or alias, economy),
                                economy=economy)
        await s.open()
        if not s.receipt.is_confidential:
            s.close()
            raise RuntimeError(s.receipt.refusal or "not confidential")
        return s

    def _announce(kind: str, detail: str) -> None:
        """A switch is NEVER SILENT. This module's own rule, forty lines up: "the model that actually
        answered is announced, because a record whose reader assumes the preferred model ran is a
        record that misleads." The lane was built with no display hook at all, so every switch happened
        behind the user — and its own note text said the quiet part: "the user saw nothing".

        The user seeing nothing is the goal for the ERROR. It is the opposite of the goal for the fact
        that a different model answered."""
        if kind == "switched":
            console.print(f"[yellow]the machine serving this session stopped responding, so it moved: "
                          f"{detail}[/]\n[grey58]still the confidential lane — every machine verified "
                          f"from this device before anything was sent to it, and the receipt names "
                          f"each one.[/]")
        elif kind == "no-standby":
            console.print(f"[grey58]{detail}[/]")

    lane = cont.Continuity(cands, opener, beliefs=beliefs,
                           policy=av.Policy(rank=av.RANK_CAPABILITY), transport=transport,
                           note=_announce)
    status = console.status("[bold]verifying the enclave from this device…", spinner="dots")
    status.start()
    try:
        await lane.open()
    except Exception:                                 # noqa: BLE001 — fall back to the ordinary path
        return None
    finally:
        status.stop()
    if lane.active.model_short != alias.short:
        console.print(f"[yellow]{alias.short} had no machine this device accepts, so this session runs "
                      f"{lane.active.model_short}[/]\n[grey58]still the confidential lane — a verified "
                      f"enclave, never the plain one.[/]")
    return lane


def _strip_prefix(receipt, *, live: bool = False) -> str:
    """The static half of the status line: `🔒 confidential · kimi-k2.6 · enclave verified 01:04Z`.
    No instance id here (it is on the receipt; the status line is the thing people screenshot).

    `live`: the continuity lane can change which model is answering, and a baked-in name would then be
    the one that ISN'T. The model is left to the shell half, which reads it from the pointer the lane
    keeps on the session serving now."""
    if live:
        return "🔒 confidential"
    when = (receipt.verified_at or receipt.started_at or "")[11:16]
    return f"🔒 confidential · {receipt.model_short} · enclave verified {when}Z"


def _current_receipt_path(receipt_path: str, live: bool) -> str:
    """The path the status line should read. For the continuity lane that is the pointer the lane keeps
    on whichever session is serving, not the receipt that happened to open first — whose counters stop
    moving at the switch while still rendering as though they had not."""
    if not live or not receipt_path:
        return receipt_path
    return str(Path(receipt_path).parent / "current.json")


def _attach_counter(status_args: list[str], receipt_path: str, *, live: bool = False) -> None:
    """Append the live privacy figures to the status-line command, read from the receipt on every
    render (the session rewrites it after each turn): how much was sealed on this device and
    that nothing left in the clear. Dependency-free shell; exit status stays 0."""
    import json
    import shlex
    if len(status_args) != 2 or not receipt_path:
        return
    try:
        settings = json.loads(status_args[1])
        cmd = settings["statusLine"]["command"]
    except (ValueError, KeyError, TypeError):
        return
    rp = shlex.quote(receipt_path)
    if live:
        # The model and the verify time come from the receipt too, so a switch is reflected rather than
        # contradicted. Read on every render, like the counters beside them.
        cmd += (f"; m=$(grep -o '\"model_short\": \"[^\"]*\"' {rp} 2>/dev/null | head -1 | cut -d'\"' -f4); "
                f"[ -n \"$m\" ] && printf ' · %s' \"$m\"; "
                f"v=$(grep -o '\"verified_at\": \"[^\"]*\"' {rp} 2>/dev/null | head -1 | cut -d'\"' -f4); "
                f"[ -n \"$v\" ] && printf ' · enclave verified %s' \"$(echo \"$v\" | cut -c12-16)Z\"")
    cmd += (f"; b=$(grep -o '\"plaintext_bytes_sealed_here\": [0-9]*' {rp} 2>/dev/null | head -1 | grep -o '[0-9]*$'); "
            f"if [ -n \"$b\" ]; then if [ \"$b\" -ge 1048576 ]; then printf ' · %s.%s MB sealed here' $((b/1048576)) $(( (b%1048576)*10/1048576 )); "
            f"else printf ' · %s KB sealed here' $((b/1024)); fi; printf ' · nothing in the clear (by construction, not a count)'; fi; "
            f"u=$(grep -o '\"estimated_cost_usd\": [0-9.]*' {rp} 2>/dev/null | head -1 | grep -o '[0-9.]*$'); "
            f"[ -n \"$u\" ] && printf ' │ $%.2f' \"$u\" 2>/dev/null || true")
    settings["statusLine"]["command"] = cmd
    status_args[1] = json.dumps(settings)


# ───────────────────────── ir --confidential ─────────────────────────

def launch(args: list[str], agent: str = "claude", *, probant: dict | None = None) -> int:
    """`probant`: set by `ir probant open` ({"matter", "date_bound"}). The pre-launch screen is then the
    plain-language Probant card (probant_trust) instead of the technical panel, and `summary` is filled in."""
    _need_extra()
    from . import launch as launch_mod, agents as agents_mod
    from inferroute_local.confidential import display
    import httpx
    import uvicorn
    from inferroute_local.confidential.server import SEALED_KEEPALIVE_S, create_app

    from .main import _extract_model_override
    from . import resume as resume_mod
    passthrough = [a for a in args if a != "--confidential"]
    user_model, passthrough = _extract_model_override(passthrough)
    # `ir probant open --web`: the same session, with Pi in RPC mode behind a local page (probant_web).
    web = bool(probant and probant.get("web"))
    if web:
        passthrough = [*passthrough, "--mode", "rpc"]
    # Probant never asks the user to pick a model from a price list: it runs the default, the model its
    # mission contract is written and tested against.
    if user_model is None and _interactive(passthrough) and probant is None:
        # No pin → the same picker as bare `ir`, narrowed to the enclave-capable models.
        from . import choose as choose_mod
        user_model = choose_mod.pick(choose_mod.confidential_options(),
                                     "confidential lane · choose an enclave model · USD per 1M tokens")
        if user_model is None:
            return 130
        hint = f"ir {agent} --model {user_model}" if agent != "claude" else f"ir --model {user_model}"
        sys.stderr.write(f"\n  Run this next time directly:  {hint}\n\n")
    # Probant's own default, not the lane's: see PROBANT_MODEL. An explicit --model still wins.
    alias = _resolve_model(user_model or (PROBANT_MODEL if probant is not None else None))
    if agent == "pi":
        from . import pi_attested
        try:
            pi_attested.check_passthrough(passthrough)       # refuse before verifying, not after
        except pi_attested.Refused as e:
            sys.stderr.write(f"\n  ir: {e}\n\n")
            return 2
    if os.environ.get("CLAUDECODE") == "1" and os.environ.get("IR_ALLOW_NESTED") != "1":
        sys.stderr.write("\n  ir: refusing to launch a nested agent session (CLAUDECODE=1). Set IR_ALLOW_NESTED=1 to force.\n\n")
        return 2
    binary = agents_mod.binary_for(agent)
    console = _console()
    # Resume (Claude Code only — the other agents manage their own sessions): `--resume <id>` or
    # `-c`. The resumed turns are sealed like fresh ones; a confidential session never silently
    # continues on the plaintext lane.
    resuming = None
    if agent == "claude":
        mode, explicit_id, passthrough = resume_mod._parse(passthrough)
        resuming = explicit_id or (resume_mod.newest(os.getcwd()) if mode == "continue" else None)
        if mode == "continue" and not resuming:
            sys.stderr.write("\n  ir: nothing to continue in this directory.\n\n")
            return 1
    session_id = resuming or launch_mod._new_session_id()
    # What Claude Code shows as the model name — the one persistent on-screen reminder
    # of the lane. The local endpoint answers to this id; the enclave sees `alias.ref_key`.
    shown_model = f"{alias.short} [confidential]"

    async def _run() -> int:
        async with httpx.AsyncClient(timeout=httpx.Timeout(600.0, connect=30.0)) as http:
            # CONTINUITY IS OFF UNTIL A CLAIM IS RULED ON, and the reason is not an engineering one.
            #
            # The lane works: verified live, a killed fleet carried mid-stream in 2.4 s, 24 tests. But
            # the /v1/messages API is STATELESS — `body` is the whole conversation — so every switch
            # re-sends the entire disclosure to a second enclave. And this is printed to the
            # professional before they type anything (probant_trust.py:80, mirrored in Pi's /proof card
            # at ir-attested.ts:159 and the browser panel), and again in French to a named client:
            #
            #     "Your text is encrypted here; only that machine can open it."
            #
            # That is a claim about WHO CAN READ THE INVENTION, and continuity makes it false in
            # substance rather than in bookkeeping. attest.LIMITATIONS has no entry conditioning it, so
            # the product's own rule — where the honest sentence is conditional, the condition is on the
            # page — is unapplied to the one condition that matters most.
            #
            # Changing a client-facing confidentiality claim is Henry's call and an audit's, not a
            # commit's. So the lane ships complete, tested and REACHABLE ONLY ON PURPOSE, and Probant
            # keeps exactly the single-session behaviour it has today until that sentence is settled.
            # ON, per Henry's ruling of 2026-09-30, once the claim it needed was conditioned rather
            # than quietly broken: probant_trust no longer says "only that machine can open it" for the
            # AI lane, the `machines-per-session` limitation carries the condition, and the Bétrancourt
            # draft says the same in the same register. The search lane's singular claim is untouched
            # because it pins expect_lifetime_id and is still earned.
            #
            # IR_PROBANT_CONTINUITY=0 turns it off again without a code change.
            use_continuity = (probant is not None
                              and os.environ.get("IR_PROBANT_CONTINUITY") != "0")
            session, receipt = await _open_session(alias, session_id, http, console,
                                                   continuity=use_continuity)
            search_endpoint = None
            if agent == "pi" and receipt.is_confidential:
                from . import pi_attested
                try:
                    pi_attested.check_workspace(os.getcwd())      # W1: never make a protected tree writable
                except pi_attested.UnsafeWorkspace as e:
                    console.print(f"[red]{e}[/]")
                    session.close()
                    return 2
                # WHAT IS IN THE FOLDER BESIDES THE DISCLOSURE, said to the PROFESSIONAL before the session
                # rather than discovered by the assistant mid-survey. On 2026-09-30 a matter held a
                # disclosure.md.bak from the previous day; the assistant read it and called it "useful
                # matter context", so a survey ran partly on a draft that had been revised away.
                # DELIBERATELY NOT IN THE SYSTEM PROMPT: that prompt is fixed and sha-pinned into every
                # session record, so per-session text there would break the pin it exists to provide. The
                # contract carries the RULE (disclosure.md is the disclosure); this notice carries the FACT
                # about this folder, and it is the professional's to act on.
                _stale, _other = pi_attested.workspace_extras(os.getcwd())
                if _stale or _other:
                    bits = []
                    if _stale:
                        bits.append(f"[yellow]{', '.join(_stale)}[/] — looks like a backup or editor file")
                    if _other:
                        bits.append(f"[yellow]{', '.join(_other)}[/]")
                    console.print("\n  besides disclosure.md this matter folder holds: " + "; ".join(bits)
                                  + "\n  [grey58]the assistant searches from disclosure.md and will ask before "
                                    "reading anything else. A superseded draft left here is worth removing — "
                                    "it is text you already decided against.[/]")
                # Decided before the verifier starts: the verifier stamps the confinement line into every
                # record from this flag. If the sandbox cannot then be built, the launch is REFUSED below.
                os.environ["IR_ATTESTED_NETNS_BIND"] = "1" if pi_attested.plan_netns_bind() else "0"
                # Started before anything is shown, so the Probant card reports a search check that RAN for
                # this launch, not one promised for later.
                # Reading a document offers no search tool, so no search verifier is started for it: nothing
                # about a whole document in context can leave for a search machine.
                search_endpoint = None if os.environ.get("IR_INTAKE_DIR") else pi_attested.start_search_proxy()
            if probant is not None and receipt.is_confidential:
                from . import pi_attested, probant_trust
                search_result = await asyncio.to_thread(pi_attested.search_verification, search_endpoint)
                summary = probant_trust.build(receipt, search_result, pi_attested.confinement_label(),
                                               matter=probant.get("matter", ""), date_bound=probant.get("date_bound", ""),
                                               surface="browser" if web else "terminal",
                                               mode=probant.get("mode", "matter"))
                probant["summary"] = summary
                probant_trust.render_card(summary, console)
                if not web:
                    probant_trust.render_howto(probant.get("matter", ""), console)
            else:
                display.render_panel(receipt, console)
            if not receipt.is_confidential:
                return 3
            if _interactive(passthrough) and not web:
                # Claude Code's full-screen TUI replaces this screen the moment it starts, so give
                # the panel a beat: Enter (or 20 s) to continue. The 🔒 status line inside Claude
                # Code and `ir confidential show` carry the proof from there on.
                await _pause("Enter to start the assistant (or wait 20 s)" if probant is not None
                             else f"Enter to open {agent} · `ir confidential show` re-prints this proof any time")
            port = _free_port()
            # Minted here, handed only to the agent this launch starts. The old constant was in the
            # published source, so it was a label rather than a credential.
            import secrets as _secrets
            local_key = "ir-" + _secrets.token_urlsafe(32)
            # Loopback, one client, for the life of one session: uvicorn's 5s idle close buys nothing here
            # and costs a race — the server's FIN can cross the agent's next request on a pooled connection.
            server = uvicorn.Server(uvicorn.Config(create_app(session, local_key), host="127.0.0.1",
                                                   port=port, log_level="critical",
                                                   timeout_keep_alive=SEALED_KEEPALIVE_S))
            server_task = asyncio.create_task(server.serve())
            while not server.started:
                if server_task.done():
                    server_task.result()
                await asyncio.sleep(0.05)
            env = os.environ.copy()
            # Before anything else about this child: a competing provider route would send the session
            # somewhere the panel has not verified, while the panel renders all-green. See
            # strip_provider_route.
            overridden_routes = strip_provider_route(env)
            # THE SEALED PROXY IS ALWAYS A LOOPBACK HOP, for every agent, so an HTTP_PROXY in the user's
            # environment could receive the plaintext on its way to 127.0.0.1. pi_attested has set this
            # since it was written, with the reason stated; nothing else did. Confirmed 2026-09-30 that
            # Claude Code's binary references HTTP_PROXY/HTTPS_PROXY/NO_PROXY/ProxyAgent, so the host
            # honours these — whether it excludes loopback BY DEFAULT is the user's environment's business,
            # not ours, which is exactly why we should not be relying on it. Applied here, before the
            # per-agent branch, so every adapter gets it rather than the one that happened to think of it.
            from .pi_attested import _with_loopback as _no_proxy_loopback
            for _pv in ("no_proxy", "NO_PROXY"):
                env[_pv] = _no_proxy_loopback(env.get("no_proxy") if env.get("no_proxy") is not None
                                              else env.get("NO_PROXY"))
            env["IR_CONFIDENTIAL"] = "1"
            agents_mod.put_agent_on_path(binary, env)      # the node it was installed with sits beside it
            if probant is not None:
                env["IR_PROBANT_SURFACE"] = "browser" if web else "terminal"
            local = f"http://127.0.0.1:{port}"
            session.shown_model = shown_model if agent == "claude" else alias.short
            if agent == "claude":
                env["ANTHROPIC_BASE_URL"] = local
                env["ANTHROPIC_AUTH_TOKEN"] = local_key
                env["ANTHROPIC_DEFAULT_HAIKU_MODEL"] = shown_model
                env["ANTHROPIC_SMALL_FAST_MODEL"] = shown_model
                env["ANTHROPIC_CUSTOM_HEADERS"] = "\n".join(
                    [h for h in [env.get("ANTHROPIC_CUSTOM_HEADERS", "").strip()] if h] + [f"x-inferroute-session: {session_id}"])
                launch_mod._apply_autocompact_env(env, alias.model_id)
                # Pinned inside Claude Code's TUI for the whole session (the pre-launch panel
                # scrolls away in fullscreen mode): lane · model · enclave · when verified, plus a
                # live "N sealed" count read from the receipt the session keeps updating.
                _live = hasattr(session, "switches")        # the continuity lane can change model
                status_args = launch_mod._product_strip_settings_args(
                    _strip_prefix(receipt, live=_live), passthrough, disable_connectors=True)
                _attach_counter(status_args, _current_receipt_path(receipt.path, _live), live=_live)
                # A settings FILE could re-enable a route the env strip removed; this cannot be skipped.
                force_provider_route_falsy(status_args, passthrough)
                if overridden_routes:
                    console.print(
                        f"[yellow]the sealed lane overrode {', '.join(overridden_routes)}[/]\n"
                        "[grey58]those settings route to another provider, which would bypass the enclave "
                        "this panel just verified. This session goes to the enclave. To use that provider "
                        "instead, run without --confidential.[/]")
                if resuming:
                    argv = [binary, "--model", shown_model, "--resume", session_id, *passthrough, *status_args]
                else:
                    argv = [binary, "--model", shown_model, "--session-id", session_id, *passthrough, *status_args]
            elif agent == "pi":
                from . import pi_attested
                argv = pi_attested.env_argv(binary, env, passthrough, base_url=local, api_key=local_key,
                                            alias=alias, upstream_name=f"{alias.model_id} [confidential]",
                                            search_endpoint=search_endpoint)
                pi_confine_ports = [port] + ([int(search_endpoint.rsplit(":", 1)[1])] if search_endpoint else [])
            elif agent == "opencode":
                argv = agents_mod.opencode_env_argv(binary, env, passthrough, base_url=local, api_key=local_key,
                                                    alias=alias, upstream_name=f"{alias.model_id} [confidential]")
            elif agent == "goose":
                argv = agents_mod.goose_env_argv(binary, env, passthrough, base_url=local, api_key=local_key, alias=alias)
            elif agent == "openhands":
                argv = agents_mod.openhands_env_argv(binary, env, passthrough, base_url=local,
                                                     api_key=local_key, alias=alias)
            elif agent == "codewhale":
                argv = agents_mod.codewhale_env_argv(binary, env, passthrough, base_url=local,
                                                     api_key=local_key, alias=alias)
            else:
                console.print(f"[red]unknown agent {agent}[/]")
                return 2
            if not resuming:
                launch_mod._record_launch(session_id, alias.model_id, "confidential", agent=agent)
            console.print(f"[grey58]{'resuming' if resuming else 'launching'} {agent} on the confidential lane · "
                          f"local endpoint 127.0.0.1:{port}[/]\n")
            reset_sigint = lambda: signal.signal(signal.SIGINT, signal.SIG_DFL)  # noqa: E731
            preexec = reset_sigint
            sandbox = None
            if agent == "pi":
                from . import pi_attested
                ok_confine, notice = pi_attested.confine_precheck()
                if notice:
                    console.print(f"[grey58]{notice}[/]")
                if not ok_confine:
                    if agent == "pi":
                        pi_attested.stop_search_proxy()
                    server.should_exit = True
                    await server_task
                    session.close()
                    return 2
                write_paths = pi_attested.confine_write_paths(env["PI_CODING_AGENT_DIR"], os.getcwd())
                if pi_attested.netns_bind_intended():
                    # Address-level: an empty network namespace whose only channels out are unix sockets to
                    # the two verifying proxies, and a filesystem built up from nothing — the matter tree and
                    # the agent's own config, nothing else. The in-sandbox forwarder binds the ports the agent
                    # expects, THEN applies the same Landlock+seccomp confinement, then execs the agent.
                    try:
                        sandbox = pi_attested.netns_sandbox(ports=pi_confine_ports, cfg_dir=env["PI_CODING_AGENT_DIR"],
                                                            rw=[os.getcwd()], binary=binary,
                                                            # the one file of ours Pi loads by path. Read-only and
                                                            # exact: installed, it sits in the bound runtime anyway;
                                                            # run from source, nothing else would make it visible.
                                                            ro=[str(pi_attested.EXTENSION)])
                        argv = sandbox.wrap(argv, write_paths=write_paths)
                    except Exception as e:                                          # noqa: BLE001
                        console.print("[red]refusing to launch: address-level confinement was promised to this "
                                      f"session's records but the sandbox could not be built ({e}).[/]")
                        pi_attested.stop_search_proxy()
                        server.should_exit = True
                        await server_task
                        session.close()
                        return 2
                else:
                    preexec = pi_attested.preexec_confine(pi_confine_ports, write_paths=write_paths, then=reset_sigint)
            signal.signal(signal.SIGINT, signal.SIG_IGN)          # Claude Code owns Ctrl-C; we outlive it
            page = None
            if web:
                from . import probant_web
                page = await probant_web.start(probant=probant, session=session, search_endpoint=search_endpoint,
                                                workspace=Path(os.getcwd()), console=console)
                proc = await asyncio.create_subprocess_exec(*argv, env=env, preexec_fn=preexec,
                                                            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)
                # A browser session outlives its terminal, so `kill` from a shell is a real way to end one —
                # and on 17 Sep a wedged session took SIGKILL, which runs none of this program's cleanup and
                # leaves the matter's search verifier and its port behind. Handle it explicitly: end the
                # agent, and stop the page lingering afterwards, because the person asked for it all to stop.
                def _asked_to_stop() -> None:
                    page.bridge.closed.set()
                    asyncio.ensure_future(page.bridge.stop_agent())

                loop = asyncio.get_running_loop()
                for sig in (signal.SIGTERM, signal.SIGHUP):
                    try:
                        loop.add_signal_handler(sig, _asked_to_stop)
                    except (NotImplementedError, RuntimeError, ValueError):       # not POSIX, or no loop slot
                        pass
                rc = await page.bridge.pump(proc)
            else:
                proc = await asyncio.create_subprocess_exec(*argv, env=env, preexec_fn=preexec)
                rc = await proc.wait()
            if agent == "pi":
                from . import pi_attested
                if sandbox is not None:
                    sandbox.close()
                pi_attested.stop_search_proxy()
            server.should_exit = True
            await server_task
            session.close()
            console.print("")
            display.render_summary(session.receipt, console)
            unknown = ((page.bridge.ended or {}) if page is not None else {}).get("unrecognised") or {}
            if unknown:
                # Names only, never content. If a session ever hangs again, this line is the first thing to
                # ask for: an event the page could not act on is the shape the 17 Sep hang took.
                console.print("[grey58]for us, if anything looked stuck: the assistant sent "
                              + ", ".join(f"{k}×{v}" for k, v in unknown.items()) + " — events this page has no word for.[/]")
            if probant is not None and not web:
                console.print(f"\n  Keep the record of this matter:  [bold]ir probant export {probant.get('matter', '')}[/]\n")
            if page is not None:
                await page.linger(console)                     # the page stays up so the record can be exported
            return rc

    try:
        return asyncio.run(_run())
    except KeyboardInterrupt:
        if agent == "pi":
            from . import pi_attested
            pi_attested.stop_search_proxy()              # it now starts before the pause; never leave it running
        # Only reachable BEFORE claude starts (verification / instance discovery): after the
        # launch the parent ignores SIGINT and claude owns it. Nothing has been sent yet.
        console.print("\n[grey58]cancelled before anything was sent.[/]")
        return 130


# ───────────────────────── ir confidential … ─────────────────────────

def run(rest: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="ir confidential", description="the confidential lane")
    sub = ap.add_subparsers(dest="action")
    sub.add_parser("show", help="Re-print the last session's panel.")
    c = sub.add_parser("card", help="Export the last session's panel as an SVG card.")
    c.add_argument("--svg", default=None, help="output path (default: next to the receipt)")
    sub.add_parser("models", help="Models that can run confidentially.")
    d = sub.add_parser("daemon", help="A confidential session that outlives the command that started it.")
    d.add_argument("op", choices=("start", "status", "stop", "serve"))
    d.add_argument("--model", default=None)
    ns = ap.parse_args(rest)
    if not ns.action:
        ap.print_help()
        return 0
    _need_extra()
    if ns.action == "daemon":
        from . import confidential_daemon as daemon
        if ns.op == "start":
            return daemon.start(ns.model)
        if ns.op == "status":
            return daemon.status()
        if ns.op == "stop":
            return daemon.stop()
        return daemon.serve(ns.model)      # `serve` is the body the detached child runs

    from inferroute_local.confidential import display, receipt as receipt_mod
    console = _console()

    if ns.action == "models":
        from . import models as models_mod
        print()
        from . import lane as lane_mod
        # Through the floor: the standard-lane banner sends people to THIS command, so a downgraded
        # catalog must not be able to make its own advice wrong.
        for a in models_mod.all_aliases():
            if lane_mod.enclave_backed(a.short):
                print(f"  ir --confidential --model {a.short:<18} {a.label}")
        print()
        return 0

    r = receipt_mod.latest()
    if r is None:
        console.print("[grey58]no confidential session recorded yet — run `ir --confidential`[/]")
        return 1
    if ns.action == "show":
        display.render_panel(r, console)
        return 0
    if ns.action == "card":
        out = Path(ns.svg) if ns.svg else Path(r.path).with_suffix(".svg")
        display.save_svg(r, out)
        print(f"card written: {out}")
        return 0
    return 2
