"""`ir pi` on the confidential lane: Pi launched so that the only code running inside it is ours, its
model requests can only reach this session's local sealed endpoint, and what this device verified is
shown in Pi's own UI rather than relayed by the model.

What the launch sets, and why (each measured on Pi 0.84.1, see the attested-agent log):

  -ne -e <ours>      extension discovery off: the user's global, settings-listed and project-local
                     extensions never load into a process that holds the plaintext. Ours loads.
  -na                project-local Pi files (settings, skills, prompts) are ignored.
  own config dir     a fresh PI_CODING_AGENT_DIR declaring one provider. The user's settings, auth and
                     models are not mirrored in; only their sessions are shared.
  no_proxy/NO_PROXY  loopback is never proxied. Pi routes all HTTP through the proxy variables, so an
                     HTTP_PROXY in the user's environment would otherwise receive the plaintext hop to
                     127.0.0.1. Both spellings, because the lowercase one takes precedence.
  PI_OFFLINE         no startup network activity (update checks, tool downloads).
  --tools            an allowlist without a shell until the agent's network is confined.

The extension refuses, at request time, any model request that is not addressed to this session's
endpoint, or that would be sent while the session's verdict is anything but verified.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from pathlib import Path

from . import agents

EXTENSION = Path(__file__).resolve().parent / "pi_attested" / "ir-attested.ts"
PROVIDER = "inferroute"
TOOLS = ("read", "edit", "write", "grep", "find", "ls")
LOOPBACK = ("127.0.0.1", "localhost", "::1")

# ── the mission contract (see pi_attested/{preamble,contract}.md and the decision record) ──
# The model's whole system prompt is preamble then contract, with HTML comments stripped. The prompt
# REPLACES Pi's default persona (--system-prompt), verified by capture to leave only a "cwd" line.
# The expected sha of each, over the SENT (stripped) bytes, is pinned here: the contract is fixed and
# changed only deliberately. A drifted on-disk sha is not silently run — the panel and session record
# say "contract modified" and the launch carries the flag.
PREAMBLE_FILE = Path(__file__).resolve().parent / "pi_attested" / "preamble.md"
CONTRACT_FILE = Path(__file__).resolve().parent / "pi_attested" / "contract.md"
PINNED_PREAMBLE_SHA = "02c4257239c895fd11e63a13f1870bf3c7bd932c391591495325a72b951290e1"
PINNED_CONTRACT_SHA = "1d9422a139614fdcd175a3066bcd75b431fd09066802848351169a1d83e1d702"


def _strip_comments(text: str) -> str:
    """The bytes actually sent to the model: HTML comments removed, one trailing newline."""
    return re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL).strip() + "\n"


def load_contract() -> dict:
    """Return {text, preamble_sha, contract_sha, modified} for the launch. `text` is preamble then
    contract, comments stripped. `modified` is True if either sha differs from the pinned value."""
    preamble = _strip_comments(PREAMBLE_FILE.read_text())
    contract = _strip_comments(CONTRACT_FILE.read_text())
    p_sha = hashlib.sha256(preamble.encode()).hexdigest()
    c_sha = hashlib.sha256(contract.encode()).hexdigest()
    return {"text": preamble + "\n" + contract, "preamble_sha": p_sha, "contract_sha": c_sha,
            "modified": p_sha != PINNED_PREAMBLE_SHA or c_sha != PINNED_CONTRACT_SHA}


def config_hash(alias, tools: tuple) -> str:
    """A hash of the launch config that shapes what the assistant is and can do — model, tool
    allowlist, provider — so the session record can pin the configuration it ran under."""
    payload = json.dumps({"model": getattr(alias, "short", ""), "provider": PROVIDER, "tools": sorted(tools)},
                         sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def pi_version(binary: str) -> str:
    import subprocess
    try:
        return subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=10).stdout.strip()[:40]
    except Exception:                                       # noqa: BLE001
        return "unknown"
# Passthrough flags that would load other code, change where requests go, or widen the tool set.
REFUSED_FLAGS = {
    "-e": "loads another extension", "--extension": "loads another extension",
    "--provider": "changes where model requests go", "--api-key": "changes where model requests go",
    "--models": "adds models outside the enclave",
    "-t": "changes the tool allowlist", "--tools": "changes the tool allowlist",
    "-a": "trusts project-local Pi files", "--approve": "trusts project-local Pi files",
    # D2: sessions are writable and persistent, so resuming one could re-inject an edited transcript.
    # v1 is a fresh session per launch; continuity belongs to the host-held matter docket, not Pi transcripts.
    "-r": "resumes a persisted transcript (disabled in attested mode)",
    "--resume": "resumes a persisted transcript (disabled in attested mode)",
    "-c": "continues a persisted transcript (disabled in attested mode)",
    "--continue": "continues a persisted transcript (disabled in attested mode)",
    "--fork": "forks a persisted transcript (disabled in attested mode)",
}
_HELPERS = ("fd", "rg")


class Refused(ValueError):
    """The launch cannot be made attested as asked; the message says which flag and why."""


def check_passthrough(passthrough: list[str]) -> None:
    for arg in passthrough:
        flag = arg.split("=", 1)[0]
        if flag in REFUSED_FLAGS:
            raise Refused(f"`{flag}` is not accepted on the attested lane: it {REFUSED_FLAGS[flag]}. "
                          "Use `ir pi --plain` for an unattested session.")


def _with_loopback(value: str | None) -> str:
    have = [h.strip() for h in (value or "").split(",") if h.strip()]
    return ",".join(list(LOOPBACK) + [h for h in have if h not in LOOPBACK])


# The only entries an attested config dir may hold. Anything else — a planted AGENTS.md, a rogue
# extension, a settings override — is removed on every launch, so a previous session cannot leave
# something the next session's Pi would load. cfg is writable under confinement, so this matters.
_CFG_KEEP = ("models.json", "settings.json", "bin", "sessions", "tmp", "attested-sessions")


def config_dir(base_url: str, api_key: str, alias, upstream_name: str, headers: dict | None = None,
               quiet: bool = False) -> Path:
    """A stable ir-owned Pi config dir, scrubbed on every launch to exactly the known-good entries. Keeps
    `bin/` (Pi's helper binaries) so offline launches still have them; sessions are a REAL dir here (not a
    symlink out), so Pi can write them under the filesystem confinement; nothing of the user's is mirrored."""
    user_dir = Path(os.environ.get("PI_CODING_AGENT_DIR") or (Path.home() / ".pi" / "agent"))
    home = Path(os.environ.get("INFERROUTE_HOME") or (Path.home() / ".inferroute"))
    d = home / "pi-attested"
    d.mkdir(parents=True, exist_ok=True)
    for entry in d.iterdir():
        if entry.name not in _CFG_KEEP:
            (shutil.rmtree if entry.is_dir() and not entry.is_symlink() else (lambda p: p.unlink()))(entry)
        elif entry.name == "sessions" and entry.is_symlink():
            entry.unlink()                    # a prior symlink-out; replace with a real dir below
    doc = agents.pi_models_json(base_url, api_key, alias, upstream_name, headers, existing=None)
    (d / "models.json").write_text(json.dumps(doc, indent=1))
    # `quiet`: a Surveyor session hides Pi's developer start-up header (key bindings, "! bash", resource
    # paths) and the model's thinking; the attorney has been shown what matters on the card, and reads the answer.
    (d / "settings.json").write_text(json.dumps({"enableInstallTelemetry": False, "defaultProjectTrust": "never",
                                                 **({"quietStartup": True, "hideThinkingBlock": True} if quiet else {})}, indent=1))
    (d / "sessions").mkdir(exist_ok=True)     # real dir, writable under confinement (was a symlink to ~/.pi)
    (d / "attested-sessions").mkdir(exist_ok=True)
    # cfg/bin helpers run inside the sandbox and are agent-writable; re-copy them each launch so a prior
    # session cannot leave a tampered fd/rg that a later session's grep/find would run.
    _provision_helpers(d / "bin", [user_dir / "bin", home / "pi-agent" / "bin"], force=True)
    return d


def _provision_helpers(bin_dir: Path, sources: list[Path], force: bool = False) -> None:
    bin_dir.mkdir(exist_ok=True)
    for name in _HELPERS:
        if (bin_dir / name).exists() and not force:
            continue
        for src in sources:
            if (src / name).is_file() and os.access(src / name, os.X_OK):
                shutil.copy2(src / name, bin_dir / name)
                break


# ── W1: the workspace is writable under confinement, so it must never be a protected tree ──
class UnsafeWorkspace(ValueError):
    """The launch directory would make a protected tree writable under the sandbox."""


def _protected() -> tuple[set, list]:
    """(exact_deny, tree_deny). exact: cwd must not BE these. tree: cwd must not be, be inside, or contain
    these. Home is exact-only so an ordinary ~/subdir is fine, but its sensitive children are trees, and
    so is INFERROUTE_HOME (which holds the config dir and the state/search.json the agent must not write)."""
    def rp(p: Path) -> Path:
        try:
            return p.resolve()
        except OSError:
            return p
    home = rp(Path.home())
    irhome = rp(Path(os.environ.get("INFERROUTE_HOME") or (Path.home() / ".inferroute")))
    exact = {rp(Path("/")), home}
    trees = [irhome] + [rp(home / n) for n in (".ssh", ".config", ".aws", ".gnupg", ".pi")]
    return exact, trees


def check_workspace(cwd: str) -> str:
    """Resolve `cwd` (so a symlink to ~ is caught) and refuse it if it would expose a protected tree once
    added to the write allow-set — launching from ~ or ~/.inferroute reopens the plant-and-run escape.
    An ordinary project or matter folder under home is fine. Returns the resolved path or raises."""
    real = Path(cwd).resolve()
    exact, trees = _protected()
    if real in exact:
        raise UnsafeWorkspace(f"refusing to run in {real}: run from a project or matter folder, not your "
                              "home or filesystem root.")
    for t in trees:
        if real == t or t in real.parents or real in t.parents:
            raise UnsafeWorkspace(f"refusing to run here: {real} is, is inside, or contains {t}. "
                                  "Run from a project or matter folder, not a config or key directory.")
    return str(real)


def env_argv(binary: str, env: dict, passthrough: list[str], *, base_url: str, api_key: str, alias, upstream_name: str,
             headers: dict | None = None, search_endpoint: str | None = None) -> list[str]:
    """`search_endpoint`: the loopback address of a running local search verifier; adds `prior_art_search`."""
    check_passthrough(passthrough)
    cfg = config_dir(base_url, api_key, alias, upstream_name, headers, quiet=bool(env.get("IR_SURVEYOR_SURFACE")))
    tools = TOOLS + ((SEARCH_TOOL, MARKS_TOOL, NEXT_TOOL) if search_endpoint else ())
    env["PI_CODING_AGENT_DIR"] = str(cfg)
    env["PI_OFFLINE"] = "1"
    env["PI_SKIP_VERSION_CHECK"] = "1"
    env["PI_TELEMETRY"] = "0"
    env["IR_ATTESTED_ENDPOINT"] = base_url.rstrip("/")
    env["IR_ATTESTED_PROVIDER"] = PROVIDER
    env["IR_ATTESTED_TOOLS"] = ",".join(tools)
    if search_endpoint:
        env["IR_SEARCH_ENDPOINT"] = search_endpoint.rstrip("/")
    else:
        env.pop("IR_SEARCH_ENDPOINT", None)
    for name in ("no_proxy", "NO_PROXY"):
        env[name] = _with_loopback(env.get("no_proxy") if env.get("no_proxy") is not None else env.get("NO_PROXY"))
    # The mission contract as the whole system prompt (replaces Pi's persona). Written to the ir-owned
    # config dir; its stamps go to the extension for the panel and the session record.
    contract = load_contract()
    sp = cfg / "system-prompt.txt"
    sp.write_text(contract["text"])
    env["IR_CONTRACT_SHA"] = contract["contract_sha"]
    env["IR_PREAMBLE_SHA"] = contract["preamble_sha"]
    env["IR_CONTRACT_MODIFIED"] = "1" if contract["modified"] else "0"
    env["IR_CONFIG_HASH"] = config_hash(alias, tools)
    env["IR_PI_VERSION"] = pi_version(binary)
    # A private tmp inside the (writable) config dir, so Node's temp files land somewhere the write
    # confinement allows rather than in /tmp.
    (cfg / "tmp").mkdir(exist_ok=True)
    env["TMPDIR"] = str(cfg / "tmp")
    # The disclosure record goes to a writable, ir-owned dir (cfg is in the write allow-set), NOT under
    # confidential/ which the filesystem confinement denies the agent.
    env["IR_ATTESTED_RECORD_DIR"] = str(cfg / "attested-sessions")
    # A Surveyor session keeps no Pi transcript. The record of a matter is the host-side record the export
    # reads; a transcript would be a second, plain-text copy of the disclosure nobody is told about, and Pi's
    # exit line "To resume this session: pi --session …" would invite continuing it in plain `pi`, unsealed.
    ephemeral = ["--no-session"] if env.get("IR_SURVEYOR_SURFACE") else []
    return [binary, "-ne", "-e", str(EXTENSION), "-na", "-nc", *ephemeral, "--tools", ",".join(tools),
            "--system-prompt", str(sp),
            "--provider", PROVIDER, "--model", alias.short, "--models", f"{PROVIDER}/{alias.short}", *passthrough]


# ───────────────────────── the local search verifier ─────────────────────────
#
# A sibling of Pi, started by this launcher, so it stays outside anything applied to Pi's process tree.
# Configured by INFERROUTE_HOME/confidential/search.json:
#   {"python": ".../bin/python", "cwd": "<dir holding the verifier package>", "enclave": "<address>",
#    "reference": "<signed reference JSON>", "reference_key": "<publication key hex>" (production identity),
#    "expect_host_data": "<pinned container policy hash>" (fallback, or cross-check), "expect_index": optional,
#    "pins": optional, "policy_file": optional base64 CCE policy archived into each evidence bundle,
#    "cutoff_date": optional YYYYMMDD (the matter's date bound; host-held), "state_file": optional path
#    to the matter state file OUTSIDE the sandbox (approvals/marks/cutoff the agent must not forge)}

SEARCH_TOOL = "prior_art_search"
# Offered with search: the professional's marks (read-only) and one-click next steps. Every tool must be in the
# launch allowlist, or the extension refuses the call.
MARKS_TOOL = "matter_marks"
NEXT_TOOL = "suggest_next_steps"
_SEARCH_PROXIES: list = []


def search_config_path() -> Path:
    return Path(os.environ.get("INFERROUTE_HOME") or (Path.home() / ".inferroute")) / "confidential" / "search.json"


def _die_with_parent() -> None:
    """Linux: have the kernel end the search verifier when the launcher dies, however it dies. A launcher
    killed outright runs none of its own cleanup, and a verifier left behind keeps a matter's state file and a
    loopback port. Elsewhere this is a no-op; the launcher's normal exit still stops it."""
    import sys
    if not sys.platform.startswith("linux"):
        return
    try:
        import ctypes
        import signal as _signal
        ctypes.CDLL(None, use_errno=True).prctl(1, int(_signal.SIGTERM))      # PR_SET_PDEATHSIG
    except Exception:                                       # noqa: BLE001
        pass


def start_search_proxy(timeout: float = 30.0) -> str | None:
    """Start the verifier and return its loopback address, or None (the session then has no search tool)."""
    import select
    import subprocess
    import sys
    try:
        cfg = json.loads(search_config_path().read_text())
    except (OSError, ValueError):
        return None
    argv = [cfg["python"], "-m", "sealedresearch.search_verifier", "serve", "--enclave", cfg["enclave"],
            *_search_pin_args(cfg), "--port", "0"]
    # The cutoff/state/record for THIS matter come as per-matter arguments (S2): `ir surveyor open` sets
    # them in the env from the host-held matter record, so the shared search.json is never mutated per
    # launch (no race, no writable date bound). Fall back to search.json only when no matter is open.
    cutoff = os.environ.get("IR_MATTER_CUTOFF") or cfg.get("cutoff_date")
    if cutoff:
        argv += ["--cutoff", str(cutoff)]
    state_file = os.environ.get("IR_MATTER_STATE_FILE") or cfg.get("state_file")
    if state_file:
        argv += ["--state-file", state_file]
        # Trust approvals persisted in the state file (no re-prompt each session) ONLY when this launch is
        # confined in require mode (Q1): forging an approval needs a WRITE to the state file, and require
        # mode means the write-scoped Landlock is enforced (confidential/ is not in the write set) or Pi
        # does not start. Never trust disk under a dev override or a port-level fallback where the sandbox
        # may not apply — there, approvals stay memory-only and are re-prompted.
        if confine_required() and not confine_disabled():
            argv += ["--trust-state"]
    # The disclosure record is written by the verifier to a file under confidential/, which the fs
    # confinement denies the agent (D1). One file PER SESSION (Q2): a fresh, unique path each launch, so a
    # later session never overwrites what an earlier one disclosed. When a matter is open the file lands in
    # that matter's records dir; otherwise in the flat attested-records dir.
    import time as _time
    sess_id = _time.strftime("%Y%m%dT%H%M%SZ", _time.gmtime()) + "-" + os.urandom(4).hex()
    rec_dir = os.environ.get("IR_MATTER_RECORD_DIR")
    rec_dir = Path(rec_dir) if rec_dir else \
        Path(os.environ.get("INFERROUTE_HOME") or (Path.home() / ".inferroute")) / "confidential" / "attested-records"
    rec_dir.mkdir(parents=True, exist_ok=True)
    argv += ["--record-file", str(rec_dir / f"{sess_id}.json")]
    # The per-search archive (signed statement + opened result + attestation evidence), kept verbatim
    # host-side per session so the export can rebuild each search's report and prove its binding (step 6).
    argv += ["--archive-file", str(rec_dir / f"{sess_id}.searches.jsonl")]
    # The deployed container policy (base64), so each search's evidence bundle can prove HOST_DATA = sha256(policy)
    # to a third party. Optional: search.json "policy_file" names the file holding the base64 policy.
    if cfg.get("policy_file"):
        argv += ["--policy-file", str(cfg["policy_file"])]
    if os.environ.get("IR_REPORT_MATTER"):
        argv += ["--report-matter", os.environ["IR_REPORT_MATTER"]]
    if os.environ.get("IR_REPORT_FIRM"):
        argv += ["--report-firm", os.environ["IR_REPORT_FIRM"]]
    # The confinement line is stamped host-side by the verifier from this label (F1 / d3): a dev-unconfined
    # session cannot ship looking confined, because the extension never gets to assert this field.
    argv += ["--confinement", confinement_label()]
    # This launch's session id, host-side source for who surfaced a document and who marked it (M1).
    argv += ["--session-id", sess_id]
    try:
        proc = subprocess.Popen(argv, cwd=cfg.get("cwd"), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                preexec_fn=_die_with_parent)
    except (OSError, KeyError):
        sys.stderr.write("\n  prior-art search is unavailable this session: the local search verifier did not start.\n\n")
        return None
    ready, _, _ = select.select([proc.stdout], [], [], timeout)
    try:
        port = int(json.loads(proc.stdout.readline())["listening"]) if ready else 0
    except (ValueError, KeyError, TypeError):
        port = 0
    if not port:
        proc.terminate()
        sys.stderr.write("\n  prior-art search is unavailable this session: the local search verifier did not start.\n\n")
        return None
    _SEARCH_PROXIES.append(proc)
    return f"http://127.0.0.1:{port}"


def _search_pin_args(cfg: dict) -> list[str]:
    """How the search verifier knows which enclave is ours. With a signed reference and its publication key
    (the production path) the verifier checks the signature at startup and derives the pins from it; a bare
    expect_host_data is the fallback for setups without one. Both are passed when both are configured — the
    verifier refuses if they disagree."""
    argv: list[str] = []
    if cfg.get("reference") and cfg.get("reference_key"):
        argv += ["--reference", str(cfg["reference"]), f"--reference-key={cfg['reference_key']}"]
    if cfg.get("expect_host_data"):
        argv += ["--expect-host-data", cfg["expect_host_data"]]
    if cfg.get("expect_index"):
        argv += ["--expect-index", cfg["expect_index"]]
    if cfg.get("pins"):
        argv += ["--pins", cfg["pins"]]
    return argv


def verify_search_once(timeout: float = 120.0) -> dict | None:
    """One live check of the configured search enclave, outside any session (`ir surveyor proof`). Same
    verifier, same pins as a session's proxy. None when search is not configured on this computer."""
    import subprocess
    try:
        cfg = json.loads(search_config_path().read_text())
    except (OSError, ValueError):
        return None
    argv = [cfg["python"], "-m", "sealedresearch.search_verifier", "verify", "--enclave", cfg["enclave"],
            *_search_pin_args(cfg)]
    try:
        out = subprocess.run(argv, cwd=cfg.get("cwd"), capture_output=True, text=True, timeout=timeout).stdout
        res = json.loads(out)
        return res if isinstance(res, dict) else {"ok": False, "refusal": "the search verifier answered nonsense", "steps": []}
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
        return {"ok": False, "refusal": "the search verifier did not answer", "steps": []}


def search_verification(endpoint: str | None, timeout: float = 90.0) -> dict | None:
    """The search verifier's live check of the search enclave (GET /enclave), for the launch screen. None when
    this session has no search; a refusal dict when the verifier does not answer — never an exception."""
    if not endpoint:
        return None
    import urllib.request
    try:
        with urllib.request.urlopen(f"{endpoint}/enclave", timeout=timeout) as r:     # loopback only
            out = json.loads(r.read())
        return out if isinstance(out, dict) else {"ok": False, "refusal": "the local search verifier answered nonsense", "steps": []}
    except Exception:                                        # noqa: BLE001
        return {"ok": False, "refusal": "the local search verifier did not answer", "steps": []}


def stop_search_proxy() -> None:
    while _SEARCH_PROXIES:
        proc = _SEARCH_PROXIES.pop()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:                                   # noqa: BLE001
            proc.kill()


# ───────────────────────── egress confinement ─────────────────────────
#
# Confine Pi's whole process tree to the local verifying proxies and nothing else, so a compromised or
# injected agent still cannot reach the network except through them. On a platform that cannot do it,
# warn and launch unconfined unless IR_ATTESTED_CONFINE=require, which refuses instead.

def confine_disabled() -> bool:
    return os.environ.get("IR_ATTESTED_CONFINE", "").strip().lower() in ("0", "off", "no", "none")


def confine_required() -> bool:
    return os.environ.get("IR_ATTESTED_CONFINE", "").strip().lower() in ("1", "require", "required", "strict")


def netns_bind_intended() -> bool:
    """True when this launch will run the agent in an empty netns with only the matter tree bound in.
    Set by the launcher BEFORE the proxies start, and honoured only on a path that ABORTS the launch if the
    sandbox cannot then be built — so the label can never say "address-level" for a session that ran without
    it. Requested and applied are the same thing here by construction."""
    return os.environ.get("IR_ATTESTED_NETNS_BIND") == "1"


def plan_netns_bind() -> bool:
    """Whether THIS launch will run the agent in the empty-netns bind: require mode, on a machine that can
    build it. Decided BEFORE the verifier starts, because the verifier stamps the confinement line into
    every record from this decision — and the launcher refuses to start if the sandbox then fails to build,
    so a record can never claim a confinement its session did not run under."""
    if confine_disabled() or os.environ.get("IR_SURVEYOR_DEV_UNCONFINED") == "1" or not confine_required():
        return False
    from inferroute_local import confinement
    return confinement.netns_bind_available()


def netns_sandbox(*, ports, cfg_dir: str, rw, ro=(), binary: str = ""):
    """The sandbox for the launch path. Raises netns.NetnsUnavailable; the caller must refuse to launch."""
    from inferroute_local import netns
    return netns.NetnsSandbox(ports=ports, cfg_dir=cfg_dir, rw=rw, ro=ro, binary=binary)


def run_in_netns_bind(argv, *, ports, cfg_dir: str, rw, ro=(), env=None, binary: str = "", timeout=None):
    """Run a command inside the sandbox synchronously. The acceptance test for step 7 drives this."""
    from inferroute_local import netns
    return netns.run_in_netns_bind(argv, ports=ports, cfg_dir=cfg_dir, rw=rw, ro=ro, env=env,
                                   binary=binary, timeout=timeout)


def confinement_label() -> str:
    """The confinement line the verifier stamps into every disclosure record — asserted host-side from the
    launch env, not from anything the sandbox composes. In require mode the launch refuses unless the
    sandbox actually applies, so by the time any search runs the line is accurate."""
    if os.environ.get("IR_SURVEYOR_DEV_UNCONFINED") == "1":
        return "unconfined (developer override)"
    if confine_disabled():
        return "not confined"
    if netns_bind_intended():
        from inferroute_local import netns
        return netns.ADDRESS_LEVEL_LABEL
    if confine_required():
        return "require (address-level egress enforced or the session does not start)"
    return "best-effort (port-level; not required)"


def confine_write_paths(cfg_dir: str, cwd: str) -> list[str]:
    """The only trees the confined agent may WRITE: its own config/session dir, the matter workspace, a
    private tmp, and the two device files Pi needs. Everything else — search.json, the matter state file,
    ~/.bashrc, ~/.ssh, git hooks — is write-denied, closing the plant-and-run-later escape."""
    cfg = Path(cfg_dir)
    return [str(cfg), cwd, str(cfg / "tmp"), "/dev/null", "/dev/tty"]


def preexec_confine(ports: list[int], write_paths: list[str] | None = None, then=None):
    """A preexec_fn that confines the child to `ports` (TCP) and `write_paths` (filesystem writes), then
    runs `then` (e.g. reset SIGINT). Confinement failure raises only when IR_ATTESTED_CONFINE=require;
    otherwise the child launches unconfined and a one-line notice is printed once from the parent."""
    from inferroute_local import confinement

    def _fn():
        try:
            confinement.apply([p for p in ports if p], write_paths=write_paths)
        except confinement.Unavailable:
            if confine_required():
                raise
        if then is not None:
            then()
    if not confine_disabled():
        return _fn
    return then if then is not None else (lambda: None)


def confine_precheck() -> tuple[bool, str]:
    """(ok_to_launch, notice). In require mode the launch must refuse unless egress can be confined by
    ADDRESS (an empty network namespace); it names the one-time install that provides it. Otherwise the
    port-level Landlock+seccomp confinement is used and its residual is stated."""
    import sys
    from inferroute_local import confinement
    if confine_disabled():
        return True, ""
    linux = sys.platform == "linux"
    try:
        abi = confinement.landlock_abi(__import__("ctypes").CDLL(None, use_errno=True)) if linux else 0
    except Exception:                                       # noqa: BLE001
        abi = 0
    # The same probe the sandbox constructor uses. Testing a weaker one here would let the launch pass a
    # check for "address-level" and then fail to build the thing that provides it.
    address_level = linux and confinement.netns_bind_available()
    if confine_required():
        if address_level:
            return True, ("network confined to the local proxies by ADDRESS (empty network namespace), and "
                          "the filesystem built up from nothing — other files are absent, not merely unwritable")
        if linux and confinement.userns_restricted():
            return False, ("IR_ATTESTED_CONFINE=require, but address-level confinement needs the one-time "
                           "AppArmor profile — run scripts/install-confine-profile.sh once (sudo), then retry. "
                           "Refusing to launch with only port-level confinement.")
        return False, ("IR_ATTESTED_CONFINE=require, but this platform cannot confine egress by address "
                       "(needs Linux with bubblewrap and unprivileged network namespaces). Refusing to launch.")
    if linux and abi >= 4:
        # Best-effort is port-level: Landlock matches a port NUMBER, and it bounds writes but not reads.
        # Both residuals are stated, because only the require-mode bind removes them, and a reader who is
        # told "confined" without them would read more into the word than it carries here.
        residual = (" (port-level: a remote host on an allowed port number is still reachable, and file READS "
                    "are not confined — the agent can read other files into model context; install the AppArmor "
                    "profile and set IR_ATTESTED_CONFINE=require for the address-level bind, which removes both)")
        return True, "network confined to the local proxies" + residual
    return True, ("this platform cannot confine the agent's network (needs Linux with Landlock ABI 4); "
                  "the agent could reach the network directly — set IR_ATTESTED_CONFINE=require to refuse instead")
