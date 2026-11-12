"""Give a client machine its patent-search configuration, from files InferRoute publishes — safely.

A fresh install has no `confidential/search.json`, so the home page says search is not set up. Writing that
file by hand is what a developer does; a client cannot. This does it from three public files:

  https://inferroute.ai/reference/current.json         the signed reference: which sealed builds are ours
  https://inferroute.ai/reference/current.json.ots     its OpenTimestamps proof, when it has one
  https://inferroute.ai/probant/search.json            where the search machine is right now
  https://inferroute.ai/policy/<sha256>.rego           the container policy each reference entry names

WHAT IS TRUSTED, AND WHAT IS NOT. The publication key is NOT fetched: it is the one inside this program
(`trust/publication-key-attestation.json`, shipped in the wheel). The reference is accepted only if that key
signed it. The policy is accepted only if it hashes to the value a signed reference names. The search
machine's ADDRESS is routing information and nothing more: the local verifier attests whatever answers
there against the signed reference before any text is sent, so a wrong address costs availability, never
confidentiality. That is why the address can come from an unsigned file while the key cannot.

It never overwrites a configuration it did not write (a developer's, with its own `python`/`cwd`), and it
never goes further than a file under `confidential/`. Offline, it keeps what is already there.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import re
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from . import pi_attested
# The search gate's exact hosts (the search address once search.json names it): one list, kept with the code that
# sends the key, which checks it again for itself.
from ._searchgate.ir_search_gate import GATE_HOSTS, gate_base

# One rule with anteriora_billing (site_base): IR_SITE_BASE only when https on inferroute.ai or a subdomain.
from .site_base import site_base as _site_base  # noqa: E402
SITE = _site_base()
MARK = "ir probant setup-search"
MAX_BYTES = 1024 * 1024
TIMEOUT = 8.0


class SetupError(RuntimeError):
    """Said in plain words; nothing was changed."""


def pinned_key() -> str:
    """The publication key this program was released with. Never from the network, never from a config."""
    here = Path(__file__).resolve().parent
    for p in (here / "trust" / "publication-key-attestation.json",
              here.parent / "docs" / "trust" / "publication-key-attestation.json"):
        try:
            key = json.loads(p.read_text())["publication_key"]
        except (OSError, ValueError, KeyError):
            continue
        if isinstance(key, str) and re.fullmatch(r"[0-9a-f]{64}", key):
            return key
    raise SetupError("this copy of Anteriora does not carry InferRoute's publication key; reinstall it")


def _trust_file(name: str) -> bytes:
    """A file this program was released with (inferroute_cli/trust in a wheel, docs/trust in a checkout)."""
    here = Path(__file__).resolve().parent
    for p in (here / "trust" / name, here.parent / "docs" / "trust" / name):
        try:
            return p.read_bytes()
        except OSError:
            continue
    raise SetupError(f"this copy of Anteriora does not carry its pinned {name}; reinstall it")


def check_on_public_log(ref_bytes: bytes, proof: Optional[bytes]) -> Dict[str, Any]:
    """The reference must be on the public Sigsum log, logged with InferRoute's transparency key and cosigned by
    the pinned witness quorum. Checked offline against the proof served beside the reference: the client never
    contacts the log. A reference that is not there could have been shown to this computer alone, so it is refused.
    Returns what the proof established (log index, tree size, witness timestamps)."""
    from . import transparency as tl
    if proof is None:
        raise SetupError("the published reference has no proof that it is on InferRoute's public log, so it was "
                         "not used. Nothing was changed.")
    try:
        keys = tl.parse_ssh_ed25519_pubkeys(_trust_file("transparency-submitter.pub").decode())
        policy = tl.parse_policy(_trust_file("sigsum-policy.txt").decode())
        res = tl.verify_proof(ref_bytes, proof.decode("ascii", "strict"), keys, policy)
    except (tl.SigsumError, UnicodeDecodeError) as exc:
        raise SetupError("the published reference is not proven to be on InferRoute's public log "
                         f"({exc}), so it was not used. Nothing was changed.") from None
    return {"leaf_index": getattr(res, "leaf_index", None), "tree_size": getattr(res, "size", None)}


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "probant-setup-search"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            data = r.read(MAX_BYTES + 1)
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise SetupError(f"could not reach {url.split('//', 1)[-1].split('/', 1)[0]} ({getattr(e, 'reason', e)})") from e
    if len(data) > MAX_BYTES:
        raise SetupError(f"{url} is larger than expected")
    return data


def _parse(raw: bytes, url: str) -> Dict[str, Any]:
    try:
        v = json.loads(raw)
    except ValueError as e:
        raise SetupError(f"{url} is not valid JSON") from e
    if not isinstance(v, dict):
        raise SetupError(f"{url} is not what was expected")
    return v


def _json(url: str) -> Dict[str, Any]:
    return _parse(_get(url), url)


def _get_optional(url: str) -> Optional[bytes]:
    """The file if the site has it, None if it does not (404). Any other failure is still a failure."""
    req = urllib.request.Request(url, headers={"User-Agent": "probant-setup-search"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            data = r.read(MAX_BYTES + 1)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise SetupError(f"could not read {url.split('//', 1)[-1].split('/', 1)[0]} (HTTP {e.code})") from e
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise SetupError(f"could not reach {url.split('//', 1)[-1].split('/', 1)[0]} ({getattr(e, 'reason', e)})") from e
    if len(data) > MAX_BYTES:
        raise SetupError(f"{url} is larger than expected")
    return data


def fixed_endpoint(value: Any) -> str:
    """http(s)://host[:port] and nothing else: no path, credentials, query or fragment.

    Two kinds of address are accepted while search moves behind InferRoute's search gate: the machine's own (the
    rule above, unchanged), and the gate, which is recognised only as https://<one of GATE_HOSTS> exactly. Only
    the gate is sent the user's key and permit (_searchgate/ir_search_gate.py); any other host, a lookalike or a
    subdomain of the gate's included, is a direct address and gets neither. The gate's own name over http or on
    another port is refused here rather than kept as a direct address that could never search."""
    from urllib.parse import urlsplit
    s = urlsplit(str(value or ""))
    if (s.scheme not in ("http", "https") or not s.hostname or s.username or s.password
            or s.path not in ("", "/") or s.query or s.fragment):
        raise SetupError("the published search address is not a plain host and port")
    if (s.hostname or "").lower().rstrip(".") in GATE_HOSTS:
        gate = gate_base(str(value))
        if gate is None:
            raise SetupError("the published search address names InferRoute's search service, but not as "
                             "https://<its name> exactly, so it was not used")
        return gate
    return f"{s.scheme}://{s.netloc}"


def _atomic(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def setup(*, force: bool = False, now: Optional[dt.datetime] = None) -> Tuple[str, str]:
    """Returns (state, words). state: 'configured' | 'unchanged' | 'kept' (a config that is not ours)."""
    from . import reference as ref_mod
    cfg_path = pi_attested.search_config_path()
    conf_dir = cfg_path.parent
    existing: Dict[str, Any] = {}
    try:
        existing = json.loads(cfg_path.read_text())
    except (OSError, ValueError):
        pass
    if existing and existing.get("provisioned_by") != MARK and not force:
        return "kept", "A search configuration that Anteriora did not write is already here, so it was left alone."

    key = pinned_key()
    # The reference is kept BYTE FOR BYTE as published. Its OpenTimestamps proof (below) is over those exact
    # bytes, an auditor compares its hash with the site's, and re-serialising it — as the first version did,
    # 2705 bytes against 2511 — silently voids both. (Found by the first audit run on ADE, 3 Oct.)
    ref_bytes = _get(f"{SITE}/reference/current.json")
    ref = _parse(ref_bytes, f"{SITE}/reference/current.json")
    ok, why = ref_mod.verify(ref, key)
    if not ok:
        raise SetupError("the published reference is not signed by InferRoute's publication key, so it was not used "
                         f"({why}). Nothing was changed.")
    # ON THE PUBLIC LOG (0.9.138). A validly signed reference shown to this computer alone, and never to anyone
    # else, is the attack a transparency log closes: every reference an Anteriora accepts is one anybody can see.
    proof = _get_optional(f"{SITE}/reference/current.json.proof")
    check_on_public_log(ref_bytes, proof)
    # NO ROLLBACK. An older reference is still validly signed, and it may still accept images a newer one retired.
    # Whoever serves the site (InferRoute included) could hand it back, so a reference older than the one already
    # kept here, which verifies under the same key, is refused and the kept one stays in force.
    _held_path = conf_dir / "reference.json"
    if _held_path.is_file():
        try:
            _held = json.loads(_held_path.read_bytes())
        except ValueError:
            _held = None
        if isinstance(_held, dict) and ref_mod.verify(_held, key)[0]:
            _held_at, _new_at = str(_held.get("published_at") or ""), str(ref.get("published_at") or "")
            if _held_at and (not _new_at or _new_at < _held_at):
                raise SetupError(f"the site served a reference published {_new_at or '(no date)'}, older than the one "
                                 f"this computer already holds ({_held_at}). An older reference can still accept "
                                 "machines a newer one retired, so it was not used; the newer one stays in force.")
    at = now or dt.datetime.now(dt.timezone.utc)
    where = _json(f"{SITE}/probant/search.json")
    enclave = fixed_endpoint(where.get("enclave"))
    # Which kind of machine answers at that address. Intel TDX (from 1 Nov 2026, when the Azure/AMD lane was shut
    # down) has no container policy: the signed reference names the boot image instead, and the verifier checks the
    # quote against it before any text is sent. The field is routing information like the address: claiming TDX
    # for an AMD machine (or the reverse) makes the check fail, never pass.
    tdx = where.get("tee") == "intel-tdx"
    if tdx:
        if not ref_mod.current_entries(ref, "tdx_image_sha384", at):
            raise SetupError("the published reference names no Intel TDX search image that is current right now. "
                             "Nothing was changed.")
        current = []
    else:
        current = ref_mod.current_entries(ref, "policy_sha256", at)
        if not current:
            raise SetupError("the published reference names no search build that is current right now. Nothing was changed.")

    policy_path = None
    for entry in current:
        sha = entry["value"]
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            continue
        rego = _get(f"{SITE}/policy/{sha}.rego")
        if hashlib.sha256(rego).hexdigest() != sha:
            raise SetupError("a published policy does not match the hash the signed reference names. Nothing was changed.")
        policy_path = conf_dir / f"search-policy-{sha[:16]}.b64"
        _atomic(policy_path, base64.b64encode(rego))
        break
    if policy_path is None and not tdx:
        raise SetupError("the published reference names no usable policy. Nothing was changed.")

    ref_path = conf_dir / "reference.json"
    ots_path = Path(str(ref_path) + ".ots")          # where an exported record looks for it: beside the reference
    # The independent date for the reference. Optional on the site (an unanchored reference simply has none),
    # and it must be the proof for THESE bytes: a stale one beside a newer reference is removed, not kept.
    ots = _get_optional(f"{SITE}/reference/current.json.ots")
    # Index entries added under the reference's delegated index key (0.9.130): kept byte for byte beside the
    # reference, where the search verifier looks for it and judges it against the reference's signature. Optional;
    # a stale one beside a newer reference is removed (it would be ignored anyway: it names another base).
    ext = _get_optional(f"{SITE}/reference/current.json.index-extension.json")
    ext_path = Path(str(ref_path) + ".index-extension.json")
    proof_path = Path(str(ref_path) + ".proof")      # kept beside the reference, so a record can show it later
    wanted = {"enclave": enclave, "reference": str(ref_path), "reference_key": key, "provisioned_by": MARK}
    if policy_path is not None:
        wanted["policy_file"] = str(policy_path)
    hours = published_hours(where)
    if hours:
        wanted["availability"] = hours
    wake = published_wake(where)
    if wake:
        wanted["wake"] = wake
    unchanged = (existing == wanted and ref_path.is_file() and ref_path.read_bytes() == ref_bytes
                 and (ots_path.read_bytes() == ots if ots is not None and ots_path.is_file() else ots is None and not ots_path.exists())
                 and (ext_path.read_bytes() == ext if ext is not None and ext_path.is_file() else ext is None and not ext_path.exists())
                 and proof_path.is_file() and proof_path.read_bytes() == proof)
    _atomic(ref_path, ref_bytes)
    _atomic(proof_path, proof)
    if ots is not None:
        _atomic(ots_path, ots)
    elif ots_path.exists():
        ots_path.unlink()
    if ext is not None:
        _atomic(ext_path, ext)
    elif ext_path.exists():
        ext_path.unlink()
    _atomic(cfg_path, json.dumps(wanted, indent=1).encode() + b"\n")
    if unchanged:
        return "unchanged", "Patent search was already set up and is up to date."
    # ONLY WHAT WAS CHECKED. This run checked InferRoute's signed files, not the search machine: it may be
    # switched off (0.9.124: "Patent search is set up" was printed for a machine whose name did not resolve).
    return "configured", ("Patent search settings are in place: InferRoute's signed reference was checked on this "
                          "computer. The search machine itself is checked before each search, before any text is sent.")


# Where a client may ask for the search machine to be started. The request carries the user's InferRoute key (the wake
# service checks it with api.inferroute.ai), and search.json is routing information that is NOT signed, so the address
# is accepted only on an exact host InferRoute runs, listed here (not "anything under inferroute.ai": a forgotten
# subdomain pointing at a third party would receive keys). Anything else is dropped and the client offers no start
# button. The request itself never follows a redirect (probant_home._NO_REDIRECT).
WAKE_HOSTS = ("ir-search-wake-851040540464.europe-west4.run.app",)


def published_wake(where: Dict[str, Any]) -> Optional[str]:
    """https://host of the wake service, when search.json names an acceptable one; None otherwise."""
    from urllib.parse import urlsplit
    v = where.get("wake") if isinstance(where, dict) else None
    if not isinstance(v, str):
        return None
    try:
        s = urlsplit(v)
        host, port = (s.hostname or "").lower(), s.port
    except ValueError:                                      # e.g. a port that is not a number: no button, setup goes on
        return None
    if (s.scheme != "https" or s.username or s.password or port or s.path not in ("", "/") or s.query or s.fragment
            or host not in WAKE_HOSTS):
        return None
    return f"https://{host}"


def published_hours(where: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The search machine's opening hours, when the published file states them; None otherwise.

    The home page shows them when a search machine is offline. Only a well-formed daily window is kept (two
    whole hours and a timezone name); anything else is dropped rather than shown, so a page never states hours
    nobody published. Like the address, this is availability information: it decides nothing about trust."""
    a = where.get("availability") if isinstance(where, dict) else None
    if not isinstance(a, dict) or a.get("mode") != "scheduled":
        return None
    w, tz = a.get("window"), a.get("tz")
    if (not isinstance(w, list) or len(w) != 2 or not all(isinstance(h, int) and 0 <= h <= 24 for h in w)
            or not isinstance(tz, str) or not re.fullmatch(r"[A-Za-z_]+(/[A-Za-z_+-]+)*", tz)):
        return None
    return {"mode": "scheduled", "window": [w[0], w[1]], "tz": tz}


def reachable(enclave: str) -> str:
    """Whether anything answers at the search address right now: "up", "unreachable" or "unknown-host".
    Liveness only, never a verification (the home page's own probe, so the two say the same)."""
    from .probant_home import _search_probe_state
    return _search_probe_state(enclave)


def ensure_quietly() -> None:
    """Called when Probant starts and when a matter opens: keep what setup() wrote current, say nothing,
    never stop anything. A machine with no config of ours and no network just stays as it was."""
    try:
        setup()
    except Exception:                                       # noqa: BLE001
        pass


def main_setup(force: bool = False) -> int:
    import sys
    try:
        state, words = setup(force=force)
    except SetupError as e:
        sys.stderr.write(f"\n  Patent search was not set up: {e}\n\n")
        return 1
    print(f"\n  {words}")
    if state != "kept":
        try:
            enclave = str(json.loads(pi_attested.search_config_path().read_text()).get("enclave") or "")
            up = reachable(enclave) == "up" if enclave else None
        except Exception:                                   # noqa: BLE001
            up = None
        if up is True:
            print("  The search machine is answering right now.")
        elif up is False:
            print("  The search machine is not answering right now, so patent search is offline for the moment.\n"
                  "  Name checks and readings work without it.")
    print("")
    return 0
