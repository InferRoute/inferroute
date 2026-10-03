"""Give a client machine its patent-search configuration, from files InferRoute publishes — safely.

A fresh install has no `confidential/search.json`, so the home page says search is not set up. Writing that
file by hand is what a developer does; a client cannot. This does it from three public files:

  https://inferroute.ai/reference/current.json         the signed reference: which sealed builds are ours
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

SITE = os.environ.get("IR_SITE_BASE", "https://inferroute.ai").rstrip("/")
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
    raise SetupError("this copy of Probant does not carry InferRoute's publication key; reinstall it")


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


def _json(url: str) -> Dict[str, Any]:
    try:
        v = json.loads(_get(url))
    except ValueError as e:
        raise SetupError(f"{url} is not valid JSON") from e
    if not isinstance(v, dict):
        raise SetupError(f"{url} is not what was expected")
    return v


def fixed_endpoint(value: Any) -> str:
    """http(s)://host[:port] and nothing else: no path, credentials, query or fragment."""
    from urllib.parse import urlsplit
    s = urlsplit(str(value or ""))
    if (s.scheme not in ("http", "https") or not s.hostname or s.username or s.password
            or s.path not in ("", "/") or s.query or s.fragment):
        raise SetupError("the published search address is not a plain host and port")
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
        return "kept", "A search configuration that Probant did not write is already here, so it was left alone."

    key = pinned_key()
    ref = _json(f"{SITE}/reference/current.json")
    ok, why = ref_mod.verify(ref, key)
    if not ok:
        raise SetupError("the published reference is not signed by InferRoute's publication key, so it was not used "
                         f"({why}). Nothing was changed.")
    at = now or dt.datetime.now(dt.timezone.utc)
    current = ref_mod.current_entries(ref, "policy_sha256", at)
    if not current:
        raise SetupError("the published reference names no search build that is current right now. Nothing was changed.")
    where = _json(f"{SITE}/probant/search.json")
    enclave = fixed_endpoint(where.get("enclave"))

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
    if policy_path is None:
        raise SetupError("the published reference names no usable policy. Nothing was changed.")

    ref_path = conf_dir / "reference.json"
    new_ref = json.dumps(ref, indent=2, sort_keys=True).encode() + b"\n"
    wanted = {"enclave": enclave, "reference": str(ref_path), "reference_key": key,
              "policy_file": str(policy_path), "provisioned_by": MARK}
    unchanged = (existing == wanted and ref_path.is_file() and ref_path.read_bytes() == new_ref)
    _atomic(ref_path, new_ref)
    _atomic(cfg_path, json.dumps(wanted, indent=1).encode() + b"\n")
    if unchanged:
        return "unchanged", "Patent search was already set up and is up to date."
    return "configured", "Patent search is set up. Probant checks the search machine against InferRoute's signed reference before any text is sent."


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
    print(f"\n  {words}\n")
    return 0
