"""Assemble the inputs an auditor needs to rebuild the enclave image and recompute HOST_DATA.

These go in the RECORD PACK, not in the published wheel. The wheel is anonymously fetchable, so
putting them there would publish them; the pack goes only to whoever receives the record. Same
verification either way, and the pack additionally covers them with the MANIFEST and SHA256SUMS the
auditor already checks, so they arrive integrity-checked by the mechanism already in use.

The ARM template is the hazard. The live one carries `imageRegistryCredentials` — a registry
username and password. This module refuses to emit a template that still contains a secret rather
than trusting a redaction to have worked.
"""
from __future__ import annotations

import copy
import json
import re
from typing import Any, Dict, List

# Keys whose VALUES are secret wherever they appear. Matched case-insensitively at any depth.
SECRET_KEYS = ("password", "secret", "key", "token", "credential", "sas", "sig", "connectionstring")
# Value shapes that are secret regardless of the key holding them.
SECRET_VALUE = re.compile(r"(sv=\d{4}-\d{2}-\d{2}|sig=[A-Za-z0-9%+/]{20,}|AccountKey=)", re.I)
REDACTED = "<redacted: not needed to regenerate the policy>"


def _walk(node: Any, path: str, found: List[str]) -> Any:
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            here = f"{path}.{k}"
            if any(s in k.lower() for s in SECRET_KEYS) and isinstance(v, str) and v:
                found.append(here)
                out[k] = REDACTED
            else:
                out[k] = _walk(v, here, found)
        return out
    if isinstance(node, list):
        return [_walk(v, f"{path}[{i}]", found) for i, v in enumerate(node)]
    if isinstance(node, str) and SECRET_VALUE.search(node):
        found.append(path)
        return REDACTED
    return node


def sanitise_arm_template(template: Dict[str, Any]) -> tuple[Dict[str, Any], List[str]]:
    """Return an auditor-safe copy of an ARM template, plus what was redacted.

    REFUSES rather than returns if anything secret-shaped survives the pass. A redaction that is
    believed rather than checked is how a credential reaches a client.
    """
    found: List[str] = []
    clean = _walk(copy.deepcopy(template), "$", found)
    blob = json.dumps(clean)
    # The check is deliberately not "did we redact" but "is anything left" — a different question,
    # and the only one that protects the recipient.
    leftover = SECRET_VALUE.findall(blob)
    if leftover:
        raise ValueError(
            f"refusing to emit an ARM template: {len(leftover)} secret-shaped value(s) survived "
            f"redaction. Sanitising must be verified, not assumed.")
    for k in SECRET_KEYS:
        for m in re.finditer(rf'"[^"]*{k}[^"]*"\s*:\s*"([^"]+)"', blob, re.I):
            if m.group(1) != REDACTED:
                raise ValueError(
                    f"refusing to emit an ARM template: a {k!r} field still holds a value")
    return clean, found
