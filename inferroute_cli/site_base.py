"""Which InferRoute site this program talks to: one rule for everything that sends the user's key or trusts the answer
(anteriora_billing, probant_search_setup).

IR_SITE_BASE is honoured only when it is https on inferroute.ai or a subdomain of it, with no port, credentials, path,
query or fragment; anything else is ignored and the default is used. A test suite points the program at a port
nothing listens on with IR_TEST_SITE_BASE, which is honoured only when IR_TESTING=1: both are environment variables,
so a subprocess a test spawns is fenced as well as the test itself."""
from __future__ import annotations

import os
from urllib.parse import urlsplit

DEFAULT = "https://inferroute.ai"


def ours(value: str) -> str | None:
    """https://<inferroute.ai or a subdomain> when `value` is exactly that; None otherwise."""
    try:
        u = urlsplit(str(value or "").strip())
        host = (u.hostname or "").lower()
        ok = (u.scheme == "https" and not u.username and not u.password and u.port is None
              and (host == "inferroute.ai" or host.endswith(".inferroute.ai")) and u.path in ("", "/")
              and not u.query and not u.fragment and u.netloc.lower() == host)
    except ValueError:
        return None
    return f"https://{host}" if ok else None


def site_base() -> str:
    if os.environ.get("IR_TESTING") == "1" and os.environ.get("IR_TEST_SITE_BASE"):
        return os.environ["IR_TEST_SITE_BASE"].rstrip("/")
    return ours(os.environ.get("IR_SITE_BASE", "")) or DEFAULT
