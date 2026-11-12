"""The relay's billing refusals on the sealed lane, read on this device (relay-entitlement contract, Nov 2026).

On ``/confidential/*`` the relay may refuse a request for a reason that belongs to the ACCOUNT, not to any enclave:
no unit came with the session, the unit is spent or for another product, the account has no credit, too many
requests at once, or billing could not be checked. It says so with a JSON body ``{"error": {"type", "code",
"message"}}`` and the same code in the ``x-inferroute-billing-code`` response header.

What this module decides, and nothing else:

  * WHICH refusals are billing refusals: a code from the fixed list below, at the status the contract gives it.
    The header is read first (the session drains at most 400 bytes of an error body); the body second.
  * WHAT a person is shown: the relay's own ``message`` verbatim when it is short plain text whose every link is
    on an inferroute.ai host, otherwise a fixed sentence written here. No other upstream text reaches a person —
    the rule in session.upstream_public stands for everything that is not one of these codes.

THE FROZEN RULE (callers enforce it; ``is_billing_code`` names it): a code starting ``permit_`` or ``billing_``, or
``out_of_credits``, says nothing about any enclave. It never blames an instance, never drops one from the pool,
never makes the client walk to another fleet or model, and never writes a failed-verify observation or belief.
"""
from __future__ import annotations

import email.utils
import re
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

HEADER = "x-inferroute-billing-code"

# 402: final. Never retried, on any route.
FINAL_CODES = frozenset({"permit_missing", "permit_invalid", "permit_expired", "permit_used_up", "permit_lane",
                         "permit_trial_paused", "permit_wrong_product", "out_of_credits"})
# 429 + Retry-After: wait once, ask once more.
BUSY_CODES = frozenset({"rate_limited", "permit_busy"})
# 503 + Retry-After: billing could not be checked. Wait once, ask once more.
UNAVAILABLE_CODES = frozenset({"billing_unavailable"})
# 401/403 from the relay's key check (PR #140): final, and about the KEY, never about an enclave.
KEY_CODES = {"key_invalid": 401, "key_not_allowed": 403}
CODES = FINAL_CODES | BUSY_CODES | UNAVAILABLE_CODES | frozenset(KEY_CODES)
_STATUS_OF = {**{c: 402 for c in FINAL_CODES}, **{c: 429 for c in BUSY_CODES}, **{c: 503 for c in UNAVAILABLE_CODES},
              **KEY_CODES}

# A Retry-After is honoured at most this long, once. A relay asking for more is answered by surfacing the refusal.
RETRY_AFTER_CAP_S = 30.0
RETRY_AFTER_DEFAULT_S = 2.0
MESSAGE_MAX = 300

# Our words for each code, used whenever the relay's own message is absent or not admissible.
FIXED = {
    "permit_missing": ("No Anteriora unit came with this session, so it was refused. Start it again from "
                       "Anteriora; nothing was sent."),
    "permit_invalid": ("This session's Anteriora unit was not accepted. Start the session again to take a new "
                       "unit; if it happens again, write to support@inferroute.ai."),
    "permit_expired": "This session's Anteriora unit has expired. Start the session again to take a new unit.",
    "permit_used_up": ("This session's Anteriora unit is used up. Start a new session to take another unit, or "
                       "buy units at inferroute.ai/anteriora."),
    "permit_lane": "This session's Anteriora unit does not cover this model. Start the session again from Anteriora.",
    "permit_trial_paused": ("Free checks are paused for today on this account. Try again tomorrow, or buy units "
                            "at inferroute.ai/anteriora."),
    "permit_wrong_product": ("This session's unit belongs to another product and cannot be used here. Start "
                             "the session again from Anteriora."),
    "out_of_credits": "This account has no credit left. Add credit or buy units at inferroute.ai/anteriora.",
    "key_invalid": "This key was not accepted. Sign in again, or check the key in your settings.",
    "key_not_allowed": "This key cannot use this service. Sign in with the right account and try again.",
    "rate_limited": "Too many requests on this account right now. Wait a minute and try again.",
    "permit_busy": "This session's unit is busy with another request. Wait a moment and try again.",
    "billing_unavailable": "Billing could not be checked right now. Nothing was sent. Try again shortly.",
}


def is_billing_code(code: str) -> bool:
    """The frozen rule's scope: a code that is never evidence about an enclave, a fleet or a model."""
    code = str(code or "")
    return (code.startswith("permit_") or code.startswith("billing_") or code == "out_of_credits"
            or code in KEY_CODES)


_URL = re.compile(r"[a-z][a-z0-9+.\-]*://[^\s]+", re.I)
_EMAIL_OR_HOST = re.compile(r"(?<![\w.\-])(?:[\w.+\-]+@)?((?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,})\b", re.I)


def _our_host(host: str) -> bool:
    h = (host or "").lower().rstrip(".")
    return h == "inferroute.ai" or h.endswith(".inferroute.ai")


def admissible_message(code: str, message) -> bool:
    """True when the relay's own sentence may be shown verbatim: a listed code, plain text, at most 300 characters,
    and every link (with or without a scheme, an e-mail address included) on inferroute.ai or a subdomain of it."""
    return code in CODES and plain_and_ours(message)


def plain_and_ours(message) -> bool:
    """The text half of the rule: plain text, at most 300 characters, every link on inferroute.ai or a subdomain."""
    if not isinstance(message, str):
        return False
    m = message.strip()
    if not m or len(m) > MESSAGE_MAX:
        return False
    if any((not ch.isprintable()) for ch in m) or any(ch in m for ch in "<>[]{}`\\"):
        return False                       # markup, console markup, control characters: not plain text
    rest = m
    for u in _URL.findall(m):
        u = u.rstrip(".,;:!?)'\"")
        try:
            parts = urlsplit(u)
            host = parts.hostname or ""
        except ValueError:
            return False
        if parts.scheme.lower() not in ("http", "https") or not _our_host(host):
            return False
        rest = rest.replace(u, " ")
    for host in _EMAIL_OR_HOST.findall(rest):
        if not _our_host(host):
            return False
    return True


def parse_retry_after(value) -> float | None:
    """Seconds, from delta-seconds or an HTTP date. None when absent or unreadable."""
    if value is None:
        return None
    s = str(value).strip()
    if not s:
        return None
    try:
        return max(0.0, float(s))
    except ValueError:
        pass
    try:
        dt = email.utils.parsedate_to_datetime(s)
        return max(0.0, dt.timestamp() - time.time())
    except (TypeError, ValueError, IndexError, OverflowError):
        return None


async def sleep(seconds: float) -> None:
    """The one wait before the one retry. A function of its own so tests can count waits without sleeping."""
    import asyncio
    await asyncio.sleep(seconds)


def wait_for(retry_after: float | None) -> float:
    """How long to wait before the one retry: the relay's Retry-After, capped."""
    if retry_after is None:
        return RETRY_AFTER_DEFAULT_S
    return min(max(0.0, float(retry_after)), RETRY_AFTER_CAP_S)


class BillingRefusal(Exception):
    """The relay refused on account of billing. Never evidence about an enclave, a fleet or a model."""

    def __init__(self, status: int, code: str, message: str = "", retry_after: float | None = None,
                 route: str = "", code_from_header: bool = True):
        self.status = int(status)
        self.code = code
        self.server_message = message if isinstance(message, str) else ""
        self.retry_after = retry_after
        self.route = route
        self.code_from_header = code_from_header
        super().__init__(self.sentence)

    @property
    def final(self) -> bool:
        return self.code in FINAL_CODES or self.code in KEY_CODES

    @property
    def retryable(self) -> bool:
        return self.code in BUSY_CODES or self.code in UNAVAILABLE_CODES

    @property
    def sentence(self) -> str:
        """What the person is shown. The relay's own words when admissible; ours otherwise.

        On invoke, a code read ONLY from the body is classified but its message is not shown: that body may have
        come from beyond the relay, and the header is the relay's own mark (see the module docstring)."""
        if (self.code_from_header or self.route != "invoke") and admissible_message(self.code, self.server_message):
            return self.server_message.strip()
        return FIXED.get(self.code, "The request was refused for a billing reason. Nothing was sent.")


def _headers_lower(headers) -> dict:
    try:
        items = headers.items()
    except AttributeError:
        return {}
    return {str(k).lower(): str(v) for k, v in items}


def _body_error(body) -> dict:
    import json
    if isinstance(body, (bytes, bytearray)):
        body = bytes(body).decode("utf-8", "replace")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except ValueError:
            return {}
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        return body["error"]
    return {}


# Set when a 402 permit_used_up is read in this process; read and cleared by inferroute_cli.anteriora_billing.
USED_UP_SEEN: set = set()


def parse(status: int, headers, body, route: str = "") -> BillingRefusal | None:
    """A BillingRefusal when (status, headers, body) is one of the contract's refusals; None otherwise.

    The code must be a listed one AND arrive at the status the contract gives it, so a stray code on another
    status (or an unlisted one on the right status) leaves the response to the ordinary handling."""
    h = _headers_lower(headers)
    code = h.get(HEADER, "").strip()
    from_header = bool(code)
    err = _body_error(body)
    if not code:
        c = err.get("code")
        code = c.strip() if isinstance(c, str) else ""
    if code not in CODES or _STATUS_OF[code] != int(status or 0):
        return None
    msg = err.get("message") if isinstance(err.get("message"), str) else ""
    if code == "permit_used_up":
        USED_UP_SEEN.add(code)          # the launcher settles the permit delivered and drops it (anteriora_billing)
    return BillingRefusal(int(status), code, msg, parse_retry_after(h.get("retry-after")), route, from_header)


# ───────────────────────── the search gate (ir-search-gate, Nov 2026) ─────────────────────────
#
# The Cloud Run gate in front of the sealed search machine refuses with the same envelope and header, and has three
# refusals of its own that are NOT billing codes: no key (401 key_required), a body of no valid length (413
# bad_length), and the machine not answering (503 search_unavailable). They are kept OUT of CODES on purpose:
# is_billing_code, parse and admissible_message do not know them, so the relay's frozen rule is exactly as it was.
# Only the search path (inferroute_cli/_searchgate) reads them, through parse_search below.
SEARCH_CODES = {"key_required": 401, "bad_length": 413, "search_unavailable": 503}
SEARCH_FIXED = {
    "key_required": "Patent search needs your Anteriora key. Sign in to Anteriora again, then search.",
    "bad_length": ("InferRoute's search service did not accept the size of this search, so nothing was searched. "
                   "If it happens again, write to support@inferroute.ai."),
    "search_unavailable": ("The search machine is not answering right now; it may be starting. Nothing was "
                           "searched. Try again in a few minutes."),
}
SEARCH_UNLISTED = "InferRoute's search service refused this search ({code}). Nothing was searched."


class SearchRefusal(Exception):
    """The search gate refused a request: an account, permit or service reason, never evidence about the search
    machine's identity. Deliberately not a BillingRefusal, so no handler of the relay's refusals ever catches it."""

    def __init__(self, status: int, code: str, message: str = "", retry_after: float | None = None,
                 code_from_header: bool = True):
        self.status = int(status)
        self.code = code
        self.server_message = message if isinstance(message, str) else ""
        self.retry_after = retry_after
        self.code_from_header = code_from_header
        super().__init__(self.sentence)

    @property
    def listed(self) -> bool:
        return self.code in CODES or self.code in SEARCH_CODES

    @property
    def retryable(self) -> bool:
        """429 and 503 are asked once more after Retry-After; everything else is final."""
        return self.status in (429, 503)

    @property
    def final(self) -> bool:
        return not self.retryable

    @property
    def sentence(self) -> str:
        """The gate's own words under the relay's rule (a listed code, short plain text, inferroute.ai links only),
        our fixed sentence otherwise. An unlisted code never carries the server's text to a person."""
        if self.listed and self.code_from_header and plain_and_ours(self.server_message):
            return self.server_message.strip()
        if self.code in SEARCH_FIXED:
            return SEARCH_FIXED[self.code]
        if self.code in FIXED:
            return FIXED[self.code]
        return SEARCH_UNLISTED.format(code=re.sub(r"[^a-z0-9_]", "", self.code.lower())[:40] or self.status)


def parse_search(status: int, headers, body) -> SearchRefusal | None:
    """A SearchRefusal when a response from the search gate is one of its refusals; None otherwise (then it is the
    search machine's own answer, passed through by the gate, and is handled exactly as if it had come direct).

    Listed codes (the relay's, and SEARCH_CODES) must arrive at their contract status. A refusal that carries the
    gate's x-inferroute-billing-code header with any other code (the site's codes are passed through unchanged) is
    still the gate's refusal, never the machine's, and is shown in our own words. A 429 or 503 with no code at all
    (Cloud Run's own front end, before the gate ran) is read as rate_limited / search_unavailable."""
    status = int(status or 0)
    h = _headers_lower(headers)
    code = h.get(HEADER, "").strip()
    from_header = bool(code)
    err = _body_error(body)
    if not code:
        c = err.get("code")
        code = c.strip() if isinstance(c, str) else ""
    msg = err.get("message") if isinstance(err.get("message"), str) else ""
    retry = parse_retry_after(h.get("retry-after"))
    if code in CODES:
        if _STATUS_OF[code] != status:
            return None
        return SearchRefusal(status, code, msg, retry, from_header)
    if code in SEARCH_CODES:
        if SEARCH_CODES[code] != status:
            return None
        return SearchRefusal(status, code, msg, retry, from_header)
    if from_header and status >= 400:
        return SearchRefusal(status, code, msg, retry, from_header)
    if status in (429, 503) and not code:
        return SearchRefusal(status, "rate_limited" if status == 429 else "search_unavailable", "", retry, False)
    return None
