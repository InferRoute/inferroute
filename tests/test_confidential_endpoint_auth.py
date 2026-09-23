"""The per-session local endpoint belongs to one session, and says so to anything else.

An audit of the installed client, 23 Sep: "That endpoint checks no credential — any process on this
computer that finds the port can send prompts through the professional's verified, billed session and can
read /confidential/receipt." The launcher did set `ir-confidential-local`, but that string is in the
published source, so checking it would have proved nothing. The credential has to be a secret AND checked.
"""
import inspect

import pytest
from fastapi.testclient import TestClient

from inferroute_local.confidential.server import create_app

TOKEN = "ir-a-real-per-session-secret"


class _Stub:
    """Enough of a session for the middleware to run in front of; the routes themselves are not the
    subject here, so reaching them at all is the pass condition."""
    def __getattr__(self, name):
        raise AssertionError(f"a rejected request must not reach the session (tried {name!r})")


def _client():
    return TestClient(create_app(_Stub(), TOKEN), raise_server_exceptions=False)


@pytest.mark.parametrize("path", ["/health", "/v1/models", "/confidential/receipt"])
def test_nothing_is_readable_without_the_session_key(path):
    assert _client().get(path).status_code == 401


@pytest.mark.parametrize("headers", [
    {},
    {"authorization": "Bearer wrong"},
    {"authorization": "Basic " + TOKEN},          # right secret, wrong scheme
    {"x-api-key": "wrong"},
    {"authorization": "Bearer ir-confidential-local"},   # the old constant is not a credential
    {"authorization": "Bearer "},
])
def test_a_wrong_or_missing_credential_is_refused(headers):
    r = _client().post("/v1/messages", json={"model": "x"}, headers=headers)
    assert r.status_code == 401
    assert "authentication_error" in r.text


@pytest.mark.parametrize("headers", [
    {"authorization": f"Bearer {TOKEN}"},          # Claude Code, and the OpenAI-dialect agents
    {"authorization": f"bearer {TOKEN}"},          # scheme is case-insensitive
    {"x-api-key": TOKEN},                          # the Anthropic dialect's own header
])
def test_the_session_key_gets_through(headers):
    """Past the middleware is the pass: the stub raises if a route is reached, and that is not a 401."""
    assert _client().get("/health", headers=headers).status_code != 401


def test_the_refusal_says_nothing_about_the_token():
    body = _client().get("/health").text
    assert TOKEN not in body and "ir-confidential-local" not in body
    assert "belongs to one confidential session" in body


def test_the_endpoint_cannot_be_built_without_a_token():
    """No default. A caller that forgets is a TypeError here rather than an open port in production."""
    p = inspect.signature(create_app).parameters["token"]
    assert p.default is inspect.Parameter.empty


def test_the_launcher_mints_a_secret_rather_than_shipping_one():
    """The old value was a constant in the published source. A grep for it is the whole test."""
    from pathlib import Path
    import inferroute_cli
    root = Path(inferroute_cli.__file__).parent
    for f in list(root.glob("*.py")) + list(root.glob("pi_attested/*.ts")):
        assert "ir-confidential-local" not in f.read_text(encoding="utf-8"), f.name
    src = (root / "confidential.py").read_text(encoding="utf-8")
    assert "secrets" in src and "token_urlsafe" in src
