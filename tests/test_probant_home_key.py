"""A computer without an InferRoute key says so first, takes the key on the page, and keeps it safely."""
import stat
from pathlib import Path

import pytest

from inferroute_cli import config, login, probant_home as H


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    monkeypatch.setenv("IR_PROBANT_ROOT", str(tmp_path / "Probant"))
    monkeypatch.delenv("INFERROUTE_API_KEY", raising=False)
    monkeypatch.setattr(config, "CREDS_FILE", tmp_path / "cfg" / "credentials")
    from fastapi.testclient import TestClient
    h = H.Home()
    h.port = 45678
    c = TestClient(h.app(), base_url="http://127.0.0.1:45678")
    c.headers.update({"authorization": f"Bearer {h.token}"})
    return h, c, tmp_path


def test_overview_says_whether_a_key_is_held_and_never_what_it_is(home, monkeypatch):
    _, c, _ = home
    assert c.get("/api/overview").json()["key"] == {"present": False}
    monkeypatch.setenv("INFERROUTE_API_KEY", "inf_SYNTHETIC_SECRET_VALUE")
    body = c.get("/api/overview").text
    assert '"present":true' in body.replace(" ", "") and "SYNTHETIC_SECRET" not in body


def test_a_session_cannot_start_without_a_key_and_the_refusal_says_where_to_add_one(home):
    h, c, _ = home
    c.post("/api/matters", json={"client": "Acme", "matter": "cooling", "priority_date": "2026-01-15", "disclosure": "x"})
    r = c.post("/api/sessions", json={"id": "Acme/cooling"})
    assert r.status_code == 409 and r.json()["needs_key"] is True and "InferRoute key" in r.json()["error"]
    assert not h.launches.items                                    # nothing was launched


@pytest.mark.parametrize("given,words", [("", "Paste the key"), ("two words", "no spaces"), ("x" * 300, "no spaces"),
                                         ("hello", "starts with inf_")])
def test_a_pasted_value_that_cannot_be_a_key_is_refused_before_the_network(home, monkeypatch, given, words):
    _, c, _ = home
    monkeypatch.setattr(login, "_verify", lambda *a: pytest.fail("the network must not be touched"))
    r = c.post("/api/key", json={"key": given})
    assert r.status_code == 400 and words in r.json()["error"]


def test_a_rejected_key_is_not_saved_and_an_unreachable_check_is_not_a_save(home, monkeypatch):
    _, c, tmp = home
    monkeypatch.setattr(login, "_verify", lambda *a: ("reject", None))
    r = c.post("/api/key", json={"key": "inf_" + "a" * 24})
    assert r.status_code == 400 and "did not accept" in r.json()["error"]
    monkeypatch.setattr(login, "_verify", lambda *a: ("unreachable", None))
    r = c.post("/api/key", json={"key": "inf_" + "a" * 24})
    assert r.status_code == 502 and "not saved" in r.json()["error"]
    assert not config.CREDS_FILE.exists()


def test_a_good_key_is_saved_private_unlocks_sessions_and_is_never_echoed(home, monkeypatch):
    _, c, tmp = home
    secret = "inf_" + "b" * 24
    monkeypatch.setattr(login, "_verify", lambda *a: ("ok", 12))
    r = c.post("/api/key", json={"key": secret})
    assert r.status_code == 200 and r.json() == {"ok": True, "present": True}
    assert secret not in r.text and secret not in c.get("/api/overview").text and secret not in c.get("/api/key").text
    assert config.CREDS_FILE.read_text().count(secret) == 1
    assert stat.S_IMODE(config.CREDS_FILE.stat().st_mode) == 0o600
    assert stat.S_IMODE(config.CREDS_FILE.parent.stat().st_mode) == 0o700
    assert config.load().api_key == secret                         # the same file `ir login` and the lane read
    assert c.get("/api/overview").json()["key"]["present"] is True


def test_the_key_file_is_never_readable_by_others_even_for_an_instant(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CREDS_FILE", tmp_path / "c" / "credentials")
    old = __import__("os").umask(0)                                # the worst case: nothing masked
    try:
        config.save("inf_" + "c" * 24)
    finally:
        __import__("os").umask(old)
    assert stat.S_IMODE(config.CREDS_FILE.stat().st_mode) == 0o600


def test_the_page_shows_the_key_card_first_and_leaves_sharing_and_help_alone():
    js = (Path(H.__file__).parent / "probant_web/home.js").read_text()
    at = js.index("async function renderMatters")
    body = js[at:at + 3000]
    assert body.index("keyCard(") < body.index("mountSearchStatus(p)")      # before anything else on the page
    for other in ("async function renderSharing", "function renderHelp"):
        seg = js[js.index(other):js.index(other) + 6000]
        assert "keyCard" not in seg and "/api/key" not in seg
    assert 'input("password"' in js and "autocomplete = \"off\"" in js        # masked, not remembered by the browser
