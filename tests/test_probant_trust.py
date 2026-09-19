"""The attorney-facing trust summary may only say what its checks proved.

Each test below is a sentence the card must NOT be able to say under the stated conditions, or a state it
must not report as better than it is. The summary is built from fixtures shaped like the real inputs: a
model receipt, the search verifier's /enclave answer, and the launcher's confinement label.
"""
import json
from types import SimpleNamespace

import pytest

from inferroute_cli import probant_trust as T
from inferroute_local import netns
from inferroute_local.confidential import attest

ADDRESS = netns.ADDRESS_LEVEL_LABEL


def _receipt(ok=True, limitations=(), verdict="confidential"):
    checks = {n: {"ok": ok, "why": "w", "label": n} for n in (*attest.REQUIRED, *attest.REQUIRED_ONLINE)}
    return SimpleNamespace(verdict=verdict, checks=checks, limitations=list(limitations),
                           verified_at="2026-09-17T14:58:28Z", started_at="2026-09-17T14:58:28Z", refusal="")


def _search(ok=True, reference=None, test_roots=False, refusal=None, identity=None):
    """`reference={"ok": True}` is the verifier's startup check of the signed file; `identity` is the live
    step comparing THIS enclave with it. By default a verified reference comes with a passing identity step."""
    steps = [{"ok": ok, "step": "hardware report", "detail": "version 3"}]
    if identity is None:
        identity = bool(reference and reference.get("ok"))
    if reference is not None:
        steps.append({"ok": identity, "step": "enclave identity (InferRoute's policy, index, encoders)", "detail": "d"})
    out = {"ok": ok, "test_roots": test_roots, "refusal": refusal, "steps": steps,
           "enclave": {"host_data": "380e3707bca09f61", "index_snapshot": "idx@1", "enclave_key": "f1416f1a"}}
    if reference is not None:
        out["reference"] = reference
    return out


def _text(summary) -> str:
    return json.dumps(summary, ensure_ascii=False)


def _item(summary, key):
    return next(i for i in summary["items"] if i["key"] == key)


def test_everything_verified_reads_private():
    s = T.build(_receipt(), _search(reference={"ok": True}), ADDRESS, matter="Acme/cooling", date_bound="2020-01-01")
    assert s["verdict"] == "private"
    # Three checks, each one a check that PASSED or did not. What the professional controls is not a fourth
    # item with a hollow dot beside them (20 Sep) — it is one line, and it is still said.
    assert [i["state"] for i in s["items"]] == [T.OK, T.OK, T.OK]
    assert [i["key"] for i in s["items"]] == ["ai", "search", "computer"]
    assert "your marks are yours alone" in s["control_note"]


def test_search_is_never_called_inferroutes_without_the_signed_reference():
    # A bare fingerprint pin says "the software this computer expects" — identity with InferRoute is a claim
    # only the signed reference, checked live, can earn. Neither the item nor the limits may make it.
    s = T.build(_receipt(), _search(), ADDRESS, date_bound="2020-01-01")
    search = _item(s, "search")
    assert search["state"] == T.OK
    assert "InferRoute" not in search["summary"] and "InferRoute" not in " ".join(search["points"])
    assert "InferRoute's own" not in " ".join(s["limits"])
    signed = T.build(_receipt(), _search(reference={"ok": True}), ADDRESS, date_bound="2020-01-01")
    assert "run by InferRoute" in _item(signed, "search")["summary"]
    assert "InferRoute's own" in " ".join(signed["limits"])


def test_an_authentic_reference_alone_does_not_earn_the_identity_line():
    # The reference file verified, but nothing compared THIS enclave with it: no "run by InferRoute".
    s = T.build(_receipt(), _search(reference={"ok": True}, identity=False), ADDRESS)
    assert "run by InferRoute" not in _item(s, "search")["summary"]
    assert "InferRoute's own" not in " ".join(s["limits"])
    assert T.search_is_inferroutes(_search(reference={"ok": True}, identity=True))


def test_a_failed_reference_does_not_earn_the_identity_line():
    s = T.build(_receipt(), _search(reference={"ok": False}), ADDRESS)
    assert "run by InferRoute" not in _item(s, "search")["summary"]


def test_an_unverified_ai_machine_blocks_and_says_nothing_was_sent():
    s = T.build(_receipt(ok=False), _search(reference={"ok": True}), ADDRESS)
    assert s["verdict"] == "blocked"
    assert _item(s, "ai")["state"] == T.FAIL
    assert "nothing was sent" in s["headline"]


def test_a_refused_session_is_blocked_even_if_every_check_row_passed():
    s = T.build(_receipt(verdict="refused"), _search(), ADDRESS)
    assert s["verdict"] == "blocked"


def test_a_missing_check_row_is_not_read_as_a_pass():
    r = _receipt()
    r.checks = {}
    assert T.build(r, _search(), ADDRESS)["verdict"] == "blocked"


@pytest.mark.parametrize("search,state", [
    (None, T.OFF),
    (_search(ok=False, refusal="the enclave did not answer"), T.FAIL),
    (_search(test_roots=True), T.WARN),
])
def test_any_search_short_of_verified_is_never_private(search, state):
    s = T.build(_receipt(), search, ADDRESS)
    assert _item(s, "search")["state"] == state
    assert s["verdict"] == "limited"


def test_an_unreachable_search_machine_is_said_plainly():
    s = T.build(_receipt(), _search(ok=False, refusal="the enclave did not answer"), ADDRESS)
    assert "isn't answering" in _item(s, "search")["points"][0]


def test_test_roots_are_named_as_a_test():
    s = T.build(_receipt(), _search(test_roots=True, reference={"ok": True}), ADDRESS)
    assert "TEST" in _item(s, "search")["summary"]


@pytest.mark.parametrize("label,state", [
    ("unconfined (developer override)", T.FAIL),
    ("not confined", T.FAIL),
    ("best-effort (port-level; not required)", T.WARN),
    ("require (address-level egress enforced or the session does not start)", T.WARN),
])
def test_anything_short_of_the_address_level_box_is_not_private(label, state):
    s = T.build(_receipt(), _search(reference={"ok": True}), label)
    assert _item(s, "computer")["state"] == state
    assert s["verdict"] == "limited"


def test_a_new_or_pending_build_caveat_reaches_the_card():
    lim = {"id": "new-build", "text": "This build is new to InferRoute."}
    s = T.build(_receipt(limitations=[lim]), _search(reference={"ok": True}), ADDRESS)
    ai = _item(s, "ai")
    assert ai["state"] == T.WARN and lim["text"] in ai["points"]
    assert s["verdict"] == "limited"


def test_the_date_bound_is_stated_when_the_matter_has_one():
    s = T.build(_receipt(), _search(), ADDRESS, date_bound="2020-01-01")
    assert any("2020-01-01" in p for p in _item(s, "search")["points"])


def test_it_never_claims_more_than_the_hardware_can_show():
    # NVIDIA does not report a GPU's confidential-computing mode, and no attestation proves what software kept.
    s = _text(T.build(_receipt(), _search(reference={"ok": True}), ADDRESS, date_bound="2020-01-01")).lower()
    for claim in ("confidential mode", "keeps nothing", "retains nothing", "guarantee", "proves novelty", "cannot be hacked"):
        assert claim not in s
    assert "doesn't prove novelty" in s


def test_it_names_no_model_provider_and_prints_no_host():
    s = _text(T.build(_receipt(), _search(reference={"ok": True}), ADDRESS)).lower()
    assert "operator.example" not in s and "http" not in s


def test_the_card_renders_every_state_without_error():
    from rich.console import Console
    c = Console(width=100, record=True)
    for summary in (T.build(_receipt(), _search(reference={"ok": True}), ADDRESS, matter="A/b"),
                    T.build(_receipt(ok=False), None, "not confined", matter="A/b"),
                    T.build(_receipt(), _search(ok=False, refusal="x"), "best-effort (port-level; not required)")):
        T.render_card(summary, c)
    out = c.export_text()
    assert "What this can't prove" in out and "ir probant proof A/b" in out
