"""The lane is decided in one place, and the plaintext launcher announces itself.

Three separate silent drops to the plaintext lane were found on 23 Sep — `_fallback`, a missing
launch-index row, and `ir cowork`. None was a wrong default; the lane was re-derived at six call sites and
each had to remember. Henry's goal is to remove that lane entirely, so these tests also hold the census of
why it still exists: `lane.REASONS` is the backlog, and when it empties the lane can be deleted.
"""
import inspect
import io

import pytest

from inferroute_cli import lane, launch


def _flat(out: str) -> str:
    """The banner wraps its reason across lines inside a box; this recovers the sentence."""
    import re
    body = [l.strip("║ ").strip() for l in out.splitlines() if l.strip().startswith("║")]
    return re.sub(r"\s+", " ", " ".join(body))


def _tee(m):        # stand-in for the catalog's -TEE marking, so these tests need no network
    return m in ("Kimi-K2.6", "kimi-k2.6")


def test_the_plaintext_launchers_cannot_be_called_without_stating_a_reason():
    """The teeth. A new entry point that forgets the lane is a TypeError the suite catches, not a
    downgrade a law firm discovers."""
    for f in (launch.launch_through_inferroute, launch.launch_goose):
        p = inspect.signature(f).parameters["why"]
        assert p.default is inspect.Parameter.empty, f"{f.__name__} lets a caller omit the reason"
        assert p.kind is inspect.Parameter.KEYWORD_ONLY, f"{f.__name__} could take it positionally by luck"


def test_every_stated_reason_is_one_of_the_enumerated_ones():
    """A free-text reason would let the backlog grow without anyone noticing."""
    assert lane.why_standard("Kimi-K2.6", _tee) in lane.REASONS
    assert lane.why_standard("anything-else", _tee) in lane.REASONS
    assert lane.INTEGRATE in lane.REASONS and lane.COWORK in lane.REASONS


def test_an_enclave_model_on_the_plaintext_lane_can_only_be_there_by_choice():
    assert lane.why_standard("Kimi-K2.6", _tee) == lane.USER_ASKED
    assert lane.why_standard("some-model", _tee) == lane.NO_ENCLAVE


def test_the_banner_is_a_block_and_names_the_lane_and_the_reason():
    buf = io.StringIO()
    lane.announce(lane.Lane(lane.STANDARD, "some-model", lane.NO_ENCLAVE), buf)
    out = buf.getvalue()
    assert out.count("\n") >= 5, "a one-line notice scrolls away; that is what this replaces"
    assert "InferRoute can read this session" in out
    # the reason is wrapped into the box, so compare on collapsed text rather than on the raw lines
    assert lane.NO_ENCLAVE in _flat(out)
    assert "ir confidential models" in out, "it must say where the sealed models are"


def test_the_banner_does_not_nag_when_the_user_asked_for_it():
    buf = io.StringIO()
    lane.announce(lane.Lane(lane.STANDARD, "Kimi-K2.6", lane.USER_ASKED), buf)
    out = buf.getvalue()
    assert "InferRoute can read this session" in out
    assert "ir confidential models" not in out, "they already know; do not train them to skip the box"


def test_a_confidential_lane_says_nothing():
    buf = io.StringIO()
    lane.announce(lane.Lane(lane.CONFIDENTIAL, "Kimi-K2.6", "sealed"), buf)
    assert buf.getvalue() == ""


def test_decide_prefers_the_sealed_lane_and_honours_the_opt_out():
    assert lane.decide("Kimi-K2.6", plain=False, enclave_backed=_tee).kind == lane.CONFIDENTIAL
    assert lane.decide("Kimi-K2.6", plain=True, enclave_backed=_tee).kind == lane.STANDARD
    assert lane.decide("some-model", plain=False, enclave_backed=_tee).kind == lane.STANDARD
    assert lane.decide(None, plain=False, enclave_backed=_tee).kind == lane.STANDARD


def test_no_caller_of_the_plaintext_launchers_omits_its_reason():
    """The census: every site that reaches the readable lane, by name. This list is the removal
    checklist — when a caller no longer needs the lane, it leaves here too."""
    import pathlib
    import re
    root = pathlib.Path(launch.__file__).parent
    callers = []
    for f in sorted(root.glob("*.py")):
        if f.name == "launch.py":
            continue          # it DEFINES them, and its module docstring names them as prose
        src = f.read_text(encoding="utf-8")
        for m in re.finditer(r"launch_(?:through_inferroute|goose)\s*\(", src):
            if src[:m.start()].rstrip().endswith("def"):
                continue
            tail = src[m.end():m.end() + 400]
            assert "why=" in tail, f"{f.name} reaches the plaintext lane without stating why"
            callers.append(f.name)
    assert set(callers) == {"choose.py", "integrate.py", "main.py", "resume.py"}, sorted(set(callers))


def test_the_launchers_themselves_announce_not_just_their_callers(monkeypatch, capsys):
    """The seam. The census proves callers state a reason and the banner test proves the banner is well
    formed — neither proves the launcher SAYS it. Removing the announce call passed both. Putting the
    announcement in the launcher is the entire point: an entry point nobody has written yet cannot
    forget it."""
    from inferroute_cli.launch import Credentials
    monkeypatch.setattr("os.execvpe", lambda *a, **k: None)
    monkeypatch.setattr("os.execvp", lambda *a, **k: None, raising=False)
    said = []
    monkeypatch.setattr(lane, "announce", lambda l, out=None: said.append(l))
    creds = Credentials(api_url="https://api.inferroute.ai", api_key="k")
    for fn in (launch.launch_through_inferroute, launch.launch_goose):
        said.clear()
        try:
            fn("moonshotai/Kimi-K2.6-TEE", creds, why=lane.NO_ENCLAVE)
        except SystemExit:
            pass
        assert said, f"{fn.__name__} ran without announcing the lane"
        assert said[0].kind == lane.STANDARD and said[0].why == lane.NO_ENCLAVE


def test_the_server_cannot_move_a_known_enclave_model_to_the_readable_lane(monkeypatch):
    """The "-TEE" marking comes from a catalog fetched from InferRoute's own server and cached here, so
    the server can stop marking a model. It can only ever downgrade — attestation still has to pass, so
    it cannot make a plain model look sealed — but downgrade is the direction that matters. The bundled
    floor is what the catalog cannot go under; same problem and same shape as `builds.BUNDLED`."""
    from inferroute_cli import models

    class _Plain:                       # what a downgraded catalog row looks like
        ref_key = "moonshotai/Kimi-K2.6"
    monkeypatch.setattr(models, "get", lambda m: _Plain())
    monkeypatch.setattr(models, "short_for_model_id", lambda m: "")
    assert lane.enclave_backed("kimi-k2.6") is True, "a downgraded catalog moved a sealed model"
    assert lane.enclave_backed("some-model-never-sealed") is False, "the floor must not vouch for anything"


def test_the_floor_names_models_the_catalog_actually_knows():
    """A floor entry that matches no real model protects nothing and would never be noticed."""
    from inferroute_cli import models
    known = {a.short.lower() for a in models.all_aliases()}
    assert lane.ENCLAVE_FLOOR <= known, sorted(lane.ENCLAVE_FLOOR - known)
    assert all(lane.enclave_backed(m) for m in lane.ENCLAVE_FLOOR)


def test_main_and_lane_do_not_hold_two_copies_of_the_predicate():
    from inferroute_cli import main
    for m in ("kimi-k2.6", "Kimi-K2.6", "minimax-m3", "claude-sonnet-5", ""):
        assert main._is_confidential_model(m) == lane.enclave_backed(m), m


def test_cowork_announces_although_it_reaches_neither_launcher():
    """cowork writes goose's config and starts the desktop app detached, so the launcher-announces rule
    does not reach it. It is the third plaintext entry point and it must say so itself."""
    import inspect

    from inferroute_cli import cowork
    src = inspect.getsource(cowork.cmd_cowork)
    assert "lane_mod.announce" in src
    i, j = src.index("lane_mod.announce"), src.index("_launch_desktop")
    assert i < j, "it must say so before it launches, not after"
    assert "lane_mod.COWORK" in src, "and cite the enumerated reason, so it stays in the backlog"


def test_the_cowork_reason_names_the_actual_blocker():
    """A placeholder reason ("not supported yet") would sit in the backlog forever with nobody knowing
    what would have to change. This one says what to fix."""
    assert "detached" in lane.COWORK and "outlive" in lane.COWORK
