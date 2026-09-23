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
    assert lane.NO_ENCLAVE in out
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
