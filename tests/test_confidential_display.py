"""The panel and the receipt must not disagree about whether the session happened.

An independent audit (23 Sep) ran the real rendering code over a receipt recording 12 sent requests and
468 KB sealed, and the panel printed "This session was NOT opened. Nothing was sent." The receipt is the
document a firm keeps and shows; a panel that contradicts its own counters is worse than no panel.
"""
import io

from rich.console import Console

from inferroute_local.confidential import display as D
from inferroute_local.confidential.receipt import Receipt


def _receipt(**kw) -> Receipt:
    r = Receipt(session_id="s1", model_short="fake", upstream_model="fake/Model-TEE",
                fleet_id="fleet-x1", transport="test")
    r.path = "/tmp/receipt.json"
    for k, v in kw.items():
        setattr(r, k, v)
    return r


def _render(fn, r) -> str:
    buf = io.StringIO()
    fn(r, Console(file=buf, width=100, no_color=True))
    return buf.getvalue()


def test_a_session_that_never_opened_still_says_nothing_was_sent():
    r = _receipt(verdict="refused", refusal="the enclave could not be verified")
    out = _render(D.render_refusal, r)
    assert "Nothing was sent" in out
    assert "refused" in out.lower()


def test_a_session_that_sent_is_never_described_as_having_sent_nothing():
    r = _receipt(verdict="degraded", refusal="the enclave could not be re-verified 3 times in a row")
    r.counters["requests"] = 12
    r.counters["plaintext_bytes_sealed_here"] = 480_000
    out = _render(D.render_refusal, r)
    # The false sentence is the headline, not the words: "nothing was sent AFTER THAT POINT" is true
    # and belongs there. Pin the claim, not a substring of it.
    assert "NOT opened" not in out, "the panel contradicted the receipt's own counters"
    assert "Nothing was sent." not in out.replace("Nothing was sent after that point.", "")
    assert "12 request" in out and "STOPPED" in out
    assert "re-verified" in out                      # the reason travels, rather than just "degraded"
    assert "stale evidence" in out or "stopped rather than continue" in out


def test_the_summary_does_not_print_a_zero_nothing_measured():
    """`plaintext that left this device: 0 bytes` was a hard-coded string sitting among real counters.
    Nothing computes it, and no code path exists that could make it non-zero — so it is a control that is
    always satisfied, dressed as telemetry."""
    r = _receipt(verdict="confidential")
    r.counters.update({"requests": 3, "plaintext_bytes_sealed_here": 1000, "response_bytes_opened_here": 900})
    out = _render(D.render_summary, r)
    assert "0 bytes" not in out
    assert "not a count" in out, "if it is a property of the code, the screen has to say so"
    assert "3 request" in out                        # the things that ARE counted still show
