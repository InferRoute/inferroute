"""One answer to "was this session in a closed box", wherever it is asked."""
import re
from pathlib import Path

from inferroute_cli import probant_export as E
from inferroute_cli import probant_trust as T
from inferroute_local import netns

VM = "require, Linux VM (no NIC or host shares; address-level guest confinement)"
ROOT = Path(__file__).resolve().parents[1]


def test_the_closed_box_question_has_one_answer_for_every_label():
    """Three places asked this of the same string, each with its own copy of the test. When the VM label was
    added one copy learned it and two did not: a VM session read "closed box" on the page that ran it, "not
    fully boxed" on the home page's session list, and "only partly boxed" in the record its user keeps."""
    assert T.closed_box(VM)
    assert T.closed_box(netns.ADDRESS_LEVEL_LABEL)
    # The backend's own fallback line, printed when the guest never reported ready, must NOT qualify — it
    # begins with "required", one letter from the prefix, which is exactly the kind of near miss to pin.
    assert not T.closed_box("required Linux VM confinement unavailable")
    assert not T.closed_box("tool-level only (no OS confinement on darwin)")
    assert not T.closed_box("require (address-level egress enforced or the session does not start)")
    assert not T.closed_box("unconfined (developer override)")
    assert not T.closed_box("") and not T.closed_box(None)

    assert T.computer_item(VM, "browser")["state"] == T.OK
    assert T.computer_item("required Linux VM confinement unavailable", "browser")["state"] != T.OK


def test_no_second_copy_of_the_test_survives_anywhere():
    """The resolver is only one if nothing else re-implements it. A `startswith("require, address-level")`
    anywhere outside probant_trust is the bug coming back."""
    for path in sorted((ROOT / "inferroute_cli").rglob("*.py")):
        if "_vendor" in path.parts or path.name == "probant_trust.py":
            continue
        text = path.read_text()
        assert not re.search(r'startswith\(\(?"require, (address-level|Linux VM)', text), path.name
    home = (ROOT / "inferroute_cli/probant_home.py").read_text()
    export = (ROOT / "inferroute_cli/probant_export.py").read_text()
    assert "probant_trust.closed_box(rec.get(\"confinement\"))" in home
    assert "all(probant_trust.closed_box(c) for c in confs)" in export


def test_a_vm_sessions_records_are_described_in_its_own_words():
    """The exported record says where the session's records were relative to the agent. For a VM session that
    is not the Linux sentence — there was no empty network namespace on the host — and it must not fall
    through to the weaker "held outside the agent's write access", which is true and undersells it."""
    note = E._reach_note(VM)
    assert "a separate Linux virtual machine" in note and "no shared folders" in note
    assert "empty network namespace" not in note
    # The Linux line keeps its own sentence, and an unavailable VM gets no credit for trying.
    assert "empty network namespace" in E._reach_note(netns.ADDRESS_LEVEL_LABEL)
    assert "virtual machine" not in E._reach_note("required Linux VM confinement unavailable")


# ── what the home page says when the Mac's virtual machine cannot start ─────────────────────────────────

import pytest
from inferroute_cli import probant_home
from inferroute_local.macos_vm import runtime as vm_runtime


@pytest.mark.parametrize("line,must,must_not", [
    ("  ir: the macOS VM runtime is not installed (the `inferroute-macos-vm-runtime` package). Refusing before Pi startup.",
     "inferroute-macos-vm-runtime", "try again in a minute"),
    ("  ir: the signed macOS VM runtime policy is not provisioned in this client. Refusing before Pi startup.",
     "cannot run sessions on a Mac yet", "AI machine"),
    ("  ir: this Mac architecture has no validated VM runtime. Refusing before Pi startup.",
     "Apple silicon", "AI machine"),
    ("  ir: macOS is older than the bundled VM runtime supports. Refusing before Pi startup.",
     "too old", "AI machine"),
    ("  ir: macOS VM vendor manifest signature refused. Refusing before Pi startup.",
     "did not pass their check", "AI machine"),
    ("  ir: runtime artifact integrity refused. Refusing before Pi startup.",
     "did not pass their check", "AI machine"),
    ("  ir: macOS VM executable signing requirement refused. Refusing before Pi startup.",
     "did not pass their check", "AI machine"),
    ("VM confinement preflight failed before Pi startup; refusing to launch outside confinement.",
     "could not be started", "AI machine"),
])
def test_a_vm_that_cannot_start_is_not_reported_as_the_ai_machine_failing_its_check(line, must, must_not):
    said = probant_home.failure_message(["Opening devclient/pedal", line])
    assert must in said and must_not not in said
    assert "nothing was sent" in said.lower()


def test_every_refusal_the_runtime_can_raise_reaches_a_vm_message_not_the_generic_one():
    """Held to the source: a new VMUnavailable text in runtime.py that the home page would mistake for a
    failed enclave check fails here."""
    import re
    source = Path(vm_runtime.__file__).read_text()
    texts = set(re.findall(r'VMUnavailable\(\s*"([^"]+)"', source))
    assert len(texts) >= 10
    generic = "The AI machine could not be verified"
    wrong = [t for t in texts if generic in probant_home.failure_message([f"  ir: {t}. Refusing before Pi startup."])]
    assert wrong == [], wrong
