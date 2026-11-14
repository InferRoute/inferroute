"""Every check the verifier can emit has a plain group in the summary (anteriora-lead, 14 Nov).

A real v18 record failed "offices was applied" and the page said only "A check that this summary has no name for did
not pass" under "Other checks": the person holding the record could not see what failed. This enumerates every check
name the record verifier can produce (the literal and f-string names passed to ``add``, plus the names it builds from
tables) and asserts none falls into "other". A new check in a re-vendored verifier fails this test until it is named.
"""
import ast
from pathlib import Path

import pytest

from inferroute_cli import probant_check as C

PKG = Path(C.__file__).resolve().parent
VERIFIERS = [PKG / "_vendor" / "sealedresearch" / "verify_record.py", PKG / "pi_attested" / "verify_record.py"]


def _static_names():
    out = set()
    for f in VERIFIERS:
        for n in ast.walk(ast.parse(f.read_text())):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "add" and len(n.args) >= 2:
                a = n.args[1]
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    out.add(a.value)
                elif isinstance(a, ast.JoinedStr):
                    # an f-string name: its fixed words decide the group, so fill the holes with a plausible word
                    out.add("".join(v.value if isinstance(v, ast.Constant) else "offices" for v in a.values))
    return out


def _table_names():
    import importlib.util, sys
    spec = importlib.util.spec_from_file_location("_vr_for_names", VERIFIERS[0])
    sys.path.insert(0, str(VERIFIERS[0].parent.parent))
    try:
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        sys.path.pop(0)
    names = {row[3] for row in getattr(mod, "CONFIDENTIALITY_POSTURE", ())}
    # names the verifier builds in a variable before calling add (read from its source, 14 Nov)
    names |= {"index additions (delegated key)", "reference firmware floor before sealing",
              "index manifest names real bytes", "encoder manifest names real bytes",
              "completeness (per-session sequence)", "completeness (per-enclave sequence)",
              "enclave identity (InferRoute's image, host configuration, index, encoders)"}
    return names


ALL = sorted(_static_names() | _table_names())


def test_there_are_names_to_check():
    assert len(ALL) > 60


@pytest.mark.parametrize("name", ALL)
def test_every_verifier_check_has_a_plain_group(name):
    assert C.group_of(name) != "other", f"the summary has no plain name for the verifier's check {name!r}"


def test_the_offices_check_that_failed_on_real_records_is_named():
    assert C.group_of("offices was applied") == "truthful"


def test_an_unknown_failure_still_says_which_check_it_was():
    text = "  FAIL a brand new check nobody named yet: detail\n\nRESULT: 1 failing record check\n"
    out = C.parse(text, 1)
    other = [g for g in out["groups"] if g["key"] == "other"]
    assert other and "a brand new check nobody named yet" in other[0]["answer"]
    assert "no name for" not in other[0]["answer"]
