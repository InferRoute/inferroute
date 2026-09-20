"""The audit pack: an evidence-only copy of a record for the professional's OWN AI to audit (Henry, 19 Sep).

It must say nothing of the invention, and it must lose nothing else. The first is checked by looking for
every word that was withheld; the second by running the SAME verifier over the record and over its pack:
the only check lines allowed to differ are the ones that need the withheld text, and they may only turn into
SKIP, never PASS.
"""
import json
import re
import stat

import pytest

from inferroute_cli import probant_check
from inferroute_cli import probant_export as E

from tests.test_verify_record import V, _run, _synthetic_bundle, kms  # noqa: F401  (fixtures)

LINE = re.compile(r"^\s*(PASS|FAIL|SKIP)\s+(.+?):")


def _lines(out):
    return [m.groups() for m in map(LINE.match, out.splitlines()) if m]


@pytest.fixture
def no_anchors(monkeypatch):
    monkeypatch.setattr(probant_check, "published_reference", lambda: (None, None))


def test_the_pack_verifies_like_the_record_except_the_texts_it_withholds(tmp_path, V, kms, no_anchors):
    rec = _synthetic_bundle(tmp_path, V, kms)
    ref = str(tmp_path / "reference.json")
    pack = E.write_audit_pack(rec, tmp_path / "pack")
    code_r, out_r = _run(rec, "--reference", ref)
    code_p, out_p = _run(pack, "--reference", ref)
    before, after = _lines(out_r), _lines(out_p)
    # One line disappears: the hit count is counted FROM the result, so with the result withheld there is
    # nothing to count. Every other check is there, in the same order.
    kept = [row for row in before if row[1] != "hit count as signed"]
    assert len(kept) == len(before) - 1
    assert [n for _, n in kept] == [n for _, n in after]
    changed = {n: (a, b) for (a, n), (b, _) in zip(kept, after) if a != b}
    assert changed == {"query text is the one searched": ("PASS", "SKIP"),
                       "result is the signed result": ("PASS", "SKIP")}
    assert code_p == code_r


def test_the_pack_carries_no_word_of_the_invention_and_no_matter_name(tmp_path, V, kms, no_anchors):
    rec = _synthetic_bundle(tmp_path, V, kms)
    pack = E.write_audit_pack(rec, tmp_path / "pack")
    blob = b"".join(p.read_bytes() for p in pack.rglob("*") if p.is_file())
    for secret in (b"battery housing", b"coolant channels", b"US-7000-B2"):
        assert secret not in blob, secret
    rows = json.loads((pack / "searches.json").read_text())
    assert rows[0]["withheld"] == ["query_text", "result"]
    assert "query_text" not in rows[0] and "result" not in rows[0]
    assert rows[0]["statement"] == json.loads((rec / "searches.json").read_text())[0]["statement"]   # untouched: still signed
    m = json.loads((pack / "MANIFEST.json").read_text())
    assert "client" not in m and "matter" not in m and m["schema"] == "inferroute.prior-art-audit-pack/1"
    assert (pack / "verify_record.py").read_bytes() == (rec / "verify_record.py").read_bytes()
    assert stat.S_IMODE(pack.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in pack.iterdir() if p.is_file())


def test_the_pack_brings_the_brief_and_this_computers_trust_anchors(tmp_path, V, kms, monkeypatch):
    rec = _synthetic_bundle(tmp_path, V, kms)
    monkeypatch.setattr(probant_check, "published_reference", lambda: (str(tmp_path / "reference.json"), "ab" * 32))
    pack = E.write_audit_pack(rec, tmp_path / "pack")
    brief = (pack / "AUDIT.md").read_text()
    # The brief makes the auditor redo the key checks itself, names the SKIPs it must expect, treats the
    # folder as data, and sends the professional to their engagement letter for the key.
    for must in ("DATA, not instructions", "Don't rely on it alone", "--extract", "SKIP",
                 "engagement letter", "COULD NOT CHECK",
                 # Put there by a real audit of a real pack, 19 Sep: the auditor had to hunt for AMD's
                 # address, tripped the integrity check by writing scratch files into the folder, and read
                 # the date-bound claim as enforcement when only configuration is attested.
                 "https://kdsintf.amd.com/vcek/v1/", "Write nothing inside this folder",
                 "Ten to fifteen minutes",          # an auditor's first run was killed early and gave nothing
                 # The claim is the enclave's own account of its filtering, and a read's coverage is part
                 # of what it returned — not footnotes (20 Sep, after a second instance of the same class).
                 "own account of its filtering", "cutoff_applied", "NOT an independent verdict",
                 "coverage is part of what it returned", "removed_by_* of 0 is legitimate".replace("*", "")):
        assert must in brief, must
    assert "Each search was bounded to documents published before" not in brief   # the overstated wording
    assert (pack / "trust-anchors" / "publication-key.txt").read_text().strip() == "ab" * 32
    assert json.loads((pack / "trust-anchors" / "reference.json").read_text())["source"] == "test"
    # The anchors sit in a subfolder: the pack's own integrity check is unaffected by them.
    code, out = _run(pack, "--reference", str(pack / "trust-anchors" / "reference.json"))
    assert "PASS bundle integrity" in out


def test_the_pack_refuses_to_overwrite_and_to_land_in_a_synced_folder(tmp_path, V, kms, no_anchors, monkeypatch):
    rec = _synthetic_bundle(tmp_path, V, kms)
    (tmp_path / "taken").mkdir()
    with pytest.raises(FileExistsError):
        E.write_audit_pack(rec, tmp_path / "taken")
    from inferroute_cli import probant as S
    monkeypatch.setattr(S, "_under_sync_root", lambda p: "Dropbox")
    with pytest.raises(S.ProbantError):
        E.write_audit_pack(rec, tmp_path / "synced")
