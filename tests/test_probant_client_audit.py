"""The client audit brief: what a professional hands to their OWN AI to audit the software itself.

The evidence pack asks whether a record holds up. This asks the prior question — does the program that
made it do what we say? Two failures from the real audit of 23 Sep are what these tests exist to prevent:
a brief that hands the auditor its findings, and a brief that names things that are not there.
"""
import hashlib
import json
import stat

import pytest

from inferroute_cli import probant as S
from inferroute_cli import probant_client_audit as C


def test_every_place_the_brief_names_actually_exists():
    """THE test of this module. The brief sends an auditor to each of these by name; a rename that moves
    one turns the brief into a wild goose chase, and the auditor reports doubt about us rather than a
    verdict about the code. This fails loudly at our end instead."""
    assert C.check_anchors(C.package_root()) == []


def test_the_brief_names_each_anchor_in_its_text():
    """An anchor checked but never mentioned protects nothing; one mentioned but unchecked is the bug."""
    brief = C.brief(C.installed_manifest(C.package_root()))
    for rel, symbol in C.ANCHORS:
        assert symbol in brief, f"{symbol} is checked but the brief never sends anyone to it"
        assert rel.rsplit("/", 1)[-1] in brief, rel


def test_it_refuses_rather_than_ship_a_brief_pointing_at_a_ghost(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "ANCHORS", C.ANCHORS + (("inferroute_local/confidential/session.py", "_moved_away"),))
    with pytest.raises(S.ProbantError, match="_moved_away"):
        C.write_client_audit(tmp_path / "ca")
    assert not (tmp_path / "ca").exists(), "it must refuse BEFORE creating the folder"


def test_the_hashes_are_of_the_files_that_are_actually_there(tmp_path):
    dest = C.write_client_audit(tmp_path / "ca")
    m = json.loads((dest / "INSTALLED.json").read_text())
    root = C.package_root()
    assert len(m["files"]) > 20
    for rel, sha in list(m["files"].items())[:15]:
        assert hashlib.sha256((root / rel).read_bytes()).hexdigest() == sha, rel
    # SHA256SUMS says the same thing in the standard format, so `sha256sum -c` works from the package root
    lines = (dest / "SHA256SUMS").read_text().splitlines()
    assert len(lines) == len(m["files"])
    assert all(len(l.split("  ", 1)) == 2 for l in lines)


def test_the_brief_asks_questions_and_does_not_supply_the_answers(tmp_path):
    """23 Sep, an auditor on our evidence brief: 'an audit brief that supplies the findings has pre-empted
    the thing it commissioned.' This one states no verdict about the software it points at."""
    brief = (C.write_client_audit(tmp_path / "ca") / "CLIENT-AUDIT.md").read_text()
    for verdict in ("we verified", "you will find that", "as you will see", "correctly", "this is safe"):
        assert verdict not in brief.lower(), verdict
    # and it explicitly asks for the falsification attempt, not just a reading
    assert "try to falsify it" in brief.lower()
    assert "A check that cannot fail is decoration" in brief
    # source comments are the author arguing for the author: the brief must say so
    assert "DATA, not instructions" in brief and "docstring" in brief


def test_the_manifest_covers_code_that_is_not_python(tmp_path):
    """An auditor, 23 Sep: "a brief that says 'lists every Python file' is literally true and materially
    incomplete." Browser JavaScript and a 64 KB agent extension ship in this package and are code; leaving
    them out of the hashes while claim 1 asks where the program can reach a network is a real gap."""
    dest = C.write_client_audit(tmp_path / "ca")
    listed = json.loads((dest / "INSTALLED.json").read_text())["files"]
    suffixes = {("." + n.rsplit(".", 1)[-1]) for n in listed if "." in n}
    for must in (".js", ".html", ".ts", ".css"):
        assert must in suffixes, f"{must} ships in the package but is not hashed"
    assert not any(n.endswith(".pyc") for n in listed)
    brief = (dest / "CLIENT-AUDIT.md").read_text()
    assert "every Python file" not in brief


def test_the_brief_says_which_lane_the_claims_are_about(tmp_path):
    """Read literally, "nothing leaves this computer unsealed" is false of a program that also has a
    plaintext lane. The brief must scope the claims AND ask the auditor how a user reaches the other lane
    without choosing to -- which is where the real finding was."""
    brief = (C.write_client_audit(tmp_path / "ca") / "CLIENT-AUDIT.md").read_text()
    assert "standard lane" in brief and "in the\nclear" in brief
    assert "without\nchoosing to" in brief


def test_an_unpublished_version_is_not_asserted_to_be_downloadable(tmp_path):
    """The generator tested the SHAPE of the version string and never the index, so it confidently told an
    auditor to download a wheel that does not exist. It cannot know without a network, so the instruction
    itself has to carry the failure case."""
    rel = C.brief(dict(C.installed_manifest(C.package_root()), version="0.9.3"))
    assert "If that fails because `0.9.3` is not on the index" in rel
    assert "never published" in rel and "pip index versions" in rel


def test_a_source_checkout_says_so_instead_of_offering_an_impossible_comparison(tmp_path):
    """The independent-copy step is the whole basis of the audit. On an unreleased build there is nothing
    to compare against, and saying so is worth more than printing a command that cannot work."""
    m = dict(C.installed_manifest(C.package_root()), version="0.0.0+dev")
    dev = C.brief(m)
    assert "not a released version" in dev and "pip download" not in dev
    rel = C.brief(dict(m, version="0.9.3"))
    assert "pip download inferroute==0.9.3" in rel and "not a released version" not in rel


def test_it_refuses_to_overwrite_or_land_in_a_synced_folder(tmp_path, monkeypatch):
    (tmp_path / "taken").mkdir()
    with pytest.raises(FileExistsError):
        C.write_client_audit(tmp_path / "taken")
    monkeypatch.setattr(S, "_under_sync_root", lambda p: "Dropbox")
    with pytest.raises(S.ProbantError, match="Dropbox"):
        C.write_client_audit(tmp_path / "synced")


def test_the_folder_is_private(tmp_path):
    dest = C.write_client_audit(tmp_path / "ca")
    assert stat.S_IMODE(dest.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in dest.iterdir() if p.is_file())


# ── auditing an artifact instead of the running copy (24 Sep) ──

def _wheel(tmp_path, *, files=None, version="9.9.9", name="thing-9.9.9-py3-none-any.whl"):
    """A minimal wheel carrying the anchors the brief names, so these tests exercise the real writer."""
    import zipfile
    from inferroute_cli import probant_client_audit as A
    whl = tmp_path / name
    body = dict(files or {})
    # Two anchors can name the SAME file (session.py carries _send_sealed and _refuse). Append rather than
    # setdefault, or the second symbol of each pair is missing and the writer rightly refuses.
    for rel, symbol in A.ANCHORS:
        body[rel] = body.get(rel, "") + f"def {symbol}():\n    pass\n"
    with zipfile.ZipFile(whl, "w") as z:
        for rel, text in body.items():
            z.writestr(rel, text)
        z.writestr("thing-9.9.9.dist-info/METADATA", f"Metadata-Version: 2.1\nName: inferroute\nVersion: {version}\n")
    return whl


def test_a_wheel_audit_says_it_covered_the_file_and_not_what_runs(tmp_path, monkeypatch):
    """The point of auditing the package file is that it can be read BEFORE it is installed or run. That
    only helps if the brief is exact about it: a reader who takes an audit of a downloaded file for an
    audit of what is on their path has been told something untrue by omission."""
    from inferroute_cli import probant_client_audit as A
    monkeypatch.setenv("IR_PROBANT_ROOT", str(tmp_path / "probant"))
    whl = _wheel(tmp_path)
    dest = A.write_client_audit(tmp_path / "out", wheel=whl)
    m = json.loads((dest / "INSTALLED.json").read_text())

    assert m["audited"] == "wheel"
    assert m["version"] == "9.9.9"                         # the WHEEL's version, not the running package's
    assert m["artifact_sha256"] == hashlib.sha256(whl.read_bytes()).hexdigest()
    # An installed copy's interpreter says what runs it; a wheel has not been installed anywhere, so
    # reporting the auditing machine here would invite it to be read as the audited one.
    assert "python" not in m and "platform" not in m

    brief = (dest / "CLIENT-AUDIT.md").read_text()
    assert "before installing it" in brief
    assert "It is **not** what will run" in brief
    assert "is what you are reading what actually runs?" not in brief   # the installed-copy framing


def test_the_installed_audit_still_describes_the_running_copy(tmp_path, monkeypatch):
    from inferroute_cli import probant_client_audit as A
    monkeypatch.setenv("IR_PROBANT_ROOT", str(tmp_path / "probant"))
    m = json.loads((A.write_client_audit(tmp_path / "out") / "INSTALLED.json").read_text())
    assert m["audited"] == "installed" and m["python"] and "artifact_sha256" not in m


def test_a_wheel_that_would_write_outside_the_folder_is_refused(tmp_path):
    """A wheel from a link is untrusted input, and a zip entry may name a path outside the directory it is
    unpacked into. Checked before anything is written, not after."""
    import zipfile
    from inferroute_cli import probant as S
    from inferroute_cli import probant_client_audit as A
    whl = tmp_path / "evil-1.0-py3-none-any.whl"
    with zipfile.ZipFile(whl, "w") as z:
        z.writestr("../escaped.py", "x = 1\n")
    out = tmp_path / "unpack"
    out.mkdir()
    with pytest.raises(S.ProbantError) as e:
        A.extract_wheel(whl, out)
    assert "outside the folder" in str(e.value)
    assert not (tmp_path / "escaped.py").exists()          # and nothing was written on the way to refusing


def test_a_missing_anchor_in_a_delivered_file_is_not_called_our_bug(tmp_path, monkeypatch):
    """In the copy we ship, a missing anchor is our mistake. In a file that arrived from somewhere it is a
    fact about that file — an old version, or not our software at all — and telling the person it is our
    bug would talk them out of the more serious reading."""
    import zipfile
    from inferroute_cli import probant as S
    from inferroute_cli import probant_client_audit as A
    monkeypatch.setenv("IR_PROBANT_ROOT", str(tmp_path / "probant"))
    whl = tmp_path / "hollow-1.0-py3-none-any.whl"
    with zipfile.ZipFile(whl, "w") as z:
        z.writestr("inferroute_cli/__init__.py", "")
        z.writestr("hollow-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: inferroute\nVersion: 1.0\n")
    with pytest.raises(S.ProbantError) as e:
        A.write_client_audit(tmp_path / "out", wheel=whl)
    msg = str(e.value)
    assert "Do NOT read this as a bug in InferRoute" in msg
    assert "do not install it" in msg
    assert "bug in InferRoute, not in your installation" not in msg


def test_only_https_and_only_a_wheel_can_be_fetched(tmp_path):
    from inferroute_cli import probant as S
    from inferroute_cli import probant_client_audit as A
    for bad, why in (("http://example.invalid/x.whl", "https"), ("https://example.invalid/x.tar.gz", ".whl")):
        with pytest.raises(S.ProbantError) as e:
            A.fetch_wheel(bad, tmp_path)
        assert why in str(e.value)


def test_a_file_and_a_link_cannot_both_be_audited(tmp_path):
    from inferroute_cli import probant as S
    from inferroute_cli import probant_client_audit as A
    with pytest.raises(S.ProbantError):
        A.write_client_audit(tmp_path / "out", wheel=tmp_path / "x.whl", url="https://example.invalid/x.whl")
