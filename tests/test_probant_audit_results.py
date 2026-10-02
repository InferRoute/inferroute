"""An audit result must describe exactly the exported record before any status is shown."""
import copy
import hashlib
import json

import pytest

from inferroute_cli import probant_audit_results as R, probant_export as E


@pytest.fixture
def pack(tmp_path):
    p = tmp_path / "audit-pack-example"
    p.mkdir()
    evidence = b"immutable evidence"
    (p / "evidence.json").write_bytes(evidence)
    digest = hashlib.sha256(evidence).hexdigest()
    (p / "SHA256SUMS").write_text(f"{digest}  evidence.json\n")
    (p / "MANIFEST.json").write_text(json.dumps({
        "files": {"evidence.json": digest},
        "contents": {"statements": 2, "searches": 1, "session_receipts": 1, "document_reads": 1},
        "audit_claims": [{"id": n, "title": title} for n, title in E.audit_claims()],
    }))
    return p


def completed(pack):
    data = R.template(pack)
    data.update(auditor={"name": "External AI auditor", "model": "Kimi"},
                completed_at="2026-10-02T12:00:00Z", verified_statement="The recorded signatures verify.",
                limitations=["This does not establish that the text stayed private."])
    for claim in data["claims"]:
        claim.update(verdict="VERIFIED", verified_statement="The stated claim holds.", evidence="Recomputed.")
        claim["coverage"].update(tool=claim["coverage"]["total"], independent=1)
    data["claims"][6].update(verdict="VERIFIED IN PART", limitations=["The receipt is not bound to the searches."])
    return data


def save(pack, data, name=None):
    path = pack.parent / (name or f"AUDIT-RESULT-{pack.name}.json")
    path.write_text(json.dumps(data))
    return path


def test_template_is_incomplete_until_an_auditor_has_answered_every_claim(pack):
    data = R.template(pack)
    assert all(c["verdict"] is None for c in data["claims"])
    save(pack, data)
    got = R.collect(pack, R.identity(pack))
    assert got["results"] == [] and got["rejected"]


def test_result_keeps_auditor_attribution_limits_and_separate_verdicts(pack):
    data = completed(pack)
    save(pack, data)
    got = R.collect(pack, R.identity(pack))
    assert not got["rejected"]
    result = got["results"][0]
    assert result["auditor"]["model"] == "Kimi"
    assert result["claims"][6]["verdict"] == "VERIFIED IN PART"
    assert result["limitations"] == data["limitations"]
    assert result["verified_statement"] == data["verified_statement"]


@pytest.mark.parametrize("change", [
    lambda d: d["pack"].update(manifest_sha256="0" * 64),
    lambda d: d["claims"].pop(),
    lambda d: d["claims"][4].update(title="Counter contiguity"),
    lambda d: d["claims"][0].update(verdict="CONDITIONALLY VERIFIED"),
    lambda d: d["claims"][0]["coverage"].update(tool=0, independent=0),
    lambda d: d["claims"][0]["coverage"].update(unchecked="The hardware chain"),
    lambda d: d["claims"][6].update(limitations=[]),
    lambda d: d["claims"][6]["coverage"].update(tool=0, independent=0),
    lambda d: d.update(verified_statement=""),
])
def test_incomplete_mismatched_or_overstated_results_do_not_light_up(pack, change):
    data = completed(pack)
    change(data)
    save(pack, data)
    got = R.collect(pack, R.identity(pack))
    assert got["results"] == [] and len(got["rejected"]) == 1


def test_edited_pack_and_changed_evidence_cannot_reuse_an_old_result(pack):
    expected = R.identity(pack)
    save(pack, completed(pack))
    (pack / "evidence.json").write_text("changed")
    assert R.collect(pack, expected)["results"] == []
    (pack / "MANIFEST.json").write_text("{}")
    assert R.collect(pack, expected)["results"] == []


def test_separate_auditors_are_not_merged_and_foreign_files_are_ignored(pack):
    first = completed(pack)
    second = copy.deepcopy(first)
    second["auditor"]["model"] = "Codex"
    second["claims"][0].update(verdict="NOT VERIFIED", limitations=["My recomputation disagreed."])
    save(pack, first, f"AUDIT-RESULT-audit-run-{pack.name}-1.json")
    save(pack, second, f"AUDIT-RESULT-audit-run-{pack.name}-2.json")
    save(pack, first, "AUDIT-RESULT-another-pack.json")
    got = R.collect(pack, R.identity(pack))
    assert len(got["results"]) == 2
    assert {r["claims"][0]["verdict"] for r in got["results"]} == {"VERIFIED", "NOT VERIFIED"}


def test_a_result_file_is_data_and_cannot_redirect_the_reader_to_another_file(pack, tmp_path):
    other = tmp_path / "elsewhere.json"
    other.write_text(json.dumps(completed(pack)))
    (pack.parent / f"AUDIT-RESULT-{pack.name}.json").symlink_to(other)
    got = R.collect(pack, R.identity(pack))
    assert not got["results"] and "link" in got["rejected"][0]["reason"]


@pytest.mark.asyncio
async def test_client_loads_only_its_own_pack_results_and_clears_them_on_new_export(pack, monkeypatch):
    import httpx
    from inferroute_cli import probant_web as W, probant_check
    b = W.Bridge(matter="Test/matter", date_bound="2020-01-01", workspace=pack,
                 summary={"verdict": "private"}, search_endpoint=None, receipt=lambda: None,
                 rebuild_summary=lambda: {}, export=lambda: pack)
    b.port = 43210
    monkeypatch.setattr(E, "write_audit_pack", lambda _: pack)
    monkeypatch.setattr(W, "can_open_terminal", lambda: False)
    monkeypatch.setattr(probant_check, "check", lambda _: {"verdict": "passed"})
    save(pack, completed(pack))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=b.app()),
                                 base_url="http://127.0.0.1:43210") as c:
        assert (await c.get("/api/audit-results")).status_code == 401
        c.headers["authorization"] = f"Bearer {b.token}"
        assert not (await c.get("/api/audit-results")).json()["prepared"]
        assert (await c.post("/api/audit-pack", json={})).status_code == 200
        got = (await c.get("/api/audit-results?path=/etc")).json()
        assert got["results"][0]["auditor"]["model"] == "Kimi"
        assert "not a new hardware verification" in got["attribution"]
        assert b.summary == {"verdict": "private"}
        (pack / "evidence.json").write_text("changed")
        assert not (await c.get("/api/audit-results")).json()["results"]
        assert (await c.post("/api/prove", json={})).status_code == 200
        assert not (await c.get("/api/audit-results")).json()["prepared"]
