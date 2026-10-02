"""Read an auditor's conclusions as attributed reports, never as hardware evidence."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

SCHEMA = "inferroute.audit-results/1"
VERDICTS = ("VERIFIED", "VERIFIED IN PART", "NOT VERIFIED", "COULD NOT CHECK")
MAX_RESULT_BYTES = 256 * 1024


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def identity(pack: Path) -> dict:
    return {"manifest_sha256": _sha((pack / "MANIFEST.json").read_bytes()),
            "evidence_list_sha256": _sha((pack / "SHA256SUMS").read_bytes())}


def template(pack: Path) -> dict:
    manifest = json.loads((pack / "MANIFEST.json").read_text())
    counts = manifest["contents"]
    totals = {6: counts["searches"], 7: counts["session_receipts"], 8: counts["document_reads"]}
    return {"schema": SCHEMA, "pack": identity(pack),
            "auditor": {"name": "", "model": ""}, "completed_at": "",
            "verified_statement": "", "limitations": [],
            "claims": [{**claim, "verdict": None, "verified_statement": "", "evidence": "",
                        "limitations": [], "coverage": {"tool": None, "independent": None,
                                                         "total": totals.get(claim["id"], counts["statements"]),
                                                         "unchecked": ""}}
                       for claim in manifest["audit_claims"]]}


def _text(value, name: str, *, required: bool = True, limit: int = 8000) -> str:
    if not isinstance(value, str) or len(value) > limit or (required and not value.strip()):
        raise ValueError(f"{name} is missing or too long")
    return value.strip()


def _limits(value, name: str, *, required: bool = False) -> list:
    if not isinstance(value, list) or len(value) > 32 or (required and not value):
        raise ValueError(f"{name} must name the limitations")
    return [_text(v, name, limit=2000) for v in value]


def validate(data, pack: Path, expected: dict) -> dict:
    """Validate association and completeness. This does not validate the auditor's reasoning."""
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise ValueError("unsupported audit result format")
    if data.get("pack") != expected or identity(pack) != expected:
        raise ValueError("this result is for a different or changed audit pack")
    manifest = json.loads((pack / "MANIFEST.json").read_text())
    claims = data.get("claims")
    if not isinstance(claims, list) or len(claims) != len(manifest["audit_claims"]):
        raise ValueError("the result must answer every claim exactly once")
    normalized = []
    counts = manifest["contents"]
    totals = {6: counts["searches"], 7: counts["session_receipts"], 8: counts["document_reads"]}
    for wanted, claim in zip(manifest["audit_claims"], claims):
        if not isinstance(claim, dict) or type(claim.get("id")) is not int or any(claim.get(k) != v for k, v in wanted.items()):
            raise ValueError("a claim was omitted, reordered or retitled")
        verdict = claim.get("verdict")
        if verdict not in VERDICTS:
            raise ValueError(f"claim {wanted['id']} has no valid verdict")
        coverage = claim.get("coverage")
        if not isinstance(coverage, dict):
            raise ValueError("coverage is missing")
        total = totals.get(wanted["id"], counts["statements"])
        if type(coverage.get("total")) is not int or coverage["total"] != total:
            raise ValueError("coverage total does not match this pack")
        for key in ("tool", "independent"):
            if type(coverage.get(key)) is not int or not 0 <= coverage[key] <= total:
                raise ValueError("coverage counts are missing or out of range")
        unchecked = _text(coverage.get("unchecked"), "unchecked coverage", required=False, limit=2000)
        if verdict == "VERIFIED" and (not total or unchecked or max(coverage["tool"], coverage["independent"]) != total):
            raise ValueError("a VERIFIED verdict leaves coverage unchecked")
        if verdict == "VERIFIED IN PART" and not max(coverage["tool"], coverage["independent"]):
            raise ValueError("a partial verification must check some evidence")
        statement = _text(claim.get("verified_statement"), "claim's supported statement",
                          required=verdict in ("VERIFIED", "VERIFIED IN PART"))
        normalized.append({**wanted, "verdict": verdict, "verified_statement": statement,
                           "evidence": _text(claim.get("evidence"), "evidence or reason"),
                           "limitations": _limits(claim.get("limitations"), "claim limitations",
                                                  required=verdict != "VERIFIED"),
                           "coverage": {**coverage, "unchecked": unchecked}})
    auditor = data.get("auditor")
    if not isinstance(auditor, dict):
        raise ValueError("auditor identity is missing")
    auditor = {k: _text(auditor.get(k), f"auditor {k}", limit=160) for k in ("name", "model")}
    completed = _text(data.get("completed_at"), "completion time", limit=64)
    try:
        date = dt.datetime.fromisoformat(completed.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("completion time must be an ISO timestamp") from None
    if date.tzinfo is None:
        raise ValueError("completion time needs a time and timezone, e.g. 2026-10-02T12:09:00Z")
    return {"schema": SCHEMA, "pack": expected, "auditor": auditor, "completed_at": completed,
            "verified_statement": _text(data.get("verified_statement"), "exact supported conclusion"),
            "limitations": _limits(data.get("limitations"), "overall limitations", required=True),
            "claims": normalized}


def _check_files(pack: Path) -> None:
    manifest = json.loads((pack / "MANIFEST.json").read_text())
    sections = [manifest["files"], manifest.get("trust_anchors", {}).get("files", {}),
                manifest.get("build_inputs", {}).get("files", {})]
    for files in sections:
        for name, digest in files.items():
            relative = Path(name)
            file = pack / relative
            if relative.is_absolute() or ".." in relative.parts or not file.resolve().is_relative_to(pack.resolve()):
                raise ValueError("audit pack contains an unsafe file path")
            if file.is_symlink() or _sha(file.read_bytes()) != digest:
                raise ValueError("audit pack files have changed")


def collect(pack: Path, expected: dict) -> dict:
    """Only sibling results named for this pack; never read a path supplied by an auditor."""
    results, rejected = [], []
    candidates = [pack.parent / f"AUDIT-RESULT-{pack.name}.json"]
    candidates += sorted(pack.parent.glob(f"AUDIT-RESULT-audit-run-{pack.name}-*.json"))
    for file in candidates:
        if not file.exists():
            continue
        try:
            if file.is_symlink() or file.stat().st_size > MAX_RESULT_BYTES:
                raise ValueError("audit result is a link or too large")
            with file.open("rb") as stream:
                raw = stream.read(MAX_RESULT_BYTES + 1)
            if len(raw) > MAX_RESULT_BYTES:
                raise ValueError("audit result is too large")
            result = validate(json.loads(raw), pack, expected)
            _check_files(pack)
            results.append({**result, "file": file.name})
        except (OSError, ValueError, KeyError, TypeError) as error:
            rejected.append({"file": file.name, "reason": str(error)[:300]})
    return {"results": results, "rejected": rejected}
