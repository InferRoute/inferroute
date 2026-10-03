"""Read an auditor's conclusions as attributed reports, never as hardware evidence."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

SCHEMA = "inferroute.audit-results/1"
VERDICTS = ("VERIFIED", "VERIFIED IN PART", "NOT VERIFIED", "COULD NOT CHECK")
MAX_RESULT_BYTES = 256 * 1024


def remember(records_dir: Path | None, pack: Path | None, bundle: Path | None = None) -> None:
    """Host-side association with a saved record, never a path supplied by the browser or auditor."""
    if records_dir is None:
        return
    state = records_dir / "last-audit-pack.state"
    if pack is None:
        state.unlink(missing_ok=True)
        return
    records_dir.mkdir(parents=True, exist_ok=True)
    temporary = state.with_suffix(".tmp")
    temporary.write_text(json.dumps({"pack": str(pack), "bundle": str(bundle), "identity": identity(pack)}))
    temporary.chmod(0o600)
    temporary.replace(state)


def restore(records_dir: Path | None, matter: str) -> dict:
    if records_dir is None:
        return {}
    state = records_dir / "last-audit-pack.state"
    if not state.exists():
        return {}
    try:
        from . import probant as S
        client, name = S._split_matter(matter)
        if state.is_symlink() or state.stat().st_size > 8192:
            raise ValueError("saved audit association is not a regular small file")
        data = json.loads(state.read_text())
        pack, bundle = Path(data["pack"]), Path(data["bundle"])
        exports = (S.probant_root() / client / "exports").resolve()
        if pack.resolve().parent != exports or bundle.resolve().parent != exports:
            raise ValueError("saved audit is outside this client's exports")
        origin = json.loads((bundle / "MANIFEST.json").read_text())
        if origin.get("client") != client or origin.get("matter") != name or identity(pack) != data["identity"]:
            raise ValueError("saved audit association or pack has changed")
        rows = json.loads((pack / "searches.json").read_text())
        source_rows = json.loads((bundle / "searches.json").read_text())
        if [r.get("statement") for r in rows] != [r.get("statement") for r in source_rows]:
            raise ValueError("saved audit statements do not match this matter's exported record")
        # Display the saved audit, but preparing another audit must export the current record.
        return {"pack": str(pack), "pack_identity": data["identity"]}
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        return {"restore_error": str(error)[:300]}


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
    got = data.get("pack")
    if not isinstance(got, dict) or set(got) != set(expected):
        # Not a different pack: a block that was not copied as given. Said as it is, because "different pack"
        # sent the first reader of such a file looking for the wrong problem (3 Oct: one key renamed).
        raise ValueError("the result's pack block is not the one this pack gave: it must have exactly the keys "
                         f"{', '.join(sorted(expected))}. Ask the auditor to rebuild the file with "
                         "stationery/check_report.py --make-json, which writes it exactly")
    if got != expected or identity(pack) != expected:
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
            raise ValueError(f"claim {wanted['id']}: coverage total is {coverage.get('total')!r}; this pack holds "
                             f"{total} operation(s) for this claim")
        for key in ("tool", "independent"):
            if type(coverage.get(key)) is not int or not 0 <= coverage[key] <= total:
                raise ValueError(f"claim {wanted['id']}: coverage '{key}' is {coverage.get(key)!r}; it must be a whole "
                                 f"number from 0 to {total} (0 for a check not performed, never empty or text)")
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
    if not isinstance(auditor, dict) or not all(str(auditor.get(k) or "").strip() for k in ("name", "model")):
        raise ValueError("the auditor must be given as {\"name\": ..., \"model\": ...} — "
                         f"this file has {sorted(auditor) if isinstance(auditor, dict) else 'none'}")
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
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            rejected.append({"file": file.name, "reason": str(error)[:300]})
    return {"results": results, "rejected": rejected}
