"""A sealed prior-art search job: what the enclave accepts, how the pipeline is invoked, what comes back.

Stdlib only and no network import: this runs inside the sealed namespace and ships in the open-source
client for payload construction. The searcher is injected (the enclave passes a PriorArt instance,
tests pass a stub), so nothing here knows how an index is reached.

Validation refuses with a CATEGORY, never the content — the refusal reaches a signed statement and a
log. The statement fields built here carry hashes and counts only: the query and the hits are sealed
to the firm's key and never appear in the clear outside the enclave.

Every result carries the claim boundary verbatim. The pipeline surfaces related art; it does not
certify completeness or absence — self-certification of a blank page is closed by every inference-
time route tested (e10, e11, D), and nobody in the market makes that claim either.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Protocol

MAX_PLAINTEXT = 262_144
MIN_QUERY, MAX_QUERY = 20, 60_000
MAX_K = 200
MAX_OFFICES = 20
ALL_LEGS = ("graph", "dense", "patents", "lexical", "cpc")
CLAIM_BOUNDARY = "surfaces related art; does not certify completeness or absence"
CLIENT_RE = re.compile(r"^[A-Za-z0-9_. -]{1,64}$")
# session_id is client-generated and travels ONLY in the sealed body, so the operator never learns which
# requests belong together. The enclave counts a per-(lifetime, session) sequence over it, so completeness
# on the record means "every search AND read of YOUR session, in order".
SESSION_RE = re.compile(r"^[0-9a-f]{32}$")
OFFICE_RE = re.compile(r"^[A-Z]{2}$")                       # jurisdiction/office two-letter code
KEY_RE = re.compile(r"^[A-Za-z]{2}-?[0-9A-Za-z-]{2,30}$")   # a publication number, loosely; not_found is the real check
KINDS = ("search", "document", "survey")
# Survey mode (SURVEY-MODE DESIGN VERDICT 09-24; runner in survey_run.py). This module stays
# stdlib-only, so the leg budget is RESTATED here; tests assert equality with survey_legs.MAX_LEGS
# (the same pattern as MARK_VALUES vs m2_ranker).
MAX_LEGS_PAYLOAD = 8
MIN_DISCLOSURE = 40                                         # below this nothing constructible exists
MAX_DISCLOSURE = 200_000                                    # chars; the plaintext cap bounds bytes anyway
# Relevance marks (verdict REVISION 2): the payload restates the ranker's two constants because this
# module ships in the open client and stays stdlib-only; tests assert equality with enclave.azure.m2_ranker
# (MAX_MARKS, MARK_VALUES) — the same pattern as KEY_RE. "cleared" is VALID and INERT: consumers match
# values positively, so a cleared key enters neither the teleport set nor the pruning set.
MAX_MARKS_PAYLOAD = 50
MARK_VALUES = ("relevant", "not-relevant", "known", "cleared")
# Release gate (2026-09-25, wiring conflict #6 decision): marks are WIRED end-to-end but NOT RELEASED
# in m2-2.0.0 — the verifier has no strip-detection yet, so a client could not distinguish "marks
# applied" from "marks stripped in transit", and half of an evidence contract is a silent downgrade.
# A payload carrying the field is refused LOUDLY with its OWN category (never "bad_marks": the client
# must learn the feature is absent from this release, not that its payload was malformed). Flip with
# m2-3.0.0 only, together with verifier-side marks checks.
MARKS_RELEASED = False
# marks_counts keys are the verdict's (REVISION 2 item 7): the three ACTING values; "cleared" is inert
# and deliberately not counted (it is still covered by marks_sha256).
MARK_COUNT_KEYS = (("relevant", "relevant"), ("not_relevant", "not-relevant"), ("known", "known"))


class RefusedPayload(ValueError):
    """The category is the whole message. Content never appears here."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class EngineError(RuntimeError):
    """A pipeline leg failed MID-QUERY (verdict REVISION 2 item 3). The searcher raises this (chained
    to the cause); run() turns it into the SIGNED refusal "engine_error" — never a degraded answer. The
    message must carry no content: a stage name at most."""


class Searcher(Protocol):
    version: str

    def search(self, text: str, k: int = 50, cutoff_date: Optional[int] = None,
               from_date: Optional[int] = None, offices: Optional[List[str]] = None,
               marks: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]: ...

    def document(self, key: str, cutoff_date: Optional[int] = None) -> Dict[str, Any]: ...


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(obj: Any) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def _valid_date(d: Any) -> bool:
    if not isinstance(d, int) or not (19000101 <= d <= 20991231):
        return False
    y, m, day = d // 10000, (d // 100) % 100, d % 100
    return 1 <= m <= 12 and 1 <= day <= 31


def _session_and_meta(p: Dict[str, Any]):
    """Every request carries a session_id (in the sealed body) and an optional client label."""
    sid = p.get("session_id")
    if not (isinstance(sid, str) and SESSION_RE.match(sid)):
        raise RefusedPayload("bad_session")
    meta = p.get("meta", {})
    if not isinstance(meta, dict) or (meta.get("client") is not None and not
                                      (isinstance(meta["client"], str) and CLIENT_RE.match(meta["client"]))):
        raise RefusedPayload("bad_meta")
    return sid, meta


def validate(raw: bytes) -> Dict[str, Any]:
    """One entry, two kinds. Every refusal is a snake_case CATEGORY the client renders by code, never by
    sniffing the message; content never appears in a code."""
    if len(raw) > MAX_PLAINTEXT:
        raise RefusedPayload("oversize")
    try:
        p = json.loads(raw)
    except ValueError:
        raise RefusedPayload("not_json") from None
    if not isinstance(p, dict):
        raise RefusedPayload("bad_kind")
    kind = p.get("kind")
    if kind == "search":
        return _validate_search(p)
    if kind == "document":
        return _validate_document(p)
    if kind == "survey":
        return _validate_survey(p)
    raise RefusedPayload("bad_kind")


def _validate_scope(p: Dict[str, Any]):
    """cutoff/from_date/offices — one definition for search and survey (two copies would drift)."""
    cutoff = p.get("cutoff_date")
    if cutoff is not None and not _valid_date(cutoff):
        raise RefusedPayload("bad_cutoff")
    from_date = p.get("from_date")
    if from_date is not None:
        if not _valid_date(from_date) or (cutoff is not None and from_date > cutoff):
            raise RefusedPayload("bad_date_window")
    offices = p.get("offices")
    if offices is not None:                              # omitted = every office; empty = a mistake
        if (not isinstance(offices, list) or not (1 <= len(offices) <= MAX_OFFICES)
                or not all(isinstance(o, str) and OFFICE_RE.match(o) for o in offices)):
            raise RefusedPayload("bad_offices")
        offices = sorted(set(offices))
    return cutoff, from_date, offices


def _validate_survey(p: Dict[str, Any]) -> Dict[str, Any]:
    """One press: the full disclosure, a leg budget, the matter's scope. Constructibility is the
    RUNNER's judgement (unconstructible_disclosure is a signed refusal there); validation only
    bounds sizes and shapes."""
    sid, meta = _session_and_meta(p)
    d = p.get("disclosure")
    if not isinstance(d, str) or not (MIN_DISCLOSURE <= len(d.strip()) <= MAX_DISCLOSURE):
        raise RefusedPayload("bad_disclosure")
    ml = p.get("max_legs", MAX_LEGS_PAYLOAD)
    if not isinstance(ml, int) or not (1 <= ml <= MAX_LEGS_PAYLOAD):
        raise RefusedPayload("bad_max_legs")
    cutoff, from_date, offices = _validate_scope(p)
    if p.get("marks") is not None and not MARKS_RELEASED:   # same release gate as search
        raise RefusedPayload("marks_not_released")
    marks = _validate_marks(p.get("marks"))
    return {"kind": "survey", "disclosure": d.strip(), "max_legs": ml, "cutoff_date": cutoff,
            "from_date": from_date, "offices": offices, "meta": meta, "session_id": sid,
            "marks": marks}


def _validate_search(p: Dict[str, Any]) -> Dict[str, Any]:
    sid, meta = _session_and_meta(p)
    q = p.get("query")
    if not isinstance(q, str) or not (MIN_QUERY <= len(q.strip()) <= MAX_QUERY):
        raise RefusedPayload("bad_query")
    k = p.get("k", 50)
    if not isinstance(k, int) or not (1 <= k <= MAX_K):
        raise RefusedPayload("bad_k")
    cutoff, from_date, offices = _validate_scope(p)
    legs = p.get("legs")                                 # accepted for back-compat; the served leg is honest in the result
    if legs is not None and (not isinstance(legs, list) or not legs or any(l not in ALL_LEGS for l in legs)):
        raise RefusedPayload("bad_legs")
    if p.get("marks") is not None and not MARKS_RELEASED:   # "marks": null counts as absent, as everywhere
        raise RefusedPayload("marks_not_released")
    marks = _validate_marks(p.get("marks"))
    return {"kind": "search", "query": q.strip(), "k": k, "cutoff_date": cutoff, "from_date": from_date,
            "offices": offices, "legs": legs, "meta": meta, "session_id": sid, "marks": marks}


def normalize_mark_key(key: str) -> str:
    """Publication numbers as the index spells them: surrounding whitespace dropped, upper-cased
    ("us-1234567-b2" → "US-1234567-B2"). Resolution against the index is the ranker's job; an
    unresolvable key proceeds-with-subset there (typo tolerance), it is not refused here."""
    return key.strip().upper()


def _validate_marks(marks: Any) -> Optional[List[Dict[str, str]]]:
    """[{key, value}] with value in MARK_VALUES, 1..MAX_MARKS_PAYLOAD entries, keys normalized. Omitted
    (None) stays None — absent and empty are different facts, so an empty list is a mistake (bad_marks),
    exactly like offices. Only key/value survive: an extra field cannot ride into the hash or the engine."""
    if marks is None:
        return None
    if not isinstance(marks, list) or not (1 <= len(marks) <= MAX_MARKS_PAYLOAD):
        raise RefusedPayload("bad_marks")
    out = []
    for m in marks:
        if not (isinstance(m, dict) and isinstance(m.get("key"), str) and m.get("value") in MARK_VALUES):
            raise RefusedPayload("bad_marks")
        key = normalize_mark_key(m["key"])
        if not KEY_RE.match(key):
            raise RefusedPayload("bad_marks")
        out.append({"key": key, "value": m["value"]})
    return out


def marks_counts(marks: Optional[List[Dict[str, str]]]) -> Optional[Dict[str, int]]:
    """Counts per acting value, or None iff no marks were given (never an all-zero dict for absent)."""
    if marks is None:
        return None
    return {name: sum(1 for m in marks if m["value"] == v) for name, v in MARK_COUNT_KEYS}


def _validate_document(p: Dict[str, Any]) -> Dict[str, Any]:
    sid, meta = _session_and_meta(p)
    key = p.get("key")
    if not (isinstance(key, str) and KEY_RE.match(key)):
        raise RefusedPayload("bad_key")
    cutoff = p.get("cutoff_date")                        # a read must honour the matter's date bound, like a search
    if cutoff is not None and not _valid_date(cutoff):
        raise RefusedPayload("bad_cutoff")
    return {"kind": "document", "key": key, "cutoff_date": cutoff, "meta": meta, "session_id": sid}


def query_hash(query: str) -> str:
    return hashlib.sha256(query.encode()).hexdigest()


def run_canaries(searcher: Searcher, canaries: List[Dict[str, Any]], depth: int = 1000) -> List[Dict[str, Any]]:
    """The control lane: public queries with known examiner gold, run in the same process just before
    the client's query. Their yield goes into the signed statement as evidence the machinery was
    healthy AT RUN TIME, not merely when it was benchmarked."""
    out = []
    for c in canaries:
        res = searcher.search(c["text"], k=depth, cutoff_date=c.get("cutoff_date"))
        keys = [h["key"] for h in res["hits"]]
        gold = set(c["gold"])
        out.append({"id": c["id"], "gold_n": len(gold),
                    "found_100": len(gold & set(keys[:100])), "found_1000": len(gold & set(keys[:depth]))})
    return out


def _searcher_failed(exc: Exception, code: str = "searcher_failed") -> "RefusedPayload":
    # Diagnosable without content: exception TYPE and the code locations (file:line), never values.
    # For an EngineError the CAUSE's type and frames are the useful ones (the wrapper's are the searcher's).
    import traceback, sys
    src = exc.__cause__ if isinstance(exc, EngineError) and exc.__cause__ is not None else exc
    frames = traceback.extract_tb(src.__traceback__)[-4:]
    where = " <- ".join(f"{f.filename.rsplit('/', 1)[-1]}:{f.lineno}" for f in frames)
    print(f"[search] {code}: {type(src).__name__} at {where}", file=sys.stderr, flush=True)
    return RefusedPayload(code)


def run(job: Dict[str, Any], searcher: Searcher, canaries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """A searcher that raises or returns a malformed result is a REFUSAL, not a crash: the statement
    must still be signed so the client can tell "the enclave could not search" from "nothing came back"."""
    if job["kind"] == "document":
        return _run_document(job, searcher)
    if job["kind"] == "survey":
        return _run_survey(job, searcher, canaries)
    marks = job.get("marks")
    try:
        canary = run_canaries(searcher, canaries) if canaries else []
        # marks is passed ONLY when given: a markless call is the exact pre-marks call (and a searcher
        # that predates marks keeps working for markless requests).
        extra = {"marks": marks} if marks is not None else {}
        res = searcher.search(job["query"], k=job["k"], cutoff_date=job.get("cutoff_date"),
                              from_date=job.get("from_date"), offices=job.get("offices"), **extra)
        if not isinstance(res, dict) or not isinstance(res.get("hits"), list) or not all(isinstance(h, dict) and "key" in h for h in res["hits"]):
            raise RefusedPayload("searcher_failed")
    except RefusedPayload:
        raise
    except EngineError as exc:  # a leg failed mid-query: signed refusal, never a degraded answer (R2 item 3)
        raise _searcher_failed(exc, "engine_error") from None
    except Exception as exc:  # noqa: BLE001 — the category is the whole message; the traceback would carry content
        raise _searcher_failed(exc) from None
    # marks_applied / marks_unresolved are taken from the engine ONLY when marks were given; for a markless
    # request they are None whatever the engine says. When marks WERE given and the engine returns no
    # marks_applied, None stands — never fabricated — so the verifier can see marks were not applied.
    unresolved = res.get("marks_unresolved") if marks is not None else None
    return {"kind": "search", "hits": res["hits"], "legs": dict(res.get("legs", {})), "candidates": int(res.get("candidates", 0)),
            "cpc": list(res.get("cpc", [])), "calibration": res.get("calibration"), "paper_coverage": res.get("paper_coverage"),
            "cutoff_applied": res.get("cutoff_applied"), "from_date_applied": res.get("from_date_applied"),
            "offices_applied": res.get("offices_applied"), "undated_hits": sum(1 for h in res["hits"] if not h.get("date_known", True)),
            "hits_by_source": res.get("hits_by_source"), "text_coverage": res.get("text_coverage"),
            "cutoff_date": job.get("cutoff_date"), "from_date": job.get("from_date"), "offices": job.get("offices"),
            "k": job["k"], "canary": canary,
            # what each ranking stage DID (verdict statement accounting); None for an engine without stages
            "stages_applied": res.get("stages_applied"),
            "marks_applied": res.get("marks_applied") if marks is not None else None,
            # the unresolved KEYS live here, in the sealed result only; the statement carries their count
            "marks_unresolved": list(unresolved) if unresolved is not None else None,
            "pipeline_version": getattr(searcher, "version", "unversioned"), "claim_boundary": CLAIM_BOUNDARY}


def _run_survey(job: Dict[str, Any], searcher: Searcher, canaries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """One press through the engine's survey() (survey_run wired inside the searcher — the SAME object
    the bench optimises). An engine without survey() refuses survey_unsupported; an unconstructible
    disclosure refuses unconstructible_disclosure — both signed, neither a crash. The result carries
    the union + per-leg texts (sealed material); the manifest is the statement's share."""
    svy = getattr(searcher, "survey", None)
    if svy is None:
        raise RefusedPayload("survey_unsupported")
    try:
        canary = run_canaries(searcher, canaries) if canaries else []
        res = svy(job["disclosure"], max_legs=job["max_legs"], cutoff_date=job.get("cutoff_date"),
                  from_date=job.get("from_date"), offices=job.get("offices"))
        if not isinstance(res, dict) or not isinstance(res.get("union"), list) \
                or not isinstance(res.get("manifest"), dict):
            raise RefusedPayload("searcher_failed")
    except RefusedPayload:
        raise
    except EngineError as exc:
        raise _searcher_failed(exc, "engine_error") from None
    except Exception as exc:  # noqa: BLE001 — includes UnconstructibleLeg, mapped by name below
        if type(exc).__name__ == "UnconstructibleLeg":       # no survey_legs import: stdlib-only module
            raise RefusedPayload("unconstructible_disclosure") from None
        raise _searcher_failed(exc) from None
    return {"kind": "survey", "union": res["union"], "legs": res.get("legs", []),
            "manifest": res["manifest"], "cutoff_date": job.get("cutoff_date"),
            "from_date": job.get("from_date"), "offices": job.get("offices"),
            "max_legs": job["max_legs"], "canary": canary,
            "pipeline_version": getattr(searcher, "version", "unversioned"),
            "claim_boundary": CLAIM_BOUNDARY}


def _run_document(job: Dict[str, Any], searcher: Searcher) -> Dict[str, Any]:
    """Read one document by key. A read honours the matter's date bound exactly as a search does — an
    attorney must not read art published on or after their own priority date. `not_found` and
    `date_out_of_bound` are signed refusals, not crashes."""
    try:
        res = searcher.document(job["key"], cutoff_date=job.get("cutoff_date"))
        if not isinstance(res, dict) or "text" not in res:
            raise RefusedPayload("searcher_failed")
    except RefusedPayload:
        raise
    except Exception as exc:  # noqa: BLE001
        raise _searcher_failed(exc) from None
    pub = res.get("publication_date")
    cutoff = job.get("cutoff_date")
    if cutoff is not None and not (isinstance(pub, int) and 0 < pub < cutoff):
        # Refuse rather than return: the text is discarded, the refusal statement carries no content.
        raise RefusedPayload("date_out_of_bound")
    return {"kind": "document", "key": job["key"], "text": res["text"], "coverage": res.get("coverage") or {},
            "publication_date": pub, "country": res.get("country"), "cutoff_date": cutoff,
            "pipeline_version": getattr(searcher, "version", "unversioned"), "claim_boundary": CLAIM_BOUNDARY}


def statement_fields(job: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
    """What the statement commits to. No query text, no hit text: hashes, counts, the control lane, and
    the claim boundary verbatim. The service overrides the hashes with request-salted ones."""
    if result.get("kind") == "survey":
        # The aggregate manifest IS the statement's share (content-free by construction in survey_run:
        # leg hashes/kinds/fates, plan_sha256, rrf constants, scope, retry counts). Plus the press
        # identity: disclosure hash, union size, control lane, claim boundary.
        return {"kind": "survey", "disclosure_sha256": query_hash(job["disclosure"]),
                "result_sha256": sha256(result), "manifest": result["manifest"],
                "union_n": len(result["union"]), "max_legs": result["max_legs"],
                "cutoff_date": result.get("cutoff_date"), "from_date": result.get("from_date"),
                "offices": result.get("offices"), "canary": result["canary"],
                "pipeline_version": result["pipeline_version"], "claim_boundary": CLAIM_BOUNDARY}
    if result.get("kind") == "document":
        return {"kind": "document", "key": result["key"], "text_sha256": query_hash(result.get("text") or ""),
                "coverage": result.get("coverage"), "publication_date": result.get("publication_date"),
                "country": result.get("country"), "cutoff_date": result.get("cutoff_date"),
                "pipeline_version": result["pipeline_version"], "claim_boundary": CLAIM_BOUNDARY}
    return {"kind": "search", "query_sha256": query_hash(job["query"]), "result_sha256": sha256(result),
            "hits_n": len(result["hits"]), "k": result["k"], "cutoff_date": result["cutoff_date"],
            "from_date": result.get("from_date"), "offices": result.get("offices"),
            "legs": result["legs"], "candidates_total": result["candidates"], "cpc_predicted": result["cpc"],
            "canary": result["canary"], "calibration": result["calibration"],
            "calibration_papers": (result.get("calibration") or {}).get("papers"), "paper_coverage": result.get("paper_coverage"),
            "undated_hits": result.get("undated_hits", 0), "hits_by_source": result.get("hits_by_source"),
            # Enforcement, not just input: what each accepted filter actually removed (or null when not asked).
            "cutoff_applied": result.get("cutoff_applied"), "from_date_applied": result.get("from_date_applied"),
            "offices_applied": result.get("offices_applied"),
            # Which documents the search could READ in full, and which it could only weigh by abstract.
            # Signed, so a coverage gap is a stated limit rather than a sentence in a rendered page.
            "text_coverage": result.get("text_coverage"),
            # What each ranking stage did (counts), or null for an engine that has no such stages.
            "stages_applied": result.get("stages_applied"),
            # Marks: ALL null iff the request carried no marks — absent (older statement), null (not
            # given) and zero (given, nothing acted) are three different facts (verdict Risk 7). The hash
            # here is a placeholder the service overrides with a request-SALTED one (work product, like
            # query_sha256). marks_unresolved is a COUNT; the unresolved keys stay in the sealed result.
            "marks_sha256": sha256(job["marks"]) if job.get("marks") is not None else None,
            "marks_counts": marks_counts(job.get("marks")),
            "marks_unresolved": (len(result["marks_unresolved"]) if result.get("marks_unresolved") is not None else None)
            if job.get("marks") is not None else None,
            "marks_applied": result.get("marks_applied") if job.get("marks") is not None else None,
            "pipeline_version": result["pipeline_version"], "claim_boundary": CLAIM_BOUNDARY}
