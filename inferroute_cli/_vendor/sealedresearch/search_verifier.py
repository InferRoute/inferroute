"""The local verifying proxy for the sealed search, and its one-shot JSON command line.

Verify, THEN seal. Before a query is sealed, this machine verifies the search enclave's evidence against
pinned AMD and Microsoft roots and a pinned container policy, and checks that the hardware report commits
to the exact keys and manifests on offer. The answer is opened here, and accepted only when it is signed
by the key the report committed to, for this request, over the same runtime data.

Every check is returned as a step so it can be shown to the user outside any model. Refusals name a
check, never a host or an address.

    python -m sealedresearch.search_verifier verify         --enclave URL --expect-host-data HEX
    python -m sealedresearch.search_verifier search "TEXT"  --enclave URL --expect-host-data HEX [-k N] [--cutoff YYYYMMDD]
    python -m sealedresearch.search_verifier serve          --enclave URL --expect-host-data HEX --port P

Output is one JSON object: {"ok", "steps", "enclave", "refusal", "test_roots", "result"?, "statement"?}.
`--pins FILE` replaces the production roots, for a test enclave only, and is reported as such.
"""
from __future__ import annotations

import argparse
import base64
import datetime as _dt
import fcntl
import hashlib
import json
import os
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple

from . import aci_evidence, cose, envelope, search, statement, verify_record
from .amd_chain import Steps
from .search_contract import HEX16, HEX32, KIND, PRIVACY_CONTRACT, salted


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _current_ref_value(reference: Dict[str, Any], field: str, at_iso: str) -> Optional[str]:
    """The reference's value for `field` that is CURRENT at `at_iso`, decided by the canonical matcher
    (verify_record._ref_match) so this derivation and the record's own verifier agree on 'current' — one
    predicate, never a second copy of the validity-window logic."""
    entries = verify_record._ref_entries(reference, field)
    for e in entries:
        ok, _why = verify_record._ref_match(entries, e["value"], at_iso)
        if ok:
            return e["value"]
    return None


def _utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

CLIENT = "sealed-search 0.1"


class Verifier:
    def __init__(self, enclave_url: str, *, expect_host_data: Optional[str], pins: Optional[Dict[str, Any]] = None,
                 expect_index: Optional[str] = None, timeout: float = 300.0,
                 reference: Optional[Dict[str, Any]] = None, session_id: Optional[str] = None):
        self.url = enclave_url.rstrip("/")
        self.expect_host_data, self.expect_index, self.timeout = expect_host_data, expect_index, timeout
        # One session id for this client, carried in the sealed body of every request so the enclave counts
        # a per-session sequence over it and the record's completeness is scoped to THIS session.
        self.session_id = session_id or os.urandom(16).hex()
        # An authenticated reference, verified by the caller before it got here. When set, EVERY live
        # verification runs verify_record.check_identity — the SAME predicate the exported record's verifier
        # runs — so "this enclave is InferRoute's" is decided against the signed reference BEFORE the
        # attorney types anything, not only after the fact in the record.
        self.reference = reference
        pins = pins or {}
        self.test_roots = bool(pins)
        self.amd_pins = pins.get("amd")
        self.uvm_root = pins.get("uvm_root", cose.UVM_ROOT_SHA256_B64URL)
        self.uvm_min_svn = int(pins.get("uvm_min_svn", cose.UVM_MIN_SVN))

    # ---- transport: ciphertext and public evidence only
    def _call(self, method: str, path: str, body: Optional[bytes] = None) -> bytes:
        req = urllib.request.Request(self.url + path, data=body, method=method,
                                     headers={"content-type": "application/octet-stream"} if body is not None else {})
        with urllib.request.urlopen(req, timeout=self.timeout) as fh:
            return fh.read()

    def _verdict(self, steps: Steps, enclave: Dict[str, Any], **extra: Any) -> Dict[str, Any]:
        return {"ok": steps.ok, "steps": list(steps), "enclave": enclave, "test_roots": self.test_roots,
                "refusal": None if steps.ok else (steps.problems or ["no checks ran"])[0], **extra}

    def _verify(self) -> Tuple[Steps, Dict[str, Any], Optional[Dict[str, Any]], bytes, Optional[Dict[str, Any]]]:
        steps: Steps = Steps()
        try:
            raw = self._call("GET", "/offer")
            offer = json.loads(raw)
            rd_bytes = base64.b64decode(offer["runtime_data"], validate=True)
            rd = json.loads(rd_bytes)
            if not isinstance(rd, dict):
                raise ValueError("runtime data is not an object")
        except Exception as exc:                                        # noqa: BLE001
            # NOTHING ANSWERED vs ANSWERED WITH RUBBISH are different events and were reported as one.
            # A reaped test enclave gives URLError, and the page then said "the search enclave did not
            # verify" — a trust verdict for a machine that was not there. Henry, 30 Sep: a connection
            # failure must not wear a verification label. HTTPError is checked FIRST because it subclasses
            # URLError: a 500 means something IS listening, which is the trust-relevant case.
            import urllib.error, socket
            if isinstance(exc, urllib.error.HTTPError):
                why = (f"answered {exc.code}, not with an offer — something is listening there, "
                       "but it is not serving a sealed search")
            elif isinstance(exc, (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError)):
                why = ("nothing answered — no connection. The search machine is probably not running; "
                       "this is a connection failure, NOT a failed verification")
            else:
                why = (f"answered, but not with a usable offer ({type(exc).__name__}) — something is "
                       "listening there and its reply could not be read as an offer")
            steps.add(False, "search enclave reachable", why)
            return steps, {}, None, b"", None
        steps.add(True, "search enclave reachable", f"offer received ({len(raw)} bytes)")
        if self.test_roots:
            steps.add(True, "roots", "NON-PRODUCTION ROOTS PINNED: this can only verify a test enclave, never Azure")
        ev, info = aci_evidence.verify_combined(offer, rd_bytes, expect_host_data=self.expect_host_data,
                                                amd_pins=self.amd_pins, uvm_root=self.uvm_root, uvm_min_svn=self.uvm_min_svn)
        steps.extend(ev)
        floor_checks = verify_record.Checks()
        verify_record.check_reference_firmware_before_sealing(
            floor_checks, offer, self.reference, pins=self.amd_pins)
        for status, name, detail in floor_checks.rows:
            steps.add(status == "PASS", name, detail)
        shape = (rd.get("v") == 1 and rd.get("kind") == KIND and bool(HEX16.match(str(rd.get("lifetime_id", ""))))
                 and all(HEX32.match(str(rd.get(k, ""))) for k in
                         ("enclave_x25519_pub", "statement_signer_pub", "index_manifest_sha256", "model_manifest_sha256"))
                 and rd.get("index_manifest_sha256") != "0" * 64)
        steps.add(shape, "runtime data commits to a search",
                  f"index {rd.get('index_snapshot')!r}, manifest {str(rd.get('index_manifest_sha256'))[:12]}…, "
                  f"encoders {str(rd.get('model_manifest_sha256'))[:12]}…" if shape else "the runtime data is not a sealed-search commitment")
        contract_ok = rd.get("privacy_contract") == PRIVACY_CONTRACT
        steps.add(contract_ok, "plaintext-handling contract is present",
                  "the runtime commits to the service's handling boundary and its explicit limits"
                  if contract_ok else "missing or unrecognized plaintext-handling contract; refusing to seal")
        if self.expect_index is not None:
            steps.add(rd.get("index_snapshot") == self.expect_index, "expected index", f"offer searches {rd.get('index_snapshot')!r}")
        # What tools this build serves; a client offers only these. The privacy contract is returned
        # because its exact value was checked above and the whole runtime_data is report-bound.
        enclave = {**info, "index_snapshot": rd.get("index_snapshot"), "index_manifest_sha256": rd.get("index_manifest_sha256"),
                   "model_manifest_sha256": rd.get("model_manifest_sha256"), "lifetime_id": rd.get("lifetime_id"),
                   "enclave_key": str(rd.get("enclave_x25519_pub", ""))[:16], "pipeline_version": rd.get("pipeline_version"),
                   "supports": rd.get("supports") or ["search"], "privacy_contract": rd.get("privacy_contract")}
        if self.reference is not None:
            # The canonical identity predicate, live: policy (HOST_DATA) + index + encoder manifests against
            # the signed reference, at NOW. A FAIL here makes the whole verification fail, so nothing seals
            # to an enclave whose identity does not match InferRoute's published reference.
            host_hex = info.get("host_data")
            p = {"host_data": bytes.fromhex(host_hex)} if host_hex else None
            c = verify_record.Checks()
            verify_record.check_identity(c, rd, p, self.reference, _now_iso())
            for status, name, detail in c.rows:
                steps.add(True if status == "PASS" else None if status == "SKIP" else False, name, detail)
        return steps, enclave, rd, rd_bytes, offer

    def verify(self) -> Dict[str, Any]:
        steps, enclave, _, _, _ = self._verify()
        return self._verdict(steps, enclave)

    def search(self, text: str, k: int = 20, cutoff_date: Optional[int] = None,
               expect_lifetime_id: Optional[str] = None, from_date: Optional[int] = None,
               offices: Optional[List[str]] = None) -> Dict[str, Any]:
        """`expect_lifetime_id`: the enclave the user approved; any other enclave is refused before sealing.
        `from_date`/`offices`: optional scope narrowing (a lower date bound ≤ cutoff, and jurisdictions)."""
        steps, enclave, rd, rd_bytes, offer = self._verify()
        if rd is not None and expect_lifetime_id is not None:
            steps.add(rd.get("lifetime_id") == expect_lifetime_id, "the approved enclave",
                      "the same enclave the user approved" if rd.get("lifetime_id") == expect_lifetime_id
                      else "a different enclave than the one the user approved; approval is per enclave")
        if not steps.ok or rd is None:
            steps.add(False, "query sealed", "not sealed: the enclave did not verify, so nothing about the query left this machine")
            return self._verdict(steps, enclave)
        reply_priv, reply_pub = envelope.gen_keypair()
        request_id = os.urandom(16).hex()
        payload = {"kind": "search", "query": text, "k": k, "cutoff_date": cutoff_date, "legs": None,
                   "from_date": from_date, "offices": offices, "session_id": self.session_id,
                   "meta": {"client": CLIENT}, "reply_to": reply_pub.hex(), "request_id": request_id}
        plain = json.dumps(payload).encode()
        try:
            search.validate(plain)
        except search.RefusedPayload as exc:
            steps.add(False, "query sealed", f"refused on this machine before sealing: {exc.code}")
            return self._verdict(steps, enclave)
        blob = envelope.seal(bytes.fromhex(rd["enclave_x25519_pub"]), plain, aad=rd["lifetime_id"].encode())
        steps.add(True, "query sealed", f"{len(blob)} bytes sealed to the verified enclave key {rd['enclave_x25519_pub'][:12]}…")
        try:
            answer = json.loads(self._call("POST", "/search", blob))
        except Exception as exc:                                        # noqa: BLE001
            # THE ENCLAVE HAS ALREADY TAKEN A SEQUENCE NUMBER. It increments seq as soon as a request is
            # readable — before it searches — so a request that times out or drops leaves a permanent gap in
            # the record's per-lifetime sequence. The completeness check is right to report that gap: a
            # search of that enclave really is missing. But an unexplained gap reads like a deleted search,
            # which is the accusation the check exists to make. Carry the facts out so the proxy can record
            # this device's own account of it.
            steps.add(False, "enclave answered", f"no answer ({type(exc).__name__})")
            return self._verdict(steps, enclave, _unanswered={
                "request_id": request_id, "lifetime_id": rd.get("lifetime_id"),
                "reason": f"{type(exc).__name__} after {self.timeout:.0f}s", "at": _utcnow()})
        if "sealed" not in answer:
            steps.add(False, "enclave answered", f"an unsigned refusal ({str(answer.get('refused'))[:40]!r}); it cannot be attributed to the enclave")
            return self._verdict(steps, enclave)
        try:
            inner = json.loads(envelope.open_(reply_priv, base64.b64decode(answer["sealed"]), aad=(request_id + "/result").encode()))
            st, result = inner["statement"], inner["result"]
        except Exception as exc:                                        # noqa: BLE001
            steps.add(False, "answer opens for this request", f"it does not ({type(exc).__name__}): not sealed to this request's key")
            return self._verdict(steps, enclave)
        steps.add(True, "answer opens for this request", "sealed to the reply key made on this machine for this query")
        # Opening the answer proves WE can read it; the signed recipient proves nobody ELSE was given a copy.
        # An older enclave that does not sign the field cannot be faulted for it — the step says so and does
        # not fail, rather than passing silently as if it had been checked.
        # LIVE PATH FAILS CLOSED, and deliberately differs from the bundle verifier. Here the search is still
        # happening: an enclave that will not say which key it sealed to is either not our build or is hiding
        # a recipient, and nothing is deployed that predates the field — so refuse. In a BUNDLE the same
        # absence gets a SKIP, because a record already made cannot be re-run and failing it retroactively
        # would punish the attorney for our version history. Same fact, different remedy, both stated.
        self._bind_checks(steps, st, rd, rd_bytes, reply_pub, request_id)
        if not steps.ok:
            return self._verdict(steps, enclave)
        if st.get("outcome") != "answered":
            steps.add(False, "enclave searched", f"the enclave refused the search: {st.get('refusal')!r} (signed)")
            return self._verdict(steps, enclave, statement=st)
        matches = (isinstance(result, dict) and salted(request_id, result) == st.get("result_sha256")
                   and len(result.get("hits", [])) == st.get("hits_n"))
        steps.add(matches, "result is the signed result", f"{st.get('hits_n')} hits, hash as signed" if matches
                  else "the result does not match the signed hash")
        # `_evidence` carries the raw attestation the local verifier used (SNP report, endorsements, UVM
        # endorsements, CCE policy, runtime_data). The serve() handler persists it host-side for the export
        # and strips it from the response — it is not part of the sealed answer, just the proof of binding.
        return self._verdict(steps, enclave, statement=st, result=result if matches else None,
                             _evidence={"offer": offer, "checks": list(steps)} if matches else None,
                             _reply_to=reply_pub.hex())

    def _bind_checks(self, steps: Steps, st: Dict[str, Any], rd: Dict[str, Any], rd_bytes: bytes,
                     reply_pub: bytes, request_id: str) -> None:
        """The three checks common to any answered operation (search or read): the enclave signed which
        key it sealed to (no second recipient), the statement's signature verifies under the hardware-bound
        signer, and the statement is about THIS request and this enclave's commitments. One copy, so a
        read and a search cannot be verified two different ways.

        Opening the answer proves WE can read it; the signed recipient proves nobody ELSE was given a copy.
        An older enclave that does not sign the field cannot be faulted for it — the step says so and fails
        (LIVE path fails closed: an enclave that will not say which key it sealed to is either not our build
        or is hiding a recipient, and nothing is deployed that predates the field). A BUNDLE gives the same
        absence a SKIP, because a record already made cannot be re-run — same fact, different remedy."""
        want_reply = hashlib.sha256(reply_pub).hexdigest()
        only = st.get("reply_to_sha256") == want_reply
        steps.add(only, "sealed to this key only",
                  "the enclave signed the recipient: this machine's one-time key for this request, no other"
                  if only else ("the enclave did not sign which key it sealed the answer to, so nothing rules out a "
                                "second recipient" if st.get("reply_to_sha256") is None
                                else "the signed recipient is NOT the key this machine made for this request"))
        signed = statement.verify_statement(bytes.fromhex(rd["statement_signer_pub"]), st)
        steps.add(signed, "statement signed by the enclave", "signature by the key the hardware report commits to"
                  if signed else "signature does NOT verify under the committed key")
        same = (st.get("request_id") == request_id and st.get("lifetime_id") == rd["lifetime_id"]
                and st.get("runtime_data_sha256") == hashlib.sha256(rd_bytes).hexdigest()
                and st.get("index_manifest_sha256") == rd["index_manifest_sha256"]
                and st.get("model_manifest_sha256") == rd["model_manifest_sha256"])
        steps.add(same, "statement is about this request", "same request, enclave lifetime, runtime data, index and encoders"
                  if same else "the statement names a different request, lifetime or commitment")

    def document(self, key: str, cutoff_date: Optional[int] = None,
                 expect_lifetime_id: Optional[str] = None) -> Dict[str, Any]:
        """Read one document by publication number. Verify-then-seal, exactly like a search: nothing about
        the key leaves until the enclave verifies, and the returned text is bound by a signed text_sha256 a
        stranger re-checks. A read honours the matter cutoff — the enclave refuses one out of bound, and the
        record's verifier re-checks it, so the record cannot carry a read past the priority date."""
        steps, enclave, rd, rd_bytes, offer = self._verify()
        if rd is not None and "document" not in (rd.get("supports") or ["search"]):
            steps.add(False, "reads supported", "this enclave build does not serve document reads")
        if rd is not None and expect_lifetime_id is not None:
            steps.add(rd.get("lifetime_id") == expect_lifetime_id, "the approved enclave",
                      "the same enclave the user approved" if rd.get("lifetime_id") == expect_lifetime_id
                      else "a different enclave than the one the user approved; approval is per enclave")
        if not steps.ok or rd is None:
            steps.add(False, "read sealed", "not sealed: the enclave did not verify, so nothing about the key left this machine")
            return self._verdict(steps, enclave)
        reply_priv, reply_pub = envelope.gen_keypair()
        request_id = os.urandom(16).hex()
        payload = {"kind": "document", "key": key, "cutoff_date": cutoff_date, "session_id": self.session_id,
                   "meta": {"client": CLIENT}, "reply_to": reply_pub.hex(), "request_id": request_id}
        plain = json.dumps(payload).encode()
        try:
            search.validate(plain)
        except search.RefusedPayload as exc:
            steps.add(False, "read sealed", f"refused on this machine before sealing: {exc.code}")
            return self._verdict(steps, enclave)
        blob = envelope.seal(bytes.fromhex(rd["enclave_x25519_pub"]), plain, aad=rd["lifetime_id"].encode())
        steps.add(True, "read sealed", f"{len(blob)} bytes sealed to the verified enclave key {rd['enclave_x25519_pub'][:12]}…")
        try:
            answer = json.loads(self._call("POST", "/search", blob))
        except Exception as exc:                                        # noqa: BLE001
            steps.add(False, "enclave answered", f"no answer ({type(exc).__name__})")
            return self._verdict(steps, enclave, _unanswered={
                "request_id": request_id, "lifetime_id": rd.get("lifetime_id"),
                "reason": f"{type(exc).__name__} after {self.timeout:.0f}s", "at": _utcnow()})
        if "sealed" not in answer:
            steps.add(False, "enclave answered", f"an unsigned refusal ({str(answer.get('refused'))[:40]!r}); it cannot be attributed to the enclave")
            return self._verdict(steps, enclave)
        try:
            inner = json.loads(envelope.open_(reply_priv, base64.b64decode(answer["sealed"]), aad=(request_id + "/result").encode()))
            st, result = inner["statement"], inner["result"]
        except Exception as exc:                                        # noqa: BLE001
            steps.add(False, "answer opens for this request", f"it does not ({type(exc).__name__}): not sealed to this request's key")
            return self._verdict(steps, enclave)
        steps.add(True, "answer opens for this request", "sealed to the reply key made on this machine for this read")
        self._bind_checks(steps, st, rd, rd_bytes, reply_pub, request_id)
        if not steps.ok:
            return self._verdict(steps, enclave)
        if st.get("outcome") != "answered":
            steps.add(False, "enclave read", f"the enclave refused the read: {st.get('refusal')!r} (signed)")
            return self._verdict(steps, enclave, statement=st)
        text = (result or {}).get("text") if isinstance(result, dict) else None
        bound = isinstance(text, str) and salted(request_id, text) == st.get("text_sha256") and st.get("key") == key
        steps.add(bound, "text is the signed document", "the returned text is exactly what the enclave signed for this key"
                  if bound else "the returned text does not match the signed text_sha256, or the key differs")
        return self._verdict(steps, enclave, statement=st, result=result if bound else None,
                             _evidence={"offer": offer, "checks": list(steps)} if bound else None,
                             _reply_to=reply_pub.hex())


class MatterState:
    """Matter state the AGENT must not be able to forge: the date bound (cutoff), which enclave
    measurements the human has approved, and relevance marks. Owned by this host-side proxy, kept in a
    file OUTSIDE the agent's sandbox. The cutoff is fixed at construction (the matter's date bound); no
    request can change it. Approvals are added only when the launcher's extension reports a human confirm,
    and the agent has no way to reach this proxy except through that extension.
    """

    def __init__(self, path: Optional[str], cutoff_date: Optional[int], trust_disk: bool = False,
                 session_id: Optional[str] = None):
        """`trust_disk`: load approvals, marks and the surfaced set from `path` on start. Only pass it when
        the filesystem is ENFORCED so the agent cannot write `path` — otherwise a prompt-injected session
        could forge an approval on disk that a later session would honour, skipping the human confirm.
        Default False: state is session-scoped in memory (the confirm re-prompts each session), safe
        regardless of the sandbox. The cutoff is always the construction argument, never from disk.
        `session_id` identifies THIS launch (the verifier process is the session); it is the host-side source
        for who surfaced a document and who made a mark — not a request field.

        The existing file is ALWAYS loaded, so this session never clobbers what earlier sessions wrote
        (approvals, marks, the surfaced set). `trust_disk` governs only whether disk state is HONOURED: an
        approval loaded from disk gates the confirm only under trust_disk; a document only in the loaded
        surfaced set counts as prior exposure only under trust_disk. What this session itself does is always
        honoured. The cutoff is always the construction argument, never from disk."""
        self.path = path
        self._cutoff = cutoff_date
        self.trust_disk = trust_disk
        self.session_id = session_id or ""
        self._data = {"approved": [], "marks": {}, "surfaced": {}}
        self._session_approved: set = set()      # approvals made in THIS session — honoured regardless of trust
        self._session_surfaced: set = set()       # documents THIS session's searches opened
        if path and os.path.exists(path):
            try:
                loaded = json.load(open(path))
                self._data["approved"] = list(loaded.get("approved", []))
                self._data["marks"] = dict(loaded.get("marks", {}))
                self._data["surfaced"] = dict(loaded.get("surfaced", {}))
            except (OSError, ValueError):
                pass

    @property
    def cutoff_date(self) -> Optional[int]:
        return self._cutoff

    @staticmethod
    def _history_of(entry: Any) -> "list[Dict[str, Any]]":
        if isinstance(entry, dict) and isinstance(entry.get("history"), list):
            return [e for e in entry["history"] if isinstance(e, dict)]
        if isinstance(entry, dict) and "value" in entry:          # tolerate a pre-history single mark
            return [entry]
        return []

    @classmethod
    def _merge(cls, a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
        """Merge two versions of the matter state so two sessions on one matter never lose each other's work
        (L5). approvals: union; mark history: union by (at, session_id, VALUE) — value is in the key
        because two marks in the same second from one session (mis-click then clear, the exact unselect
        gesture) are two REAL events, and an (at, session_id) key silently collapsed them (found by the
        "cleared" feature's own test, 2026-09-25); an identical triple is a genuinely replayed row.
        latest recomputed; surfaced: union of sessions, best (lowest) rank."""
        approved = list(dict.fromkeys([*a.get("approved", []), *b.get("approved", [])]))
        marks: Dict[str, Any] = {}
        for k in set(a.get("marks", {})) | set(b.get("marks", {})):
            seen: Dict[tuple, Dict[str, Any]] = {}
            for e in [*cls._history_of(a.get("marks", {}).get(k)), *cls._history_of(b.get("marks", {}).get(k))]:
                seen[(e.get("at"), e.get("session_id"), e.get("value"))] = e
            # same-second entries keep INSERTION order within the key sort (python sort is stable), so a
            # relevant→cleared pair in one second lands cleared-last and latest reads correctly
            hist = sorted(seen.values(), key=lambda e: (e.get("at") or "", e.get("session_id") or ""))
            marks[k] = {"latest": hist[-1] if hist else None, "history": hist}
        surfaced: Dict[str, Any] = {}
        for src in (a.get("surfaced", {}), b.get("surfaced", {})):
            for k, e in src.items():
                m = surfaced.setdefault(k, {"sessions": [], "rank": e.get("rank")})
                for s in e.get("sessions", []):
                    if s not in m["sessions"]:
                        m["sessions"].append(s)
                ranks = [r for r in (m.get("rank"), e.get("rank")) if r is not None]
                m["rank"] = min(ranks) if ranks else None
        return {"approved": approved, "marks": marks, "surfaced": surfaced}

    def _save(self) -> None:
        if not self.path:
            return
        # Two sessions may be open on one matter. Take an exclusive lock on a stable sidecar, re-read the
        # file, MERGE this session's in-memory copy into it, and write — so no session clobbers another's
        # approvals, marks or surfaced set (L5, last-writer-wins → union). Adopt the merged result in memory.
        lock_path = self.path + ".lock"
        with open(lock_path, "w") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                disk: Dict[str, Any] = {}
                if os.path.exists(self.path):
                    try:
                        disk = json.load(open(self.path))
                    except (OSError, ValueError):
                        disk = {}
                merged = self._merge(disk, self._data)
                tmp = self.path + ".tmp"
                with open(tmp, "w") as fh:
                    json.dump({**merged, "cutoff_date": self._cutoff}, fh)
                os.replace(tmp, self.path)
                self._data = merged
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)

    def state(self) -> Dict[str, Any]:
        return {"approved": list(self._data["approved"]), "marks": dict(self._data["marks"]),
                "surfaced": dict(self._data["surfaced"]), "cutoff_date": self._cutoff}

    def is_approved(self, measurement: str) -> bool:
        # An approval is honoured if THIS session made it, or if it is on disk AND the disk is trusted (the
        # filesystem is enforced so the agent could not have forged it).
        if not measurement:
            return False
        if measurement in self._session_approved:
            return True
        return self.trust_disk and measurement in self._data["approved"]

    def approve(self, measurement: str) -> None:
        if not measurement:
            return
        self._session_approved.add(measurement)
        if measurement not in self._data["approved"]:
            self._data["approved"].append(measurement)
            self._save()

    def record_surfaced(self, hits: "list[Tuple[str, int]]") -> None:
        """Remember every document THIS machine's verified search opened, and at what rank, tagged by the
        session that returned it. This is the ground truth for a mark's exposure — the extension's own list
        is only UI (M1). Kept host-side, written by the proxy, never by the agent."""
        changed = False
        for key, rank in hits:
            if not key:
                continue
            self._session_surfaced.add(key)
            e = self._data["surfaced"].setdefault(key, {"sessions": [], "rank": rank})
            if self.session_id and self.session_id not in e["sessions"]:
                e["sessions"].append(self.session_id)
            e["rank"] = min(int(e.get("rank", rank)), int(rank))
            changed = True
        if changed:
            self._save()

    def exposure(self, key: str) -> "Tuple[str, Optional[int]]":
        """How the marked document was exposed to the attorney. Different measurements that must not be
        conflated when the marks become labels (FRAMEWORK §6.2), and a value the verifier cannot know is
        never asserted (R12): a document THIS session's search opened is this_session; a document only in the
        disk-loaded surfaced set is earlier_session, but only when the disk is trusted (else it could be
        forged, so nothing prior can be claimed → unknown_prior); truly absent is not_surfaced only when the
        earlier sessions were actually consulted (trust_disk)."""
        if key in self._session_surfaced:
            e = self._data["surfaced"].get(key) or {}
            return "this_session", e.get("rank")
        if not self.trust_disk:
            return "unknown_prior", None      # earlier sessions not consulted / not trustworthy
        e = self._data["surfaced"].get(key)
        if e and e.get("sessions"):
            return "earlier_session", e.get("rank")
        return "not_surfaced", None           # earlier sessions were loaded; the document is truly absent

    def mark(self, key: str, value: str, session_id: Optional[str] = None) -> None:
        # A relevance mark on a document. It can only arrive from a user-typed slash command (the model has
        # no way to reach this endpoint), so actor is "human" — and the Tuner uses only human rows later
        # (SYSTEM-SPEC R5). Time, actor, session and exposure are all stamped HERE, host-side, never taken
        # from the request. The record is append-only (M2): a changed mind is signal, so we keep the history
        # and expose the latest.
        # "cleared" (2026-09-25, Henry): the professional takes a mark back OFF. Append-only like any
        # changed mind — a new human row with its own at/actor/surfaced/rank, latest.value == "cleared";
        # consumers match values POSITIVELY, so a cleared document falls out of relevance/teleport/pruning
        # by construction while the history keeps both rows for the Tuner. An unknown value now RAISES
        # (surfaced as 400) instead of silently no-opping — a silent no-op on a write made the page able
        # to lie about a human judgement (the client read back 200 + unchanged state).
        if not key:
            raise ValueError("mark: missing key")
        if value not in ("relevant", "not-relevant", "known", "cleared"):
            raise ValueError(f"mark: unknown value {value!r}")
        surfaced, rank = self.exposure(key)
        entry: Dict[str, Any] = {"value": value, "actor": "human", "session_id": self.session_id or "",
                                 "at": _utcnow(), "surfaced": surfaced}
        if rank is not None:
            entry["rank"] = rank
        m = self._data["marks"].get(key)
        if not isinstance(m, dict) or "history" not in m:
            m = {"latest": None, "history": []}
            self._data["marks"][key] = m
        m["history"].append(entry)
        m["latest"] = entry
        self._save()


class RecordStore:
    """The per-session disclosure record ("which surface saw what"), WRITTEN BY THIS HOST-SIDE PROXY to a
    file outside the agent's sandbox. The extension composes it from the model receipt and the search
    proofs — sources the agent does not control — and POSTs it here; the agent has no way to write the file
    or reach this endpoint, so it cannot rewrite or delete the record the export puts in the client file."""

    def __init__(self, path: Optional[str], confinement: Optional[str] = None):
        self.path = path
        self.confinement = confinement
        self._last: Dict[str, Any] = {}
        self._created = False

    def put(self, record: Dict[str, Any]) -> None:
        # The confinement line is asserted HERE, host-side, from what the launcher passed — never from the
        # posted body, which is composed in the sandbox. A session opened --dev-unconfined is stamped as such
        # even if the extension's content claimed otherwise, so an unconfined session cannot ship to a client
        # file looking confined.
        if self.confinement is not None:
            record = {**record, "confinement": self.confinement}
        self._last = record
        if not self.path:
            return
        # One record file per session, append-only across sessions (Q2): the first write EXCLUSIVELY
        # creates the file, so this session can never clobber another session's record if two session ids
        # ever collide. Later POSTs within THIS session update it in place (the record accumulates as more
        # searches run). The path is per-session, chosen by the launcher, under confidential/ (write-denied).
        if not self._created:
            try:
                os.close(os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
            except FileExistsError as e:
                raise RuntimeError(f"a disclosure record already exists at {self.path}; refusing to overwrite "
                                   "another session's record") from e
            self._created = True
        # UNIQUE tmp per writer: a shared ".tmp" name makes the atomic replace non-atomic under concurrent
        # writes (two writers truncate/interleave the same tmp -> a corrupt record that reads as TAMPERING
        # downstream; surfaced 2026-09-24 by the survey fan-out firing 5 writes in 5s). pid+uuid + fsync.
        import uuid as _uuid
        tmp = f"{self.path}.{os.getpid()}.{_uuid.uuid4().hex}.tmp"
        try:
            with open(tmp, "w") as fh:
                json.dump(record, fh, indent=1)
                fh.flush(); os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                try: os.unlink(tmp)
                except OSError: pass

    def get(self) -> Dict[str, Any]:
        if self.path and os.path.exists(self.path):
            try:
                return json.load(open(self.path))
            except (OSError, ValueError):
                pass
        return self._last


class SearchArchive:
    """Everything the export needs to REBUILD each sealed search's report and prove its binding, kept host-side
    where the agent cannot reach it. Per search, written by the proxy from what it received over /search (the
    agent never composes or reaches it): the enclave-signed statement VERBATIM (with its sig), the opened
    RESULT (hits and passages — so the Form-1503 report can be re-rendered at export time, not just a hit
    count), and the ATTESTATION EVIDENCE the local verifier used (the raw /offer: SNP report, endorsements, UVM
    endorsements, CCE policy, runtime_data) so a firm can recompute REPORT_DATA = sha256(runtime_data) and find
    the signing key in it. Append-only JSONL, one file per session, under confidential/."""

    def __init__(self, path: Optional[str]) -> None:
        self.path = path

    @staticmethod
    def _sha(obj: Any) -> str:
        return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()

    def add_unanswered(self, note: Dict[str, Any]) -> None:
        """A search this device SEALED and sent, whose answer never came back. The enclave takes its sequence
        number before it searches, so the record will have a gap there for ever. Writing the attempt down does
        not close the gap and must not look as though it does — it gives the reader this device's account of
        it, so an unexplained hole (which reads as a deleted search) becomes an explained one."""
        if not self.path or not isinstance(note, dict):
            return
        row = {"kind": "unanswered", "at": note.get("at") or _utcnow(),
               "request_id": note.get("request_id"), "lifetime_id": note.get("lifetime_id"),
               "reason": note.get("reason")}
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(self.path, "a") as fh:
                fcntl.flock(fh, fcntl.LOCK_EX)
                try:
                    fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                finally:
                    fcntl.flock(fh, fcntl.LOCK_UN)
        except OSError:
            pass

    def add(self, statement: Dict[str, Any], result: Optional[Dict[str, Any]], evidence: Optional[Dict[str, Any]],
            enclave: Dict[str, Any], report_html: Optional[str] = None, query_text: Optional[str] = None,
            cutoff: Optional[int] = None, policy_b64: Optional[str] = None, reply_to: Optional[str] = None) -> None:
        if not self.path or not isinstance(statement, dict) or "sig" not in statement:
            return
        # The signer key comes from the runtime data the hardware report binds — read here from the evidence,
        # never from anything the extension or model could supply.
        signer = None
        try:
            rd = json.loads(base64.b64decode(((evidence or {}).get("offer") or {}).get("runtime_data", ""), validate=True))
            signer = rd.get("statement_signer_pub")
        except Exception:                                      # noqa: BLE001
            signer = None
        # THE DOCUMENT THIS ROW SHOWS, lifted to the top level where search_bundle and verify_record's
        # check_document look for it. Taken from the OPENED result, not from the signed statement, so the
        # check that compares them can still fail: it catches a row showing the text of one document under
        # the statement for another. Copying the statement's own key here would make that check a control
        # that is always satisfied.
        doc_key = None
        if isinstance(result, dict) and result.get("kind") == "document":
            doc_key = result.get("key")
        row = {"at": _utcnow(), "statement": statement, "result": result if isinstance(result, dict) else None,
               "signer_pub": signer or enclave.get("statement_signer_pub"),
               "measurement": enclave.get("measurement"), "host_data": enclave.get("host_data"),
               "index_snapshot": enclave.get("index_snapshot"), "cutoff_date": cutoff}
        if doc_key is not None:
            row["key"] = doc_key
        # The plaintext query THIS proxy sealed — the client's own text, kept host-side so the export can open
        # the statement's query_sha256 and bind the signed search to exactly this wording.
        if query_text is not None:
            row["query_text"] = query_text
        # The public half of the one-time key THIS proxy made for that search. Public by nature — it is the
        # address a result was sealed to, not a secret — and it is what a stranger hashes to check the
        # enclave's signed recipient. The private half never leaves memory and is discarded after opening.
        if reply_to is not None:
            row["reply_to"] = reply_to
        if report_html:
            row["report_html"] = report_html
        if isinstance(evidence, dict) and policy_b64:
            evidence = {**evidence, "policy_b64": policy_b64}   # so HOST_DATA = sha256(policy) is redoable
        if isinstance(evidence, dict):
            row["evidence"] = evidence
            row["evidence_sha256"] = self._sha(evidence)
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            with open(self.path, "a") as fh:
                fcntl.flock(fh, fcntl.LOCK_EX)
                try:
                    fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                finally:
                    fcntl.flock(fh, fcntl.LOCK_UN)
        except OSError:
            pass


def serve(verifier: Verifier, port: int, host: str = "127.0.0.1", state: Optional[MatterState] = None,
          record: Optional[RecordStore] = None, lifecycle: Optional[Any] = None,
          archive: Optional[SearchArchive] = None, report_matter: str = "", report_firm: str = "",
          policy_b64: Optional[str] = None, reference_info: Optional[Dict[str, Any]] = None) -> ThreadingHTTPServer:
    """GET /enclave → verification; POST /search {"text","k"} → verification and result (the cutoff is the
    host-held matter date bound, NOT a request field); GET /matter/state; POST /matter/approve|/matter/mark;
    POST /record writes the disclosure record to a host file the agent cannot reach; GET /record reads it;
    GET /lifecycle → the managed enclave's status; POST /keep-warm resets its idle countdown; POST /activity
    marks user activity (so a reap never lands mid-read). `lifecycle` is an optional LifecycleManager.
    """
    state = state if state is not None else MatterState(None, None)
    record = record if record is not None else RecordStore(None)
    archive = archive if archive is not None else SearchArchive(None)

    def _lifecycle_status() -> Dict[str, Any]:
        if lifecycle is None:
            return {"running": False, "managed": False, "note": "no managed enclave lifecycle this session"}
        return {"managed": True, **lifecycle.status()}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _json(self, code: int, obj: Dict[str, Any]) -> None:
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _body(self) -> Dict[str, Any]:
            n = int(self.headers.get("content-length") or 0)
            return json.loads(self.rfile.read(min(n, search.MAX_PLAINTEXT)) or b"{}")

        def do_GET(self):
            if self.path == "/enclave":
                out = verifier.verify()
                if reference_info is not None:
                    # What the launch screen reads to say "sealed, AND InferRoute's own (signed reference
                    # verified)". `ok` is the reference's OWN authenticity (signature + kind, checked at
                    # startup); whether THIS enclave matches it is the "enclave identity …" step in `steps`.
                    out["reference"] = reference_info
                self._json(200, out)
            elif self.path == "/matter/state":
                self._json(200, state.state())
            elif self.path == "/record":
                self._json(200, record.get())
            elif self.path == "/lifecycle":
                self._json(200, _lifecycle_status())
            else:
                self._json(404, {"ok": False, "refusal": "not found"})

        def do_POST(self):
            try:
                req = self._body()
            except Exception:                                           # noqa: BLE001
                self._json(400, {"ok": False, "refusal": "bad request"})
                return
            if self.path == "/keep-warm":
                if lifecycle is not None:
                    lifecycle.keep_warm()
                self._json(200, _lifecycle_status())
                return
            if self.path == "/activity":
                # User input (a turn start). Counts as activity so an idle reap never lands mid-read; returns
                # the refreshed status so the caller can update the budget line in one call.
                if lifecycle is not None:
                    lifecycle.touch()
                self._json(200, _lifecycle_status())
                return
            if self.path == "/matter/approve":
                state.approve(str(req.get("measurement", "")))
                self._json(200, state.state())
            elif self.path == "/matter/mark":
                # The session is the verifier's own (host-side), not a request field.
                try:
                    state.mark(str(req.get("key", "")), str(req.get("mark", "")))
                except ValueError as e:
                    self._json(400, {"ok": False, "refusal": str(e)}); return
                self._json(200, state.state())
            elif self.path == "/record":
                if isinstance(req.get("record"), dict):
                    record.put(req["record"])
                self._json(200, {"ok": True})
            elif self.path == "/search":
                if lifecycle is not None:
                    lifecycle.touch()                                   # a search is activity
                try:
                    text, k = str(req["text"]), int(req.get("k", 20))
                    lifetime = req.get("expect_lifetime_id")
                except Exception:                                       # noqa: BLE001
                    self._json(400, {"ok": False, "refusal": "bad request"})
                    return
                # The cutoff is the host-held matter date bound, never a request field: the agent cannot
                # widen it. A `cutoff_date` in the request is ignored.
                result = verifier.search(text, k, state.cutoff_date,
                                         expect_lifetime_id=str(lifetime) if lifetime is not None else None)
                # Record what this verified search opened, host-side, for a later mark's exposure (M1).
                evidence = result.pop("_evidence", None) if isinstance(result, dict) else None
                unanswered = result.pop("_unanswered", None) if isinstance(result, dict) else None
                if unanswered:
                    archive.add_unanswered(unanswered)
                # Host-stamped, exactly like the confinement line: this proxy MADE the reply key, so the
                # bundle carries the host's own copy to compare against the enclave's signature. Neither
                # side can move it alone — a lie by either fails the check in the bundle.
                reply_to = result.pop("_reply_to", None) if isinstance(result, dict) else None
                if isinstance(result, dict) and result.get("ok"):
                    hits = (result.get("result") or {}).get("hits") or []
                    state.record_surfaced([(str(h.get("key", "")), i + 1) for i, h in enumerate(hits) if h.get("key")])
                    if isinstance(result.get("statement"), dict):
                        # Render the Form-1503 report here, where render_report lives and from the exact opened
                        # result, and persist it beside the signed statement so the export re-shows it verbatim.
                        report_html = None
                        try:
                            from . import search_report
                            report_html = search_report.render_report(result["statement"], result.get("result") or {},
                                                                      matter=report_matter, firm=report_firm)
                        except Exception:                              # noqa: BLE001
                            report_html = None
                        archive.add(result["statement"], result.get("result"), evidence,
                                    result.get("enclave") or {}, report_html=report_html, query_text=text,
                                    cutoff=state.cutoff_date, policy_b64=policy_b64, reply_to=reply_to)
                self._json(200, result)
            elif self.path == "/document":
                # READ ONE DOCUMENT. The sealed path for this existed end to end — enclave, client,
                # archive, record verifier, bundle rendering, all tested — and was reachable from nothing:
                # the agent had no route to it, so on 2026-09-30 it correctly told a user it could not open
                # a patent while the live enclave was advertising supports: ["search", "document"].
                if lifecycle is not None:
                    lifecycle.touch()                                   # a read is activity
                try:
                    key = str(req["key"])
                    lifetime = req.get("expect_lifetime_id")
                except Exception:                                       # noqa: BLE001
                    self._json(400, {"ok": False, "refusal": "bad request"})
                    return
                # Same rule as a search: the cutoff is the host-held matter date bound, never a request
                # field. An attorney must not read art published on or after their own priority date, and
                # the agent must not be able to widen that by asking.
                result = verifier.document(key, state.cutoff_date,
                                           expect_lifetime_id=str(lifetime) if lifetime is not None else None)
                evidence = result.pop("_evidence", None) if isinstance(result, dict) else None
                unanswered = result.pop("_unanswered", None) if isinstance(result, dict) else None
                if unanswered:
                    archive.add_unanswered(unanswered)
                reply_to = result.pop("_reply_to", None) if isinstance(result, dict) else None
                if isinstance(result, dict) and result.get("ok") and isinstance(result.get("statement"), dict):
                    # No report_html: search_bundle renders a plain block per document read at export
                    # time, so rendering one here would be a second source for the same page.
                    archive.add(result["statement"], result.get("result"), evidence,
                                result.get("enclave") or {}, cutoff=state.cutoff_date,
                                policy_b64=policy_b64, reply_to=reply_to)
                self._json(200, result)
            else:
                self._json(404, {"ok": False, "refusal": "not found"})

    server = ThreadingHTTPServer((host, port), Handler)
    return server


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(prog="search_verifier", description=__doc__.split("\n\n")[0])
    p.add_argument("cmd", choices=("verify", "search", "serve"))
    p.add_argument("text", nargs="?")
    p.add_argument("--enclave", required=True)
    p.add_argument("--expect-host-data", default=None)
    p.add_argument("--expect-index", default=None)
    p.add_argument("--pins", default=None, help="JSON {amd, uvm_root, uvm_min_svn}: test roots, never production")
    p.add_argument("-k", type=int, default=20)
    p.add_argument("--cutoff", type=int, default=None, help="the matter's date bound (YYYYMMDD); host-held, not the model's")
    p.add_argument("--state-file", default=None, help="serve: host file owning approvals/marks/cutoff, outside the sandbox")
    p.add_argument("--trust-state", action="store_true", help="load approvals/marks from the state file; ONLY when the filesystem is enforced")
    p.add_argument("--record-file", default=None, help="serve: host file the disclosure record is written to, outside the sandbox")
    p.add_argument("--confinement", default=None,
                   help="serve: the confinement line the host stamps into every record (e.g. require, unconfined (developer override))")
    p.add_argument("--session-id", default=None, help="serve: identifies this launch; the host-side source for who surfaced a document and who marked it")
    p.add_argument("--archive-file", default=None, help="serve: append-only host file for the per-search archive (signed statement, opened result, attestation evidence, report), outside the sandbox")
    p.add_argument("--report-matter", default="", help="serve: matter label shown on the rendered search report")
    p.add_argument("--report-firm", default="", help="serve: firm label shown on the rendered search report")
    p.add_argument("--policy-file", default=None,
                   help="serve: file holding the deployed container policy (base64), archived with each search's evidence so HOST_DATA = sha256(policy) is redoable")
    p.add_argument("--reference", default=None,
                   help="serve: InferRoute's SIGNED published reference (current.json). When given, the live "
                        "identity claim rests on it: its signature is checked at startup and refused if bad, "
                        "expect_host_data is DERIVED from it, and every /enclave and /search re-checks policy + "
                        "index + encoder manifests against it — not just the exported record afterwards")
    p.add_argument("--reference-key", default=None, metavar="ED25519_PUB_HEX",
                   help="serve: the publication key hex recorded at first use; required with --reference")
    p.add_argument("--port", type=int, default=0)
    a = p.parse_args(argv)
    pins = json.load(open(a.pins)) if a.pins else None

    # An authenticated reference turns the bare, unverifiable --expect-host-data into a signed identity the
    # launch screen can stand behind BEFORE the attorney types anything. Refuse to serve if it does not hold.
    reference: Optional[Dict[str, Any]] = None
    reference_info: Optional[Dict[str, Any]] = None
    if a.reference:
        reference = json.load(open(a.reference))
        c = verify_record.Checks()
        verify_record.check_reference_signature(c, reference, a.reference_key)
        signed_ok = any(s == "PASS" and n == "reference signature" for s, n, _ in c.rows)
        if c.failed or not signed_ok:
            why = c.failed or ["--reference-key must be given and the signature must verify (an unsigned or "
                               "unauthenticated reference cannot anchor a production identity)"]
            raise SystemExit("refusing to serve: the signed reference did not verify — " + "; ".join(why))
        at = _now_iso()
        pol = _current_ref_value(reference, "policy_sha256", at)
        if not pol:
            raise SystemExit("refusing to serve: the reference carries no policy_sha256 entry current now")
        if a.expect_host_data and a.expect_host_data.lower() != pol:
            raise SystemExit("refusing to serve: --expect-host-data contradicts the signed reference "
                             f"(flag {a.expect_host_data[:16]}… vs reference {pol[:16]}…) — drop the flag and trust the reference")
        a.expect_host_data = pol
        reference_info = {"ok": True, "source": reference.get("source"),
                          "published": reference.get("published_at") or reference.get("published"),
                          "key_prefix": (a.reference_key or "")[:16]}

    v = Verifier(a.enclave, expect_host_data=a.expect_host_data, pins=pins, expect_index=a.expect_index,
                 reference=reference)
    if a.cmd == "serve":
        policy_b64 = None
        if a.policy_file:
            try:
                policy_b64 = open(a.policy_file).read().strip() or None
            except OSError:
                policy_b64 = None
        server = serve(v, a.port,
                       state=MatterState(a.state_file, a.cutoff, trust_disk=a.trust_state, session_id=a.session_id),
                       record=RecordStore(a.record_file, confinement=a.confinement),
                       archive=SearchArchive(a.archive_file), report_matter=a.report_matter, report_firm=a.report_firm,
                       policy_b64=policy_b64, reference_info=reference_info)
        print(json.dumps({"listening": server.server_address[1]}), flush=True)
        server.serve_forever()
        return 0
    if a.cmd == "search" and not a.text:
        p.error("search needs TEXT")
    out = v.verify() if a.cmd == "verify" else v.search(a.text, a.k, a.cutoff)
    if reference_info is not None:
        # Same block serve's GET /enclave returns, from the same source, so the one-shot `verify`/`search`
        # and a live session over the same enclave cannot make different claims about the reference.
        out["reference"] = reference_info
    print(json.dumps(out, indent=1))
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
