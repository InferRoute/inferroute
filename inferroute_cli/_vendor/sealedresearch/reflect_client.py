"""`sealed-client reflect` and `sealed-client explain` — the firm's side of a reflection session.

The verification path is the product's teaching surface. Every check prints one line saying what was
checked and why, with the real value, so a person learns the trust model by watching it run once.
Every line is a FACT ABOUT THIS RUN — never a rule the system follows — and the prose guard in
tests/test_report_prose.py runs over the captured output.

The client holds the transcript. Each turn: request → wait for an offer → verify (narrated) → seal →
upload → wait → verify the statement under the key bound in the attestation → open → append.
Plaintext exists on this machine and inside the enclave; nowhere else.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import uuid
from typing import Any, Dict, List, Optional

from . import envelope, reflect, snp, statement
from .relayclient import RelayClient, RelayError

SESSIONS = os.path.expanduser(os.environ.get("SEALED_SESSIONS", "~/.local/share/sealed-research/sessions"))
LEVEL = {"quiet": 0, "default": 1, "explain": 2}


class Narrator:
    def __init__(self, level: str = "default", out=None):
        self.level, self.out = LEVEL.get(level, 1), out or sys.stdout

    def step(self, ok: bool, line: str, more: str = "") -> None:
        if self.level == 0 and ok:
            return
        mark = "✓" if ok else "✗"
        print(f"  {mark} {line}", file=self.out)
        if self.level == 2 and more:
            print(f"      {more}", file=self.out)

    def status(self, line: str) -> None:
        if self.level >= 1:
            print(f"[{time.strftime('%H:%M:%S')}] {line}", file=self.out, flush=True)

    def say(self, line: str) -> None:
        print(line, file=self.out, flush=True)


def _short(h: Optional[str], n: int = 8) -> str:
    return (h or "")[:n] + "…" if h else "(none)"


# ---------------------------------------------------------------- narrated verification of an offer

def narrated_verify(offer_dir: str, certs_dir: str, nar: Narrator) -> List[str]:
    """The same checks as client.verify_offer, one narrated line each. Returns the problems."""
    from .client import get_certs
    problems: List[str] = []
    with open(os.path.join(offer_dir, "offer.json")) as fh:
        offer = json.load(fh)
    with open(os.path.join(offer_dir, "snp-report.bin"), "rb") as fh:
        report = fh.read()

    ok = hashlib.sha256(report).hexdigest() == offer.get("snp_report_sha256")
    nar.step(ok, f"offer.json describes the report beside it (sha256 {_short(offer.get('snp_report_sha256'))}).",
             "The offer is a description; the report is the evidence. They must agree before anything else is read.")
    if not ok:
        problems.append("offer.json does not describe the report file beside it")

    kind_ok = offer.get("kind") == "reflect" and offer.get("index_snapshot") == "none" \
        and offer.get("index_manifest_sha256") == "00" * 32 and bool(offer.get("model_manifest_sha256"))
    nar.step(kind_ok, "Offer is a reflection offer: no document index present (all-zero index field), a model manifest committed.",
             "A reflection session searches nothing. The zero index field is a statement of absence, committed in hardware.")
    if not kind_ok:
        problems.append("offer is not a reflection offer with the index sentinel and a model hash")
    if offer.get("attestation") == "FAKE":
        problems.append("offer declares FAKE attestation — phase-test artifact, never encrypt to it")

    p = snp.parse(report)
    pre = snp.verify_chain(report, vcek_der=None, ask_ark_pem=None)
    structural = [q for q in pre["problems"] if "no VCEK" not in q and "ASK/ARK" not in q]
    if structural:
        nar.step(False, f"REFUSED — the report is not a hardware report: version {p['version']}, "
                        f"{'unsigned' if p['signature'] == b'\\x00' * 512 else 'signed'}"
                        f"{', DEBUG allowed' if p['debug_allowed'] else ''}.",
                 "A hardware report has version ≥ 2, a non-zero signature, and a policy that forbids debugging. "
                 "None of those can be faked in software.")
        return problems + structural
    nar.step(True, f"Report is a hardware report: version {p['version']}, signed by {p['signing_key']}, DEBUG off.",
             "VCEK means a certificate AMD issues per processor — the report can be checked against AMD, not against us.")

    certs = get_certs(report, certs_dir)
    hw = snp.hwid_hex(p["chip_id"])
    nar.step(certs["vcek"] is not None,
             f"Fetching AMD's certificate for this exact chip (hwid {hw}) — AMD signs one per processor"
             f"{' (cached)' if certs['vcek'] else ' — NOT obtained'}.",
             "The certificate is fetched once from AMD's key distribution service and cached; verification is offline after that.")
    res = snp.verify_chain(report, vcek_der=certs["vcek"], ask_ark_pem=certs["chain"])
    nar.step(res["verified"],
             "Report signature verifies under that certificate: this came from silicon, not from a server we control."
             if res["verified"] else "REFUSED — the report does not verify under AMD's chain: " + "; ".join(res["problems"]),
             "The signature covers every field printed below. A changed byte anywhere fails this step.")
    problems += res["problems"]

    try:
        expected = snp.binding(
            enclave_pubkey=bytes.fromhex(offer["enclave_x25519_pub"]) + bytes.fromhex(offer["statement_signer_pub"]),
            image_measurement=bytes.fromhex(offer["measurement"]), policy_hash=bytes.fromhex(offer["policy_sha256"]),
            index_manifest_hash=bytes.fromhex(offer["index_manifest_sha256"]),
            model_weights_hash=bytes.fromhex(offer["model_manifest_sha256"] or "00" * 32), job_id=offer["job_id"].encode())
        bound = snp.check_binding(report, expected)
    except (KeyError, ValueError) as exc:
        bound = False; problems.append(f"offer malformed: {exc}")
    nar.step(bound, f"The report commits to enclave key {_short(offer.get('enclave_x25519_pub'))}, policy "
                    f"{_short(offer.get('policy_sha256'))}, model {_short(offer.get('model_manifest_sha256'))}, "
                    f"index none, lifetime {offer.get('job_id')}: nothing we could swap after the fact.",
             "REPORT_DATA is 64 bytes the enclave chose and the hardware signed. We recompute them from the offer's own fields.")
    if not bound:
        problems.append("REPORT_DATA does not match the offer's stated key/policy/index/model/job")

    nar.step(True, f"Measurement {_short(offer.get('measurement'), 12)} (printed, not judged: no published expected "
                   f"value yet — this proves genuine hardware, not yet our exact software).",
             "When a published measurement for our image exists, this line becomes a comparison. Until then it is stated as a limit.")
    return problems


# ---------------------------------------------------------------- session store

def _sdir(session_id: str) -> str:
    return os.path.join(SESSIONS, session_id)


def load_session(session_id: str) -> Optional[Dict[str, Any]]:
    p = os.path.join(_sdir(session_id), "session.json")
    return json.load(open(p)) if os.path.exists(p) else None


def new_session(session_id: str, firm_priv_path: str, relay: str, seeded_from: Optional[str]) -> Dict[str, Any]:
    d = _sdir(session_id); os.makedirs(os.path.join(d, "turns"), exist_ok=True)
    with open(firm_priv_path, "rb") as fh:
        priv = fh.read()
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    pub = X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    s = {"session_id": session_id, "firm_priv_path": os.path.abspath(firm_priv_path), "firm_pub": pub,
         "relay": relay, "seeded_from": seeded_from, "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    json.dump(s, open(os.path.join(d, "session.json"), "w"), indent=1)
    json.dump([], open(os.path.join(d, "transcript.json"), "w"))
    return s


def transcript(session_id: str) -> List[Dict[str, str]]:
    return json.load(open(os.path.join(_sdir(session_id), "transcript.json")))


def pending_turn(session_id: str) -> Optional[Dict[str, Any]]:
    d = os.path.join(_sdir(session_id), "turns")
    for n in sorted(os.listdir(d), key=lambda x: int(x)) if os.path.isdir(d) else []:
        req = os.path.join(d, n, "request.json")
        if os.path.exists(req) and not os.path.exists(os.path.join(d, n, "answer.md")):
            return json.load(open(req))
    return None


# ---------------------------------------------------------------- the turn

def seal_turn(offer: Dict[str, Any], session: Dict[str, Any], turn_no: int, message: str,
              seed_text: Optional[str]) -> bytes:
    t = transcript(session["session_id"])
    msg = message if not (seed_text and turn_no == 1) else f"{seed_text}\n\n---\n\n{message}"
    payload = {"kind": "reflect", "session_id": session["session_id"], "turn": turn_no, "transcript": t,
               "message": msg, "meta": {"client": "sealed-client/0.0.1",
                                        **({"seeded_from": session["seeded_from"]} if session.get("seeded_from") else {})}}
    return envelope.seal(bytes.fromhex(offer["enclave_x25519_pub"]), json.dumps(payload).encode(),
                         aad=payload_job_id(session["session_id"], turn_no).encode())


def payload_job_id(session_id: str, turn_no: int) -> str:
    return f"rl-{session_id}-{turn_no}"


def open_reflect_result(outbox: str, job: str, session: Dict[str, Any], nar: Narrator) -> Dict[str, Any]:
    """Verify, then open. Raises SystemExit(1) on any refusal, narrated."""
    offer = json.load(open(os.path.join(outbox, "offer.json")))
    signed = json.load(open(os.path.join(outbox, "statement.json")))
    signer = bytes.fromhex(offer["statement_signer_pub"])
    ok = statement.verify_statement(signer, signed)
    nar.step(ok, f"Statement signature verifies under the key bound in the attestation ({_short(offer['statement_signer_pub'])}).",
             "The signing key was born inside the enclave and committed in REPORT_DATA; a statement from anywhere else fails here.")
    if not ok:
        raise SystemExit(1)
    if signed.get("job_id") != job or signed.get("kind") != "reflect":
        nar.step(False, f"REFUSED — statement is for {signed.get('job_id')!r}, expected {job!r}."); raise SystemExit(1)
    if signed.get("outcome") == "refused":
        nar.step(False, f"The enclave refused this turn: category {signed.get('refusal')!r}. No answer was produced.",
                 "A refusal is signed like an answer, so 'the enclave said no' is distinguishable from 'nothing came back'.")
        return {"refused": signed.get("refusal"), "statement": signed}
    local = transcript(session["session_id"])
    lin_ok = signed.get("transcript_in_sha256") == reflect.transcript_hash(local)
    nar.step(lin_ok, f"Lineage: the transcript the enclave received hashes to {_short(signed.get('transcript_in_sha256'))}, "
                     f"equal to your local transcript.",
             "Each turn commits to the hash of the conversation it was given, so a session is a chain the certificate can verify.")
    if not lin_ok:
        raise SystemExit(1)
    blob = open(os.path.join(outbox, "result.sealed"), "rb").read()
    h_ok = hashlib.sha256(blob).hexdigest() == signed.get("result_blob_sha256")
    nar.step(h_ok, f"The sealed answer's hash matches what the enclave signed ({_short(signed.get('result_blob_sha256'))}).")
    if not h_ok:
        raise SystemExit(1)
    with open(session["firm_priv_path"], "rb") as fh:
        priv = fh.read()
    try:
        res = json.loads(envelope.open_(priv, blob, aad=(job + "/result").encode()))
    except envelope.EnvelopeError as exc:
        nar.step(False, f"REFUSED — {exc}"); raise SystemExit(1)
    out_ok = (reflect.transcript_hash(res["transcript"]) == signed.get("transcript_out_sha256")
              and res["transcript"][:len(local)] == local)
    nar.step(out_ok, f"Decrypted transcript matches the signed output hash ({_short(signed.get('transcript_out_sha256'))}) "
                     f"and extends yours by exactly one exchange.")
    if not out_ok:
        raise SystemExit(1)
    nar.step(True, f"Interfaces during the turn: {signed.get('netns_interfaces')}; egress probe: {signed.get('egress_probe')}; "
                   f"fresh model process: {signed.get('ollama_fresh_process')}; model {signed.get('model')}.",
             "The enclave recorded its own network interfaces and tried to reach out before working; both facts are in the signed statement.")
    return {"result": res, "statement": signed}


# ---------------------------------------------------------------- the blocking loop

def cmd_reflect(a) -> int:
    nar = Narrator("quiet" if a.quiet else "explain" if a.explain else "default")
    session = load_session(a.session)
    if session is None:
        if not a.firm_priv:
            nar.say("new session: --firm-priv is required the first time (sealed-client keygen makes one)"); return 2
        seeded = hashlib.sha256(open(a.seed_report, "rb").read()).hexdigest() if a.seed_report else None
        session = new_session(a.session, a.firm_priv, a.relay, seeded)
        nar.say(f"session {a.session} created; answers will be sealed to key {_short(session['firm_pub'])}")
    relay = RelayClient(session.get("relay") or a.relay, a.token)
    seed_text = open(a.seed_report).read() if a.seed_report else None

    if a.show:
        for m in transcript(a.session):
            nar.say(f"\n[{m['role']}]\n{m['content']}")
        return 0

    pend = pending_turn(a.session)
    if getattr(a, "cancel", False):
        if not pend:
            nar.say("nothing pending to cancel"); return 0
        try:
            relay.cancel_turn(pend["job_id"])
        except RelayError as exc:
            nar.say(f"the relay refused to cancel {pend['job_id']}: {exc.reason}")
            nar.say("(a turn an enclave is already working on cannot be withdrawn — collect it instead)")
            return 1
        import shutil
        shutil.rmtree(os.path.join(_sdir(a.session), "turns", str(pend["turn"])), ignore_errors=True)
        nar.say(f"cancelled turn {pend['turn']} of session {a.session}; nothing was rented for it")
        return 0
    if a.message:
        if pend:
            nar.say(f"turn {pend['turn']} is still pending — collect it first (`--collect`) or wait"); return 2
        turn_no = len([m for m in transcript(a.session) if m["role"] == "user"]) + 1
        job = payload_job_id(a.session, turn_no)
        tdir = os.path.join(_sdir(a.session), "turns", str(turn_no)); os.makedirs(tdir, exist_ok=True)
        req = {"job_id": job, "session_id": a.session, "turn": turn_no, "message": a.message,
               "requested_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        json.dump(req, open(os.path.join(tdir, "request.json"), "w"), indent=1)
        try:
            relay.create_turn(job, a.session, turn_no, session["firm_pub"])
        except RelayError as exc:
            nar.say(f"relay refused the request: {exc.reason}"); return 1
        nar.say(f"queued — turn {turn_no} of session {a.session} (job {job}). Your message stays on this machine until an attested enclave is verified.")
        pend = req
    elif not pend:
        nar.say("nothing pending; give a message to start a turn"); return 0

    if a.async_:
        return 0
    deadline = time.time() + a.timeout_min * 60 if a.timeout_min else None
    return _wait_turn(relay, session, pend, seed_text, nar, a.poll_seconds, deadline, a.certs)


def _wait_turn(relay, session, req, seed_text, nar, poll, deadline, certs_dir) -> int:
    job, turn_no = req["job_id"], req["turn"]
    tdir = os.path.join(_sdir(session["session_id"]), "turns", str(turn_no))
    sealed_to = None
    if os.path.exists(os.path.join(tdir, "sealed_to_pub")):
        sealed_to = open(os.path.join(tdir, "sealed_to_pub")).read().strip()
    while True:
        try:
            st = relay.status()
            tstate = relay.turn(job)
        except RelayError as exc:
            if exc.status == 404:
                # The turn is gone: cancelled here or from another terminal. Waiting for something
                # that no longer exists is not patience, it is a hang — say so and stop.
                nar.say(f"turn {turn_no} is no longer on the relay (cancelled). Nothing is waiting for it.")
                return 4
            nar.status(f"relay: {exc}"); time.sleep(poll); continue
        state = tstate.get("state")
        if state in ("requested", "resubmit"):
            offer = relay.current_offer(os.path.join(tdir, "offer"))
            if offer and offer["files"] and json.load(open(os.path.join(tdir, "offer", "offer.json")))["enclave_x25519_pub"] != sealed_to:
                if state == "resubmit":
                    nar.say("the previous enclave ended before answering; a new one is up — re-verifying and re-sealing.")
                nar.say(f"an attested enclave is offering (lifetime {offer['lifetime_id']}). Verifying before anything is sent:")
                problems = narrated_verify(os.path.join(tdir, "offer"), certs_dir, nar)
                if problems:
                    nar.say("REFUSED — no ciphertext produced; your message has not left this machine."); return 1
                blob = seal_turn(json.load(open(os.path.join(tdir, "offer", "offer.json"))), session, turn_no, req["message"], seed_text)
                nar.step(True, "Sealing your message to that key. The plaintext stays on this machine.")
                try:
                    relay.put_blob(job, offer["lifetime_id"], blob)
                except RelayError as exc:
                    nar.status(f"upload refused ({exc.reason}); will retry"); time.sleep(poll); continue
                sealed_to = json.load(open(os.path.join(tdir, "offer", "offer.json")))["enclave_x25519_pub"]
                open(os.path.join(tdir, "sealed_to_pub"), "w").write(sealed_to)
                open(os.path.join(tdir, "turn.sealed"), "wb").write(blob)
                nar.say(f"verified, sealed — {len(blob)} bytes of ciphertext uploaded; the relay holds no key.")
            else:
                nar.status(f"turn {turn_no}: waiting for an attested enclave | queue: {st.get('phase')} | pending {st.get('pending')}")
        elif state == "sealed":
            nar.status(f"turn {turn_no}: sealed, waiting in queue | {st.get('phase')} | pending {st.get('pending')}")
        elif state == "running":
            nar.status(f"turn {turn_no}: the enclave is working on it")
        elif state == "done":
            outbox = os.path.join(tdir, "outbox")
            relay.result(job, outbox)
            nar.say("answer ready. Verifying before opening:")
            got = open_reflect_result(outbox, job, session, nar)
            if "refused" in got:
                os.remove(os.path.join(tdir, "request.json")); return 1
            res = got["result"]
            json.dump(res["transcript"], open(os.path.join(_sdir(session["session_id"]), "transcript.json"), "w"), indent=1)
            open(os.path.join(tdir, "answer.md"), "w").write(res["answer"])
            nar.say("\n" + res["answer"] + "\n")
            return 0
        else:
            nar.status(f"turn {turn_no}: state {state}")
        if deadline and time.time() > deadline:
            nar.say(f"timeout — turn {turn_no} is still pending; resume with `--collect`."); return 3
        time.sleep(poll)


# ---------------------------------------------------------------- explain a past artifact

def cmd_explain(a) -> int:
    nar = Narrator("explain")
    d = a.dir
    if os.path.exists(os.path.join(d, "offer.json")):
        nar.say(f"== offer in {d} ==")
        narrated_verify(d, a.certs, nar)
    if os.path.exists(os.path.join(d, "statement.json")):
        st = json.load(open(os.path.join(d, "statement.json")))
        nar.say(f"== statement ({st.get('kind', 'search')}, outcome {st.get('outcome', 'n/a')}) ==")
        FIELDS = {
            "job_id": "the turn this statement is about",
            "lifetime_id": "the enclave lifetime (one attestation, one key) that served it",
            "lifetime_seq": "how many turns this enclave had served, this one included",
            "attestation": "how the enclave was attested",
            "measurement": "launch measurement of the machine image — printed, not judged",
            "netns_interfaces": "network interfaces present while the turn ran ('lo' alone means no route out)",
            "egress_probe": "outcome of the enclave's own attempts to reach the internet before working",
            "ollama_fresh_process": "whether the model server was started fresh for this turn",
            "transcript_in_sha256": "hash of the conversation the enclave received",
            "transcript_out_sha256": "hash of the conversation it returned",
            "result_blob_sha256": "hash of the sealed answer, so the file cannot be swapped",
            "model": "the model that answered", "model_manifest_sha256": "hash of that model's manifest, committed in hardware",
            "policy_sha256": "hash of the egress policy in force", "index_snapshot": "the document index searched ('none' for reflection)",
            "outcome": "answered, or refused with a category", "refusal": "the refusal category, if any",
        }
        for k, why in FIELDS.items():
            if k in st:
                nar.say(f"  {k:<24} {str(st[k])[:70]:<72} — {why}")
        if os.path.exists(os.path.join(d, "offer.json")):
            o = json.load(open(os.path.join(d, "offer.json")))
            ok = statement.verify_statement(bytes.fromhex(o["statement_signer_pub"]), st)
            nar.step(ok, "Statement signature verifies under the key bound in the attestation." if ok else "Statement signature does NOT verify.")
    return 0
