"""The client half of InferRoute's search gate (ir-search-ctl/gate/main.py is the contract).

What must hold:
  * the user's key and the search unit's permit go to the gate's exact host over https, on POST /search only, and
    never to a direct address, a lookalike, plain http, or the target of a redirect;
  * each refusal costs one request, or two for 429/503 (one wait, one retry), and is said in the gate's admissible
    words or ours, never as a failed verification;
  * the attestation is unchanged: a tampered /offer that came through the gate is refused exactly as a direct one.
"""
from __future__ import annotations

import base64
import io
import json
import os
import subprocess
import sys
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from inferroute_cli import pi_attested as PA
from inferroute_cli._searchgate import ir_search_gate as G
from inferroute_local.confidential import billing_refusal as BR

GATE = "https://ir-search-gate-851040540464.europe-west4.run.app"
DIRECT = "http://34.90.1.2:8000"


@pytest.fixture
def SV(monkeypatch):
    monkeypatch.syspath_prepend(str(PA.VENDOR_DIR))
    from sealedresearch import search_verifier
    return search_verifier


# ───────────────────────── a fake gate ─────────────────────────

class _Resp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class FakeOpener:
    """Answers each request from a script of (status, headers, body); records every request it was handed."""

    def __init__(self, script):
        self.script = list(script)
        self.requests = []

    def open(self, req, timeout=None):
        self.requests.append(req)
        status, headers, body = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        if status < 300:
            return _Resp(body)
        raise urllib.error.HTTPError(req.full_url, status, "refused", headers, io.BytesIO(body))


def refusal(status, code, message, retry_after=None, header=True):
    h = {"content-type": "application/json"}
    if header:
        h["x-inferroute-billing-code"] = code
    if retry_after is not None:
        h["Retry-After"] = str(retry_after)
    return status, h, json.dumps({"error": {"type": "billing_error", "code": code, "message": message}}).encode()


def gate(script, key="ak-secret", permit="5b0c8a3e-permit"):
    waits = []
    g = G.Gate(GATE, key, permit, sleep=waits.append, say=lambda s: None, opener=FakeOpener(script))
    return g, waits


def keyed(req):
    return req.get_header("X-api-key"), req.get_header("X-inferroute-permit")


# ───────────────────────── which address is the gate ─────────────────────────

@pytest.mark.parametrize("url", [GATE, GATE + "/", GATE.upper().replace("HTTPS", "https")])
def test_the_gate_is_recognised_by_its_exact_host_over_https(url):
    assert G.gate_base(url) == GATE


@pytest.mark.parametrize("url", [
    GATE.replace("https://", "http://"),                         # plain http: the key would travel in clear
    GATE + ":443", GATE + ":8443",                               # any explicit port
    "https://x." + GATE[8:],                                     # a subdomain of it
    GATE + ".evil.example",                                      # a suffix
    "https://evil" + GATE[8:],                                   # a prefix
    GATE + ".",                                                  # a trailing dot
    "https://user:pw@" + GATE[8:], GATE + "/search", GATE + "?x=1", GATE + "#f",
    DIRECT, "https://34.90.1.2:8000", "https://ir-search-wake-851040540464.europe-west4.run.app", "", None,
])
def test_anything_else_is_not_the_gate(url):
    assert G.gate_base(url) is None


def test_setup_accepts_both_addresses_and_refuses_the_gate_name_on_the_wrong_scheme_or_port():
    from inferroute_cli import probant_search_setup as SS
    assert SS.GATE_HOSTS is G.GATE_HOSTS
    assert SS.fixed_endpoint(DIRECT) == DIRECT                   # the direct-address rule, unchanged
    assert SS.fixed_endpoint("https://search.example:9000") == "https://search.example:9000"
    assert SS.fixed_endpoint(GATE + "/") == GATE
    for bad in (GATE.replace("https", "http"), GATE + ":443"):
        with pytest.raises(SS.SetupError):
            SS.fixed_endpoint(bad)


# ───────────────────────── where the key and the permit go ─────────────────────────

def test_the_key_and_permit_go_on_post_search_to_the_gate_and_nowhere_else():
    g, _ = gate([(200, {}, b'{"sealed": "x"}')])
    g.call(GATE, "POST", "/search", b"blob", 5)
    g.call(GATE, "GET", "/offer", None, 5)
    post, offer = g.opener.requests
    assert post.full_url == GATE + "/search" and keyed(post) == ("ak-secret", "5b0c8a3e-permit")
    assert offer.full_url == GATE + "/offer" and keyed(offer) == (None, None)


def test_billing_off_sends_the_key_and_no_permit():
    g, _ = gate([(200, {}, b"{}")], permit="")
    g.call(GATE, "POST", "/search", b"blob", 5)
    assert keyed(g.opener.requests[0]) == ("ak-secret", None)


def test_the_gate_transport_refuses_any_other_address():
    g, _ = gate([(200, {}, b"{}")])
    for url in (DIRECT, GATE + ".evil.example", GATE.replace("https", "http")):
        with pytest.raises(ValueError):
            g.call(url, "POST", "/search", b"blob", 5)
    assert g.opener.requests == []
    with pytest.raises(ValueError):
        G.Gate(DIRECT, "k")


def test_a_verifier_on_a_direct_address_never_sends_the_key(SV, monkeypatch):
    """install() only reroutes the gate's own address. A verifier pointed at the machine's IP goes through the
    vendored transport untouched: no key, no permit, whatever credentials the process was handed."""
    seen = []

    def fake_urlopen(req, timeout=None):
        seen.append(req)
        raise urllib.error.URLError("no route")

    monkeypatch.setattr(SV.urllib.request, "urlopen", fake_urlopen)

    class V(SV.Verifier):
        pass

    g, _ = gate([(200, {}, b"{}")])
    G.install(V, g)
    v = V(DIRECT, expect_host_data=None)
    out = v.verify()
    with pytest.raises(urllib.error.URLError):
        v._call("POST", "/search", b"blob")
    assert not out["ok"] and "gate_refusal" not in out
    assert out["steps"][0]["detail"].startswith("nothing answered")
    assert all(keyed(r) == (None, None) for r in seen) and len(seen) == 2
    assert g.opener.requests == []


class _Redirector(BaseHTTPRequestHandler):
    hits = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        _Redirector.hits.append((self.path, self.headers.get("x-api-key")))
        self.send_response(307)
        self.send_header("Location", "/stolen")
        self.send_header("Content-Length", "0")
        self.end_headers()


def test_the_gate_transport_never_follows_a_redirect():
    srv = HTTPServer(("127.0.0.1", 0), _Redirector)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        opener = G.Gate(GATE, "k").opener
        req = __import__("urllib.request").request.Request(
            f"http://127.0.0.1:{srv.server_port}/search", data=b"x", method="POST", headers={"x-api-key": "k"})
        with pytest.raises(urllib.error.HTTPError) as e:
            opener.open(req, timeout=5)
        assert e.value.code == 307
        assert [p for p, _ in _Redirector.hits] == ["/search"]          # /stolen was never asked for
    finally:
        srv.shutdown()


# ───────────────────────── refusals ─────────────────────────

FINAL = [
    (402, "permit_missing", "A search needs a permit. Start the search from the Anteriora app."),
    (402, "permit_invalid", "This permit does not cover a search. Start the search again from the app."),
    (402, "permit_used_up", "This permit has no searches left. Start a new search from the app."),
    (402, "permit_wrong_product", "This is not an Anteriora key. Sign in to Anteriora again."),
    (402, "out_of_credits", "No credit left. Buy units at inferroute.ai/anteriora."),
    (401, "key_required", "An Anteriora key is required to search."),
    (413, "bad_length", "The request has no valid length."),
]


@pytest.mark.parametrize("status,code,message", FINAL)
def test_a_final_refusal_is_one_request_and_the_gates_own_words(status, code, message):
    g, waits = gate([refusal(status, code, message)])
    with pytest.raises(G.GateRefused) as e:
        g.call(GATE, "POST", "/search", b"blob", 5)
    assert len(g.opener.requests) == 1 and waits == []
    assert e.value.refusal.code == code and e.value.refusal.final
    assert e.value.refusal.sentence == message


@pytest.mark.parametrize("status,code", [(402, "permit_missing"), (401, "key_required"), (413, "bad_length")])
def test_a_message_that_is_not_admissible_is_replaced_by_our_sentence(status, code):
    g, _ = gate([refusal(status, code, "Pay at https://evil.example/now")])
    with pytest.raises(G.GateRefused) as e:
        g.call(GATE, "POST", "/search", b"blob", 5)
    s = e.value.refusal.sentence
    assert "evil" not in s and s == (BR.SEARCH_FIXED.get(code) or BR.FIXED[code])


@pytest.mark.parametrize("status,code,retry_after,wait", [
    (429, "rate_limited", 30, 30.0),                    # the account's limits
    (503, "billing_unavailable", 60, 30.0),             # capped at 30 s
    (503, "search_unavailable", 60, 30.0),
])
def test_429_and_503_wait_once_and_ask_once_more(status, code, retry_after, wait):
    g, waits = gate([refusal(status, code, "Please try again.", retry_after)])
    with pytest.raises(G.GateRefused) as e:
        g.call(GATE, "POST", "/search", b"blob", 5)
    assert len(g.opener.requests) == 2 and waits == [wait]
    assert e.value.refusal.code == code
    # the retry carries the same body, key and permit
    assert [keyed(r) for r in g.opener.requests] == [("ak-secret", "5b0c8a3e-permit")] * 2


def test_a_retry_that_succeeds_returns_the_machines_reply():
    g, waits = gate([refusal(503, "search_unavailable", "starting", 5), (200, {}, b'{"sealed": "ok"}')])
    assert g.call(GATE, "POST", "/search", b"blob", 5) == b'{"sealed": "ok"}'
    assert len(g.opener.requests) == 2 and waits == [5.0]


@pytest.mark.parametrize("retry_after,wait", [(150, 150.0), (400, 160.0), (12, 12.0)])
def test_a_search_waiting_for_the_machine_waits_for_the_slot_up_to_160_s(retry_after, wait):
    said = []
    waits = []
    g = G.Gate(GATE, "k", "p", sleep=waits.append, say=said.append, opener=FakeOpener([
        refusal(429, "rate_limited", "Another search is running on the search machine. Yours will start when it "
                "finishes.", retry_after), (200, {}, b"{}")]))
    g.begin()
    g.call(GATE, "POST", "/search", b"blob", 5)
    assert waits == [wait]
    if wait > 30:
        assert said == [f"another search is running, waiting {int(wait)} s"]
    assert g.finish({"ok": True, "steps": []})["gate_notes"] == said


def test_an_offer_is_never_held_longer_than_30_s():
    g, waits = gate([refusal(429, "rate_limited", "Too many requests; try again later.", 60), (200, {}, b"{}")])
    g.call(GATE, "GET", "/offer", None, 5)
    assert waits == [30.0]


def test_a_cloud_run_429_or_503_with_no_code_is_read_as_the_gate_busy_or_the_machine_away():
    g, waits = gate([(503, {}, b"<html>Service Unavailable</html>")])
    with pytest.raises(G.GateRefused) as e:
        g.call(GATE, "GET", "/offer", None, 5)
    assert e.value.refusal.code == "search_unavailable" and len(g.opener.requests) == 2


def test_the_machines_own_error_passed_through_is_handled_as_if_direct():
    g, waits = gate([(400, {"content-type": "application/json"}, b'{"refused": "bad_request"}')])
    with pytest.raises(urllib.error.HTTPError) as e:
        g.call(GATE, "POST", "/search", b"blob", 5)
    assert not isinstance(e.value, G.GateRefused) and e.value.code == 400 and len(g.opener.requests) == 1


def test_an_unlisted_code_from_the_gate_is_still_the_gates_and_said_in_our_words():
    g, _ = gate([refusal(402, "units_none", "Visit https://evil.example")])
    with pytest.raises(G.GateRefused) as e:
        g.call(GATE, "POST", "/search", b"blob", 5)
    assert e.value.refusal.sentence == BR.SEARCH_UNLISTED.format(code="units_none")


# ───────────────────────── verdicts ─────────────────────────

class _Verified:
    """A verifier whose machine checks are stubbed to pass, so a search reaches POST /search."""

    def __init__(self, SV):
        from sealedresearch import envelope
        from sealedresearch.amd_chain import Steps
        _, pub = envelope.gen_keypair()
        self.rd = {"enclave_x25519_pub": pub.hex(), "lifetime_id": "ab" * 8}
        self.Steps = Steps

    def __call__(self, verifier):
        steps = self.Steps()
        steps.add(True, "search enclave reachable", "offer received")
        steps.add(True, "quote verified", "stubbed")
        return steps, {"lifetime_id": self.rd["lifetime_id"]}, self.rd, json.dumps(self.rd).encode(), {}


def _verifier(SV, script, permit="p"):
    class V(SV.Verifier):
        pass

    g, waits = gate(script, permit=permit)
    G.install(V, g)
    return V(GATE, expect_host_data=None), g, waits


@pytest.mark.parametrize("status,code,message", FINAL)
def test_a_refused_search_is_said_as_the_services_refusal_never_as_a_failed_verification(SV, status, code, message):
    v, g, _ = _verifier(SV, [refusal(status, code, message)])
    v._verify = lambda: _Verified(SV)(v)
    out = v.search("a wheel with a sensor", 10)
    assert out["ok"] is False and out["refusal"] == message
    assert out["gate_refusal"] == {"status": status, "code": code, "final": True, "path": "/search"}
    assert out["steps"][-1] == {"ok": False, "step": G.GATE_STEP, "detail": message}
    assert all(s["ok"] for s in out["steps"][:-1])                       # what was checked still stands
    text = json.dumps(out).lower()
    assert "not verified" not in text and "could not be verified" not in text and "did not verify" not in text
    assert len(g.opener.requests) == 1


def test_a_refusal_that_may_follow_the_machines_answer_is_noted_for_the_record(SV):
    v, g, _ = _verifier(SV, [refusal(402, "permit_used_up", "This permit has no searches left.")])
    v._verify = lambda: _Verified(SV)(v)
    out = v.search("a wheel with a sensor", 10)
    assert "permit_used_up" in out["_unanswered"]["reason"]
    v2, _, _ = _verifier(SV, [refusal(401, "key_required", "An Anteriora key is required to search.")])
    v2._verify = lambda: _Verified(SV)(v2)
    assert "_unanswered" not in v2.search("x", 10)                       # refused before the machine: no gap


def test_an_offer_the_gate_refuses_is_offline_or_the_services_refusal_never_a_failed_check(SV):
    from inferroute_cli import probant_trust as T
    v, g, waits = _verifier(SV, [refusal(503, "search_unavailable", "The search machine is not answering.", 60)])
    out = v.verify()
    assert len(g.opener.requests) == 2 and waits == [30.0]
    assert T.search_offline(out)
    assert T.search_item(out)["state"] == T.OFF
    v, g, _ = _verifier(SV, [refusal(429, "rate_limited", "Too many requests; try again later.", 60)])
    out = v.verify()
    item = T.search_item(out)
    assert out["gate_refusal"]["code"] == "rate_limited" and item["state"] == T.OFF
    assert "verified" not in item["summary"] and item["points"] == ["Too many requests; try again later."]


def _tampered_offer() -> bytes:
    rd = {"v": 1, "kind": "sealed-search", "lifetime_id": "ab" * 8, "enclave_x25519_pub": "11" * 32,
          "statement_signer_pub": "22" * 32, "index_manifest_sha256": "33" * 32, "model_manifest_sha256": "44" * 32}
    quote = bytearray(b"\x04\x00\x02\x00\x81\x00\x00\x00" + b"\x00" * 1200)
    quote[700] ^= 0xFF                                                   # one flipped byte in the signed body
    return json.dumps({"runtime_data": base64.b64encode(json.dumps(rd).encode()).decode(),
                       "evidence": {"tee": "intel-tdx", "quote": base64.b64encode(bytes(quote)).decode()}}).encode()


def test_a_tampered_offer_through_the_gate_is_refused_exactly_as_a_direct_one(SV, monkeypatch):
    offer = _tampered_offer()
    monkeypatch.setattr(SV.urllib.request, "urlopen", lambda req, timeout=None: _Resp(offer))
    direct = SV.Verifier(DIRECT, expect_host_data=None).verify()
    v, g, _ = _verifier(SV, [(200, {}, offer)])
    via = v.verify()
    assert direct["ok"] is False and via["ok"] is False
    assert via["steps"] == direct["steps"] and via["refusal"] == direct["refusal"]
    assert "gate_refusal" not in via and keyed(g.opener.requests[0]) == (None, None)


# ───────────────────────── the launcher ─────────────────────────

@pytest.fixture
def launch_rig(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    (tmp_path / "ir" / "confidential").mkdir(parents=True)
    for k in ("IR_MATTER_CUTOFF", "IR_MATTER_STATE_FILE", "IR_MATTER_RECORD_DIR", "IR_ATTESTED_CONFINE",
              "IR_PROBANT_DEV_UNCONFINED", "IR_REPORT_MATTER", "IR_REPORT_FIRM", "INFERROUTE_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    from inferroute_cli import config
    monkeypatch.setattr(config, "load", lambda: config.Credentials(api_url="https://x", api_key="ak-secret"))
    got = {}

    class Proc:
        def __init__(self, argv, **kw):
            got.update(argv=argv, kw=kw)
            self.stdin = io.StringIO() if kw.get("stdin") is not None else None
            if self.stdin is not None:
                self.stdin.close = lambda: got.__setitem__("stdin", self.stdin.getvalue())
            self.stdout = io.StringIO(json.dumps({"listening": 4444}) + "\n")

        def terminate(self):
            pass

    import select
    monkeypatch.setattr(subprocess, "Popen", Proc)
    monkeypatch.setattr(select, "select", lambda r, w, x, t: (r, [], []))
    monkeypatch.setattr(PA, "_SEARCH_PROXIES", [])

    def configure(enclave, **extra):
        (tmp_path / "ir" / "confidential" / "search.json").write_text(json.dumps({"enclave": enclave, **extra}))
    return got, configure


def test_a_session_on_the_gate_hands_the_key_and_permit_on_stdin_only(launch_rig):
    got, configure = launch_rig
    configure(GATE)
    assert PA.start_search_proxy(permit="5b0c8a3e-permit") == "http://127.0.0.1:4444"
    argv, env = got["argv"], got["kw"]["env"]
    assert argv[1:3] == ["-m", "ir_search_gate"] and "sealedresearch.search_verifier" not in argv
    assert env["PYTHONPATH"].split(os.pathsep)[0] == str(PA.GATE_DIR)   # first: ir_search_gate is always ours
    assert env["PYTHONSAFEPATH"] == "1" and got["kw"]["cwd"] == str(PA.VENDOR_DIR)  # nothing from the workspace
    sent = json.loads(got["stdin"])
    assert {k: sent[k] for k in ("key", "permit")} == {"key": "ak-secret", "permit": "5b0c8a3e-permit"}
    assert set(sent) <= {"key", "permit", "used_up_file"}
    assert "ak-secret" not in " ".join(argv) and "ak-secret" not in json.dumps(env)
    assert "5b0c8a3e-permit" not in " ".join(argv)


def test_billing_off_hands_the_key_and_no_permit(launch_rig):
    got, configure = launch_rig
    configure(GATE)
    PA.start_search_proxy()
    assert json.loads(got["stdin"]) == {"key": "ak-secret", "permit": ""}


@pytest.mark.parametrize("enclave", [DIRECT, GATE.replace("https", "http"), GATE + ".evil.example"])
def test_a_session_on_any_other_address_is_launched_as_before_with_no_credentials(launch_rig, enclave):
    got, configure = launch_rig
    configure(enclave)
    PA.start_search_proxy(permit="5b0c8a3e-permit")
    assert got["argv"][1:3] == ["-m", "sealedresearch.search_verifier"]
    assert "stdin" not in got["kw"] and "stdin" not in got
    assert str(PA.GATE_DIR) not in got["kw"]["env"].get("PYTHONPATH", "")


def test_a_development_config_keeps_its_own_verifier_and_gains_only_the_gate_module(launch_rig, tmp_path):
    got, configure = launch_rig
    configure(GATE, python="/repo/.venv/bin/python", cwd=str(tmp_path))
    PA.start_search_proxy(permit="p")
    assert got["argv"][0] == "/repo/.venv/bin/python" and got["kw"]["cwd"] == str(tmp_path)
    # the gate module first, then the checkout the config names (no longer reached through the current directory)
    assert got["kw"]["env"]["PYTHONPATH"].split(os.pathsep)[:2] == [str(PA.GATE_DIR), str(tmp_path)]
    assert str(PA.VENDOR_DIR) not in got["kw"]["env"]["PYTHONPATH"]
    assert got["kw"]["env"]["PYTHONSAFEPATH"] == "1"


def test_the_wrapper_reads_its_credentials_and_installs_only_for_the_gate(SV, monkeypatch):
    calls = []
    monkeypatch.setattr(SV, "main", lambda argv: calls.append(argv) or 0)
    for name in ("_call", "verify", "search", "document"):
        monkeypatch.setattr(SV.Verifier, name, getattr(SV.Verifier, name))
    before = SV.Verifier._call
    assert G.main(["verify", "--enclave", DIRECT], stdin=io.StringIO('{"key": "k"}\n')) == 0
    assert SV.Verifier._call is before
    assert G.main(["serve", f"--enclave={GATE}"], stdin=io.StringIO('{"key": "k", "permit": "p"}\n')) == 0
    assert SV.Verifier._call is not before and len(calls) == 2
    assert G.read_credentials(io.StringIO("")) == {} and G.read_credentials(io.StringIO("[1]\n")) == {}


def test_the_wrapper_finds_the_refusal_rules_without_the_package_installed(tmp_path):
    """A development config runs the verifier under sealed-research's interpreter, where inferroute is not
    installed: the wrapper then loads billing_refusal from the file beside it."""
    r = subprocess.run([sys.executable, "-S", "-c", "import ir_search_gate as g; print(g.BR.__name__, "
                        "g.BR.SEARCH_CODES['search_unavailable'])"],
                       env={"PYTHONPATH": str(PA.GATE_DIR), "PATH": os.environ.get("PATH", "")},
                       cwd=tmp_path, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert r.stdout.split() == ["_ir_billing_refusal", "503"]


# ───────────────────────── the relay's frozen rule is untouched ─────────────────────────

def test_the_search_codes_do_not_widen_the_relays_rule():
    for code, status in BR.SEARCH_CODES.items():
        assert code not in BR.CODES and not BR.is_billing_code(code)
        body = json.dumps({"error": {"code": code, "message": "m"}})
        assert BR.parse(status, {"x-inferroute-billing-code": code}, body) is None
        assert not BR.admissible_message(code, "m")
        r = BR.parse_search(status, {"x-inferroute-billing-code": code}, body)
        assert r is not None and not isinstance(r, BR.BillingRefusal)
    # a listed code at the wrong status is not a refusal on the search path either, as on the relay's
    assert BR.parse_search(500, {"x-inferroute-billing-code": "search_unavailable"}, "{}") is None
    assert BR.parse_search(500, {}, json.dumps({"error": {"code": "search_unavailable"}})) is None
    assert BR.parse_search(402, {"x-inferroute-billing-code": "bad_length"}, "{}") is None


# ───────────────────────── what the assistant is told ─────────────────────────

def test_the_extension_says_a_gate_refusal_as_the_services_not_as_a_failed_check():
    import shutil
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not on PATH here")
    ts = (Path(PA.__file__).resolve().parent / "pi_attested" / "ir-attested.ts").read_text()
    fn = ts[ts.index("function gateRefusalError"):ts.index("\n}\n", ts.index("function gateRefusalError")) + 3]
    plain = ts[ts.index("function plainRefusal"):ts.index("\n}\n", ts.index("function plainRefusal")) + 3]
    js = (fn + plain + "\nconst v = {ok: false, steps: [], refusal: 'A search needs a permit.', "
          "gate_refusal: {code: 'permit_missing', status: 402, final: true}};\n"
          "console.log(JSON.stringify([gateRefusalError(v), gateRefusalError({ok: false, steps: [], refusal: 'x'}),"
          " plainRefusal(\"InferRoute's search service refused this search: A search needs a permit.\")]));")
    r = subprocess.run([node, "--experimental-strip-types", "--input-type=module-typescript", "-e", js],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0 and "input-type" in r.stderr:
        pytest.skip("this node cannot run TypeScript from -e")
    said, none, status = json.loads(r.stdout.strip().splitlines()[-1])
    assert "A search needs a permit." in said and "verif" not in said.split("checks")[0].lower()
    assert none is None
    assert status.startswith("InferRoute's search service") and "not verified" not in status
    # and the two places that used to say "did not verify" ask the gate first
    for anchor in ("const gate = gateRefusalError(verified);", "const gate = gateRefusalError(out);"):
        assert anchor in ts


def test_the_proof_command_says_a_gate_refusal_as_the_services(monkeypatch, capsys):
    from inferroute_cli import probant as S
    monkeypatch.setattr(S, "_split_matter", lambda spec: ("C", "m"))
    monkeypatch.setattr(S, "load_record", lambda c, m: {"date_bound": "2026-01-01"})
    monkeypatch.setattr(S, "latest_session_record", lambda c, m: None)
    monkeypatch.setattr(PA, "verify_search_once", lambda: {
        "ok": False, "refusal": "Too many requests; try again later.",
        "steps": [{"ok": False, "step": G.GATE_STEP, "detail": "Too many requests; try again later."}],
        "gate_refusal": {"status": 429, "code": "rate_limited", "final": False, "path": "/offer"}})
    assert S.cmd_proof("C/m") == 1
    out = capsys.readouterr().out
    assert "InferRoute's search service said: Too many requests" in out and "Not verified" not in out
