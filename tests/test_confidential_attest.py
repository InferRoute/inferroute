"""Attestation verifier: a synthetic instance shaped like the real evidence (base64-JSON body
signed over the DECODED bytes, quote with an embedded PEM chain, report_data bound to the cert's
SPKI) verifies; each check has a known-negative that REFUSES; the empty fleet never verifies."""
import base64
import datetime as dt
import hashlib
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from inferroute_local.confidential import attest as A

NONCE = "ab" * 32


def _cert(cn="selftest-leaf", key=None, issuer=None, issuer_key=None):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer or name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
            .sign(issuer_key or key, hashes.SHA256()))
    return key, cert


def _quote(report_data: bytes, *, tee=0x81, ver=4, debug=False, mrtd=b"\xAA" * 48, chain=b"") -> bytes:
    body = bytearray(A._BODY)
    body[120:128] = bytes([1 if debug else 0]) + b"\x00" * 7
    body[136:184] = mrtd
    for i, (a, b) in enumerate([(328, 376), (376, 424), (424, 472), (472, 520)]):
        body[a:b] = bytes([0xB0 + i]) * 48
    body[520:584] = report_data
    return ver.to_bytes(2, "little") + b"\x00\x00" + tee.to_bytes(4, "little") + b"\x00" * 40 + bytes(body) + chain


@pytest.fixture(autouse=True)
def _record_fixture_build(monkeypatch):
    """The synthetic quote's build (MRTD aa…, RTMR1-3 b1/b2/b3…) is a recorded build for these tests."""
    from inferroute_local.confidential import builds
    monkeypatch.setattr(builds, "BUNDLED", [{"id": "fixture", "status": "reviewed", "first_seen": "2026-01-01",
                                            "mrtd": "aa" * 48, "rtmr1": "b1" * 48, "rtmr2": "b2" * 48, "rtmr3": "b3" * 48}])
    monkeypatch.setattr(builds, "_EXTRA", [])


@pytest.fixture
def world():
    key, cert = _cert()
    pem = cert.public_bytes(serialization.Encoding.PEM)
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    e2e_pk = base64.b64encode(b"\x42" * 1184).decode()
    rd = hashlib.sha256((NONCE + e2e_pk).encode()).digest() + hashlib.sha256(spki).digest()
    inner = json.dumps({"evidence": {"tdx_quote": "…"}, "nonce": NONCE}).encode()
    sig = base64.b64encode(key.sign(inner, padding.PKCS1v15(), hashes.SHA256())).decode()
    inst = {"instance_id": "i-good", "quote": base64.b64encode(_quote(rd, chain=pem)).decode(),
            "certificate": pem.decode(), "signature": sig,
            "attested_body": base64.b64encode(inner).decode(), "gpu_evidence": [{}] * 8}
    ref = {"configs": [{"name": "h200-x8", "mrtd": "aa" * 48, "rtmrs": ["b0" * 48, "b1" * 48, "b2" * 48, "b3" * 48]},
                       {"name": "other", "mrtd": "cc" * 48, "rtmrs": ["dd" * 48] * 4}]}
    return {"key": key, "cert": cert, "pem": pem.decode(), "rd": rd, "inst": inst, "ref": ref, "inner": inner, "e2e_pk": e2e_pk}


def test_known_positive_verifies_every_check(world):
    r = A.verify_instance(world["inst"], NONCE, world["ref"], world["e2e_pk"])
    assert r.verified, r.failing
    assert r.e2e_pubkey == world["e2e_pk"]
    assert r.gpu_count == 8 and r.mrtd == "aa" * 48 and len(r.rtmrs) == 4
    assert "h200-x8" in r.checks["measurement_ok"].why
    assert r.checks["sig_ok"].why.startswith("verifies over the base64-decoded JSON")


def test_wrong_nonce_is_refused(world):
    r = A.verify_instance(world["inst"], "ff" * 32, world["ref"], world["e2e_pk"])
    assert not r.verified and r.failing == ["nonce_in_body", "e2e_key_bound"], "a foreign nonce breaks both the body and the key binding"


def test_tampered_body_and_wrong_key_signature_are_refused(world):
    inst = dict(world["inst"], attested_body=base64.b64encode(world["inner"] + b" ").decode())
    assert not A.verify_instance(inst, NONCE, world["ref"], world["e2e_pk"]).checks["sig_ok"].ok
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sig2 = base64.b64encode(other.sign(world["inner"], padding.PKCS1v15(), hashes.SHA256())).decode()
    assert not A.verify_instance(dict(world["inst"], signature=sig2), NONCE, world["ref"], world["e2e_pk"]).checks["sig_ok"].ok


def test_quote_not_bound_to_the_certificate_is_refused(world):
    q = base64.b64encode(_quote(b"\x22" * 64, chain=world["pem"].encode())).decode()
    r = A.verify_instance(dict(world["inst"], quote=q), NONCE, world["ref"], world["e2e_pk"])
    assert not r.checks["spki_bound"].ok and "MISMATCH" in r.checks["spki_bound"].why


@pytest.mark.parametrize("kw,expect", [
    ({"debug": True}, "DEBUG"), ({"tee": 0x00}, "not TDX"), ({"ver": 3}, "version 3")])
def test_debuggable_non_tdx_and_wrong_version_quotes_are_refused(world, kw, expect):
    q = base64.b64encode(_quote(world["rd"], chain=world["pem"].encode(), **kw)).decode()
    r = A.verify_instance(dict(world["inst"], quote=q), NONCE, world["ref"], world["e2e_pk"])
    assert not r.checks["tdx_shape"].ok and expect in r.checks["tdx_shape"].why


def test_short_buffer_is_refused_not_crashed(world):
    r = A.verify_instance(dict(world["inst"], quote=base64.b64encode(b"\x00" * 10).decode()), NONCE, world["ref"], world["e2e_pk"])
    assert not r.verified and not r.checks["tdx_shape"].ok and not r.checks["spki_bound"].ok


def test_measurements_must_all_sit_in_one_registry_config(world):
    split = {"configs": [{"name": "a", "mrtd": "aa" * 48, "rtmrs": ["b0" * 48, "b1" * 48]},
                         {"name": "b", "rtmrs": ["b2" * 48, "b3" * 48]}]}
    assert not A.verify_instance(world["inst"], NONCE, split).checks["measurement_ok"].ok
    q = base64.b64encode(_quote(world["rd"], mrtd=b"\xCC" * 48, chain=world["pem"].encode())).decode()
    assert not A.verify_instance(dict(world["inst"], quote=q), NONCE, world["ref"], world["e2e_pk"]).checks["measurement_ok"].ok


def test_chain_without_certificates_or_with_a_stranger_is_refused(world):
    q = base64.b64encode(_quote(world["rd"])).decode()          # no embedded PEM
    r = A.verify_instance(dict(world["inst"], quote=q), NONCE, world["ref"], world["e2e_pk"])
    assert not r.checks["chain_ok"].ok and "no certificates" in r.checks["chain_ok"].why
    _, stranger = _cert("stranger")
    leafkey, leaf = _cert("leaf2", issuer=world["cert"].subject, issuer_key=world["key"])
    assert A.check_chain([leaf, world["cert"]]).ok
    assert not A.check_chain([leaf, stranger]).ok
    assert not A.check_chain([]).ok


def test_a_substituted_encryption_key_is_refused_and_an_absent_one_never_passes(world):
    """The join between 'attested' and 'encrypted to': the quote must commit to the key we seal to."""
    other = base64.b64encode(b"\x43" * 1184).decode()
    r = A.verify_instance(world["inst"], NONCE, world["ref"], other)
    assert not r.verified and r.failing == ["e2e_key_bound"] and "MISMATCH" in r.checks["e2e_key_bound"].why
    assert r.e2e_pubkey == ""
    r = A.verify_instance(world["inst"], NONCE, world["ref"], None)
    assert not r.verified and "no encryption key" in r.checks["e2e_key_bound"].why


def test_fleet_report_arithmetic_and_empty_fleet(world):
    doc = {"evidence": [world["inst"], dict(world["inst"], instance_id="i-bad", attested_body=base64.b64encode(b"{}").decode())],
           "failed_instance_ids": ["i-dead"]}
    fr = A.verify_fleet("chute-1", doc, world["ref"], NONCE, {"i-good": world["e2e_pk"], "i-bad": world["e2e_pk"]})
    assert fr.verified_ids == ["i-good"] and fr.failed_instance_ids == ["i-dead"]
    assert fr.as_dict()["verified"] == 1
    assert A.verify_fleet("chute-1", {"evidence": []}, world["ref"], NONCE, {}).verified_ids == []
    assert A.verify_fleet("chute-1", doc, world["ref"], NONCE).verified_ids == [], "no keys supplied → nothing verifies"


def test_labels_cover_every_required_check_and_limitations_name_the_key_gap():
    assert set(A.LABELS) == set(A.REQUIRED) | set(A.REQUIRED_ONLINE)
    assert not any(k == "attributed-key" for k, _ in A.LIMITATIONS), "the key binding is a CHECK now, not a limitation"
    assert "e2e_key_bound" in A.REQUIRED


def test_evidence_fetch_backs_off_on_429_then_succeeds_and_gives_up_after_attempts(monkeypatch):
    import asyncio
    calls = {"n": 0}
    real_sleep = asyncio.sleep
    monkeypatch.setattr(asyncio, "sleep", lambda s: real_sleep(0))

    class R:
        def __init__(self, code):
            self.status_code, self.headers = code, {"Retry-After": "0"}
        def raise_for_status(self):
            if self.status_code >= 400:
                raise RuntimeError(f"HTTP {self.status_code}")
        def json(self):
            return {}

    class Http:
        async def get(self, url, headers=None, timeout=None):
            calls["n"] += 1
            return R(429 if calls["n"] < 3 else 200)
    r = asyncio.run(A._get_retry(Http(), "u", {}, 1.0))
    assert r.status_code == 200 and calls["n"] == 3

    class Dead:
        async def get(self, url, headers=None, timeout=None):
            return R(429)
    with pytest.raises(RuntimeError):
        asyncio.run(A._get_retry(Dead(), "u", {}, 1.0, attempts=2))


def test_an_unrecorded_build_is_refused_unless_explicitly_allowed(world, monkeypatch):
    from inferroute_local.confidential import builds
    q = base64.b64encode(_quote(world["rd"], mrtd=b"\xCC" * 48, chain=world["pem"].encode())).decode()
    ref = {"configs": [{"name": "x", "mrtd": "cc" * 48, "rtmrs": ["b0" * 48, "b1" * 48, "b2" * 48, "b3" * 48]}]}
    r = A.verify_instance(dict(world["inst"], quote=q), NONCE, ref, world["e2e_pk"])
    assert r.checks["measurement_ok"].ok, "published by the operator…"
    assert not r.checks["build_recorded"].ok and "not recorded" in r.checks["build_recorded"].why and not r.verified
    monkeypatch.setenv("IR_CONFIDENTIAL_ALLOW_NEW_BUILD", "1")
    r = A.verify_instance(dict(world["inst"], quote=q), NONCE, ref, world["e2e_pk"])
    assert r.checks["build_recorded"].ok and "NEW BUILD" in r.checks["build_recorded"].why
    monkeypatch.delenv("IR_CONFIDENTIAL_ALLOW_NEW_BUILD")
    # A build served at run time is accepted so a genuine new operator build can be recorded in
    # minutes — but it is NOT what "recorded by InferRoute" means, and it must not be able to
    # claim that it is. It is the seam a compromised relay would use: every other check would pass
    # truthfully against an enclave the attacker controls, so this row is the whole attack.
    assert builds.absorb_remote([{"id": "later", "status": "reviewed", "mrtd": "cc" * 48, "rtmr1": "b1" * 48, "rtmr2": "b2" * 48, "rtmr3": "b3" * 48}]) == 1
    r = A.verify_instance(dict(world["inst"], quote=q), NONCE, ref, world["e2e_pk"])
    why = r.checks["build_recorded"].why
    assert r.checks["build_recorded"].ok
    assert "PENDING" in why and "run time" in why
    assert "recorded by InferRoute since" not in why and "reviewed by InferRoute" not in why
    assert builds.lookup("cc" * 48, ["", "b1" * 48, "b2" * 48, "b3" * 48])["origin"] == "relay"
    assert builds.absorb_remote([{"id": "dup", "mrtd": "cc" * 48, "rtmr1": "b1" * 48, "rtmr2": "b2" * 48, "rtmr3": "b3" * 48}]) == 0


def test_a_run_time_build_can_never_displace_our_own_record_of_the_same_measurements(world):
    """The shipped entry must win, whatever the relay says about the same measurements."""
    from inferroute_local.confidential import builds
    b = builds.BUNDLED[0]
    assert builds.absorb_remote([{"id": "impostor", "status": "reviewed", "mrtd": b["mrtd"],
                                  "rtmr1": b["rtmr1"], "rtmr2": b["rtmr2"], "rtmr3": b["rtmr3"]}]) == 0
    got = builds.lookup(b["mrtd"], ["", b["rtmr1"], b["rtmr2"], b["rtmr3"]])
    assert got["id"] == b["id"] and got["origin"] == "bundled"


def test_rtmr0_is_not_part_of_the_build_identity(world):
    """RTMR0 (host boot firmware config) varies across hosts of one fleet; a different RTMR0 with the
    same image is the same recorded build."""
    q = _quote(world["rd"], chain=world["pem"].encode())
    body = bytearray(q[A._HDR:A._HDR + A._BODY])
    body[328:376] = b"\x99" * 48
    q2 = q[:A._HDR] + bytes(body) + q[A._HDR + A._BODY:]
    ref = {"configs": [{"name": "h", "mrtd": "aa" * 48, "rtmrs": ["99" * 48, "b1" * 48, "b2" * 48, "b3" * 48]}]}
    r = A.verify_instance(dict(world["inst"], quote=base64.b64encode(q2).decode()), NONCE, ref, world["e2e_pk"])
    assert r.checks["build_recorded"].ok


def test_measurements_must_be_field_values_not_substrings_of_the_registry(world):
    """The registry is fetched from a URL the relay supplies, so "the hex appears somewhere in
    this JSON" is not a property worth checking. One field holding all five concatenated used to
    pass."""
    q = A.quote_fields(base64.b64decode(world["inst"]["quote"]))
    mine = {k: q[k].hex() for k in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3")}
    honest = {"configs": [{"name": "real", "mrtd": mine["mrtd"],
                           "rtmrs": [mine["rtmr0"], mine["rtmr1"], mine["rtmr2"], mine["rtmr3"]]}]}
    assert A.check_measurements(q, honest).ok
    smuggled = {"configs": [{"name": "x", "notes": "".join(mine.values())}]}
    assert not A.check_measurements(q, smuggled).ok
    # nor may values be borrowed across two different images
    split = {"configs": [{"name": "a", "mrtd": mine["mrtd"], "rtmrs": [mine["rtmr0"], mine["rtmr1"]]},
                         {"name": "b", "rtmrs": [mine["rtmr2"], mine["rtmr3"]]}]}
    assert not A.check_measurements(q, split).ok


def test_a_session_caveat_becomes_a_limitation_so_it_reaches_the_receipt_and_the_model():
    """A caveat that only reaches the screen does not reach the person reading the receipt later,
    nor the assistant answering "is this private?"."""
    def lims(why):
        return dict(A.situational_limitations({"build_recorded": {"why": why}}))
    assert "pending-build" in lims("build x — PENDING — served at run time, not shipped")
    assert "new-build" in lims("NEW BUILD — not yet recorded by InferRoute")
    # "recomputed BY INFERROUTE", not "here": three auditors read "here" as this device having done the
    # recomputation, when InferRoute did it on its own machine on the build date. The limitation text always
    # said so; the check's own `why` contradicted it.
    repro = lims("build x — recorded by InferRoute since 2026-09-12; MRTD+RTMR1 recomputed BY INFERROUTE from published artifacts")
    assert "reproduced" in repro and "MRTD+RTMR1" in repro["reproduced"]
    # a plain recorded build makes no claim either way
    assert lims("build x — recorded by InferRoute since 2026-09-12") == {}


def test_the_standing_limitation_states_the_real_coverage_of_the_measurements():
    """Written into every receipt. It must not claim a per-build reproduction, and it must not
    claim that any change to the image is caught: the measured set covers the firmware, the boot
    chain and a short config list, not the filesystem the model runs from, and the operator holds
    the disk key. Verified against the operator's own published image on 2026-09-12."""
    text = dict(A.LIMITATIONS)["build-review"]
    assert "NOT the whole" in text
    assert "without changing any measurement" in text
    # and it must not make the older, stronger claim
    assert "any change" not in text.replace("without changing any measurement", "")


def test_the_gpu_limitation_does_not_imply_a_binding_nvidia_does_not_provide():
    text = dict(A.LIMITATIONS)["gpu-binding"]
    assert "no way to prove from the outside" in text.replace("\n", " ").replace("  ", " ") or \
           "provides no way" in text
    assert "confidential-computing mode" in text


# ── model fallback, and the two lines it must not cross ──────────────────────────────────────────
# Measured 2026-09-30: the kimi-k2.6 fleet had grown to 12 instances of which this device accepted ONE
# (7 refused for an enclave build InferRoute has not recorded, 7 for an e2e key the quote does not commit
# to). A pool of one is why sessions kept reporting "the AI machine couldn't be reached" — the pinned
# instance cycles out and there is no alternative. The other fleets were healthy, so it was never a
# carrier outage, and falling back across MODELS is the availability fix.

def test_probant_runs_its_own_default_without_changing_the_lane_default():
    """Probant is premium and low-volume, so it leads with the stronger model on the healthier fleet.
    Bare `ir --confidential` is deliberately left alone: this is Probant's choice, not everyone's."""
    from inferroute_cli import confidential as C
    assert C.PROBANT_MODEL == "kimi-k3"
    assert C.DEFAULT_MODEL == "kimi-k2.6", "the lane default must not move with Probant's"
    # what launch() resolves: probant gets its default, an explicit --model still wins
    assert C._resolve_model(C.PROBANT_MODEL).short == "kimi-k3"
    assert C._resolve_model("glm-5.2").short == "glm-5.2"


def test_the_fallback_chain_never_leaves_the_confidential_lane():
    """The line that must not be crossed. Falling back to the plain lane would send a client's disclosure
    to a machine nobody attested — the one thing this product exists to prevent — and it would do it at the
    moment the user is least likely to be watching, because something had already gone wrong."""
    from inferroute_cli import confidential as C
    from inferroute_cli import lane as L
    assert C.FALLBACK_MODELS, "an empty chain is not a fallback"
    off_lane = [m for m in C.FALLBACK_MODELS if not L.enclave_backed(m)]
    assert not off_lane, f"fallback would leave the confidential lane via {off_lane}"
    # ordering: capability first, cheapest last. glm-5.1 ahead of deepseek (Henry, 30 Sep).
    order = list(C.FALLBACK_MODELS)
    assert order[0] == "kimi-k3"
    assert order.index("glm-5.1") < order.index("deepseek-v4-flash")


def test_a_fallback_is_announced_and_a_candidate_is_skipped_not_fatal():
    """Never silent: a reader who assumes the preferred model answered has been misled by omission. And a
    fallback candidate missing from the catalog is SKIPPED — _resolve_model exits the process, which is
    right for what the user asked for and wrong for a guess this code made."""
    from inferroute_cli import confidential as C
    import inspect
    src = inspect.getsource(C._open_session)
    assert "had no machine this device accepts" in src, "a silent model swap"
    assert "still the confidential lane" in src, "the announcement must say the lane did not change"
    assert "IR_NO_MODEL_FALLBACK" in src, "no way to turn it off"
    # the chain is only reached for per-fleet failures: a refused key or an unreachable carrier exits above
    assert src.index("RelayUnavailable") < src.index("for short in order")
    assert C._resolve_model_quietly("definitely-not-a-model") is None


# ── a competing provider route must not survive into a sealed session ─────────────────────────────
# Supply audit 2026-09-12 (A2), confirmed independently, shipped unfixed pending a design call. With
# CLAUDE_CODE_USE_BEDROCK=1 the child ignored our ANTHROPIC_BASE_URL, resolved real AWS credentials and
# enumerated the Bedrock deployment — while the panel rendered every check green and "plaintext that left
# this device: 0 bytes". Every check was TRUE and the session was not using what they verified. Worse than
# a failed check, because a failure refuses and this displayed success.

def test_every_competing_provider_route_is_stripped_and_named():
    from inferroute_cli import confidential as C
    env = {k: "1" for k in C.PROVIDER_ROUTE_VARS}
    env["ANTHROPIC_BASE_URL"] = "http://127.0.0.1:1"      # ours, must survive
    found = C.strip_provider_route(env)
    assert set(found) == set(C.PROVIDER_ROUTE_VARS), found
    assert not [k for k in C.PROVIDER_ROUTE_VARS if k in env], "a route survived the strip"
    assert env["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:1", "the sealed proxy route was stripped too"
    # the names are returned so the user can be TOLD: silent denial is as bad as silent bypass
    assert found, "an override with nothing to report cannot be announced"
    # Mantle is in the list — it was the third route neither reviewer listed first
    assert "CLAUDE_CODE_USE_MANTLE" in C.PROVIDER_ROUTE_VARS
    # empty/whitespace values are not "set": they route nowhere and must not raise a false announcement
    assert C.strip_provider_route({"CLAUDE_CODE_USE_BEDROCK": "  "}) == []


def test_the_falsy_settings_override_is_applied_even_when_the_status_line_backs_off():
    """THE property. `_product_strip_settings_args` returns [] when IR_NO_STATUSLINE is set or the user has
    their own statusLine. A security override that is skipped because someone customised their status bar
    is not an override — so this must create its own --settings layer when there is none."""
    import json
    from inferroute_cli import confidential as C
    status_args: list[str] = []                            # the back-off case
    C.force_provider_route_falsy(status_args, [])
    assert status_args[0] == "--settings"
    envb = json.loads(status_args[1])["env"]
    assert all(envb[k] == "0" for k in C.PROVIDER_ROUTE_VARS), envb
    # "0" is falsy to Claude Code for these flags — measured 2026-09-12, along with "" and "false"
    assert envb["CLAUDE_CODE_USE_BEDROCK"] == "0"


def test_the_override_merges_without_discarding_the_caller_s_settings():
    """It rides in whichever --settings layer exists, and must not throw away what is already there --
    the status line lives in that same blob."""
    import json
    from inferroute_cli import confidential as C
    status_args = ["--settings", json.dumps({"statusLine": {"command": "echo hi"}, "env": {"FOO": "bar"}})]
    C.force_provider_route_falsy(status_args, [])
    doc = json.loads(status_args[1])
    assert doc["statusLine"]["command"] == "echo hi", "the status line was discarded"
    assert doc["env"]["FOO"] == "bar", "an unrelated env entry was discarded"
    assert doc["env"]["CLAUDE_CODE_USE_BEDROCK"] == "0"
    # a caller's own --settings in passthrough is honoured the same way
    passthrough = ["--settings", json.dumps({"tui": {"x": 1}})]
    C.force_provider_route_falsy([], passthrough)
    assert json.loads(passthrough[1])["tui"] == {"x": 1}
    assert json.loads(passthrough[1])["env"]["CLAUDE_CODE_USE_VERTEX"] == "0"


def test_malformed_settings_still_get_an_override_rather_than_a_crash():
    """Someone else's malformed --settings must not be rewritten, and must not stop the override either."""
    from inferroute_cli import confidential as C
    import json
    status_args = ["--settings", "{not json"]
    C.force_provider_route_falsy(status_args, [])
    assert status_args[1] == "{not json", "a malformed value was rewritten"
    assert status_args.count("--settings") == 2, "no override layer was added"
    assert json.loads(status_args[-1])["env"]["CLAUDE_CODE_USE_BEDROCK"] == "0"


def test_the_loopback_hop_is_never_proxied_for_any_adapter():
    """The sealed proxy is a loopback hop for EVERY agent, so an HTTP_PROXY in the user's environment
    could receive the plaintext on its way to 127.0.0.1. pi_attested has set no_proxy since it was
    written, with the reason in its header; nothing else did — the other five adapters inherited whatever
    the user had.

    Confirmed 2026-09-30 that Claude Code's shipped binary references HTTP_PROXY/HTTPS_PROXY/NO_PROXY and
    ProxyAgent, so the host honours these. Whether it excludes loopback BY DEFAULT is a property of the
    user's environment, which is the reason not to depend on it."""
    import inspect
    from inferroute_cli import confidential as C
    from inferroute_cli.pi_attested import _with_loopback, LOOPBACK

    src = inspect.getsource(C.launch)
    # applied BEFORE the per-agent branch, so a new adapter cannot forget it
    assert "no_proxy" in src and "NO_PROXY" in src, "the loopback hop is proxied for some adapters"
    # Landmark is the ADAPTER CHAIN, not `if agent == "claude":` — that string also appears earlier, in a
    # pre-launch check, so the first version of this assertion compared against the wrong position and
    # failed on correct code. `elif agent == "pi":` occurs once and only in the chain.
    assert src.count('elif agent == "pi":') == 1
    assert src.index("_no_proxy_loopback") < src.index('elif agent == "pi":')

    # both spellings, because the lowercase one takes precedence in most clients
    assert _with_loopback(None).split(",")[:3] == list(LOOPBACK)
    # the user's own exclusions survive — this defends the hop, it does not seize their proxy config
    assert _with_loopback("corp.example.com").endswith("corp.example.com")
    # and it does not duplicate an entry they already had
    assert _with_loopback("127.0.0.1,corp.example.com").count("127.0.0.1") == 1
