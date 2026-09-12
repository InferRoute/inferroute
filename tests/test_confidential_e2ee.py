"""e2ee envelope: round-trips through a server-side re-implementation, and REFUSES the things
it must refuse. Every negative here is a real attack shape, not a typo."""
import base64
import json
import os

import pytest

from inferroute_local.confidential import e2ee
from tests.confidential_fake_enclave import FakeEnclave


def test_request_round_trips_and_carries_a_fresh_response_key():
    enc = FakeEnclave()
    sealed = e2ee.seal_request(enc.pubkey_b64, {"model": "m", "messages": [{"role": "user", "content": "hi"}]})
    assert len(sealed.blob) > e2ee.MLKEM_CT_SIZE + 12 + 16
    body, client_pk = enc.open_request(sealed.blob)
    assert body == {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
    assert len(client_pk) == e2ee.MLKEM_PK_SIZE
    # a second request uses a DIFFERENT response key (no key reuse across turns)
    sealed2 = e2ee.seal_request(enc.pubkey_b64, {"x": 1})
    _, client_pk2 = enc.open_request(sealed2.blob)
    assert client_pk2 != client_pk


def test_response_round_trip():
    enc = FakeEnclave()
    sealed = e2ee.seal_request(enc.pubkey_b64, {"q": 1})
    _, client_pk = enc.open_request(sealed.blob)
    blob = enc.seal_response(client_pk, {"choices": [{"message": {"content": "hello"}}]})
    assert e2ee.open_response(blob, sealed.response_sk)["choices"][0]["message"]["content"] == "hello"


def test_response_for_a_different_client_key_is_refused():
    enc = FakeEnclave()
    a = e2ee.seal_request(enc.pubkey_b64, {"q": 1})
    b = e2ee.seal_request(enc.pubkey_b64, {"q": 2})
    _, pk_a = enc.open_request(a.blob)
    blob = enc.seal_response(pk_a, {"secret": True})
    with pytest.raises(e2ee.E2EEError):
        e2ee.open_response(blob, b.response_sk)


def test_a_flipped_byte_anywhere_in_the_request_is_rejected_by_the_enclave():
    enc = FakeEnclave()
    sealed = e2ee.seal_request(enc.pubkey_b64, {"q": 1})
    for pos in (0, e2ee.MLKEM_CT_SIZE + 3, len(sealed.blob) - 1):
        tampered = bytearray(sealed.blob)
        tampered[pos] ^= 0x01
        with pytest.raises(Exception):
            enc.open_request(bytes(tampered))


def test_a_tampered_response_is_refused_not_decoded():
    enc = FakeEnclave()
    sealed = e2ee.seal_request(enc.pubkey_b64, {"q": 1})
    _, pk = enc.open_request(sealed.blob)
    blob = bytearray(enc.seal_response(pk, {"ok": 1}))
    blob[-1] ^= 0x01
    with pytest.raises(e2ee.E2EEError):
        e2ee.open_response(bytes(blob), sealed.response_sk)


def test_request_to_a_key_that_is_not_ml_kem_768_is_refused():
    with pytest.raises(e2ee.E2EEError):
        e2ee.seal_request(base64.b64encode(os.urandom(32)).decode(), {"q": 1})


def test_stream_reassembles_plaintext_regardless_of_chunking():
    enc = FakeEnclave()
    sealed = e2ee.seal_request(enc.pubkey_b64, {"stream": True})
    _, pk = enc.open_request(sealed.blob)
    plaintext = b"data: {\"a\":1}\n\ndata: {\"b\":2}\n\ndata: [DONE]\n\n"
    # the server chunks mid-line; the gateway relays those frames in arbitrary byte splits
    wire = enc.stream(pk, [plaintext[:5], plaintext[5:20], plaintext[20:]])
    opener = e2ee.StreamOpener(sealed.response_sk)
    out = b"".join(opener.feed(wire[i:i + 7]) for i in range(0, len(wire), 7)) + opener.flush()
    assert out == plaintext
    assert opener.frames == 3 and opener.passthrough == []


def test_stream_chunk_before_init_is_an_error_and_a_clear_frame_is_surfaced():
    enc = FakeEnclave()
    sealed = e2ee.seal_request(enc.pubkey_b64, {"stream": True})
    opener = e2ee.StreamOpener(sealed.response_sk)
    with pytest.raises(e2ee.E2EEError):
        opener.feed(b'data: {"e2e": "' + base64.b64encode(os.urandom(40)).decode().encode() + b'"}\n')
    opener2 = e2ee.StreamOpener(sealed.response_sk)
    assert opener2.feed(b'data: {"error": {"message": "instance gone"}}\n') == b""
    assert opener2.passthrough == [{"error": {"message": "instance gone"}}]


def test_stream_key_from_a_foreign_init_is_refused():
    enc = FakeEnclave()
    mine = e2ee.seal_request(enc.pubkey_b64, {"stream": True})
    other = e2ee.seal_request(enc.pubkey_b64, {"stream": True})
    _, pk_other = enc.open_request(other.blob)
    wire = enc.stream(pk_other, [b"data: x\n"])
    opener = e2ee.StreamOpener(mine.response_sk)
    with pytest.raises(e2ee.E2EEError):
        opener.feed(wire)


def test_backend_is_fips_203_sized():
    b = e2ee.backend()
    pk, sk = b.keygen()
    shared, ct = b.encaps(pk)
    assert (len(pk), len(ct), len(shared)) == (1184, 1088, 32)
    assert b.decaps(sk, ct) == shared
    assert b.name


def test_plaintext_size_counts_the_json_that_was_encrypted():
    enc = FakeEnclave()
    payload = {"messages": [{"role": "user", "content": "x" * 1000}]}
    sealed = e2ee.seal_request(enc.pubkey_b64, payload)
    assert sealed.plaintext_size >= 1000
    assert json.dumps(payload) not in sealed.blob.decode("latin-1")
