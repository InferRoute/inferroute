"""A client machine gets its search configuration from published files — and from nothing it cannot check."""
import base64
import datetime as dt
import hashlib
import json
import stat
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from inferroute_cli import probant_search_setup as SS, reference as R

REGO = b"package policy\n# synthetic container policy\n"
SHA = hashlib.sha256(REGO).hexdigest()
NOW = dt.datetime(2026, 10, 5, tzinfo=dt.timezone.utc)


def signed_reference(key, *, policy=SHA, valid_to=None):
    pub = key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
    body = {"schema": "inferroute.enclave-reference/1", "published_at": "2026-10-01T00:00:00Z",
            "policy_sha256": [{"value": policy, "valid_from": "2026-01-01T00:00:00Z", "valid_to": valid_to}],
            "publication_key": pub}
    return {**body, "sig": key.sign(R.canonical(body)).hex()}, pub


@pytest.fixture
def site(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    ref, pub = signed_reference(key)
    files = {"/reference/current.json": json.dumps(ref, indent=4).encode() + b"\n",       # deliberately NOT the form we would write
             "/reference/current.json.ots": b"\x00OpenTimestamps\x00 synthetic proof",
             "/probant/search.json": json.dumps({"enclave": "http://203.0.113.9:8000"}).encode(),
             f"/policy/{SHA}.rego": REGO}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = files.get(self.path)
            if body is None:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setattr(SS, "SITE", f"http://127.0.0.1:{server.server_address[1]}")
    monkeypatch.setattr(SS, "pinned_key", lambda: pub)
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / "ir"))
    yield files, key, pub, tmp_path
    server.shutdown()


def cfg(tmp_path):
    return json.loads((tmp_path / "ir/confidential/search.json").read_text())


def test_a_fresh_machine_gets_a_working_configuration(site):
    files, key, pub, tmp = site
    state, words = SS.setup(now=NOW)
    assert state == "configured" and "signed reference" in words
    c = cfg(tmp)
    assert c["enclave"] == "http://203.0.113.9:8000" and c["reference_key"] == pub
    assert "expect_host_data" not in c and "python" not in c and "cwd" not in c      # the verifier derives its pins
    assert (tmp / "ir/confidential/reference.json").is_file() and c["reference"].endswith("reference.json")
    assert base64.b64decode(open(c["policy_file"]).read()) == REGO
    for p in (tmp / "ir/confidential").iterdir():
        assert stat.S_IMODE(p.stat().st_mode) in (0o600, 0o700), p


def test_a_second_run_changes_nothing(site):
    SS.setup(now=NOW)
    assert SS.setup(now=NOW)[0] == "unchanged"


def test_a_reference_not_signed_by_the_pinned_key_is_refused_and_nothing_is_written(site):
    files, key, pub, tmp = site
    other = Ed25519PrivateKey.generate()
    ref, _ = signed_reference(other)                       # validly signed — by a key we do not trust
    files["/reference/current.json"] = json.dumps(ref).encode()
    with pytest.raises(SS.SetupError, match="not signed by InferRoute"):
        SS.setup(now=NOW)
    assert not (tmp / "ir/confidential").exists()


def test_a_tampered_reference_is_refused(site):
    files, key, pub, tmp = site
    ref = json.loads(files["/reference/current.json"])
    ref["policy_sha256"][0]["value"] = "0" * 64
    files["/reference/current.json"] = json.dumps(ref).encode()
    with pytest.raises(SS.SetupError, match="not signed by InferRoute"):
        SS.setup(now=NOW)


def test_a_policy_that_does_not_hash_to_what_the_reference_names_is_refused(site):
    files, key, pub, tmp = site
    files[f"/policy/{SHA}.rego"] = REGO + b"# one byte of difference\n"
    with pytest.raises(SS.SetupError, match="does not match the hash"):
        SS.setup(now=NOW)
    assert not (tmp / "ir/confidential/search.json").exists()


def test_a_reference_with_nothing_current_is_refused(site):
    files, key, pub, tmp = site
    ref, _ = signed_reference(key, valid_to="2026-02-01T00:00:00Z")
    files["/reference/current.json"] = json.dumps(ref).encode()
    with pytest.raises(SS.SetupError, match="no search build that is current"):
        SS.setup(now=NOW)


@pytest.mark.parametrize("address", ["http://u:p@203.0.113.9:8000", "http://203.0.113.9:8000/steal", "ftp://203.0.113.9",
                                     "http://203.0.113.9:8000/?x=1", "", None, "javascript:alert(1)"])
def test_a_search_address_that_is_more_than_a_host_and_port_is_refused(site, address):
    files, key, pub, tmp = site
    files["/probant/search.json"] = json.dumps({"enclave": address}).encode()
    with pytest.raises(SS.SetupError, match="plain host and port"):
        SS.setup(now=NOW)


def test_a_configuration_that_probant_did_not_write_is_left_alone_unless_forced(site):
    files, key, pub, tmp = site
    d = tmp / "ir/confidential"
    d.mkdir(parents=True)
    (d / "search.json").write_text(json.dumps({"python": "/dev/py", "cwd": "/dev/tree", "enclave": "http://dev:1"}))
    state, words = SS.setup(now=NOW)
    assert state == "kept" and cfg(tmp)["enclave"] == "http://dev:1"
    assert SS.setup(force=True, now=NOW)[0] == "configured" and cfg(tmp)["enclave"] == "http://203.0.113.9:8000"


def test_the_machine_moving_is_picked_up_without_the_person_doing_anything(site):
    files, key, pub, tmp = site
    SS.setup(now=NOW)
    files["/probant/search.json"] = json.dumps({"enclave": "http://203.0.113.77:8000"}).encode()
    assert SS.setup(now=NOW)[0] == "configured" and cfg(tmp)["enclave"] == "http://203.0.113.77:8000"


def test_offline_keeps_what_is_there_and_never_raises_from_the_quiet_path(site, monkeypatch):
    SS.setup(now=NOW)
    before = (cfg(site[3]), (site[3] / "ir/confidential/reference.json").read_bytes())
    monkeypatch.setattr(SS, "SITE", "http://127.0.0.1:9")
    with pytest.raises(SS.SetupError, match="could not reach"):
        SS.setup(now=NOW)
    SS.ensure_quietly()                                    # must not raise
    assert (cfg(site[3]), (site[3] / "ir/confidential/reference.json").read_bytes()) == before


def test_the_key_comes_from_the_program_never_from_the_network_or_a_config(monkeypatch):
    monkeypatch.undo()
    key = SS.pinned_key()
    shipped = json.loads(__import__("pathlib").Path(SS.__file__).resolve().parent.parent.joinpath(
        "docs/trust/publication-key-attestation.json").read_text())["publication_key"]
    assert key == shipped == "748e4c8e4ca334c5f804ffcdbd85f2dca29713e71c1c7c9c0737e3b898e2e204"
    src = open(SS.__file__).read()
    assert "reference_key\"]" not in src.split("def setup")[1].split("wanted")[0]      # not read back from a config


def test_the_reference_is_kept_byte_for_byte_and_its_timestamp_proof_comes_with_it(site):
    """The first audit run found it: the client held a re-serialised reference (2705 bytes against 2511
    published) and no .ots, so its exported records lost the OpenTimestamps anchor the letter promises."""
    files, key, pub, tmp = site
    SS.setup(now=NOW)
    held = tmp / "ir/confidential/reference.json"
    assert held.read_bytes() == files["/reference/current.json"]                  # not one byte different
    assert hashlib.sha256(held.read_bytes()).hexdigest() == hashlib.sha256(files["/reference/current.json"]).hexdigest()
    assert (tmp / "ir/confidential/reference.json.ots").read_bytes() == files["/reference/current.json.ots"]


def test_a_reference_with_no_timestamp_proof_is_fine_and_a_stale_proof_is_removed(site):
    files, key, pub, tmp = site
    SS.setup(now=NOW)
    ots = tmp / "ir/confidential/reference.json.ots"
    assert ots.is_file()
    del files["/reference/current.json.ots"]                                     # the site no longer has one for this reference
    assert SS.setup(now=NOW)[0] == "configured"
    assert not ots.exists()                                                      # never left beside bytes it does not stamp
    assert SS.setup(now=NOW)[0] == "unchanged"


def test_a_timestamp_that_fails_to_download_stops_the_setup_rather_than_keeping_a_stale_one(site, monkeypatch):
    files, key, pub, tmp = site
    SS.setup(now=NOW)
    real = SS._get_optional

    def broken(url):
        if url.endswith(".ots"):
            raise SS.SetupError("could not reach the site (synthetic)")
        return real(url)

    monkeypatch.setattr(SS, "_get_optional", broken)
    with pytest.raises(SS.SetupError):
        SS.setup(now=NOW)
