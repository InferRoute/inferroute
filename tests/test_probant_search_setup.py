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


def test_setup_claims_only_what_it_checked_and_says_when_the_machine_is_offline(site, capsys, monkeypatch):
    """0.9.124: the installer printed "Patent search is set up" for a search machine whose name did not resolve.
    Setup checks InferRoute's signed files, not the machine; it says so, and then says whether anything answers."""
    files, key, pub, tmp = site
    files["/probant/search.json"] = json.dumps({"enclave": "http://search.invalid:8000"}).encode()
    monkeypatch.setattr(SS, "reachable", lambda enclave: "unknown-host")
    assert SS.main_setup() == 0
    out = capsys.readouterr().out
    assert "Patent search is set up" not in out
    assert "signed reference was checked" in out and "checked before each search" in out
    assert "not answering right now" in out and "offline" in out
    monkeypatch.setattr(SS, "reachable", lambda enclave: "up")
    SS.main_setup(force=True)
    assert "answering right now" in capsys.readouterr().out


def test_the_unresolvable_address_is_probed_for_real(site, monkeypatch):
    """The probe is the home page's own: an address that does not resolve reads as such, never as up."""
    from inferroute_cli import probant_home as H
    monkeypatch.setattr(H, "_search_probe", {"at": 0.0, "state": "unreachable"})
    assert SS.reachable("http://search.invalid:8000") == "unknown-host"


@pytest.mark.parametrize("published,kept", [
    ({"mode": "scheduled", "window": [13, 15], "tz": "Europe/Paris"},
     {"mode": "scheduled", "window": [13, 15], "tz": "Europe/Paris"}),
    ({"mode": "always"}, None),
    ({"mode": "scheduled", "window": ["13", 15], "tz": "Europe/Paris"}, None),
    ({"mode": "scheduled", "window": [13, 15], "tz": "<b>Paris</b>"}, None),
    (None, None),
])
def test_published_hours_reach_the_configuration_only_when_well_formed(site, published, kept):
    """If InferRoute publishes the search machine's hours, the home page can show them when it is offline."""
    files, key, pub, tmp = site
    where = {"enclave": "http://203.0.113.9:8000"}
    if published is not None:
        where["availability"] = published
    files["/probant/search.json"] = json.dumps(where).encode()
    SS.setup(force=True, now=NOW)
    assert cfg(tmp).get("availability") == kept


def _tdx_site(files, key, *, image=True):
    pub = key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
    body = {"schema": "inferroute.enclave-reference/1", "published_at": "2026-10-01T00:00:00Z", "publication_key": pub}
    if image:
        body["tdx_image_sha384"] = [{"value": "ab" * 48, "loads": ["cd" * 48], "valid_from": "2026-01-01T00:00:00Z"}]
        body["tdx_rtmr0"] = [{"shape": "c3-standard-22-nodisk", "value": "ef" * 48, "valid_from": "2026-01-01T00:00:00Z"}]
    ref = {**body, "sig": key.sign(R.canonical(body)).hex()}
    files["/reference/current.json"] = json.dumps(ref).encode()
    files["/probant/search.json"] = json.dumps({"enclave": "http://203.0.113.9:8000", "tee": "intel-tdx"}).encode()


def test_an_intel_tdx_search_machine_is_set_up_without_a_container_policy(site):
    """1 Nov 2026: Azure/AMD shut down; the search machine is Intel TDX, which has no container policy."""
    files, key, pub, tmp = site
    _tdx_site(files, key)
    state, _ = SS.setup(now=NOW)
    c = cfg(tmp)
    assert state == "configured" and c["enclave"] == "http://203.0.113.9:8000" and "policy_file" not in c
    assert json.loads((tmp / "ir/confidential/reference.json").read_bytes())["tdx_image_sha384"][0]["value"] == "ab" * 48


def test_a_tdx_location_with_no_current_tdx_image_in_the_reference_is_refused(site):
    files, key, pub, tmp = site
    _tdx_site(files, key, image=False)
    with pytest.raises(SS.SetupError, match="no Intel TDX search image"):
        SS.setup(now=NOW)
    assert not (tmp / "ir/confidential/search.json").exists()


@pytest.mark.parametrize("published,kept", [
    ("https://ir-search-wake-851040540464.europe-west4.run.app", "https://ir-search-wake-851040540464.europe-west4.run.app"),
    ("https://wake.inferroute.ai/", None),            # only the listed hosts, not any subdomain
    ("https://x.inferroute.ai:abc", None),            # malformed: dropped, and setup still completes
    ("https://attacker.example", None),                 # the saved key would go there: dropped, no start button
    ("http://wake.inferroute.ai", None),
    (None, None),
])
def test_a_wake_service_reaches_the_configuration_only_on_inferroute_hosts(site, published, kept):
    """0.9.129: the search machine starts on request; the client asks the wake service search.json names."""
    files, key, pub, tmp = site
    where = {"enclave": "http://203.0.113.9:8000"}
    if published is not None:
        where["wake"] = published
    files["/probant/search.json"] = json.dumps(where).encode()
    SS.setup(force=True, now=NOW)
    assert cfg(tmp).get("wake") == kept


def test_the_delegated_index_extension_is_kept_beside_the_reference_byte_for_byte(site):
    """0.9.130: index entries added under the reference's delegated key travel in a file beside it, where the search
    verifier looks for it. Kept byte for byte when published; removed when the site no longer has one."""
    files, key, pub, tmp = site
    blob = b'{"schema": "inferroute.reference-index-extension/1", "entries": []}\n'
    files["/reference/current.json.index-extension.json"] = blob
    SS.setup(force=True, now=NOW)
    p = tmp / "ir/confidential/reference.json.index-extension.json"
    assert p.read_bytes() == blob
    assert SS.setup(now=NOW)[0] == "unchanged"
    del files["/reference/current.json.index-extension.json"]
    SS.setup(force=True, now=NOW)
    assert not p.exists()


def _signed_at(key, published_at):
    pub = key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex()
    body = {"schema": "inferroute.enclave-reference/1", "published_at": published_at,
            "policy_sha256": [{"value": SHA, "valid_from": "2026-01-01T00:00:00Z", "valid_to": None}],
            "publication_key": pub}
    return {**body, "sig": key.sign(R.canonical(body)).hex()}


def test_an_older_validly_signed_reference_is_refused_and_the_newer_one_stays(site):
    files, key, pub, tmp = site
    files["/reference/current.json"] = json.dumps(_signed_at(key, "2026-10-03T00:00:00Z")).encode()
    SS.setup(now=NOW)
    held = (tmp / "ir/confidential/reference.json").read_bytes()
    files["/reference/current.json"] = json.dumps(_signed_at(key, "2026-10-02T00:00:00Z")).encode()
    with pytest.raises(SS.SetupError, match="older than the one"):
        SS.setup(now=NOW)
    assert (tmp / "ir/confidential/reference.json").read_bytes() == held


def test_a_newer_reference_replaces_the_held_one(site):
    files, key, pub, tmp = site
    files["/reference/current.json"] = json.dumps(_signed_at(key, "2026-10-02T00:00:00Z")).encode()
    SS.setup(now=NOW)
    newer = json.dumps(_signed_at(key, "2026-10-03T00:00:00Z")).encode()
    files["/reference/current.json"] = newer
    SS.setup(now=NOW)
    assert (tmp / "ir/confidential/reference.json").read_bytes() == newer
