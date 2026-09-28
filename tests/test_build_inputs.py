"""The credential boundary between our deployment template and a client's record pack."""
import json

import pytest

from inferroute_cli import build_inputs as B


def _live_shaped():
    """The shape session_m2.arm_m2 actually produces, including the parts that must not travel."""
    return {"resources": [{"properties": {
        "imageRegistryCredentials": [{"server": "x.azurecr.io", "username": "u", "password": "REAL-ACR-PW"}],
        "containers": [{"name": "search", "properties": {
            "image": "x.azurecr.io/ir@sha256:" + "a" * 64,
            "environmentVariables": [
                {"name": "INDEX_SUBDIR", "value": "sealed-patent-root-usall-epwo"},
                {"name": "INDEX_URL", "secureValue": "https://s.blob.core.windows.net/i/x.tar?sv=2024-01-01&sig=AAAAAAAAAAAAAAAAAAAAAAAA"}],
            "resources": {"requests": {"cpu": 3, "memoryInGB": 52}}}}]}}]}


def test_the_registry_password_does_not_survive():
    clean, found = B.sanitise_arm_template(_live_shaped())
    assert "REAL-ACR-PW" not in json.dumps(clean)
    assert any("password" in f for f in found)


def test_a_sas_token_does_not_survive_even_under_an_innocent_key():
    """`secureValue` contains no secret-looking KEY, so a key-name filter alone would pass it
    through. The value's own shape is what condemns it."""
    clean, _ = B.sanitise_arm_template(_live_shaped())
    blob = json.dumps(clean)
    assert "sig=" not in blob and "sv=2024" not in blob


def test_what_the_auditor_NEEDS_is_kept():
    """Sanitising must not gut the artifact: the image digest, the measured env values and the
    resource shape are exactly what the policy is generated from."""
    clean, _ = B.sanitise_arm_template(_live_shaped())
    blob = json.dumps(clean)
    assert "sha256:" + "a" * 64 in blob
    assert "sealed-patent-root-usall-epwo" in blob
    assert '"memoryInGB": 52' in blob


def test_it_REFUSES_when_redaction_SILENTLY_FAILS(monkeypatch):
    """The final check exists for the case where the redactor does not do its job — a bug, a new
    template shape, a key spelled a way the filter misses. Simulate that directly by disabling the
    redactor, because a fixture the redactor HANDLES never reaches this guard and would prove
    nothing. An earlier version of this test did exactly that and passed for the wrong reason.
    """
    monkeypatch.setattr(B, "_walk", lambda node, path, found: node)
    with pytest.raises(ValueError, match="survived redaction|still holds a value"):
        B.sanitise_arm_template(_live_shaped())


def test_the_refusal_names_the_problem_rather_than_failing_blankly(monkeypatch):
    monkeypatch.setattr(B, "_walk", lambda node, path, found: node)
    try:
        B.sanitise_arm_template(_live_shaped())
    except ValueError as e:
        assert "refusing" in str(e).lower()
        assert "password" in str(e).lower() or "secret-shaped" in str(e).lower()


def test_the_test_fixture_actually_contains_a_secret():
    """A sanitiser test whose fixture is already clean passes for the wrong reason."""
    assert "REAL-ACR-PW" in json.dumps(_live_shaped())
    assert "sig=" in json.dumps(_live_shaped())
