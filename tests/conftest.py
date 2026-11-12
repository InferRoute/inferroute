import pytest


@pytest.fixture(autouse=True)
def _no_test_reaches_the_real_site(monkeypatch):
    """Probant keeps its search configuration current whenever it starts or a matter opens, by fetching three
    small files from the site. A test must never do that by accident: point it at a port nothing listens on
    (a test of the setup itself serves its own files and says so)."""
    monkeypatch.setenv("IR_SITE_BASE", "http://127.0.0.1:9")
    from inferroute_cli import probant_search_setup
    monkeypatch.setattr(probant_search_setup, "SITE", "http://127.0.0.1:9", raising=False)


@pytest.fixture(autouse=True)
def _no_test_writes_the_real_credentials(monkeypatch, tmp_path):
    """config.CREDS_FILE is ~/.config/inferroute/credentials, fixed when the module is imported, so setting
    INFERROUTE_HOME does not move it: a test that saved a key wrote over the developer's real one (28 Oct, a test
    of this suite did exactly that). Every test gets its own file; a test that needs a key saves one there."""
    from inferroute_cli import config
    monkeypatch.setattr(config, "CREDS_FILE", tmp_path / "_credentials" / "credentials")
    monkeypatch.delenv("INFERROUTE_API_KEY", raising=False)


@pytest.fixture(autouse=True)
def _no_test_reaches_the_account_service(monkeypatch, tmp_path):
    """anteriora_billing ignores an IR_SITE_BASE that is not https on inferroute.ai, so the port above does not reach
    it: its default is pointed at the same dead port. And its remembered billing answer lives under each test's own
    directory, never in the developer's app home."""
    from inferroute_cli import anteriora_billing
    monkeypatch.setattr(anteriora_billing, "DEFAULT_SITE", "http://127.0.0.1:9")
    monkeypatch.setattr(anteriora_billing, "_cache_path", lambda: tmp_path / "_billing" / "anteriora-billing.json")


@pytest.fixture(autouse=True)
def _no_permit_refusal_outlives_its_test():
    """billing_refusal.PERMIT_REFUSALS is per process, as in the app: each test starts with none."""
    from inferroute_local.confidential import billing_refusal
    billing_refusal.PERMIT_REFUSALS.clear()
    yield
    billing_refusal.PERMIT_REFUSALS.clear()
