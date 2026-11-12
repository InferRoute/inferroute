import pytest


@pytest.fixture(autouse=True)
def _no_test_reaches_the_real_site(monkeypatch):
    """Probant keeps its search configuration current whenever it starts or a matter opens, by fetching three
    small files from the site. A test must never do that by accident: point it at a port nothing listens on
    (a test of the setup itself serves its own files and says so)."""
    # The program honours IR_SITE_BASE only on https InferRoute hosts (site_base); a test points it at a dead port
    # through the test-only override, in the environment, so a subprocess a test spawns is fenced too.
    monkeypatch.setenv("IR_TESTING", "1")
    monkeypatch.setenv("IR_TEST_SITE_BASE", "http://127.0.0.1:9")
    monkeypatch.delenv("IR_SITE_BASE", raising=False)
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
def _no_test_writes_the_real_billing_answer(monkeypatch, tmp_path):
    """anteriora_billing keeps its billing answer under the app home: each test keeps its own."""
    from inferroute_cli import anteriora_billing
    monkeypatch.setattr(anteriora_billing, "_cache_path", lambda: tmp_path / "_billing" / "anteriora-billing.json")


@pytest.fixture(autouse=True)
def _no_permit_refusal_outlives_its_test():
    """billing_refusal.PERMIT_REFUSALS is per process, as in the app: each test starts with none."""
    from inferroute_local.confidential import billing_refusal
    billing_refusal.PERMIT_REFUSALS.clear()
    yield
    billing_refusal.PERMIT_REFUSALS.clear()
