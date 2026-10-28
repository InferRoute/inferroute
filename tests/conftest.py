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
