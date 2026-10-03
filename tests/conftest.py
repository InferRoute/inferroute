import pytest


@pytest.fixture(autouse=True)
def _no_test_reaches_the_real_site(monkeypatch):
    """Probant keeps its search configuration current whenever it starts or a matter opens, by fetching three
    small files from the site. A test must never do that by accident: point it at a port nothing listens on
    (a test of the setup itself serves its own files and says so)."""
    monkeypatch.setenv("IR_SITE_BASE", "http://127.0.0.1:9")
    from inferroute_cli import probant_search_setup
    monkeypatch.setattr(probant_search_setup, "SITE", "http://127.0.0.1:9", raising=False)
