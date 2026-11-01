"""Henry, 1 Nov 2026: no "client" concept for the user. New matters are filed under the default folder and a
matter is named on its own; anyone who wants a client or a source puts it in the matter name. Matters made before
keep working, by their old <client>/<matter> spelling and in the home page, where a non-default client shows."""
import os
import pathlib

from inferroute_cli import probant

HOME_JS = pathlib.Path(probant.__file__).parent / "probant_web" / "home.js"


def test_a_bare_matter_name_is_filed_under_the_default_folder():
    assert probant._split_matter("acme-cooling") == (probant.DEFAULT_CLIENT, "acme-cooling")


def test_an_old_client_slash_matter_spelling_still_resolves():
    assert probant._split_matter("Acme/cooling") == ("Acme", "cooling")


def test_new_with_one_name_files_it_under_the_default_folder_and_two_names_still_work(tmp_path, monkeypatch):
    # BOTH roots: the matter records live under INFERROUTE_HOME, and a test that set only the workspace root wrote
    # two records into the real ~/.inferroute (1 Nov; found and removed by hand).
    monkeypatch.setenv("IR_PROBANT_ROOT", str(tmp_path / "Anteriora"))
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / ".inferroute"))
    real = pathlib.Path.home() / ".inferroute" / "confidential" / "matters"
    before = sorted(str(p) for p in real.rglob("*")) if real.exists() else []
    assert probant.main(["new", "acme-cooling", "--priority-date", "2026-01-01"]) == 0
    assert (probant.probant_root() / probant.DEFAULT_CLIENT / "acme-cooling").is_dir()
    assert probant.main(["new", "Acme", "cooling", "--priority-date", "2026-01-01"]) == 0
    assert (probant.probant_root() / "Acme" / "cooling").is_dir()
    assert (sorted(str(p) for p in real.rglob("*")) if real.exists() else []) == before, "the test touched the real home"


def test_the_home_page_never_asks_for_a_client():
    js = HOME_JS.read_text()
    assert 'validation.field("client"' not in js
    assert "Use Personal" not in js
    assert "<client>" not in js
    taught = [l for l in pathlib.Path(probant.__file__).read_text().splitlines()
              if "<client>" in l and "anteriora " in l and "still works" not in l]
    assert not taught, f"the CLI help still teaches a client: {taught}"
    assert 'matterLabel(m)' in js and 'm.client !== "Personal"' in js
