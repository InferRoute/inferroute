"""The command that CREATES the key shows the key.

Henry, 24 Sep, on making the delivery easy for a recipient who is a patent attorney, not an engineer:
print it "at the end of the install". Before this, first run printed a PATH — so the one thing he has to
do, send his key back, began with going to find a file and opening it.
"""
import json

import pytest

from inferroute_cli import probant as S
from inferroute_cli import probant_share as SH


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("INFERROUTE_HOME", str(tmp_path / ".inferroute"))
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: tmp_path))
    yield


def test_the_first_run_prints_the_key_itself_not_a_path_to_it(capsys):
    assert S.cmd_identity() == 0
    out = capsys.readouterr().out
    assert "mlkem_pub" in out and "ed_pub" in out, "the key must be on screen, ready to copy"
    assert "copy everything between the lines" in out
    # and it must say what is safe about it, since he is being asked to email it
    assert "public keys only" in out


def test_what_is_printed_is_the_real_card(capsys):
    S.cmd_identity()
    out = capsys.readouterr().out
    body = out[out.index("{"):out.rindex("}") + 1]
    assert json.loads(body) == SH.public_card(SH.identity())


def test_no_secret_is_ever_printed(capsys):
    """The card is public material; the identity file beside it is not."""
    S.cmd_identity()
    out = capsys.readouterr().out
    me = SH.identity()
    for k in ("mlkem_sk", "ed_sk", "mlkem_seed"):
        if me.get(k):
            assert me[k] not in out, k


def test_a_later_run_does_not_reprint_it(capsys):
    """Every later run wants the fingerprint; 1.7 KB of JSON would be noise, and noise is how people stop
    reading a screen that sometimes matters."""
    S.cmd_identity()
    capsys.readouterr()
    S.cmd_identity()
    out = capsys.readouterr().out
    assert "mlkem_pub" not in out
    assert "fingerprint" in out.lower() and "contact card" in out


def test_show_prints_it_again_on_demand(capsys):
    S.cmd_identity()
    capsys.readouterr()
    S.cmd_identity(show=True)
    assert "mlkem_pub" in capsys.readouterr().out


def test_the_cli_exposes_show():
    import subprocess
    import sys
    r = subprocess.run([sys.executable, "-c",
                        "from inferroute_cli import probant; probant.main(['identity','--help'])"],
                       capture_output=True, text=True)
    assert "--show" in r.stdout
