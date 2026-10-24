"""rc 0.9.125 e2e (D12): the sandbox re-bound only a Python under the home folder. A Python under /tmp, /nix, /snap
or /home/linuxbrew made every session fail with "bwrap: execvp …/python". The interpreter's own tree is bound now,
wherever it is, read-only — and still never a whole home folder."""
import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

import pytest

from inferroute_local import confinement, netns


def _venv_outside_home():
    d = tempfile.mkdtemp(prefix="ir-py-", dir="/tmp")
    venv.EnvBuilder(with_pip=False, symlinks=True).create(d)
    return Path(d)


def test_an_interpreter_outside_the_home_folder_is_bound(monkeypatch):
    v = _venv_outside_home()
    try:
        py = str(v / "bin" / "python")
        monkeypatch.setattr(netns.sys, "executable", py)
        binds = netns.runtime_ro_binds()
        assert str(v) in binds, binds
        # The interpreter it points at is bound too (wherever that lives), unless the system dirs already hold it.
        real = os.path.realpath(py)
        assert any(real.startswith(b + os.sep) for b in binds) or real.startswith(netns.SYSTEM_RO)
        # Never the root, never a whole home folder.
        home = os.path.realpath(os.path.expanduser("~"))
        assert os.sep not in binds and home not in binds
    finally:
        import shutil
        shutil.rmtree(v, ignore_errors=True)


def test_a_python_in_a_home_bin_never_exposes_the_whole_home(monkeypatch, tmp_path):
    home = tmp_path / "h"
    (home / "bin").mkdir(parents=True)
    (home / "lib").mkdir()
    py = home / "bin" / "python"
    py.write_text("")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(netns.sys, "executable", str(py))
    binds = netns.runtime_ro_binds()
    assert str(home) not in binds and str(home / "bin") in binds


@pytest.mark.skipif(not confinement.netns_bind_available(), reason="needs an unprivileged netns (install-confine-profile.sh)")
def test_a_session_runs_with_a_python_outside_the_home_folder(monkeypatch):
    """The real sandbox, with its forwarder run by an interpreter under /tmp."""
    v = _venv_outside_home()
    root = tempfile.mkdtemp(dir=os.path.expanduser("~"), prefix="ir-d12-")
    try:
        py = str(v / "bin" / "python")
        monkeypatch.setattr(netns.sys, "executable", py)
        cfg, matter = os.path.join(root, "cfg"), os.path.join(root, "matter")
        os.makedirs(cfg)
        os.makedirs(matter)
        r = netns.run_in_netns_bind([py, "-c", "import sys; print('inside', sys.executable)"], ports=[47911], cfg_dir=cfg,
                                    rw=[matter], binary="python3", timeout=120)
        assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
        assert "inside" in r.stdout and "execvp" not in r.stderr
    finally:
        import shutil
        shutil.rmtree(v, ignore_errors=True)
        shutil.rmtree(root, ignore_errors=True)
