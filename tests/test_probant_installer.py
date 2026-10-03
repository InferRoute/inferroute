"""The one-line installer: what it is filled with, and what it refuses."""
import importlib.util
import os
import subprocess
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("render_install_script", REPO / "scripts/render_install_script.py")
render = importlib.util.module_from_spec(spec)
spec.loader.exec_module(render)


def wheels(tmp_path, client_v="1.2.3", runtime_v="1.2.3"):
    c = tmp_path / f"inferroute-{client_v}-py3-none-any.whl"
    r = tmp_path / f"inferroute_macos_vm_runtime-{runtime_v}-py3-none-macosx_11_0_arm64.whl"
    c.write_bytes(b"CLIENT")
    r.write_bytes(b"RUNTIME")
    return c, r


def test_the_script_names_exactly_the_files_it_is_given(tmp_path):
    c, r = wheels(tmp_path)
    text = render.render(c, r)
    import hashlib
    assert f'CLIENT_SHA256="{hashlib.sha256(b"CLIENT").hexdigest()}"' in text
    assert f'RUNTIME_SHA256="{hashlib.sha256(b"RUNTIME").hexdigest()}"' in text
    assert 'VERSION="1.2.3"' in text and "@" not in text.replace("@" + "1.2.3", "")


def test_a_release_ships_one_version_of_each(tmp_path):
    c, r = wheels(tmp_path, runtime_v="1.2.4")
    with pytest.raises(SystemExit, match="one version"):
        render.render(c, r)


def test_the_template_never_reaches_for_privilege_or_the_shell_profile():
    text = (REPO / "scripts/install_probant.sh.in").read_text()
    for forbidden in ("sudo", ".zshrc", ".bashrc", ".profile", "chmod 777", "eval "):
        assert forbidden not in text.replace("It does not use sudo, edit your shell profile", "")


def _run(tmp_path, base, home, extra_env=None):
    c, r = wheels(tmp_path)
    script = tmp_path / "install.sh"
    script.write_text(render.render(c, r))
    # a stand-in uv: records what it was asked to do, installs nothing
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    uv = bin_dir / "uv"
    uv.write_text(textwrap.dedent(f"""\
        #!/bin/sh
        echo "$@" >> {tmp_path}/uv.calls
        case "$1" in venv) shift; for a; do last="$a"; done; mkdir -p "$last/bin"; printf '#!/bin/sh\\nexit 0\\n' > "$last/bin/python"; chmod +x "$last/bin/python"; printf '#!/bin/sh\\necho ir\\n' > "$last/bin/ir"; chmod +x "$last/bin/ir";; esac
        exit 0
        """))
    uv.chmod(0o755)
    env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", IR_INSTALL_BASE=f"file://{base}", PROBANT_HOME=str(home),
               HOME=str(tmp_path / "home"), **(extra_env or {}))
    (tmp_path / "home").mkdir(exist_ok=True)
    return subprocess.run(["sh", str(script)], env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL)


def test_a_download_that_differs_from_the_fingerprint_installs_nothing(tmp_path):
    site = tmp_path / "site"
    site.mkdir()
    c, _ = wheels(site)
    (site / c.name).write_bytes(b"CLIENT-TAMPERED")
    done = _run(tmp_path, site, tmp_path / "home-target")
    assert done.returncode != 0 and "does not match the fingerprint" in done.stderr
    assert not (tmp_path / "home-target").exists()
    assert not (tmp_path / "uv.calls").exists() or "pip" not in (tmp_path / "uv.calls").read_text()


def test_an_occupied_folder_is_never_written_into(tmp_path):
    site = tmp_path / "site"
    site.mkdir()
    wheels(site)
    target = tmp_path / "target"
    target.mkdir()
    (target / "precious.txt").write_text("mine")
    done = _run(tmp_path, site, target)
    assert done.returncode != 0 and "not a Probant environment" in done.stderr
    assert sorted(p.name for p in target.iterdir()) == ["precious.txt"]


def test_on_linux_only_the_client_is_fetched_and_installed(tmp_path, monkeypatch):
    import sys
    if sys.platform != "linux":
        pytest.skip("this asserts the Linux branch")
    site = tmp_path / "site"
    site.mkdir()
    c, r = wheels(site)
    r.unlink()                                         # the runtime is not even on the server
    done = _run(tmp_path, site, tmp_path / "ok-target")
    assert done.returncode == 0, done.stderr
    pip = [l for l in (tmp_path / "uv.calls").read_text().splitlines() if l.startswith("pip")][0]
    assert "macos_vm_runtime" not in pip and "[confidential]" in pip
