"""Installer rejection checks require no Mac, vendor keys or installed runtime."""

from pathlib import Path
import subprocess


def test_unprovisioned_installer_cannot_modify_user_home(tmp_path):
    home = tmp_path / "synthetic-home"
    home.mkdir()
    canary = home / "do-not-touch.txt"
    canary.write_bytes(b"SYNTHETIC EXISTING CLIENT STATE")
    installer = Path(__file__).resolve().parents[1] / "native/macos/install.sh.in"
    result = subprocess.run(
        ["/bin/sh", str(installer), str(tmp_path / "unsigned.app")],
        env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=3,
    )
    assert result.returncode == 78
    assert "vendor policy has not been provisioned" in result.stderr
    assert sorted(p.name for p in home.iterdir()) == [canary.name]
    assert canary.read_bytes() == b"SYNTHETIC EXISTING CLIENT STATE"
