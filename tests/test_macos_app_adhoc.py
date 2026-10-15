"""The ad-hoc Probant.app recipe (native/macos/build_app_adhoc.sh): checks that need no Mac.

The build itself runs only on a Mac; what can be held here is that every input is pinned, that the pins agree
with the signed release when its files are on this machine, and that the recipe keeps the properties it
claims (the runner is never re-signed, the one entitlement is the documented one, nothing writes bytecode
into the sealed bundle).
"""

import hashlib
import json
import plistlib
import re
import subprocess
from pathlib import Path
from urllib.parse import unquote

import pytest

MAC = Path(__file__).resolve().parents[1] / "native/macos"
PINS = json.loads((MAC / "pins.json").read_text())
FILE_KEYS = ("python", "client_wheel", "runtime_wheel", "lock")


def test_every_input_is_pinned_by_sha256():
    for key in FILE_KEYS:
        entry = PINS[key]
        assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]), key
        assert entry["file"] and "/" not in entry["file"], key
    assert re.fullmatch(r"[0-9a-f]{64}", PINS["runner_sha256"])
    py = PINS["python"]
    assert py["url"].startswith("https://github.com/astral-sh/python-build-standalone/releases/download/")
    assert unquote(py["url"]).endswith("/" + py["file"])
    assert f"/{py['release']}/" in py["url"] and py["version"] in py["file"]
    assert "aarch64-apple-darwin-install_only" in py["file"]
    version = PINS["app"]["version"]
    assert version in PINS["client_wheel"]["file"] and version in PINS["runtime_wheel"]["file"]
    assert version in PINS["lock"]["file"]
    assert re.fullmatch(r"\d+\.\d+", PINS["app"]["minimum_macos"])


def test_build_script_reads_every_pin_it_relies_on():
    script = (MAC / "build_app_adhoc.sh").read_text()
    for key in FILE_KEYS:
        assert f'check "$k"' in script and key in script
    for key in ("app.version", "app.bundle_id", "app.minimum_macos", "runner_sha256"):
        assert f"pin {key}" in script
    subprocess.run(["sh", "-n", str(MAC / "build_app_adhoc.sh")], check=True)


def test_runner_is_never_resigned_and_is_checked_after_signing():
    script = (MAC / "build_app_adhoc.sh").read_text()
    assert '[ "$f" = "$RUNNER" ] && continue' in script
    assert "--deep" not in script.split("ad-hoc signatures")[1].split("codesign --verify")[0]
    assert script.count('[ "$(sha "$RUNNER")" = "$RUNNER_SHA" ]') == 2


def test_python_entitlement_is_only_library_validation():
    ent = plistlib.loads((MAC / "python.entitlements.plist").read_bytes())
    assert ent == {"com.apple.security.cs.disable-library-validation": True}


def test_no_bytecode_is_written_inside_the_bundle():
    assert 'os.environ["PYTHONDONTWRITEBYTECODE"] = "1"' in (MAC / "app_entry.py").read_text()
    swift = (MAC / "AppMain.swift").read_text()
    assert '"-I", "-B"' in swift and "PYTHONDONTWRITEBYTECODE=1" in swift


def test_app_shell_passes_no_credentials_and_can_be_quit():
    swift = (MAC / "AppMain.swift").read_text()
    env_line = swift.split("var env = [")[1].split("]")[0]
    names = re.findall(r'"([A-Z_]+)=', env_line)
    assert set(names) == {"HOME", "PATH", "IR_ATTESTED_CONFINE", "PYTHONNOUSERSITE", "PYTHONSAFEPATH",
                          "PYTHONDONTWRITEBYTECODE"}
    assert "setActivationPolicy(.regular)" in swift and "Quit Probant" in swift
    assert "applicationShouldHandleReopen" in swift and "kill(-pid, SIGINT)" in swift


def test_dmg_readme_has_both_languages_and_only_the_version_placeholder():
    text = (MAC / "dmg-README.txt").read_text()
    assert "=== FRANÇAIS ===" in text and "=== ENGLISH ===" in text
    assert "Open Anyway" in text and "Ouvrir quand même" in text
    assert set(re.findall(r"@[A-Z_]+@", text)) == {"@VERSION@"}


RELEASE = Path.home() / "inferroute-publication/macos-release" / PINS["app"]["version"]


@pytest.mark.skipif(not RELEASE.is_dir(), reason="the signed release files are not on this machine")
def test_pins_match_the_signed_release_files():
    for key in ("client_wheel", "runtime_wheel", "lock"):
        f = RELEASE / PINS[key]["file"]
        assert hashlib.sha256(f.read_bytes()).hexdigest() == PINS[key]["sha256"], key
    import zipfile
    with zipfile.ZipFile(RELEASE / PINS["runtime_wheel"]["file"]) as z:
        manifest = json.loads(z.read("inferroute_macos_vm_runtime/runtime.json"))
    assert manifest["artifacts"]["ProbantVM"]["sha256"] == PINS["runner_sha256"]
    assert manifest["minimum_macos"] == PINS["app"]["minimum_macos"]
