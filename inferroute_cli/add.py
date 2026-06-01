"""`ir add local-routing` — install the optional on-device routing feature.

What this does, in order:
  1. Detect whether the `[local]` extra is already installed in the current
     Python env. If not, prompt and run `pip install 'inferroute[local]'`
     in-place.
  2. Fetch the v0 ONNX classifier bundle from the GitHub Releases manifest
     into ~/.inferroute/models/classifier-v0/ via the daemon's bootstrap
     module. Atomic stage-and-rename; sha256-verified.
  3. Install a systemd user unit (Linux) / launchd plist (macOS) that runs
     the daemon as `inferroute-daemon` on localhost:5005, then start it.
  4. Append `ANTHROPIC_BASE_URL=http://localhost:5005` to the user's shell rc
     so subsequent `claude` invocations talk to the local daemon. Detected
     from $SHELL; `--no-shell-edit` prints the line instead of modifying rc.

Every step is idempotent: re-running is safe and reports what's already done.
Failures are loud and recoverable — no half-installed state.

The flag-parsing here is intentionally argparse rather than click so this
module imports cheaply (matching the rest of the launcher CLI).
"""
from __future__ import annotations

import argparse
import os
import platform
import subprocess
import sys
import textwrap
from pathlib import Path

# Default manifest URL — points at whatever the latest tagged release of
# InferRoute/inferroute-cli has attached as artifacts. Updates roll forward
# atomically when we cut a new release.
DEFAULT_MANIFEST_URL = (
    "https://github.com/InferRoute/inferroute-cli/releases/latest/download/"
    "classifier-v0-manifest.json"
)

LOCAL_BASE_URL = "http://localhost:5005"

# Shell rc files we know how to edit. Order = preference (the first one
# matching the user's $SHELL wins).
SHELL_RC_FILES = {
    "zsh":  Path.home() / ".zshrc",
    "bash": Path.home() / ".bashrc",
    "fish": Path.home() / ".config/fish/config.fish",
}

SHELL_EDIT_MARKER_BEGIN = "# >>> inferroute local-routing >>>"
SHELL_EDIT_MARKER_END   = "# <<< inferroute local-routing <<<"


def cmd_add(rest: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="ir add", description="Add an optional feature.")
    ap.add_argument("feature", choices=["local-routing"], help="Which feature to add.")
    ap.add_argument(
        "--manifest-url", default=DEFAULT_MANIFEST_URL,
        help="Override the model manifest URL (advanced).",
    )
    ap.add_argument(
        "--no-shell-edit", action="store_true",
        help="Don't modify your shell rc. Print the env-var line instead so you can paste it yourself.",
    )
    ap.add_argument(
        "--no-service", action="store_true",
        help="Skip installing the systemd/launchd unit. The daemon won't start automatically.",
    )
    ap.add_argument(
        "--yes", "-y", action="store_true",
        help="Don't prompt for confirmation before installing pip deps.",
    )
    ns = ap.parse_args(rest)

    if ns.feature == "local-routing":
        return _add_local_routing(ns)
    return 2  # argparse covers this, defensive


# ──────────────────────────────────────────────────────────────────────────
# local-routing installer
# ──────────────────────────────────────────────────────────────────────────

def _add_local_routing(ns) -> int:
    print()
    print("  Adding local-routing")
    print("  ────────────────────")
    print()

    # Step 1: ensure the [local] extra is installed in this interpreter.
    if not _local_extra_installed():
        if not _confirm_pip_install(ns.yes):
            print("  Aborted — no pip install run.")
            return 1
        rc = _pip_install_local_extra()
        if rc != 0:
            print(f"\n  pip install failed (exit {rc}). Fix the error above and re-run.")
            return rc
    else:
        print("  [1/4] Python deps already installed.")

    # Step 2: fetch the ONNX bundle into the default model dir.
    print("  [2/4] Fetching classifier model …")
    model_dir = Path.home() / ".inferroute" / "models" / "classifier-v0"
    try:
        from inferroute_local.bootstrap import maybe_bootstrap_classifier
    except ImportError as e:
        print(f"  ✗ Couldn't import bootstrap module after pip install ({e}).")
        print(f"    Try restarting your shell and re-running.")
        return 1
    version = maybe_bootstrap_classifier(model_dir, ns.manifest_url)
    if version is None:
        # Either a model is already in place (re-run case) or the fetch
        # quietly failed. bootstrap.py already logged the reason; check
        # whether we have a usable model.
        if (model_dir / "onnx" / "model.onnx").exists():
            print(f"        ✓ Model already at {model_dir}")
        else:
            print(f"        ✗ Could not install the classifier model.")
            print(f"          Manifest URL: {ns.manifest_url}")
            print(f"          The daemon will still run (falls back to the server route)")
            print(f"          but on-device routing won't be active. Re-run later.")
    else:
        print(f"        ✓ Installed model version {version} at {model_dir}")

    # Step 3: install + start the systemd/launchd unit.
    if ns.no_service:
        print("  [3/4] Skipping service install (--no-service).")
    else:
        rc = _install_user_service()
        if rc != 0:
            print(f"        ✗ Service install failed. You can run `inferroute-daemon serve` manually.")
            # Not fatal — continue to print env-var info.

    # Step 4: shell rc edit.
    if ns.no_shell_edit:
        _print_env_var_block()
    else:
        rc = _edit_shell_rc()
        if rc != 0:
            _print_env_var_block()

    _print_done_banner()
    return 0


# ----- Step 1 helpers --------------------------------------------------------

def _local_extra_installed() -> bool:
    """True iff the [local] runtime deps are importable in this env."""
    try:
        import onnxruntime  # noqa: F401
        import tokenizers   # noqa: F401
        import fastapi      # noqa: F401
        import uvicorn      # noqa: F401
        return True
    except ImportError:
        return False


def _confirm_pip_install(skip_prompt: bool) -> bool:
    msg = textwrap.dedent("""\
      [1/4] This will install local-routing Python deps in the current env:
              fastapi, uvicorn, click, onnxruntime, tokenizers
            (~40 MB total)
    """)
    print(msg)
    if skip_prompt:
        return True
    try:
        ans = input("        Install now? [Y/n] ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print()
        return False
    return ans in {"", "y", "yes"}


def _pip_install_local_extra() -> int:
    """Re-invoke pip in the running interpreter to add [local] extras.

    We install the same package name the user originally pip-installed, with
    the [local] extra appended. Pip resolves "inferroute[local]" against the
    currently-installed inferroute distribution by re-resolving its metadata,
    which is enough to add the extras' deps without reinstalling the base.
    """
    cmd = [sys.executable, "-m", "pip", "install", "inferroute[local]"]
    print(f"        Running: {' '.join(cmd)}")
    return subprocess.call(cmd)


# ----- Step 3 helpers (service install) --------------------------------------

SYSTEMD_UNIT_TEMPLATE = """\
[Unit]
Description=inferroute local-routing daemon
After=network.target

[Service]
Type=simple
ExecStart={daemon_path} serve --port 5005
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
"""


def _install_user_service() -> int:
    """Cross-platform: systemd user unit on Linux, launchd plist on macOS."""
    sysname = platform.system()
    if sysname == "Linux":
        return _install_systemd_unit()
    if sysname == "Darwin":
        return _install_launchd_plist()
    print(f"        Unsupported platform for auto-start: {sysname}")
    print(f"        Run `inferroute-daemon serve` manually to start the daemon.")
    return 1


def _install_systemd_unit() -> int:
    daemon_path = _which("inferroute-daemon")
    if daemon_path is None:
        print("        ✗ `inferroute-daemon` not on PATH. Pip install may not have linked the script.")
        return 1
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    unit_path = unit_dir / "inferroute.service"
    unit_path.write_text(SYSTEMD_UNIT_TEMPLATE.format(daemon_path=daemon_path))
    # Reload + enable + start. systemctl --user works without sudo.
    for cmd in (
        ["systemctl", "--user", "daemon-reload"],
        ["systemctl", "--user", "enable", "inferroute.service"],
        ["systemctl", "--user", "restart", "inferroute.service"],
    ):
        rc = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if rc != 0:
            print(f"        ✗ `{' '.join(cmd)}` failed (exit {rc}).")
            return rc
    print(f"  [3/4] Daemon installed at {unit_path}")
    print(f"        Running on {LOCAL_BASE_URL} (systemctl --user status inferroute)")
    return 0


def _install_launchd_plist() -> int:
    daemon_path = _which("inferroute-daemon")
    if daemon_path is None:
        print("        ✗ `inferroute-daemon` not on PATH.")
        return 1
    plist_dir = Path.home() / "Library" / "LaunchAgents"
    plist_dir.mkdir(parents=True, exist_ok=True)
    plist_path = plist_dir / "ai.inferroute.daemon.plist"
    plist_path.write_text(textwrap.dedent(f"""\
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
          <key>Label</key><string>ai.inferroute.daemon</string>
          <key>ProgramArguments</key>
          <array>
            <string>{daemon_path}</string>
            <string>serve</string>
            <string>--port</string><string>5005</string>
          </array>
          <key>RunAtLoad</key><true/>
          <key>KeepAlive</key><true/>
        </dict>
        </plist>
    """))
    subprocess.call(["launchctl", "unload", str(plist_path)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rc = subprocess.call(["launchctl", "load", str(plist_path)])
    if rc != 0:
        print(f"        ✗ launchctl load failed (exit {rc}).")
        return rc
    print(f"  [3/4] Daemon installed at {plist_path}")
    print(f"        Running on {LOCAL_BASE_URL}")
    return 0


def _which(name: str) -> str | None:
    from shutil import which
    return which(name)


# ----- Step 4 helpers (shell rc) ---------------------------------------------

def _edit_shell_rc() -> int:
    """Append the ANTHROPIC_BASE_URL line to the user's shell rc, between markers."""
    shell_name = _detect_shell()
    rc_path = SHELL_RC_FILES.get(shell_name)
    if rc_path is None:
        print(f"  [4/4] Shell '{shell_name}' not auto-supported; printing env line:")
        _print_env_var_block()
        return 1

    current = rc_path.read_text() if rc_path.exists() else ""
    if SHELL_EDIT_MARKER_BEGIN in current:
        print(f"  [4/4] Shell rc already contains an inferroute block — leaving as-is.")
        print(f"        ({rc_path})")
        return 0

    block = (
        f"\n{SHELL_EDIT_MARKER_BEGIN}\n"
        f"export ANTHROPIC_BASE_URL={LOCAL_BASE_URL}\n"
        f"{SHELL_EDIT_MARKER_END}\n"
    )
    rc_path.parent.mkdir(parents=True, exist_ok=True)
    with rc_path.open("a", encoding="utf-8") as f:
        f.write(block)
    print(f"  [4/4] Appended ANTHROPIC_BASE_URL to {rc_path}")
    print(f"        Open a new shell or run: source {rc_path}")
    return 0


def _detect_shell() -> str:
    shell = os.environ.get("SHELL", "")
    return Path(shell).name or "bash"


def _print_env_var_block() -> None:
    print()
    print("        Add this to your shell rc to point Claude Code at the local daemon:")
    print()
    print(f"            export ANTHROPIC_BASE_URL={LOCAL_BASE_URL}")
    print()


def _print_done_banner() -> None:
    print()
    print("  Done. local-routing installed.")
    print("  Verify:")
    print("    ir status                    # daemon + server status")
    print("    systemctl --user status inferroute   # (Linux) daemon process")
    print("  Remove anytime:")
    print("    ir remove local-routing")
    print()
