"""`ir remove local-routing` — symmetric reverse of `ir add local-routing`.

What this does:
  1. Stop + disable the systemd unit (Linux) / launchd plist (macOS).
  2. Remove the rc-edit block from the user's shell config (between the
     `# >>> inferroute local-routing >>>` markers `ir add` wrote).
  3. Optionally remove the ~/.inferroute/models/classifier-v0/ directory
     and the decision logs (off by default — `--purge` to wipe).
  4. Optionally uninstall the [local] pip extras (off by default — `--uninstall-deps`).

The default behavior is intentionally CONSERVATIVE: stop the daemon and
disconnect the shell, but leave artifacts on disk in case the user wants
to come back. `--purge` is the "really, all of it" flag.
"""
from __future__ import annotations

import argparse
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from .add import (
    SHELL_EDIT_MARKER_BEGIN,
    SHELL_EDIT_MARKER_END,
    SHELL_RC_FILES,
    _detect_shell,
)


def cmd_remove(rest: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="ir remove")
    ap.add_argument("feature", choices=["local-routing"])
    ap.add_argument("--purge", action="store_true",
                    help="Also delete the classifier model and decision logs.")
    ap.add_argument("--uninstall-deps", action="store_true",
                    help="Also uninstall the [local] pip extras (onnxruntime, tokenizers, fastapi, uvicorn).")
    ns = ap.parse_args(rest)

    if ns.feature == "local-routing":
        return _remove_local_routing(ns)
    return 2


def _remove_local_routing(ns) -> int:
    print()
    print("  Removing local-routing")
    print("  ──────────────────────")

    # Step 1: stop + disable the user service.
    sysname = platform.system()
    if sysname == "Linux":
        _stop_systemd()
    elif sysname == "Darwin":
        _stop_launchd()
    else:
        print(f"  [1/3] Platform {sysname}: no auto-managed service to stop.")

    # Step 2: remove the shell rc block.
    _undo_shell_rc()

    # Step 3: optional purge of artifacts on disk.
    if ns.purge:
        for path in [
            Path.home() / ".inferroute" / "models" / "classifier-v0",
            Path.home() / ".inferroute" / "logs",
        ]:
            if path.exists():
                shutil.rmtree(path, ignore_errors=True)
                print(f"  [3/3] Removed {path}")
    else:
        print("  [3/3] Leaving model + logs on disk (use --purge to delete).")

    # Optional: uninstall the [local] extras themselves.
    if ns.uninstall_deps:
        # We don't uninstall `inferroute` itself — that'd remove `ir`. We just
        # remove the optional deps. Pip has no "remove extras" verb, so we
        # explicitly list them.
        cmd = [sys.executable, "-m", "pip", "uninstall", "-y",
               "fastapi", "uvicorn", "onnxruntime", "tokenizers", "click"]
        subprocess.call(cmd)
        print("        Uninstalled [local] pip deps.")

    print()
    print("  Done. Local-routing removed.")
    print("  `ir` continues to work as the lightweight launcher.")
    print()
    return 0


# ----- service stop --------------------------------------------------------

def _stop_systemd() -> None:
    unit_path = Path.home() / ".config" / "systemd" / "user" / "inferroute.service"
    if not unit_path.exists():
        print("  [1/3] No systemd unit installed — skipping.")
        return
    for cmd in (
        ["systemctl", "--user", "stop", "inferroute.service"],
        ["systemctl", "--user", "disable", "inferroute.service"],
    ):
        subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    unit_path.unlink()
    subprocess.call(["systemctl", "--user", "daemon-reload"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"  [1/3] Stopped + removed {unit_path}")


def _stop_launchd() -> None:
    plist_path = Path.home() / "Library" / "LaunchAgents" / "ai.inferroute.daemon.plist"
    if not plist_path.exists():
        print("  [1/3] No launchd plist installed — skipping.")
        return
    subprocess.call(["launchctl", "unload", str(plist_path)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    plist_path.unlink()
    print(f"  [1/3] Stopped + removed {plist_path}")


# ----- shell rc undo --------------------------------------------------------

def _undo_shell_rc() -> None:
    rc_path = SHELL_RC_FILES.get(_detect_shell())
    if rc_path is None or not rc_path.exists():
        print("  [2/3] No managed shell rc detected — skipping.")
        return
    text = rc_path.read_text()
    if SHELL_EDIT_MARKER_BEGIN not in text:
        print(f"  [2/3] No inferroute block in {rc_path} — skipping.")
        return
    # Find begin/end markers (with surrounding newline if present) and excise.
    start = text.find(SHELL_EDIT_MARKER_BEGIN)
    end = text.find(SHELL_EDIT_MARKER_END, start)
    if end == -1:
        print(f"  [2/3] Found begin marker but no end marker in {rc_path} — skipping (edit manually).")
        return
    end += len(SHELL_EDIT_MARKER_END)
    # Strip the trailing newline if it belongs to the marker block.
    while end < len(text) and text[end] == "\n":
        end += 1
    # Also strip a single leading newline if it was the separator before the block.
    if start > 0 and text[start - 1] == "\n":
        start -= 1
    new = text[:start] + text[end:]
    rc_path.write_text(new)
    print(f"  [2/3] Removed inferroute block from {rc_path}")
    print(f"        Open a new shell to pick up the change.")
