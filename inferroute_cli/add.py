"""`ir add recording` — install the optional on-device recorder.

Recording is fully local and fully private. When enabled, a small daemon runs
on localhost:5005; `ir` routes your sessions through it so it can log, on YOUR
machine only, which model you picked for each task and how the turn went. That
local corpus is yours — to inspect (`ir data show`), export, or wipe
(`ir data wipe`). The corpus is never uploaded; inferroute keeps only a one-way
hash of each turn (a fingerprint, never the text).

What this does, in order:
  1. Ask how much to record. Default: full — keeps the prompt text locally, which
     is what lets it learn your preferences; it never leaves the machine.
     'cost-only' (level=off) records NOTHING but still runs the daemon so the
     status line can show your real per-session cost.
  2. Install the `[local]` deps (fastapi, uvicorn) if missing.
  3. Install a systemd user unit (Linux) / launchd plist (macOS) that runs the
     recorder daemon, with the chosen record level baked in, and start it.
  4. (Intentionally NOT done.) We never touch your shell rc. Native `claude` must
     always reach Anthropic directly — even if the daemon is down — so we never
     write a global `ANTHROPIC_BASE_URL`. The `ir` launcher injects the recorder
     base URL into ONLY the processes it spawns (see launch.py), never the global
     shell. `--no-shell-edit` is accepted for back-compat but is now the only
     behavior. `ir remove recording` still strips any legacy shell block a prior
     version (or a hand edit) left behind.

There is NO classifier and NO routing — the daemon is a pure pass-through
recorder. See shared-docs/inferroute/local-decision-recorder-spec.md.

Every step is idempotent. `local-routing` is accepted as a deprecated alias for
`recording`.
"""
from __future__ import annotations

import argparse
import os
import platform
import subprocess
import sys
import textwrap
from pathlib import Path

LOCAL_BASE_URL = "http://localhost:5005"

# The systemd user unit / launchd label for the recorder daemon. We use the
# established name `inferroute-local.service` so this installer and any
# pre-existing (hand-crafted) unit converge on one name — no second daemon, no
# :5005 collision. The record LEVEL is applied via a drop-in (see below) rather
# than baked into the base unit, so re-running `ir add recording` never clobbers
# a richer hand-written unit.
SERVICE_NAME = "inferroute-local.service"
# Marker written into base units WE create, so `ir remove recording` only ever
# deletes installer-created units and leaves hand-crafted ones in place.
UNIT_MARKER = "# Managed-by: ir add recording"
# Drop-in that carries just the record level. Layers on top of the base unit.
DROPIN_NAME = "10-record-level.conf"

# Shell rc files we know how to edit. Order = preference.
SHELL_RC_FILES = {
    "zsh":  Path.home() / ".zshrc",
    "bash": Path.home() / ".bashrc",
    "fish": Path.home() / ".config/fish/config.fish",
}

# Markers kept stable so `ir remove` can clean up. The legacy pair is recognised
# too, so blocks written by older versions are still removable.
SHELL_EDIT_MARKER_BEGIN = "# >>> inferroute recording >>>"
SHELL_EDIT_MARKER_END   = "# <<< inferroute recording <<<"
_LEGACY_MARKER_BEGIN = "# >>> inferroute local-routing >>>"
_LEGACY_MARKER_END   = "# <<< inferroute local-routing <<<"

_VALID_LEVELS = ("metadata", "full", "off")


def cmd_add(rest: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="ir add", description="Add an optional feature.")
    ap.add_argument(
        "feature", choices=["recording", "local-routing"],
        help="Which feature to add (use 'recording').",
    )
    ap.add_argument(
        "--level", choices=_VALID_LEVELS, default=None,
        help="Recording level (skips the prompt). full (default) | metadata | off.",
    )
    ap.add_argument(
        "--no-shell-edit", action="store_true",
        help="(deprecated, no-op) the shell rc is never modified now — kept so "
             "older invocations don't error.",
    )
    ap.add_argument(
        "--no-service", action="store_true",
        help="Skip installing the systemd/launchd unit (daemon won't auto-start).",
    )
    ap.add_argument(
        "--yes", "-y", action="store_true",
        help="Accept defaults without prompting (level=full unless --level given).",
    )
    ns = ap.parse_args(rest)

    if ns.feature == "local-routing":
        print("  note: `local-routing` is now `recording` (no router anymore). "
              "Installing recording.")
    return _add_recording(ns)


# ──────────────────────────────────────────────────────────────────────────
# recording installer
# ──────────────────────────────────────────────────────────────────────────

def _add_recording(ns) -> int:
    print()
    print("  Add local recording")
    print("  ───────────────────")

    level = ns.level or _prompt_level(ns.yes)
    if level == "abort":
        print("\n  Nothing was changed. `ir` keeps working as the lightweight launcher.")
        print("  (Already have the daemon? `ir remove recording` takes it off.)")
        return 0
    # level == "off" is NOT "install nothing" — it's COST-ONLY: the daemon still
    # runs (so the status line can show the real session cost) but records no
    # corpus. The only way to have no daemon at all is to never add it / remove it.
    if level == "off":
        print("\n  Cost-only mode: the daemon will run to show this machine's real")
        print("  session cost in Claude Code's status line, and record NOTHING else")
        print("  (no prompts, no responses, no events). Turn off entirely with")
        print("  `ir remove recording`.")

    # Step 1: ensure the [local] deps are installed.
    if not _local_extra_installed():
        if not _confirm_pip_install(ns.yes):
            print("  Aborted — no pip install run.")
            return 1
        rc = _pip_install_local_extra()
        if rc != 0:
            print(f"\n  pip install failed (exit {rc}). Fix the error above and re-run.")
            return rc
    else:
        print("  [1/3] Python deps already installed.")

    # Step 2: install + start the service with the chosen record level.
    if ns.no_service:
        print("  [2/3] Skipping service install (--no-service).")
        print(f"        Run: INFERROUTE_RECORD_LEVEL={level} inferroute-daemon")
    else:
        rc = _install_user_service(level)
        if rc != 0:
            print("        ✗ Service install failed. You can run the daemon manually:")
            print(f"          INFERROUTE_RECORD_LEVEL={level} inferroute-daemon")

    # Step 3: install the Claude Code SessionEnd hook — the content-recorder path.
    # It ingests each finished session's transcript out of band (no proxy, no
    # request-path cost). Cost-only (level=off) records no corpus, so there's
    # nothing to ingest → skip the hook there.
    if level != "off":
        _install_ingest_hook()

    # Step 4: shell rc — deliberately NOT edited. Native `claude` stays pointed at
    # Anthropic; the `ir` launcher injects the recorder base URL per-process. This
    # is the core safety property of the redesign (no global ANTHROPIC_BASE_URL).
    _print_no_shell_edit_note()

    _print_done_banner(level)
    return 0


def _install_ingest_hook() -> None:
    """Install the Claude Code SessionEnd transcript-ingest hook (idempotent)."""
    try:
        from . import cc_hook
        status = cc_hook.install()
    except Exception as e:
        print(f"  [hook] Could not install the SessionEnd hook ({e}).")
        print(f"         You can add it later by re-running `ir add recording`.")
        return
    msg = {
        "installed": "Installed Claude Code SessionEnd hook (records each session).",
        "updated": "Refreshed the Claude Code SessionEnd hook.",
        "exists": "Claude Code SessionEnd hook already present.",
    }.get(status, f"SessionEnd hook: {status}")
    print(f"  [hook] {msg}")


def _prompt_level(skip_prompt: bool) -> str:
    if skip_prompt:
        return "full"
    print(textwrap.dedent("""
      Inferroute can learn YOUR model preferences over time, to route for you
      later. To do that it records, on THIS machine only:
        • which model you pick for each task
        • the prompt + how the turn went

      ✔ The corpus stays in ~/.inferroute on your computer — never uploaded.
      ✔ inferroute keeps only a one-way hash of each turn — a fingerprint, never
        the text. The prompts & responses themselves never leave this machine.
      ✔ Inspect any time:  ir data show
      ✔ Delete any time:   ir data wipe

      'full' keeps the prompt text, which is what actually lets it learn your
      preferences later — and it never leaves this machine. 'minimal' keeps only
      the model choice + outcome (no prompt text), which is lighter but can't
      train a personal router. 'cost-only' records NOTHING — the daemon just runs
      so the status line can show your real session cost.

      Record locally to build your own router?
        [1] Yes — full: choices, outcomes + prompt text   (recommended)
        [2] Yes — minimal: choices + outcomes only, no prompt text
        [3] No  — cost-only: show real cost, store nothing
        [4] Don't install the daemon at all
    """))
    try:
        ans = input("        Choose [1]: ").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return "abort"
    return {"": "full", "1": "full", "2": "metadata", "3": "off", "4": "abort"}.get(ans, "full")


# ----- Step 1 helpers --------------------------------------------------------

def _local_extra_installed() -> bool:
    """True iff the recorder daemon's runtime deps are importable in this env."""
    try:
        import fastapi   # noqa: F401
        import uvicorn   # noqa: F401
        import httpx     # noqa: F401
        return True
    except ImportError:
        return False


def _confirm_pip_install(skip_prompt: bool) -> bool:
    print(textwrap.dedent("""\
      [1/3] This installs the recorder daemon's deps in the current env:
              fastapi, uvicorn, httpx   (~15 MB)
    """))
    if skip_prompt:
        return True
    try:
        ans = input("        Install now? [Y/n] ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print()
        return False
    return ans in {"", "y", "yes"}


def _pip_install_local_extra() -> int:
    cmd = [sys.executable, "-m", "pip", "install", "inferroute[local]"]
    print(f"        Running: {' '.join(cmd)}")
    return subprocess.call(cmd)


# ----- Step 2 helpers (service install) --------------------------------------

SYSTEMD_UNIT_TEMPLATE = """\
[Unit]
Description=inferroute-local daemon (Claude Code traffic recorder on :5005)
{marker}
After=network-online.target
Wants=network-online.target
# Crash-loop guard: give up after 5 failed starts in 60s instead of restarting
# forever (the henry-ft 266k-restarts failure). A clean exit-3 "deps missing"
# from the daemon also trips this, so a broken install fails fast and visibly.
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart={daemon_path} --port 5005
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
"""

DROPIN_TEMPLATE = """\
# Written by `ir add recording`. Sets the record level without touching the
# base unit, so a hand-crafted base unit is preserved. Remove via `ir remove
# recording`.
[Service]
Environment=INFERROUTE_RECORD_LEVEL={level}
"""


def _install_user_service(level: str) -> int:
    sysname = platform.system()
    if sysname == "Linux":
        return _install_systemd_unit(level)
    if sysname == "Darwin":
        return _install_launchd_plist(level)
    print(f"        Unsupported platform for auto-start: {sysname}")
    print(f"        Run: INFERROUTE_RECORD_LEVEL={level} inferroute-daemon")
    return 1


def _install_systemd_unit(level: str) -> int:
    # Fall back to the conventional path: a non-interactive/systemd environment
    # often lacks ~/.local/bin on PATH, but that's where the console script lives.
    daemon_path = _which("inferroute-daemon") or str(Path.home() / ".local/bin/inferroute-daemon")
    if not Path(daemon_path).exists() and _which("inferroute-daemon") is None:
        print("        ✗ `inferroute-daemon` not found (PATH or ~/.local/bin). Pip install may not have linked the script.")
        return 1
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    unit_path = unit_dir / SERVICE_NAME
    unit_dir.mkdir(parents=True, exist_ok=True)

    # Unit-writing policy:
    #   • no unit yet            → write ours (marked).
    #   • OUR managed unit        → REGENERATE it, so a stale/broken ExecStart
    #     (e.g. an old `serve` template) is fixed on upgrade instead of being
    #     preserved forever (the bug that crash-looped henry-ft 266k times).
    #   • hand-crafted (no marker)→ never touch it. The record level rides in a
    #     drop-in that layers on top of whatever base exists.
    desired = SYSTEMD_UNIT_TEMPLATE.format(daemon_path=daemon_path, marker=UNIT_MARKER)
    existing = unit_path.read_text() if unit_path.exists() else None
    created_base = False  # True ⇒ we should (re-)enable the unit below
    if existing is None:
        unit_path.write_text(desired)
        created_base = True
    elif UNIT_MARKER in existing:
        if existing != desired:
            unit_path.write_text(desired)
            print(f"  [2/3] Regenerated managed unit {unit_path} (was stale).")
        created_base = True  # ours → safe (idempotent) to ensure enabled
    else:
        print(f"  [2/3] Using existing hand-crafted unit {unit_path} (preserved).")

    dropin_dir = unit_dir / f"{SERVICE_NAME}.d"
    dropin_dir.mkdir(parents=True, exist_ok=True)
    (dropin_dir / DROPIN_NAME).write_text(DROPIN_TEMPLATE.format(level=level))

    cmds = [["systemctl", "--user", "daemon-reload"]]
    if created_base:
        cmds.append(["systemctl", "--user", "enable", SERVICE_NAME])
    cmds.append(["systemctl", "--user", "restart", SERVICE_NAME])
    for cmd in cmds:
        rc = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if rc != 0:
            print(f"        ✗ `{' '.join(cmd)}` failed (exit {rc}).")
            return rc
    where = "installed" if created_base else "updated"
    print(f"  [2/3] Recorder {where} (level={level} via drop-in)")
    print(f"        Running on {LOCAL_BASE_URL} (systemctl --user status {SERVICE_NAME})")
    return 0


def _install_launchd_plist(level: str) -> int:
    daemon_path = _which("inferroute-daemon") or str(Path.home() / ".local/bin/inferroute-daemon")
    if not Path(daemon_path).exists() and _which("inferroute-daemon") is None:
        print("        ✗ `inferroute-daemon` not found (PATH or ~/.local/bin).")
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
            <string>--port</string><string>5005</string>
          </array>
          <key>EnvironmentVariables</key>
          <dict><key>INFERROUTE_RECORD_LEVEL</key><string>{level}</string></dict>
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
    print(f"  [2/3] Recorder installed at {plist_path} (level={level})")
    print(f"        Running on {LOCAL_BASE_URL}")
    return 0


def _which(name: str) -> str | None:
    from shutil import which
    return which(name)


# ----- Step 3 helpers (shell rc) ---------------------------------------------
#
# We DO NOT write the shell rc anymore. Writing a global
# `export ANTHROPIC_BASE_URL=http://localhost:5005` made EVERY `claude` depend on
# the daemon being up — when it wasn't (crash loop, upgrade, port conflict),
# native Claude Code broke with no fallback. The `ir` launcher injects the base
# URL per-process instead (launch.py), so native `claude` is never endangered.
#
# `_detect_shell` and `SHELL_RC_FILES` are retained because `ir remove recording`
# still uses them to STRIP any legacy block a prior version (or hand edit) wrote.


def _detect_shell() -> str:
    shell = os.environ.get("SHELL", "")
    return Path(shell).name or "bash"


def _print_no_shell_edit_note() -> None:
    print("  [3/3] Shell rc: left untouched (by design).")
    print("        Native `claude` keeps talking to Anthropic directly; only `ir`")
    print("        launches flow through the recorder (per-process, never global).")


def _print_done_banner(level: str) -> None:
    print()
    if level == "off":
        print("  Done. Cost-only daemon is ON (recording corpus: OFF).")
        print("  Your real session cost now shows in Claude Code's status line.")
        print("  Nothing else is stored. Manage:")
        print("    ir add recording --level full   # also record, to train a router")
        print("    ir remove recording             # stop the daemon entirely")
    else:
        print(f"  Done. Local recording is ON (level: {level}).")
        print("  The corpus stays in ~/.inferroute on this machine; inferroute keeps")
        print("  only a one-way hash of each turn (a fingerprint, never the text).")
        print("  Verify / manage:")
        print("    ir data show     # what's been recorded (counts, models, size)")
        print("    ir data wipe     # delete it all")
        print("    ir remove recording")
    print()
