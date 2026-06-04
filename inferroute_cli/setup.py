"""`ir setup` — one-shot guided onboarding for first-time users.

Two steps, in order:
  1. Log in (paste your inferroute key) — skipped if already logged in.
  2. Optionally enable local recording (the same prompt as `ir add recording`;
     choosing "no" is a clean no-op).

It's just `ir login` + `ir add recording` wrapped in one friendly flow, so a new
user runs a single command after install. After setup, start any time with `ir`.
"""
from __future__ import annotations

from . import config, login as login_mod


def run(rest=None) -> int:
    print()
    print("  Welcome to inferroute — let's get you set up.")
    print("  ─────────────────────────────────────────────")

    # ── Step 1: authentication ────────────────────────────────────────
    creds = config.load()
    if creds.is_valid:
        print("\n  [1/2] Already logged in — skipping.")
        print("        (Run `ir login` to switch keys.)")
    else:
        print("\n  [1/2] Log in")
        rc = login_mod.run(None)
        if rc != 0:
            print("\n  Setup paused — login didn't complete.")
            print("  Re-run `ir setup` once you have your key from https://inferroute.ai")
            return rc

    # ── Step 2: optional local recording ──────────────────────────────
    print("\n  [2/2] Optional — local recording (fully private, on-device)")
    from . import add as add_mod
    # Prompts full / minimal / no; "no" installs nothing. We don't gate setup on
    # its exit code — recording is optional, so a skip or failure here is fine.
    add_mod.cmd_add(["recording"])

    # ── Done ──────────────────────────────────────────────────────────
    print()
    print("  ✓ You're all set. Start any time with:")
    print("      ir                   # pick a model, then launch")
    print("      ir --model minimax   # or pin one directly")
    print()
    return 0
