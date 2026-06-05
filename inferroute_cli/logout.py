"""`ir logout` — remove the saved inferroute API key."""

from __future__ import annotations

import os
import sys

from . import config


def _mask(key: str) -> str:
    if not key:
        return ""
    if len(key) <= 10:
        return key[:2] + "…"
    return f"{key[:6]}…{key[-4:]}"


def run(args=None) -> int:
    print()
    path = config.CREDS_FILE
    existed = path.exists()

    # Pull the stored key (file only, not env) just for a masked confirmation.
    stored = ""
    if existed:
        try:
            stored = config._parse(path).get("INFERROUTE_API_KEY", "")
        except Exception:
            stored = ""

    if existed:
        try:
            path.unlink()
        except OSError as e:
            sys.stderr.write(f"  ✗ couldn't remove {path}: {e}\n")
            return 1
        suffix = f" ({_mask(stored)})" if stored else ""
        print(f"  ✓ logged out — removed {path}{suffix}")
    else:
        print("  You're not logged in (no saved key).")

    # The file is gone, but an env var still authenticates and takes precedence,
    # so warn — otherwise `ir status` still working looks like a failed logout.
    if os.environ.get("INFERROUTE_API_KEY"):
        print()
        sys.stderr.write(
            "  ⚠ INFERROUTE_API_KEY is still set in your environment — it overrides\n"
            "    the file, so you're effectively still logged in. To fully log out:\n"
            "        unset INFERROUTE_API_KEY\n"
        )

    print()
    print("  Log back in anytime with `ir login`.")
    return 0
