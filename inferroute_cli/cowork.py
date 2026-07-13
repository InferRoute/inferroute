"""`ir cowork` — InferRoute's everyday-work surface, powered by goose.

goose (https://github.com/block/goose, Apache-2.0) is an open-source agent with
a desktop app *and* a CLI. `ir cowork` wires it to InferRoute and launches it:

  • provider  → anthropic (goose speaks the Anthropic Messages API, like Claude Code)
  • routing   → the on-device recorder daemon when it's running, else the cloud
  • key       → your saved inferroute key
  • tag       → x-inferroute-client: cowork  (so the dashboard can attribute it)

Why this is cheap and stable:
  • Config-only — we do NOT fork goose. We own a small set of goose config/secret
    keys and re-assert them on every launch, so a goose update can't drift us out
    of sync (and goose's CLI is a pinned binary you update with `goose update`).
  • goose reads these from files, so the desktop app (launched from the menu) and
    the CLI both pick them up.

The desktop app is the point-and-click way to use InferRoute for everyday work —
research, writing, files — no terminal needed. The CLI is the same engine in the
terminal.
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from . import config

GOOSE_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")) / "goose"
CONFIG_FILE = GOOSE_DIR / "config.yaml"
SECRETS_FILE = GOOSE_DIR / "secrets.yaml"
CLIENT_TAG = "cowork"
GOOSE_DESKTOP_DOWNLOAD = "https://block.github.io/goose/"
# Homebrew cask for Goose Desktop on macOS (best-effort auto-install; we fall
# back to the download page if brew is absent or the cask name is off).
GOOSE_BREW_CASK = "block-goose"


# ── small YAML helpers (PyYAML) ──────────────────────────────────────────────
def _load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        import yaml

        data = yaml.safe_load(path.read_text()) or {}
        return data if isinstance(data, dict) else {}
    except Exception:
        # A malformed/locked file shouldn't crash the launcher — start fresh,
        # but don't clobber: only merge our keys in _write_merged below.
        return {}


def _write_merged(path: Path, updates: dict, *, secret: bool) -> None:
    """Merge ``updates`` into the YAML at ``path``, preserving the user's other
    keys. Secret files are written 0600."""
    import yaml

    data = _load_yaml(path)
    data.update(updates)
    path.parent.mkdir(parents=True, exist_ok=True)
    if secret:
        os.chmod(path.parent, stat.S_IRWXU)
    path.write_text(yaml.safe_dump(data, default_flow_style=False, sort_keys=False))
    if secret:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


# ── resolution ───────────────────────────────────────────────────────────────
def _default_model() -> str:
    """A balanced model InferRoute serves. Mirrors the `ir` default agent model."""
    try:
        from . import models

        alias = models.get("kimi")
        if alias is not None:
            return alias.short
    except Exception:
        pass
    return "kimi-k2.6"


def _anthropic_host(creds: config.Credentials) -> str:
    """Route through the on-device recorder daemon when it's up (records + tags
    the session, then forwards to the cloud), else talk to the cloud directly."""
    try:
        from . import launch

        return launch._recording_daemon_url() or creds.api_url
    except Exception:
        return creds.api_url


def _goose_desktop() -> str | None:
    """Path to the Goose **Desktop** app/binary for this platform, or None.

    cowork is desktop-only — we never touch the goose CLI. On macOS we return the
    `.app` bundle path (launched via `open`); elsewhere the executable.
    """
    home = Path.home()
    if sys.platform == "darwin":
        for app in (Path("/Applications/Goose.app"), home / "Applications" / "Goose.app"):
            if app.exists():
                return str(app)
        return None
    if sys.platform.startswith("win"):
        la = os.environ.get("LOCALAPPDATA", "")
        cands = [Path(la) / "Programs" / "goose" / "Goose.exe"] if la else []
        return next((str(p) for p in cands if p.exists()), None)
    # linux
    cands = [home / ".local" / "opt" / "goose" / "Goose", Path("/usr/lib/goose/Goose")]
    w = shutil.which("Goose") or shutil.which("goose-desktop")
    if w:
        cands.insert(0, Path(w))
    return next((str(p) for p in cands if p.exists()), None)


def _launch_desktop(app: str, env: dict) -> bool:
    """Launch the Goose Desktop app. Returns True if it started.

    macOS GUI apps don't inherit our shell env, so we pass GOOSE_DISABLE_KEYRING
    through `open --env` (goose then reads secrets.yaml instead of the keyring).
    """
    try:
        if sys.platform == "darwin":
            subprocess.Popen(
                ["open", "--env", "GOOSE_DISABLE_KEYRING=true", app],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        elif sys.platform.startswith("win"):
            subprocess.Popen([app], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:  # linux — chrome-sandbox isn't setuid in a user-local install
            subprocess.Popen([app, "--no-sandbox"], env=env, start_new_session=True,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception as e:
        print(f"  ✗ couldn't launch Goose Desktop ({e}).")
        return False


# ── configure (idempotent, re-asserted every launch) ─────────────────────────
def configure(creds: config.Credentials, model: str | None = None) -> str:
    """Write InferRoute's goose config + secrets. Returns the routing host.

    Uses the OpenAI provider so Goose talks to /v1/chat/completions natively
    (no Anthropic↔OpenAI double-translation that mangles tool names).
    """
    model = model or _default_model()
    host = _anthropic_host(creds)  # reuse the same routing logic (daemon or cloud)

    _write_merged(
        CONFIG_FILE,
        {
            "GOOSE_PROVIDER": "openai",
            "GOOSE_MODEL": model,
            "OPENAI_BASE_URL": host,
            "active_provider": "openai",
            "providers": {
                "openai": {
                    "enabled": True,
                    "model": model,
                    "configured": True,
                }
            },
        },
        secret=False,
    )
    _write_merged(
        SECRETS_FILE,
        {
            "OPENAI_API_KEY": creds.api_key,
            "ANTHROPIC_API_KEY": creds.api_key,  # keep for backward compat
            "ANTHROPIC_CUSTOM_HEADERS": {"x-inferroute-client": CLIENT_TAG},
        },
        secret=True,
    )
    # goose stores secrets in the OS keyring by default; mgld-style headless boxes
    # (and many Linux desktops) have no working keyring, so point goose at its file
    # secret store. Set it for the GUI session too (Linux), so a menu-launched
    # desktop also reads secrets.yaml.
    if not sys.platform.startswith("win") and sys.platform != "darwin":
        envd = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")) / "environment.d"
        try:
            envd.mkdir(parents=True, exist_ok=True)
            (envd / "99-inferroute-goose.conf").write_text("GOOSE_DISABLE_KEYRING=true\n")
        except Exception:
            pass
    return host


def _launch_env() -> dict:
    env = dict(os.environ)
    env["GOOSE_DISABLE_KEYRING"] = "true"
    return env


def _ensure_desktop(assume_yes: bool) -> str | None:
    """Return the Goose Desktop path, installing it if needed. Desktop-ONLY —
    cowork never installs or launches the goose CLI.

    macOS with Homebrew: offer `brew install --cask block-goose` (best-effort).
    Otherwise (or on failure): point to the official download. Returns the app
    path once present, else None.
    """
    d = _goose_desktop()
    if d:
        return d

    print("\n  Goose Desktop isn't installed.")
    if sys.platform == "darwin" and shutil.which("brew"):
        go = assume_yes or input(
            f"  Install it now with Homebrew (brew install --cask {GOOSE_BREW_CASK})? [Y/n] "
        ).strip().lower() not in ("n", "no")
        if go:
            print("  Installing Goose Desktop…")
            try:
                subprocess.call(["brew", "install", "--cask", GOOSE_BREW_CASK])
            except Exception as e:  # pragma: no cover
                print(f"  ✗ brew install failed: {e}")
            d = _goose_desktop()
            if d:
                return d
            print("  ✗ Homebrew didn't complete the install.")

    print(f"  Get the desktop app:  {GOOSE_DESKTOP_DOWNLOAD}")
    if sys.platform == "darwin":
        try:
            subprocess.call(["open", GOOSE_DESKTOP_DOWNLOAD])  # open the download page
        except Exception:
            pass
    return None


# ── commands ─────────────────────────────────────────────────────────────────
def setup_cowork() -> int:
    """Called from `ir setup`: configure + point at the desktop app (no launch)."""
    creds = config.load()
    if not creds.is_valid:
        print("  Skipping cowork — log in first (`ir login`).")
        return 0
    host = configure(creds)
    routed = "the on-device recorder" if "localhost" in host else "InferRoute"
    print(f"\n  ✓ Cowork is wired to {routed}.")
    if _goose_desktop():
        print("      Launch the Goose Desktop app anytime, or run:  ir cowork")
    else:
        print(f"      Get the Goose Desktop app:  {GOOSE_DESKTOP_DOWNLOAD}")
        print("      Then run:  ir cowork")
    return 0


def cmd_cowork(rest: list[str]) -> int:
    """`ir cowork [--configure-only] [--model NAME]`.

    Desktop-only: wires goose to InferRoute and launches the Goose **Desktop**
    app, installing it if needed. cowork never installs or runs the goose CLI.
    """
    import argparse

    ap = argparse.ArgumentParser(prog="ir cowork", add_help=True)
    ap.add_argument("--configure-only", action="store_true", help="wire goose to InferRoute, don't launch")
    ap.add_argument("--model", default=None, help="model to pin (default: kimi)")
    ns, _ = ap.parse_known_args(rest)

    creds = config.load()
    if not creds.is_valid:
        sys.stderr.write("\n  Not logged in. Run `ir login` (or `ir setup`) first.\n\n")
        return 2

    model = None
    if ns.model:
        try:
            from . import models

            alias = models.get(ns.model)
            model = alias.short if alias is not None else ns.model
        except Exception:
            model = ns.model

    host = configure(creds, model=model)

    if ns.configure_only:
        print(f"  ✓ goose wired to InferRoute ({host}).")
        return 0

    desktop = _ensure_desktop(assume_yes=False)
    if not desktop:
        print("\n  Cowork uses the Goose Desktop app — install it (above), then run `ir cowork` again.")
        return 1

    print(f"  Launching Goose Desktop (InferRoute · {host})…")
    return 0 if _launch_desktop(desktop, _launch_env()) else 1
