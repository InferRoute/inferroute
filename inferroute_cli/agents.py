"""Agent adapters for the confidential lane: how each coding agent is pointed at the
per-session sealed endpoint on 127.0.0.1 (and, on the plain lane, at api.inferroute.ai).

Dialects (Henry, 2026-09-12: native formats end to end, translate only where the agent cannot):
the enclaves speak OpenAI Chat Completions. Claude Code speaks only Anthropic Messages, so it gets
the local endpoint's translated `/v1/messages`. Pi and OpenCode speak OpenAI natively, so they are
configured in that mode and hit `/v1/chat/completions`, sealed as-is — no translation anywhere.

  claude    Claude Code — env (ANTHROPIC_BASE_URL/AUTH_TOKEN) + `--model`; status line via --settings.
  pi        Pi (pi-coding-agent) — a per-launch config dir (PI_CODING_AGENT_DIR) holding a
            models.json that declares an `inferroute` provider (openai-completions) on the local endpoint. The user's
            own ~/.pi/agent (settings, auth, extensions, skills, themes, prompts) is mirrored in
            by symlink and their sessions dir is reused, so nothing of theirs is touched or lost.
  opencode  OpenCode — OPENCODE_CONFIG_CONTENT (inline JSON) declaring an `inferroute` provider
            through the bundled @ai-sdk/openai-compatible on the local endpoint; session sharing is
            disabled on the confidential lane (a share would upload the transcript).
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

AGENTS = ("claude", "pi", "opencode", "goose")
INSTALL_HINT = {
    "goose": "Goose is an open-source agent from https://github.com/block/goose — one way: `pipx install goose-ai`",
    "pi": "Pi is an open-source agent: `npm install -g @earendil-works/pi-coding-agent` (https://pi.dev)",
    "opencode": "OpenCode is an open-source agent: `npm install -g opencode-ai` (https://opencode.ai)",
}


# ────────────────────── clipboard preflight ──────────────────────
# Terminal agents copy through a system clipboard helper. When none is installed they fall
# back to an OSC 52 terminal escape, which most terminals ignore — so the agent reports
# "copied to clipboard" and the paste is empty. That looks like an agent bug and isn't one.
# We detect it and name the one package that fixes it. We never install anything ourselves:
# it needs root, and silently touching a user's system packages is not ours to do.

CLIPBOARD_TOOLS = ("wl-copy", "xclip", "xsel", "pbcopy", "termux-clipboard-set")
CLIPBOARD_PACKAGE = {"wayland": "wl-clipboard", "x11": "xclip"}


def clipboard_gap() -> str | None:
    """Return the display server whose clipboard helper is missing, or None if fine."""
    if sys.platform == "darwin" or any(shutil.which(t) for t in CLIPBOARD_TOOLS):
        return None
    if os.environ.get("WAYLAND_DISPLAY"):
        return "wayland"
    if os.environ.get("DISPLAY"):
        return "x11"
    return None  # no display at all: nothing on this machine to copy into


def clipboard_install_cmd(kind: str) -> list[str] | None:
    """The install command for this distro, or None if we don't recognise the package manager."""
    pkg = CLIPBOARD_PACKAGE[kind]
    for mgr, argv in (("apt-get", ["apt-get", "install", "-y", pkg]),
                      ("dnf", ["dnf", "install", "-y", pkg]),
                      ("pacman", ["pacman", "-S", "--noconfirm", pkg]),
                      ("zypper", ["zypper", "install", "-y", pkg]),
                      ("apk", ["apk", "add", pkg])):
        if shutil.which(mgr):
            return ["sudo", *argv]
    return None


def _clipboard_marker() -> Path:
    home = Path(os.environ.get("INFERROUTE_HOME") or (Path.home() / ".inferroute"))
    return home / ".clipboard-notice"


def warn_clipboard_once() -> None:
    """Print the notice at most once per machine, so it informs without nagging."""
    kind = clipboard_gap()
    if not kind:
        return
    marker = _clipboard_marker()
    if marker.exists():
        return
    cmd = clipboard_install_cmd(kind)
    fix = "ir fix-clipboard" if cmd else f"install {CLIPBOARD_PACKAGE[kind]} with your package manager"
    sys.stderr.write(
        f"\n \033[33m•\033[0m no clipboard helper found, so copying from the agent will silently do nothing.\n"
        f"   run `{fix}` once to fix it. (shown once)\n\n")
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("shown\n")
    except OSError:
        pass


def fix_clipboard() -> int:
    """`ir fix-clipboard` — install the missing helper, with the user's own sudo prompt."""
    kind = clipboard_gap()
    if not kind:
        print(" ✓ a clipboard helper is already available.")
        return 0
    cmd = clipboard_install_cmd(kind)
    if not cmd:
        print(f" install `{CLIPBOARD_PACKAGE[kind]}` with your package manager, then re-run the agent.")
        return 1
    print(f" installing {CLIPBOARD_PACKAGE[kind]} ({kind} session): {' '.join(cmd)}")
    import subprocess
    rc = subprocess.call(cmd)
    if rc == 0:
        _clipboard_marker().unlink(missing_ok=True)
        print(" ✓ done — copy in the agent will now reach your clipboard.")
    return rc


def binary_for(agent: str) -> str:
    warn_clipboard_once()
    if agent == "claude":
        from .launch import _require_claude_binary
        return _require_claude_binary()
    b = shutil.which(agent)
    if not b:
        sys.stderr.write(f"\n ❌ `{agent}` not found on PATH.\n    {INSTALL_HINT.get(agent, '')}\n\n")
        sys.exit(127)
    return b


# ───────────────────────── Pi ─────────────────────────

def _price(alias) -> dict:
    """Catalog USD/1M for the standard lane ({input, cached, output}); zeros if unknown."""
    try:
        from . import models as models_mod
        row = next((m for m in models_mod._rows() if m.get("short") == alias.short), None) or {}
        return dict(row.get("standard") or {})
    except Exception:
        return {}


def pi_models_json(base_url: str, api_key: str, alias, upstream_name: str, headers: dict | None = None,
                   existing: dict | None = None) -> dict:
    """A models.json declaring the `inferroute` provider, merged over the user's own file."""
    doc = dict(existing or {})
    providers = dict(doc.get("providers") or {})
    pr = _price(alias)
    prov: dict = {
        "name": "InferRoute", "baseUrl": base_url.rstrip("/") + "/v1", "api": "openai-completions", "apiKey": api_key,
        # open-weight reasoning models return `reasoning_content`; Pi's deepseek thinking format reads it
        "compat": {"thinkingFormat": "deepseek", "supportsDeveloperRole": False, "maxTokensField": "max_tokens"},
        "models": [{"id": alias.short, "name": upstream_name, "reasoning": True, "input": ["text", "image"],
                    "cost": {"input": pr.get("input", 0), "output": pr.get("output", 0),
                             "cacheRead": pr.get("cached", 0), "cacheWrite": pr.get("input", 0)},
                    "contextWindow": 262144, "maxTokens": 32768}],
    }
    if headers:
        prov["headers"] = headers
    providers["inferroute"] = prov
    doc["providers"] = providers
    return doc


def pi_config_dir(base_url: str, api_key: str, alias, upstream_name: str, headers: dict | None = None) -> Path:
    """The PI_CODING_AGENT_DIR for an `ir pi` launch: a STABLE ir-owned dir (~/.inferroute/pi-agent)
    re-populated on every launch with symlinks to the user's ~/.pi/agent entries (settings, auth,
    extensions, skills, themes, prompts, sessions — all theirs, untouched) plus a merged
    models.json. Stable so Pi's own downloads (its `bin/` with fd and ripgrep) persist across
    launches instead of being fetched every time (Henry saw that on each `ir pi`)."""
    user_dir = Path(os.environ.get("PI_CODING_AGENT_DIR") or (Path.home() / ".pi" / "agent"))
    d = Path(os.environ.get("INFERROUTE_HOME") or (Path.home() / ".inferroute")) / "pi-agent"
    d.mkdir(parents=True, exist_ok=True)
    for entry in d.iterdir():                      # drop last launch's links; keep real dirs (bin/)
        if entry.is_symlink() or entry.name == "models.json":
            entry.unlink()
    existing = None
    if user_dir.is_dir() and user_dir.resolve() != d.resolve():
        for entry in user_dir.iterdir():
            if entry.name == "models.json":
                try:
                    existing = json.loads(entry.read_text())
                except (OSError, ValueError):
                    existing = None
                continue
            if (d / entry.name).exists():
                continue                            # e.g. our persistent bin/ when the user has none
            try:
                os.symlink(entry, d / entry.name)
            except OSError:
                pass
    (d / "models.json").write_text(json.dumps(pi_models_json(base_url, api_key, alias, upstream_name, headers, existing), indent=1))
    (d / "sessions").mkdir(exist_ok=True)
    (d / "bin").mkdir(exist_ok=True)
    return d


def pi_env_argv(binary: str, env: dict, passthrough: list[str], *, base_url: str, api_key: str, alias, upstream_name: str,
                headers: dict | None = None) -> list[str]:
    cfg = pi_config_dir(base_url, api_key, alias, upstream_name, headers)
    env["PI_CODING_AGENT_DIR"] = str(cfg)
    env.setdefault("PI_TELEMETRY", "0")
    return [binary, "--provider", "inferroute", "--model", alias.short, *passthrough]


# ───────────────────────── OpenCode ─────────────────────────

def opencode_config(base_url: str, api_key: str, alias, upstream_name: str, headers: dict | None = None,
                    confidential: bool = True) -> dict:
    options: dict = {"baseURL": base_url.rstrip("/") + "/v1", "apiKey": api_key}
    pr = _price(alias)
    if headers:
        options["headers"] = headers
    cfg: dict = {
        "$schema": "https://opencode.ai/config.json",
        "provider": {"inferroute": {"npm": "@ai-sdk/openai-compatible", "name": "InferRoute", "options": options,
                                    "models": {alias.short: {"name": upstream_name, "limit": {"context": 262144, "output": 32768},
                                                             "cost": {"input": pr.get("input", 0), "output": pr.get("output", 0),
                                                                      "cache_read": pr.get("cached", 0), "cache_write": pr.get("input", 0)}}}}},
        "model": f"inferroute/{alias.short}",
        "small_model": f"inferroute/{alias.short}",
    }
    if confidential:
        cfg["share"] = "disabled"          # a share would upload the transcript to opencode.ai
    return cfg


def opencode_env_argv(binary: str, env: dict, passthrough: list[str], *, base_url: str, api_key: str, alias, upstream_name: str,
                      headers: dict | None = None, confidential: bool = True) -> list[str]:
    env["OPENCODE_CONFIG_CONTENT"] = json.dumps(opencode_config(base_url, api_key, alias, upstream_name, headers, confidential))
    return [binary, *passthrough]


# ───────────────────────── Goose ─────────────────────────

def goose_env_argv(binary: str, env: dict, passthrough: list[str], *, base_url: str, api_key: str, alias) -> list[str]:
    """Goose speaks OpenAI natively: point its openai provider at the sealed local endpoint."""
    from .launch import _write_goose_config
    env["OPENAI_BASE_URL"] = base_url
    env["OPENAI_API_KEY"] = api_key
    env["GOOSE_PROVIDER"] = "openai"
    env["GOOSE_MODEL"] = alias.short
    _write_goose_config(alias.short, base_url, api_key)
    # `goose session` (interactive) by default; a leading `run`/`session` from the user is honoured
    # so `ir goose run -t "…" --no-session` works headless like plain goose.
    if passthrough and passthrough[0] in ("run", "session"):
        return [binary, *passthrough]
    return [binary, "session", *passthrough]
