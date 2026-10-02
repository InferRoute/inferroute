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

AGENTS = ("claude", "pi", "opencode", "goose", "openhands", "codewhale")
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


def find_agent(agent: str) -> str | None:
    """Where the agent's program is, whether or not the PATH we inherited mentions it.

    A page started from a desktop icon, a systemd unit, or a login shell that never sourced nvm has a PATH
    that a terminal does not: on 20 Sep Probant home refused every session with "Pi could not be found",
    and the advice it could honestly give was "start it from a terminal where `pi --version` works" — which
    is precisely what a person using a browser page should never have to do. So look where these programs
    actually install, not only where this process happens to be able to see.
    """
    override = os.environ.get(f"IR_{agent.upper()}_BIN")
    if override and os.access(override, os.X_OK):
        return override
    found = shutil.which(agent)
    if found:
        return found
    home = Path.home()
    roots = [home / ".local" / "bin", Path("/usr/local/bin"), Path("/opt/homebrew/bin"),
             home / ".bun" / "bin", home / ".npm-global" / "bin", home / "node_modules" / ".bin"]
    if agent == "pi":
        # The Probant installer keeps a pinned Pi release in an app-managed prefix so it
        # does not depend on a system-wide npm install. A home server launched directly
        # (rather than through the `ir` wrapper) must still find that binary.
        managed_pi = home / ".local" / "share"
        roots = sorted((d / "bin" for d in managed_pi.glob("pi-test-*") if d.is_dir()), reverse=True) + roots
    nvm = Path(os.environ.get("NVM_DIR") or (home / ".nvm")) / "versions" / "node"
    if nvm.is_dir():
        # Newest node first, so a stale old install does not win over the one the person uses.
        roots = sorted((d / "bin" for d in nvm.iterdir() if d.is_dir()), reverse=True) + roots
    for d in roots:
        candidate = d / agent
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def put_agent_on_path(binary: str, env: dict) -> dict:
    """Ensure the child can run the agent it was given.

    These agents are node scripts whose shebang is `/usr/bin/env node`. Found by absolute path but started
    with a service's PATH, `pi` picks up whatever old node sits in /usr/bin and dies with a syntax error
    nobody can act on (measured 20 Sep: node 18 against a build needing 22). The node it was installed with
    sits beside it — in the directory the command was FOUND in, never where its symlink points: these bins
    are symlinks into lib/node_modules, and following them lands somewhere with no node at all.
    """
    d = os.path.dirname(os.path.abspath(binary))
    if d and d not in env.get("PATH", "").split(os.pathsep):
        env["PATH"] = d + os.pathsep + env.get("PATH", "")
    return env


def binary_for(agent: str) -> str:
    warn_clipboard_once()
    if agent == "claude":
        from .launch import _require_claude_binary
        return _require_claude_binary()
    b = find_agent(agent)
    if not b:
        sys.stderr.write(f"\n ❌ `{agent}` is not installed on this computer (PATH and the usual install "
                         f"directories were checked).\n    {INSTALL_HINT.get(agent, '')}\n\n")
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


# Descriptions for the picker. Kept here beside AGENTS so a new agent cannot be added without one.
_AGENT_DESC = {
    "claude": "Anthropic's Claude Code — the default",
    "pi": "Pi — attested tool use, used by Probant",
    "opencode": "OpenCode — open-source terminal agent",
    "goose": "Goose — Block's agent (CLI here; `ir goose-cowork` for the desktop app)",
    "openhands": "OpenHands — autonomous multi-step agent",
    "codewhale": "CodeWhale — terminal agent, open models first",
}


def installed() -> list[str]:
    """The agents actually present on this machine, in AGENTS order."""
    return [a for a in AGENTS if find_agent(a)]


def agent_options() -> list[tuple]:
    """Picker rows for the installed agents: (id, badge, colour, name, desc) — the shape choose.pick
    takes, so the agent step looks like the model step rather than inventing a second idiom."""
    colours = {"claude": "#d97757", "pi": "#7aa2f7", "opencode": "#9ece6a", "goose": "#e0af68"}
    return [(a, a.upper(), colours.get(a, "#9ece6a"), a.replace("opencode", "OpenCode").capitalize()
             if a != "opencode" else "OpenCode", _AGENT_DESC.get(a, ""))
            for a in installed()]


def openhands_env_argv(binary: str, env: dict, passthrough: list[str], *, base_url: str, api_key: str,
                       alias) -> list[str]:
    """OpenHands reaches its model through LiteLLM, so the model name carries the dialect.

    `openai/<model>` tells LiteLLM to speak OpenAI chat-completions, which is what the sealed endpoint
    serves, and LiteLLM appends `/chat/completions` to the base URL — hence the `/v1`. The `LLM_*`
    variables are only consulted when `--override-with-envs` is passed, so passing it is not optional:
    without it OpenHands would quietly keep whatever provider the user configured before, which on this
    lane means the session would not be sealed at all.
    """
    env["LLM_MODEL"] = f"openai/{alias.short}"
    env["LLM_BASE_URL"] = base_url.rstrip("/") + "/v1"
    env["LLM_API_KEY"] = api_key
    return [binary, "--override-with-envs", *passthrough]


def _codewhale_set_key(binary: str, api_key: str) -> None:
    """Hand CodeWhale the session key on STDIN.

    Measured, not assumed: with OPENAI_API_KEY in the environment it sends no Authorization header at all
    (the request arrives with an empty auth), so the sealed endpoint would 401 every turn. `--api-key`
    works but puts the token in the process table — CodeWhale's own help calls that "discouraged". `auth
    set --api-key-stdin` is the path that neither leaks nor silently drops it; the key lands in
    ~/.codewhale/secrets/ and is replaced by the next launch.
    """
    import subprocess
    try:
        subprocess.run([binary, "auth", "set", "--provider", "openai", "--api-key-stdin"],
                       input=api_key, text=True, capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        pass          # the launch continues and fails loudly at the endpoint rather than silently here


def codewhale_env_argv(binary: str, env: dict, passthrough: list[str], *, base_url: str, api_key: str,
                       alias) -> list[str]:
    """CodeWhale through its built-in `openai` provider, pointed by environment.

    Its docs describe a `[providers.<name>]` table for custom gateways; the real binary (0.10.0) answers
    `--provider inferroute` with "configured custom providers are accepted only by exec and fleet", so
    that design does not work at all. `--provider openai` with OPENAI_BASE_URL resolves cleanly.

    `--telemetry false` because CodeWhale reports usage to PostHog by default, and we suppress an agent's
    own telemetry on this lane exactly as we do for Pi.
    """
    _codewhale_set_key(binary, api_key)
    env["OPENAI_BASE_URL"] = base_url.rstrip("/") + "/v1"
    return [binary, "--provider", "openai", "--model", alias.short, "--telemetry", "false", *passthrough]
