"""`ir pi` on the confidential lane: Pi launched so that the only code running inside it is ours, its
model requests can only reach this session's local sealed endpoint, and what this device verified is
shown in Pi's own UI rather than relayed by the model.

What the launch sets, and why (each measured on Pi 0.84.1, see the attested-agent log):

  -ne -e <ours>      extension discovery off: the user's global, settings-listed and project-local
                     extensions never load into a process that holds the plaintext. Ours loads.
  -na                project-local Pi files (settings, skills, prompts) are ignored.
  own config dir     a fresh PI_CODING_AGENT_DIR declaring one provider. The user's settings, auth and
                     models are not mirrored in; only their sessions are shared.
  no_proxy/NO_PROXY  loopback is never proxied. Pi routes all HTTP through the proxy variables, so an
                     HTTP_PROXY in the user's environment would otherwise receive the plaintext hop to
                     127.0.0.1. Both spellings, because the lowercase one takes precedence.
  PI_OFFLINE         no startup network activity (update checks, tool downloads).
  --tools            an allowlist without a shell until the agent's network is confined.

The extension refuses, at request time, any model request that is not addressed to this session's
endpoint, or that would be sent while the session's verdict is anything but verified.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from . import agents

EXTENSION = Path(__file__).resolve().parent / "pi_attested" / "ir-attested.ts"
PROVIDER = "inferroute"
TOOLS = ("read", "edit", "write", "grep", "find", "ls")
LOOPBACK = ("127.0.0.1", "localhost", "::1")
# Passthrough flags that would load other code, change where requests go, or widen the tool set.
REFUSED_FLAGS = {
    "-e": "loads another extension", "--extension": "loads another extension",
    "--provider": "changes where model requests go", "--api-key": "changes where model requests go",
    "--models": "adds models outside the enclave",
    "-t": "changes the tool allowlist", "--tools": "changes the tool allowlist",
    "-a": "trusts project-local Pi files", "--approve": "trusts project-local Pi files",
}
_HELPERS = ("fd", "rg")


class Refused(ValueError):
    """The launch cannot be made attested as asked; the message says which flag and why."""


def check_passthrough(passthrough: list[str]) -> None:
    for arg in passthrough:
        flag = arg.split("=", 1)[0]
        if flag in REFUSED_FLAGS:
            raise Refused(f"`{flag}` is not accepted on the attested lane: it {REFUSED_FLAGS[flag]}. "
                          "Use `ir pi --plain` for an unattested session.")


def _with_loopback(value: str | None) -> str:
    have = [h.strip() for h in (value or "").split(",") if h.strip()]
    return ",".join(list(LOOPBACK) + [h for h in have if h not in LOOPBACK])


def config_dir(base_url: str, api_key: str, alias, upstream_name: str, headers: dict | None = None) -> Path:
    """A stable ir-owned Pi config dir, rewritten on every launch. Keeps `bin/` (Pi's helper binaries)
    so offline launches still have them; shares the user's sessions; mirrors nothing else."""
    user_dir = Path(os.environ.get("PI_CODING_AGENT_DIR") or (Path.home() / ".pi" / "agent"))
    home = Path(os.environ.get("INFERROUTE_HOME") or (Path.home() / ".inferroute"))
    d = home / "pi-attested"
    d.mkdir(parents=True, exist_ok=True)
    for entry in d.iterdir():
        if entry.is_symlink() or entry.name in ("models.json", "settings.json"):
            entry.unlink()
    doc = agents.pi_models_json(base_url, api_key, alias, upstream_name, headers, existing=None)
    (d / "models.json").write_text(json.dumps(doc, indent=1))
    (d / "settings.json").write_text(json.dumps({"enableInstallTelemetry": False, "defaultProjectTrust": "never"}, indent=1))
    sessions = d / "sessions"
    if not sessions.exists():
        if (user_dir / "sessions").is_dir() and user_dir.resolve() != d.resolve():
            os.symlink(user_dir / "sessions", sessions)
        else:
            sessions.mkdir()
    _provision_helpers(d / "bin", [user_dir / "bin", home / "pi-agent" / "bin"])
    return d


def _provision_helpers(bin_dir: Path, sources: list[Path]) -> None:
    bin_dir.mkdir(exist_ok=True)
    for name in _HELPERS:
        if (bin_dir / name).exists():
            continue
        for src in sources:
            if (src / name).is_file() and os.access(src / name, os.X_OK):
                shutil.copy2(src / name, bin_dir / name)
                break


def env_argv(binary: str, env: dict, passthrough: list[str], *, base_url: str, api_key: str, alias, upstream_name: str,
             headers: dict | None = None) -> list[str]:
    check_passthrough(passthrough)
    cfg = config_dir(base_url, api_key, alias, upstream_name, headers)
    env["PI_CODING_AGENT_DIR"] = str(cfg)
    env["PI_OFFLINE"] = "1"
    env["PI_SKIP_VERSION_CHECK"] = "1"
    env["PI_TELEMETRY"] = "0"
    env["IR_ATTESTED_ENDPOINT"] = base_url.rstrip("/")
    env["IR_ATTESTED_PROVIDER"] = PROVIDER
    env["IR_ATTESTED_TOOLS"] = ",".join(TOOLS)
    for name in ("no_proxy", "NO_PROXY"):
        env[name] = _with_loopback(env.get("no_proxy") if env.get("no_proxy") is not None else env.get("NO_PROXY"))
    return [binary, "-ne", "-e", str(EXTENSION), "-na", "--tools", ",".join(TOOLS),
            "--provider", PROVIDER, "--model", alias.short, "--models", f"{PROVIDER}/{alias.short}", *passthrough]
