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
             headers: dict | None = None, search_endpoint: str | None = None) -> list[str]:
    """`search_endpoint`: the loopback address of a running local search verifier; adds `prior_art_search`."""
    check_passthrough(passthrough)
    cfg = config_dir(base_url, api_key, alias, upstream_name, headers)
    tools = TOOLS + ((SEARCH_TOOL,) if search_endpoint else ())
    env["PI_CODING_AGENT_DIR"] = str(cfg)
    env["PI_OFFLINE"] = "1"
    env["PI_SKIP_VERSION_CHECK"] = "1"
    env["PI_TELEMETRY"] = "0"
    env["IR_ATTESTED_ENDPOINT"] = base_url.rstrip("/")
    env["IR_ATTESTED_PROVIDER"] = PROVIDER
    env["IR_ATTESTED_TOOLS"] = ",".join(tools)
    if search_endpoint:
        env["IR_SEARCH_ENDPOINT"] = search_endpoint.rstrip("/")
    else:
        env.pop("IR_SEARCH_ENDPOINT", None)
    for name in ("no_proxy", "NO_PROXY"):
        env[name] = _with_loopback(env.get("no_proxy") if env.get("no_proxy") is not None else env.get("NO_PROXY"))
    return [binary, "-ne", "-e", str(EXTENSION), "-na", "--tools", ",".join(tools),
            "--provider", PROVIDER, "--model", alias.short, "--models", f"{PROVIDER}/{alias.short}", *passthrough]


# ───────────────────────── the local search verifier ─────────────────────────
#
# A sibling of Pi, started by this launcher, so it stays outside anything applied to Pi's process tree.
# Configured by INFERROUTE_HOME/confidential/search.json:
#   {"python": ".../bin/python", "cwd": "<dir holding the verifier package>", "enclave": "<address>",
#    "expect_host_data": "<pinned container policy hash>", "expect_index": optional, "pins": optional test roots}

SEARCH_TOOL = "prior_art_search"
_SEARCH_PROXIES: list = []


def search_config_path() -> Path:
    return Path(os.environ.get("INFERROUTE_HOME") or (Path.home() / ".inferroute")) / "confidential" / "search.json"


def start_search_proxy(timeout: float = 30.0) -> str | None:
    """Start the verifier and return its loopback address, or None (the session then has no search tool)."""
    import select
    import subprocess
    import sys
    try:
        cfg = json.loads(search_config_path().read_text())
    except (OSError, ValueError):
        return None
    argv = [cfg["python"], "-m", "sealedresearch.search_verifier", "serve", "--enclave", cfg["enclave"],
            "--expect-host-data", cfg["expect_host_data"], "--port", "0"]
    if cfg.get("expect_index"):
        argv += ["--expect-index", cfg["expect_index"]]
    if cfg.get("pins"):
        argv += ["--pins", cfg["pins"]]
    try:
        proc = subprocess.Popen(argv, cwd=cfg.get("cwd"), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    except (OSError, KeyError):
        sys.stderr.write("\n  prior-art search is unavailable this session: the local search verifier did not start.\n\n")
        return None
    ready, _, _ = select.select([proc.stdout], [], [], timeout)
    try:
        port = int(json.loads(proc.stdout.readline())["listening"]) if ready else 0
    except (ValueError, KeyError, TypeError):
        port = 0
    if not port:
        proc.terminate()
        sys.stderr.write("\n  prior-art search is unavailable this session: the local search verifier did not start.\n\n")
        return None
    _SEARCH_PROXIES.append(proc)
    return f"http://127.0.0.1:{port}"


def stop_search_proxy() -> None:
    while _SEARCH_PROXIES:
        proc = _SEARCH_PROXIES.pop()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:                                   # noqa: BLE001
            proc.kill()


# ───────────────────────── egress confinement ─────────────────────────
#
# Confine Pi's whole process tree to the local verifying proxies and nothing else, so a compromised or
# injected agent still cannot reach the network except through them. On a platform that cannot do it,
# warn and launch unconfined unless IR_ATTESTED_CONFINE=require, which refuses instead.

def confine_disabled() -> bool:
    return os.environ.get("IR_ATTESTED_CONFINE", "").strip().lower() in ("0", "off", "no", "none")


def confine_required() -> bool:
    return os.environ.get("IR_ATTESTED_CONFINE", "").strip().lower() in ("1", "require", "required", "strict")


def preexec_confine(ports: list[int], then=None):
    """A preexec_fn that confines the child to `ports` then runs `then` (e.g. reset SIGINT). Confinement
    failure raises only when IR_ATTESTED_CONFINE=require; otherwise the child launches unconfined and a
    one-line notice is printed once from the parent (see confine_notice)."""
    import sys
    from inferroute_local import confinement

    def _fn():
        try:
            confinement.apply([p for p in ports if p])
        except confinement.Unavailable:
            if confine_required():
                raise
        if then is not None:
            then()
    if not confine_disabled():
        return _fn
    return then if then is not None else (lambda: None)


def confine_notice(ports: list[int]) -> str | None:
    """What to tell the user about confinement before launch: the ports allowed, or why it is off. Returns
    None when confinement is disabled by the user."""
    import sys
    if confine_disabled():
        return None
    from inferroute_local import confinement
    try:
        abi = confinement.landlock_abi(__import__("ctypes").CDLL(None, use_errno=True)) if sys.platform == "linux" else 0
    except Exception:                                       # noqa: BLE001
        abi = 0
    if sys.platform == "linux" and abi >= 4:
        return f"network confined to the local proxies (ports {', '.join(str(p) for p in ports if p)})"
    if confine_required():
        return "IR_ATTESTED_CONFINE=require but this platform cannot confine egress; the launch will refuse"
    return ("this platform cannot confine the agent's network (needs Linux with Landlock ABI 4); "
            "the agent could reach the network directly — set IR_ATTESTED_CONFINE=require to refuse instead")
