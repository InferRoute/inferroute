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

import hashlib
import json
import os
import re
import shutil
from pathlib import Path

from . import agents

EXTENSION = Path(__file__).resolve().parent / "pi_attested" / "ir-attested.ts"
PROVIDER = "inferroute"
TOOLS = ("read", "edit", "write", "grep", "find", "ls")
LOOPBACK = ("127.0.0.1", "localhost", "::1")

# ── the mission contract (see pi_attested/{preamble,contract}.md and the decision record) ──
# The model's whole system prompt is preamble then contract, with HTML comments stripped. The prompt
# REPLACES Pi's default persona (--system-prompt), verified by capture to leave only a "cwd" line.
# The expected sha of each, over the SENT (stripped) bytes, is pinned here: the contract is fixed and
# changed only deliberately. A drifted on-disk sha is not silently run — the panel and session record
# say "contract modified" and the launch carries the flag.
PREAMBLE_FILE = Path(__file__).resolve().parent / "pi_attested" / "preamble.md"
CONTRACT_FILE = Path(__file__).resolve().parent / "pi_attested" / "contract.md"
PINNED_PREAMBLE_SHA = "02c4257239c895fd11e63a13f1870bf3c7bd932c391591495325a72b951290e1"
PINNED_CONTRACT_SHA = "08a79e5159d8097a6507111f9dfc06dc5fa62136fd7456ba0755cc2a69a459ab"


def _strip_comments(text: str) -> str:
    """The bytes actually sent to the model: HTML comments removed, one trailing newline."""
    return re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL).strip() + "\n"


def load_contract() -> dict:
    """Return {text, preamble_sha, contract_sha, modified} for the launch. `text` is preamble then
    contract, comments stripped. `modified` is True if either sha differs from the pinned value."""
    preamble = _strip_comments(PREAMBLE_FILE.read_text())
    contract = _strip_comments(CONTRACT_FILE.read_text())
    p_sha = hashlib.sha256(preamble.encode()).hexdigest()
    c_sha = hashlib.sha256(contract.encode()).hexdigest()
    return {"text": preamble + "\n" + contract, "preamble_sha": p_sha, "contract_sha": c_sha,
            "modified": p_sha != PINNED_PREAMBLE_SHA or c_sha != PINNED_CONTRACT_SHA}


def config_hash(alias, tools: tuple) -> str:
    """A hash of the launch config that shapes what the assistant is and can do — model, tool
    allowlist, provider — so the session record can pin the configuration it ran under."""
    payload = json.dumps({"model": getattr(alias, "short", ""), "provider": PROVIDER, "tools": sorted(tools)},
                         sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def pi_version(binary: str) -> str:
    import subprocess
    try:
        return subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=10).stdout.strip()[:40]
    except Exception:                                       # noqa: BLE001
        return "unknown"
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
    # The mission contract as the whole system prompt (replaces Pi's persona). Written to the ir-owned
    # config dir; its stamps go to the extension for the panel and the session record.
    contract = load_contract()
    sp = cfg / "system-prompt.txt"
    sp.write_text(contract["text"])
    env["IR_CONTRACT_SHA"] = contract["contract_sha"]
    env["IR_PREAMBLE_SHA"] = contract["preamble_sha"]
    env["IR_CONTRACT_MODIFIED"] = "1" if contract["modified"] else "0"
    env["IR_CONFIG_HASH"] = config_hash(alias, tools)
    env["IR_PI_VERSION"] = pi_version(binary)
    return [binary, "-ne", "-e", str(EXTENSION), "-na", "--tools", ",".join(tools),
            "--system-prompt", str(sp),
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


def confine_precheck() -> tuple[bool, str]:
    """(ok_to_launch, notice). In require mode the launch must refuse unless egress can be confined by
    ADDRESS (an empty network namespace); it names the one-time install that provides it. Otherwise the
    port-level Landlock+seccomp confinement is used and its residual is stated."""
    import sys
    from inferroute_local import confinement
    if confine_disabled():
        return True, ""
    linux = sys.platform == "linux"
    try:
        abi = confinement.landlock_abi(__import__("ctypes").CDLL(None, use_errno=True)) if linux else 0
    except Exception:                                       # noqa: BLE001
        abi = 0
    address_level = linux and confinement.netns_available()
    if confine_required():
        if address_level:
            return True, "network confined to the local proxies by ADDRESS (empty network namespace)"
        if linux and confinement.userns_restricted():
            return False, ("IR_ATTESTED_CONFINE=require, but address-level confinement needs the one-time "
                           "AppArmor profile — run scripts/install-confine-profile.sh once (sudo), then retry. "
                           "Refusing to launch with only port-level confinement.")
        return False, ("IR_ATTESTED_CONFINE=require, but this platform cannot confine egress by address "
                       "(needs Linux with bubblewrap and unprivileged network namespaces). Refusing to launch.")
    if linux and abi >= 4:
        residual = " (port-level: a remote host on an allowed port number is still reachable; install the "
        residual += "AppArmor profile and set IR_ATTESTED_CONFINE=require for address-level)" if not address_level else ""
        base = "network confined to the local proxies by ADDRESS" if address_level else "network confined to the local proxies"
        return True, base + residual
    return True, ("this platform cannot confine the agent's network (needs Linux with Landlock ABI 4); "
                  "the agent could reach the network directly — set IR_ATTESTED_CONFINE=require to refuse instead")
