"""Pure guest launch-plan builder for macOS VM sessions.

This module describes a guest Pi invocation. It deliberately does not read the
host environment, inspect matter paths, create files, or launch a process.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json
from pathlib import PurePosixPath
import re
from types import SimpleNamespace
from typing import Mapping, Sequence

from inferroute_cli import pi_attested

MODEL_PORT = 40502
SEARCH_PORT = 40503
GUEST_NODE = "/usr/bin/node"
GUEST_PI_CLI = "/opt/pi/node_modules/@earendil-works/pi-coding-agent/dist/cli.js"
GUEST_EXTENSION = "/opt/probant/client/inferroute_cli/pi_attested/ir-attested.ts"
GUEST_CAPABILITY = "vm-local-capability"

_ALLOWED_HOST_LABELS = frozenset(
    {"IR_REPORT_FIRM", "IR_REPORT_MATTER", "IR_ROUND_LABEL"}
)
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DOC_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_BAD_PROMPT_PATH_RE = re.compile(
    r"^(?:/|\\\\|~/|\.\.?/|\.\.\\|[A-Za-z]:[/\\]|file://|@)"
)


class PlanRefused(ValueError):
    """The requested guest session cannot be represented safely."""


@dataclass(frozen=True)
class LaunchPlan:
    """An immutable-by-convention guest invocation and its guest configuration files."""

    argv: tuple[str, ...]
    env: dict[str, str]
    config: dict[str, bytes]
    mode: str
    tools: tuple[str, ...]
    cwd: str = "/matter"

    @property
    def request(self) -> dict:
        """Return a JSON-ready transfer description; file content is base64 encoded."""
        return {
            "version": 1,
            "mode": self.mode,
            "cwd": self.cwd,
            "argv": list(self.argv),
            "env": dict(self.env),
            "files": {
                f"/config/{name}": base64.b64encode(self.config[name]).decode("ascii")
                for name in sorted(self.config)
            },
        }


def _model_fields(alias) -> tuple[str, str, object]:
    if isinstance(alias, str):
        short, display = alias, alias
        alias_for_hash = SimpleNamespace(short=short)
    else:
        short = getattr(alias, "short", None)
        display = getattr(alias, "model_id", short)
        alias_for_hash = alias
    if not isinstance(short, str) or not _MODEL_RE.fullmatch(short):
        raise PlanRefused("model alias is invalid")
    if not isinstance(display, str) or not display or len(display) > 160:
        raise PlanRefused("model display name is invalid")
    return short, display, alias_for_hash


def _validate_passthrough(passthrough: Sequence[str]) -> tuple[str, ...]:
    if isinstance(passthrough, (str, bytes)):
        raise PlanRefused("Pi arguments must be a sequence of argument strings")
    args = tuple(passthrough)
    if any(not isinstance(arg, str) or "\x00" in arg for arg in args):
        raise PlanRefused("Pi arguments must be NUL-free strings")

    # Preserve the shipped fail-closed checks for the known dangerous Pi options.
    try:
        pi_attested.check_passthrough(list(args))
    except pi_attested.Refused as exc:
        raise PlanRefused(str(exc)) from None

    clean: list[str] = []
    rpc_seen = False
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == "--mode":
            if rpc_seen or i + 1 >= len(args) or args[i + 1] != "rpc":
                raise PlanRefused("only `--mode rpc` is accepted")
            rpc_seen = True
            i += 2
            continue
        if arg in ("--print", "-p"):
            clean.append(arg)
            i += 1
            continue
        if arg.startswith("-"):
            raise PlanRefused("unknown Pi option is not accepted in the VM plan")
        if (
            arg.startswith((".", "~"))
            or _BAD_PROMPT_PATH_RE.match(arg)
            or (
                not any(ch.isspace() for ch in arg)
                and ("/" in arg or "\\" in arg or bool(PurePosixPath(arg).suffix))
            )
        ):
            raise PlanRefused("file-like positional arguments are not accepted")
        clean.append(arg)
        i += 1
    return tuple(clean)


def _host_labels(host_env: Mapping[str, str] | None) -> dict[str, str]:
    if host_env is None:
        return {}
    if not isinstance(host_env, Mapping):
        raise PlanRefused("host metadata must be a mapping")
    if set(host_env) - _ALLOWED_HOST_LABELS:
        # Do not echo key names or values: rejected input may contain credentials.
        raise PlanRefused(
            "host environment contains a field outside the safe label allowlist"
        )
    out: dict[str, str] = {}
    for key, value in host_env.items():
        if not isinstance(value, str) or not value or len(value) > 256:
            raise PlanRefused("host label is invalid")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
            raise PlanRefused("host label contains control characters")
        if value.startswith(("/", "~", "\\")) or "://" in value or ".." in value:
            raise PlanRefused("host label resembles a path or URL")
        if key == "IR_REPORT_MATTER":
            parts = value.split("/")
            if len(parts) != 2 or any(
                not part or part in (".", "..") for part in parts
            ):
                raise PlanRefused("matter label is invalid")
        elif "/" in value or "\\" in value:
            raise PlanRefused("host label contains a path separator")
        out[key] = value
    return out


def _document_titles(documents: Mapping[str, str] | None) -> dict[str, str]:
    if documents is None:
        return {}
    if not isinstance(documents, Mapping):
        raise PlanRefused("document titles must be a mapping")
    if len(documents) > 10_000:
        raise PlanRefused("document title map is too large")
    out: dict[str, str] = {}
    for key, title in documents.items():
        if not isinstance(key, str) or not _DOC_KEY_RE.fullmatch(key):
            raise PlanRefused("document key is invalid")
        if not isinstance(title, str) or not title or len(title) > 300:
            raise PlanRefused("document title is invalid")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in title):
            raise PlanRefused("document title contains control characters")
        out[key] = title
    return dict(sorted(out.items()))


def build_plan(
    *,
    alias,
    passthrough: Sequence[str] = (),
    mode: str = "matter",
    create_drafts: bool = False,
    surface_browser_only: bool = False,
    host_env: Mapping[str, str] | None = None,
    documents: Mapping[str, str] | None = None,
) -> LaunchPlan:
    """Build a guest-only Pi plan for one confined model/search session.

    Terminal launches are refused until a supported browser surface exists. The
    returned environment is newly constructed and never inherits host variables.
    """
    if not surface_browser_only:
        raise PlanRefused(
            "the VM gate supports browser-only sessions; terminal launch is refused"
        )
    if mode not in ("matter", "intake"):
        raise PlanRefused("unsupported VM session mode")
    if not isinstance(create_drafts, bool):
        raise PlanRefused("create_drafts must be a boolean")
    if mode != "intake" and create_drafts:
        raise PlanRefused("draft creation is available only for document intake")

    short, display, alias_for_hash = _model_fields(alias)
    extra = _validate_passthrough(passthrough)
    labels = _host_labels(host_env)
    docs = _document_titles(documents)
    if mode == "intake" and labels:
        raise PlanRefused("matter labels are not accepted for document intake")
    if docs and mode != "matter":
        raise PlanRefused("matter document titles are not accepted for intake")

    if mode == "intake":
        if create_drafts:
            tools = ("read", "grep", "find", "ls", "create_draft_matter")
            contract = pi_attested.load_intake_prompt(True)
        else:
            tools = pi_attested.TOOLS + (
                pi_attested.PROPOSE_TOOL,
                pi_attested.BATCH_TOOL,
            )
            contract = pi_attested.load_intake_prompt(False)
    else:
        tools = pi_attested.MATTER_TOOLS + (
            pi_attested.SEARCH_TOOL,
            pi_attested.DEEP_TOOL,
            pi_attested.OPEN_TOOL,
            pi_attested.MARKS_TOOL,
            pi_attested.NEXT_TOOL,
        )
        contract = pi_attested.load_contract()

    config_hash = pi_attested.config_hash(alias_for_hash, tools)
    model_base = f"http://127.0.0.1:{MODEL_PORT}"
    model_config = {
        "providers": {
            "inferroute": {
                "name": "InferRoute",
                "baseUrl": model_base + "/v1",
                "api": "openai-completions",
                "apiKey": GUEST_CAPABILITY,
                "compat": {
                    "thinkingFormat": "deepseek",
                    "supportsDeveloperRole": False,
                    "maxTokensField": "max_tokens",
                },
                "models": [
                    {
                        "id": short,
                        "name": display,
                        "reasoning": True,
                        "input": ["text", "image"],
                        "cost": {
                            "input": 0,
                            "output": 0,
                            "cacheRead": 0,
                            "cacheWrite": 0,
                        },
                        "contextWindow": 262144,
                        "maxTokens": 32768,
                    }
                ],
            }
        }
    }
    settings = {
        "enableInstallTelemetry": False,
        "defaultProjectTrust": "never",
        "quietStartup": True,
        "hideThinkingBlock": True,
    }
    config: dict[str, bytes] = {
        "models.json": (
            json.dumps(model_config, sort_keys=True, indent=2) + "\n"
        ).encode("utf-8"),
        "settings.json": (json.dumps(settings, sort_keys=True, indent=2) + "\n").encode(
            "utf-8"
        ),
        "system-prompt.txt": contract["text"].encode("utf-8"),
    }
    if docs:
        config["matter-docs.json"] = (
            json.dumps(docs, ensure_ascii=False, sort_keys=True) + "\n"
        ).encode("utf-8")

    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/root",
        "TMPDIR": "/config/tmp",
        "LANG": "C.UTF-8",
        "PI_CODING_AGENT_DIR": "/config",
        "PI_OFFLINE": "1",
        "PI_SKIP_VERSION_CHECK": "1",
        "PI_TELEMETRY": "0",
        "IR_ATTESTED_CONFINE": "require",
        "IR_PROBANT_SURFACE": "browser",
        "IR_ATTESTED_ENDPOINT": model_base,
        "IR_ATTESTED_KEY": GUEST_CAPABILITY,
        "IR_ATTESTED_PROVIDER": pi_attested.PROVIDER,
        "IR_ATTESTED_TOOLS": ",".join(tools),
        "IR_ATTESTED_RECORD_DIR": "/config/attested-sessions",
        "IR_CONFIG_HASH": config_hash,
        "IR_CONTRACT_SHA": contract["contract_sha"],
        "IR_PREAMBLE_SHA": contract["preamble_sha"],
        "IR_CONTRACT_MODIFIED": "1" if contract["modified"] else "0",
        "IR_PI_VERSION": "0.84.1",
        "no_proxy": "127.0.0.1,localhost,::1",
        "NO_PROXY": "127.0.0.1,localhost,::1",
    }
    env.update(labels)
    if mode == "intake":
        env["IR_INTAKE_DIR"] = "/matter"
        env["IR_INTAKE_OUT"] = "/matter/proposals.jsonl"
        env["IR_INTAKE_CREATE_DRAFTS"] = "1" if create_drafts else "0"
    else:
        env["IR_SEARCH_ENDPOINT"] = f"http://127.0.0.1:{SEARCH_PORT}"
        if docs:
            env["IR_MATTER_DOCS"] = "/config/matter-docs.json"

    pi_args = [
        GUEST_NODE,
        GUEST_PI_CLI,
        "-ne",
        "-e",
        GUEST_EXTENSION,
        "-na",
        "-nc",
        "--no-session",
        "--tools",
        ",".join(tools),
        "--system-prompt",
        "/config/system-prompt.txt",
        "--provider",
        pi_attested.PROVIDER,
        "--model",
        short,
        "--models",
        f"{pi_attested.PROVIDER}/{short}",
        "--mode",
        "rpc",
    ]
    pi_args.extend(extra)
    return LaunchPlan(
        argv=tuple(pi_args), env=env, config=config, mode=mode, tools=tuple(tools)
    )
