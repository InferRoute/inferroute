"""`ir --confidential` and `ir confidential …` — the confidential lane.

    ir --confidential [--model kimi-k2.6] [claude flags]   verify an enclave, pin it, launch
    ir confidential show                                   re-print the last session's panel
    ir confidential card [--svg PATH]                      export the last session's panel as an SVG card
    ir confidential models                                 which models can run confidentially

How a session runs: a per-session endpoint on 127.0.0.1 translates each Claude Code request,
seals it to the pinned enclave's key, hands the ciphertext to the carrier, opens the enclave's
reply on this device and hands Claude Code the plaintext. The endpoint dies with the session.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import signal
import socket
import sys
from pathlib import Path

DEFAULT_MODEL = "kimi-k2.6"


def _console():
    from rich.console import Console
    return Console()


def _need_extra():
    try:
        import cryptography  # noqa: F401
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
        from inferroute_local.confidential import e2ee
        e2ee.backend()
    except Exception as e:
        sys.stderr.write(f"\n  The confidential lane needs extra packages ({e}).\n"
                         "  Fix: pip install 'inferroute[confidential]'\n\n")
        sys.exit(2)


def _resolve_model(short: str | None):
    from . import models as models_mod
    short = short or DEFAULT_MODEL
    alias = models_mod.get(short)
    if alias is None or not (alias.ref_key or "").endswith("-TEE"):
        tee = [a.short for a in models_mod.all_aliases() if (a.ref_key or "").endswith("-TEE")]
        sys.stderr.write(f"\n  `{short}` cannot run confidentially. Models that can: {', '.join(tee) or '(none in catalog)'}\n\n")
        sys.exit(2)
    return alias


def _interactive(passthrough: list[str]) -> bool:
    """A human at a terminal (not `-p`/`--print`, not a pipe): the picker and the pause apply."""
    return sys.stdin.isatty() and sys.stdout.isatty() and not any(a in ("-p", "--print") or a.startswith("--print=") for a in passthrough)


async def _pause(prompt: str, timeout: float = 20.0) -> None:
    """Wait for Enter or `timeout` seconds, whichever first; never blocks a non-tty."""
    import select
    sys.stdout.write(f"\033[90m  {prompt}\033[0m ")
    sys.stdout.flush()
    loop = asyncio.get_running_loop()

    def _wait() -> None:
        r, _, _ = select.select([sys.stdin], [], [], timeout)
        if r:
            try:
                sys.stdin.readline()
            except Exception:
                pass
    await loop.run_in_executor(None, _wait)
    sys.stdout.write("\n")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _open_session(alias, session_id: str, http, console):
    from inferroute_local.confidential.session import ConfidentialSession
    from inferroute_local.confidential.transport import RelayUnavailable, make_transport
    from . import config as cfg
    creds = cfg.load()
    try:
        transport = make_transport(http, api_url=creds.api_url, api_key=creds.api_key, session_id=session_id)
    except ValueError as e:
        console.print(f"[red]{e}[/]")
        sys.exit(2)
    import httpx
    with console.status(f"[bold]resolving {alias.ref_key} on the confidential lane…", spinner="dots"):
        try:
            catalog = await transport.models()
        except RelayUnavailable as e:
            console.print(f"[red]{e}[/]\n[grey58]Nothing was sent.[/]")
            sys.exit(3)
        except httpx.HTTPStatusError as e:
            body = (e.response.text or "")[:200].replace("\n", " ")
            import re
            body = re.sub(r"https?://\S+", "<url>", body)
            code = e.response.status_code
            hint = ("your InferRoute key was refused — run `ir login`" if code in (401, 403)
                    else "try again in a minute")
            console.print(f"[red]the carrier answered {code} while listing confidential models[/]"
                          f"\n[grey58]{transport.name} · {body}[/]\n[grey58]Nothing was sent; {hint}.[/]")
            sys.exit(3)
        except httpx.HTTPError as e:
            console.print(f"[red]cannot reach the carrier ({type(e).__name__})[/]\n[grey58]Nothing was sent.[/]")
            sys.exit(3)
    fleet_id = next((m.get("fleet_id") or m.get("chute_id") for m in catalog if m.get("name") == alias.ref_key), None)
    if not fleet_id:
        console.print(f"[red]{alias.ref_key} is not offered on the confidential lane right now[/]")
        sys.exit(3)
    session = ConfidentialSession(session_id=session_id, model_short=alias.short, upstream_model=alias.ref_key,
                                  fleet_id=fleet_id, transport=transport, http=http)
    status = console.status("[bold]verifying the enclave from this device…", spinner="dots")
    status.start()
    try:
        receipt = await session.open(progress=lambda s: status.update(f"[bold]{s}"))
    except Exception as e:  # session.open() refuses on expected failures; anything else is a bug, shown cleanly
        status.stop()
        from inferroute_local.confidential.session import public_reason
        console.print(f"[red]could not open the confidential session ({public_reason(e)})[/]\n[grey58]Nothing was sent.[/]")
        sys.exit(3)
    finally:
        status.stop()
    return session, receipt


def _strip_prefix(receipt) -> str:
    """The static half of the status line: `🔒 confidential · kimi-k2.6 · enclave verified 01:04Z`.
    No instance id here (it is on the receipt; the status line is the thing people screenshot)."""
    when = (receipt.verified_at or receipt.started_at or "")[11:16]
    return f"🔒 confidential · {receipt.model_short} · enclave verified {when}Z"


def _attach_counter(status_args: list[str], receipt_path: str) -> None:
    """Append the live privacy figures to the status-line command, read from the receipt on every
    render (the session rewrites it after each turn): how much was sealed on this device and
    that nothing left in the clear. Dependency-free shell; exit status stays 0."""
    import json
    import shlex
    if len(status_args) != 2 or not receipt_path:
        return
    try:
        settings = json.loads(status_args[1])
        cmd = settings["statusLine"]["command"]
    except (ValueError, KeyError, TypeError):
        return
    rp = shlex.quote(receipt_path)
    cmd += (f"; b=$(grep -o '\"plaintext_bytes_sealed_here\": [0-9]*' {rp} 2>/dev/null | head -1 | grep -o '[0-9]*$'); "
            f"if [ -n \"$b\" ]; then if [ \"$b\" -ge 1048576 ]; then printf ' · %s.%s MB sealed here' $((b/1048576)) $(( (b%1048576)*10/1048576 )); "
            f"else printf ' · %s KB sealed here' $((b/1024)); fi; printf ' · 0 B in the clear'; fi || true")
    settings["statusLine"]["command"] = cmd
    status_args[1] = json.dumps(settings)


# ───────────────────────── ir --confidential ─────────────────────────

def launch(args: list[str], agent: str = "claude") -> int:
    _need_extra()
    from . import launch as launch_mod, agents as agents_mod
    from inferroute_local.confidential import display
    import httpx
    import uvicorn
    from inferroute_local.confidential.server import create_app

    from .main import _extract_model_override
    from . import resume as resume_mod
    passthrough = [a for a in args if a != "--confidential"]
    user_model, passthrough = _extract_model_override(passthrough)
    if user_model is None and _interactive(passthrough):
        # No pin → the same picker as bare `ir`, narrowed to the enclave-capable models.
        from . import choose as choose_mod
        user_model = choose_mod.pick(choose_mod.confidential_options(),
                                     "confidential lane · choose an enclave model · USD per 1M tokens")
        if user_model is None:
            return 130
        hint = f"ir {agent} --model {user_model}" if agent != "claude" else f"ir --model {user_model}"
        sys.stderr.write(f"\n  Run this next time directly:  {hint}\n\n")
    alias = _resolve_model(user_model)
    if os.environ.get("CLAUDECODE") == "1" and os.environ.get("IR_ALLOW_NESTED") != "1":
        sys.stderr.write("\n  ir: refusing to launch a nested agent session (CLAUDECODE=1). Set IR_ALLOW_NESTED=1 to force.\n\n")
        return 2
    binary = agents_mod.binary_for(agent)
    console = _console()
    # Resume (Claude Code only — the other agents manage their own sessions): `--resume <id>` or
    # `-c`. The resumed turns are sealed like fresh ones; a confidential session never silently
    # continues on the plaintext lane.
    resuming = None
    if agent == "claude":
        mode, explicit_id, passthrough = resume_mod._parse(passthrough)
        resuming = explicit_id or (resume_mod.newest(os.getcwd()) if mode == "continue" else None)
        if mode == "continue" and not resuming:
            sys.stderr.write("\n  ir: nothing to continue in this directory.\n\n")
            return 1
    session_id = resuming or launch_mod._new_session_id()
    # What Claude Code shows as the model name — the one persistent on-screen reminder
    # of the lane. The local endpoint answers to this id; the enclave sees `alias.ref_key`.
    shown_model = f"{alias.short} [confidential]"

    async def _run() -> int:
        async with httpx.AsyncClient(timeout=httpx.Timeout(600.0, connect=30.0)) as http:
            session, receipt = await _open_session(alias, session_id, http, console)
            display.render_panel(receipt, console)
            if not receipt.is_confidential:
                return 3
            if _interactive(passthrough):
                # Claude Code's full-screen TUI replaces this screen the moment it starts, so give
                # the panel a beat: Enter (or 20 s) to continue. The 🔒 status line inside Claude
                # Code and `ir confidential show` carry the proof from there on.
                await _pause(f"Enter to open {agent} · `ir confidential show` re-prints this proof any time")
            port = _free_port()
            server = uvicorn.Server(uvicorn.Config(create_app(session), host="127.0.0.1", port=port, log_level="critical"))
            server_task = asyncio.create_task(server.serve())
            while not server.started:
                if server_task.done():
                    server_task.result()
                await asyncio.sleep(0.05)
            env = os.environ.copy()
            env["IR_CONFIDENTIAL"] = "1"
            local = f"http://127.0.0.1:{port}"
            session.shown_model = shown_model if agent == "claude" else alias.short
            if agent == "claude":
                env["ANTHROPIC_BASE_URL"] = local
                env["ANTHROPIC_AUTH_TOKEN"] = "ir-confidential-local"
                env["ANTHROPIC_DEFAULT_HAIKU_MODEL"] = shown_model
                env["ANTHROPIC_SMALL_FAST_MODEL"] = shown_model
                env["ANTHROPIC_CUSTOM_HEADERS"] = "\n".join(
                    [h for h in [env.get("ANTHROPIC_CUSTOM_HEADERS", "").strip()] if h] + [f"x-inferroute-session: {session_id}"])
                launch_mod._apply_autocompact_env(env, alias.model_id)
                # Pinned inside Claude Code's TUI for the whole session (the pre-launch panel
                # scrolls away in fullscreen mode): lane · model · enclave · when verified, plus a
                # live "N sealed" count read from the receipt the session keeps updating.
                status_args = launch_mod._product_strip_settings_args(
                    _strip_prefix(receipt), passthrough, disable_connectors=True)
                _attach_counter(status_args, receipt.path)
                if resuming:
                    argv = [binary, "--model", shown_model, "--resume", session_id, *passthrough, *status_args]
                else:
                    argv = [binary, "--model", shown_model, "--session-id", session_id, *passthrough, *status_args]
            elif agent == "pi":
                argv = agents_mod.pi_env_argv(binary, env, passthrough, base_url=local, api_key="ir-confidential-local",
                                              alias=alias, upstream_name=f"{alias.model_id} [confidential]")
            elif agent == "opencode":
                argv = agents_mod.opencode_env_argv(binary, env, passthrough, base_url=local, api_key="ir-confidential-local",
                                                    alias=alias, upstream_name=f"{alias.model_id} [confidential]")
            elif agent == "goose":
                argv = agents_mod.goose_env_argv(binary, env, passthrough, base_url=local, api_key="ir-confidential-local", alias=alias)
            else:
                console.print(f"[red]unknown agent {agent}[/]")
                return 2
            if not resuming:
                launch_mod._record_launch(session_id, alias.model_id, "confidential", agent=agent)
            console.print(f"[grey58]{'resuming' if resuming else 'launching'} {agent} on the confidential lane · "
                          f"local endpoint 127.0.0.1:{port}[/]\n")
            signal.signal(signal.SIGINT, signal.SIG_IGN)          # Claude Code owns Ctrl-C; we outlive it
            proc = await asyncio.create_subprocess_exec(
                *argv, env=env, preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL))
            rc = await proc.wait()
            server.should_exit = True
            await server_task
            session.close()
            console.print("")
            display.render_summary(session.receipt, console)
            return rc

    try:
        return asyncio.run(_run())
    except KeyboardInterrupt:
        # Only reachable BEFORE claude starts (verification / instance discovery): after the
        # launch the parent ignores SIGINT and claude owns it. Nothing has been sent yet.
        console.print("\n[grey58]cancelled before anything was sent.[/]")
        return 130


# ───────────────────────── ir confidential … ─────────────────────────

def run(rest: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="ir confidential", description="the confidential lane")
    sub = ap.add_subparsers(dest="action")
    sub.add_parser("show", help="Re-print the last session's panel.")
    c = sub.add_parser("card", help="Export the last session's panel as an SVG card.")
    c.add_argument("--svg", default=None, help="output path (default: next to the receipt)")
    sub.add_parser("models", help="Models that can run confidentially.")
    ns = ap.parse_args(rest)
    if not ns.action:
        ap.print_help()
        return 0
    _need_extra()
    from inferroute_local.confidential import display, receipt as receipt_mod
    console = _console()

    if ns.action == "models":
        from . import models as models_mod
        print()
        for a in models_mod.all_aliases():
            if (a.ref_key or "").endswith("-TEE"):
                print(f"  ir --confidential --model {a.short:<18} {a.label}")
        print()
        return 0

    r = receipt_mod.latest()
    if r is None:
        console.print("[grey58]no confidential session recorded yet — run `ir --confidential`[/]")
        return 1
    if ns.action == "show":
        display.render_panel(r, console)
        return 0
    if ns.action == "card":
        out = Path(ns.svg) if ns.svg else Path(r.path).with_suffix(".svg")
        display.save_svg(r, out)
        print(f"card written: {out}")
        return 0
    return 2
