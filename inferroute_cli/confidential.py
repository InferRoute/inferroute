"""`ir --confidential` and `ir confidential …` — the confidential lane.

    ir --confidential [--model kimi-k2.6] [claude flags]   verify an enclave, pin it, launch
    ir confidential verify [--model M]                     show every instance's checks, send nothing
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
            console.print(f"[red]{e}[/]\n[grey58]For now set IR_CHUTES_API_KEY to use your own Chutes key directly.[/]")
            sys.exit(3)
        except httpx.HTTPStatusError as e:
            body = (e.response.text or "")[:200].replace("\n", " ")
            console.print(f"[red]the carrier answered {e.response.status_code} while listing confidential models[/]"
                          f"\n[grey58]{transport.name} · {body}[/]\n[grey58]Nothing was sent. Try again in a minute, "
                          f"or set IR_CHUTES_API_KEY to go direct.[/]")
            sys.exit(3)
        except httpx.HTTPError as e:
            console.print(f"[red]cannot reach the carrier ({type(e).__name__}: {e})[/]\n[grey58]Nothing was sent.[/]")
            sys.exit(3)
    chute_id = next((m["chute_id"] for m in catalog if m.get("name") == alias.ref_key), None)
    if not chute_id:
        console.print(f"[red]{alias.ref_key} is not offered on the confidential lane right now[/]")
        sys.exit(3)
    session = ConfidentialSession(session_id=session_id, model_short=alias.short, upstream_model=alias.ref_key,
                                  chute_id=chute_id, transport=transport, http=http)
    status = console.status("[bold]verifying the enclave from this device…", spinner="dots")
    status.start()
    try:
        receipt = await session.open(progress=lambda s: status.update(f"[bold]{s}"))
    except Exception as e:  # session.open() refuses on expected failures; anything else is a bug, shown cleanly
        status.stop()
        console.print(f"[red]could not open the confidential session ({type(e).__name__}: {e})[/]\n[grey58]Nothing was sent.[/]")
        sys.exit(3)
    finally:
        status.stop()
    return session, receipt


# ───────────────────────── ir --confidential ─────────────────────────

def launch(args: list[str]) -> int:
    _need_extra()
    from . import launch as launch_mod
    from inferroute_local.confidential import display
    import httpx
    import uvicorn
    from inferroute_local.confidential.server import create_app

    from .main import _extract_model_override
    from . import resume as resume_mod
    passthrough = [a for a in args if a != "--confidential"]
    user_model, passthrough = _extract_model_override(passthrough)
    alias = _resolve_model(user_model)
    if os.environ.get("CLAUDECODE") == "1" and os.environ.get("IR_ALLOW_NESTED") != "1":
        sys.stderr.write("\n  ir: refusing to launch a nested Claude Code session (CLAUDECODE=1). Set IR_ALLOW_NESTED=1 to force.\n\n")
        return 2
    binary = launch_mod._require_claude_binary()
    console = _console()
    # Resume: `--resume <id>` (also what `ir --resume`'s menu hands us for a confidential
    # session) or `-c`. The resumed turns are sealed like fresh ones; a confidential
    # session never silently continues on the plaintext lane.
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
            port = _free_port()
            server = uvicorn.Server(uvicorn.Config(create_app(session), host="127.0.0.1", port=port, log_level="warning"))
            server_task = asyncio.create_task(server.serve())
            while not server.started:
                if server_task.done():
                    server_task.result()
                await asyncio.sleep(0.05)
            env = os.environ.copy()
            env["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{port}"
            env["ANTHROPIC_AUTH_TOKEN"] = "ir-confidential-local"
            env["ANTHROPIC_DEFAULT_HAIKU_MODEL"] = shown_model
            env["ANTHROPIC_SMALL_FAST_MODEL"] = shown_model
            env["IR_CONFIDENTIAL"] = "1"
            env["ANTHROPIC_CUSTOM_HEADERS"] = "\n".join(
                [h for h in [env.get("ANTHROPIC_CUSTOM_HEADERS", "").strip()] if h] + [f"x-inferroute-session: {session_id}"])
            launch_mod._apply_autocompact_env(env, alias.model_id)
            session.shown_model = shown_model
            if resuming:
                argv = [binary, "--model", shown_model, "--resume", session_id, *passthrough]
            else:
                argv = [binary, "--model", shown_model, "--session-id", session_id, *passthrough]
                launch_mod._record_launch(session_id, alias.model_id, "confidential")
            console.print(f"[grey58]{'resuming' if resuming else 'launching'} claude on the confidential lane · "
                          f"local endpoint 127.0.0.1:{port} · Ctrl-C twice in claude to leave[/]\n")
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
    v = sub.add_parser("verify", help="Verify every instance of a model from this device. Sends nothing.")
    v.add_argument("--model", default=None)
    v.add_argument("--json", action="store_true")
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

    if ns.action == "verify":
        import httpx
        import json
        from inferroute_local.confidential import attest
        from inferroute_local.confidential.transport import make_transport
        from . import config as cfg
        alias = _resolve_model(ns.model)

        async def _v():
            async with httpx.AsyncClient(timeout=httpx.Timeout(300.0, connect=30.0)) as http:
                creds = cfg.load()
                chute_id = None
                try:
                    t = make_transport(http, api_url=creds.api_url, api_key=creds.api_key)
                    chute_id = next((m["chute_id"] for m in await t.models() if m.get("name") == alias.ref_key), None)
                except Exception:
                    pass
                if not chute_id:
                    r = await http.get("https://llm.chutes.ai/v1/models", timeout=30)
                    chute_id = next((m["chute_id"] for m in r.json().get("data", []) if m.get("id") == alias.ref_key), None)
                if not chute_id:
                    console.print(f"[red]cannot resolve {alias.ref_key} to a chute[/]")
                    return 3
                with console.status("[bold]fetching evidence from Chutes with a fresh challenge…", spinner="dots"):
                    fleet = await attest.fetch_and_verify(chute_id, http)
                if ns.json:
                    print(json.dumps(fleet.as_dict(), indent=1))
                else:
                    display.render_fleet(fleet, console)
                    console.print(f"\n[grey58]{len(fleet.verified_ids)} of {len(fleet.instances)} verified. "
                                  f"This is fleet-level evidence; a session pins one verified instance and seals to it.[/]")
                return 0 if fleet.verified_ids else 1

        return asyncio.run(_v())

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
        console.print(f"[bold]card written:[/] {out}")
        return 0
    return 2
