"""CLI entry point for inferroute-local."""

import logging
import os
import shutil
import subprocess
import sys
import webbrowser
from pathlib import Path

import click
import httpx

from . import credentials
from .config import Config

# NOTE: `uvicorn` and `.server` (which imports fastapi) are imported lazily
# inside the commands that need them — see `_require_local_extra()`. They live
# in the optional [local] extra; importing them at module load would make the
# `inferroute-daemon` console script crash-loop with an ImportError when the
# extra isn't installed (the henry-ft failure). `click`/`httpx` are core deps.

# Where the user creates / manages keys
KEYS_URL = "https://inferroute.ai/dashboard/api-keys"


def _require_local_extra():
    """Import the recorder daemon's optional deps, or exit cleanly with guidance.

    Returns (uvicorn_module, create_app_callable). On a missing [local] extra it
    prints a one-line fix and raises SystemExit(3) — a clean, non-looping exit so
    a systemd unit fails fast (paired with StartLimit) instead of crash-looping
    on a raw ImportError traceback."""
    try:
        import uvicorn
        from .server import create_app
        return uvicorn, create_app
    except ImportError as e:
        click.echo(
            "Recorder deps are not installed (%s).\n"
            "  Fix: pip install 'inferroute[local]'   (adds fastapi + uvicorn)" % e,
            err=True,
        )
        raise SystemExit(3)


@click.group(invoke_without_command=True)
@click.option("--host", default=None, help="Bind address (default: 127.0.0.1)")
@click.option("--port", default=None, type=int, help="Port (default: 5005)")
@click.option("--server-url", default=None, envvar="INFERROUTE_SERVER_URL", help="inferroute-server URL")
@click.option("--api-key", default=None, envvar="INFERROUTE_API_KEY", help="inferroute API key")
@click.option("--debug", is_flag=True, default=False)
@click.pass_context
def main(ctx, host, port, server_url, api_key, debug):
    """Run the inferroute local proxy daemon (default) or a subcommand."""
    if ctx.invoked_subcommand is not None:
        return

    uvicorn, create_app = _require_local_extra()

    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    config = Config.from_env()
    if host:
        config.host = host
    if port:
        config.port = port
    if server_url:
        config.inferroute_server_url = server_url
    if api_key:
        config.inferroute_api_key = api_key
    elif not config.inferroute_api_key:
        # Fall back to credentials file
        config.inferroute_api_key = credentials.get_api_key()

    if not config.inferroute_api_key:
        click.echo(
            "Warning: no INFERROUTE_API_KEY set and no credentials file. "
            "Run `inferroute login` first.",
            err=True,
        )

    app = create_app(config)
    uvicorn.run(
        app,
        host=config.host,
        port=config.port,
        log_level="debug" if debug else "warning",
        access_log=debug,
    )


@main.command()
@click.option("--token", default=None, help="Paste your inferroute API token. Will prompt if omitted.")
@click.option("--no-browser", is_flag=True, help="Don't try to open the browser.")
def login(token, no_browser):
    """Log in by storing an inferroute API token in ~/.inferroute/credentials.json.

    Opens https://inferroute.ai/dashboard/api-keys in your browser so you can
    create a key, then prompts you to paste it back. The token never leaves
    your machine after that — the daemon reads it from a 0600 local file.
    """
    if not token:
        click.echo(f"Opening {KEYS_URL} — create a key there, then come back here.")
        if not no_browser:
            try:
                webbrowser.open(KEYS_URL)
            except Exception:
                pass
        token = click.prompt(
            "\nPaste your inferroute API token (starts with 'inf_')",
            hide_input=True,
        )
    if not token.startswith("inf_"):
        click.echo("Warning: token doesn't start with 'inf_' — double check you copied the right value.", err=True)
    credentials.save({"inferroute_token": token})
    click.echo(f"\nSaved to {credentials.CRED_FILE} (0600).")
    click.echo("Now start the daemon:  inferroute install-service  →  systemctl --user start inferroute-local")
    click.echo("Or run in the foreground:  inferroute")


@main.command()
def status():
    """Show daemon health and configured server."""
    config = Config.from_env()
    if not config.inferroute_api_key:
        config.inferroute_api_key = credentials.get_api_key()

    try:
        r = httpx.get(f"http://{config.host}:{config.port}/health", timeout=2)
        daemon = f"OK ({r.json()})" if r.status_code == 200 else f"ERR status={r.status_code}"
    except Exception as e:
        daemon = f"DOWN ({e})"

    server_url = config.inferroute_server_url
    try:
        r = httpx.get(f"{server_url}/", timeout=3)
        server = f"reachable (status={r.status_code})"
    except Exception as e:
        server = f"UNREACHABLE ({e})"

    click.echo(f"daemon:         {daemon}")
    click.echo(f"server URL:     {server_url}")
    click.echo(f"server status:  {server}")
    click.echo(f"api key:        {'set' if config.inferroute_api_key else 'MISSING'}")
    click.echo(f"recording:      {config.record_level}")


@main.command(name="install-service")
@click.option("--port", default=5005, type=int, help="Port the daemon will bind to.")
@click.option("--enable", is_flag=True, help="Enable the service to start at login.")
@click.option("--start", is_flag=True, help="Also start the service now.")
def install_service(port, enable, start):
    """Install a systemd --user service so the daemon runs on login.

    Writes ~/.config/systemd/user/inferroute-local.service pointing at the
    `inferroute` binary on PATH and binding to INFERROUTE_PORT.
    """
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    unit_dir.mkdir(parents=True, exist_ok=True)
    unit_path = unit_dir / "inferroute-local.service"
    # The daemon binary is `inferroute-daemon` (this CLI). `inferroute` is NOT a
    # console script — resolving it would write a broken ExecStart.
    binary = shutil.which("inferroute-daemon") or str(Path.home() / ".local/bin/inferroute-daemon")
    unit_path.write_text(f"""[Unit]
Description=inferroute-local daemon (Claude Code traffic recorder on :{port})
After=network-online.target
Wants=network-online.target
# Crash-loop guard: stop after 5 failed starts in 60s instead of looping forever.
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart={binary} --port {port}
Environment=INFERROUTE_HOST=127.0.0.1
Environment=INFERROUTE_PORT={port}
# INFERROUTE_API_KEY is read from ~/.inferroute/credentials.json by default;
# uncomment + set here if you'd rather pin it explicitly.
#Environment=INFERROUTE_API_KEY=inf_xxx
Restart=on-failure
RestartSec=3
StandardOutput=journal
StandardError=journal
LimitNOFILE=4096

[Install]
WantedBy=default.target
""")
    click.echo(f"Wrote {unit_path}")
    subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
    if enable:
        subprocess.run(["systemctl", "--user", "enable", "inferroute-local.service"], check=False)
        click.echo("Enabled (will start at next login).")
    if start:
        subprocess.run(["systemctl", "--user", "start", "inferroute-local.service"], check=False)
        click.echo("Started. Check with: systemctl --user status inferroute-local")
    if not (enable or start):
        click.echo("\nTo enable + start now:")
        click.echo("  systemctl --user enable --now inferroute-local")
        click.echo("Logs: journalctl --user -u inferroute-local -f")


@main.command()
def doctor():
    """Diagnose common configuration issues.

    Validates credentials, server reachability, AND the systemd unit itself —
    the latter is what the original `serve`/crash-loop incident slipped past,
    because the old doctor only checked the API key."""
    config = Config.from_env()
    if not config.inferroute_api_key:
        config.inferroute_api_key = credentials.get_api_key()

    problems: list[str] = []
    warnings: list[str] = []

    if not config.inferroute_api_key:
        problems.append("No INFERROUTE_API_KEY env or saved token. Run `inferroute login`.")
    try:
        httpx.get(f"{config.inferroute_server_url}/", timeout=3)
    except Exception as e:
        problems.append(f"inferroute-server unreachable: {e}")

    # Recorder deps present? (the henry-ft ImportError crash-loop)
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
    except ImportError as e:
        problems.append(f"Recorder deps missing ({e}). Run: pip install 'inferroute[local]'.")

    # Validate the systemd user unit on Linux.
    problems_unit, warnings_unit = _check_systemd_unit()
    problems.extend(problems_unit)
    warnings.extend(warnings_unit)

    for w in warnings:
        click.echo(f"  ⚠ {w}")
    if problems:
        for p in problems:
            click.echo(f"  ✗ {p}")
        sys.exit(1)
    click.echo("All checks passed.")


def _check_systemd_unit() -> tuple[list[str], list[str]]:
    """Inspect ~/.config/systemd/user/inferroute-local.service and the running
    service. Returns (problems, warnings). No-op (empty) off Linux."""
    import platform
    if platform.system() != "Linux":
        return [], []

    problems: list[str] = []
    warnings: list[str] = []
    unit = Path.home() / ".config" / "systemd" / "user" / "inferroute-local.service"
    if not unit.exists():
        warnings.append(
            "No systemd unit (inferroute-local.service). The daemon won't "
            "auto-start; run `ir add recording` or `inferroute-daemon install-service`."
        )
        return problems, warnings

    text = unit.read_text(errors="replace")
    execstart = ""
    for line in text.splitlines():
        if line.strip().startswith("ExecStart="):
            execstart = line.split("=", 1)[1].strip()
            break
    if not execstart:
        problems.append(f"Unit {unit} has no ExecStart.")
    else:
        # The classic break: a `serve` subcommand that the daemon CLI doesn't have.
        if " serve" in f" {execstart} ":
            problems.append(
                f"Unit ExecStart uses a nonexistent `serve` subcommand: "
                f"`{execstart}`. Re-run `ir add recording` to regenerate it."
            )
        bin_path = execstart.split()[0]
        base = Path(bin_path).name
        if base not in ("inferroute-daemon",):
            warnings.append(
                f"Unit ExecStart runs `{base}`, expected `inferroute-daemon`: `{execstart}`."
            )
        elif not Path(bin_path).exists() and shutil.which(base) is None:
            problems.append(f"Unit ExecStart binary not found: `{bin_path}`.")

    # Live state: catch a crash loop even if the unit text looks fine.
    try:
        out = subprocess.run(
            ["systemctl", "--user", "show", "inferroute-local.service",
             "-p", "ActiveState", "-p", "SubState", "-p", "NRestarts", "-p", "ExecMainStatus"],
            capture_output=True, text=True, timeout=5,
        ).stdout
        props = dict(
            line.split("=", 1) for line in out.splitlines() if "=" in line
        )
        sub = props.get("SubState", "")
        nrestarts = int(props.get("NRestarts", "0") or 0)
        if sub in ("auto-restart", "failed") or props.get("ActiveState") == "failed":
            problems.append(
                f"Daemon is {props.get('ActiveState','?')}/{sub} "
                f"(NRestarts={nrestarts}, last exit={props.get('ExecMainStatus','?')}). "
                f"Check: journalctl --user -u inferroute-local -n 30"
            )
        elif nrestarts >= 20:
            warnings.append(f"Daemon has restarted {nrestarts} times — possible instability.")
    except Exception:
        pass  # systemctl absent / no user bus — unit-file checks above still ran.

    return problems, warnings


@main.command()
@click.argument("transcript_path", required=False)
@click.option("--stdin", "from_stdin", is_flag=True,
              help="Read the Claude Code hook JSON from stdin and use its "
                   "transcript_path (this is how the SessionEnd hook calls it).")
@click.option("--force", is_flag=True, help="Re-ingest from the start, ignoring the progress marker.")
@click.option("--quiet", is_flag=True, help="Print nothing (hook mode).")
def ingest(transcript_path, from_stdin, force, quiet):
    """Ingest a Claude Code transcript into the local corpus as metadata turns.

    The out-of-band content recorder: reads a ~/.claude/projects/**/*.jsonl
    transcript and records inferroute's metadata DELTA (one turn per assistant
    message), never duplicating the transcript content. Idempotent and dep-light
    (no fastapi/uvicorn needed). NEVER blocks Claude Code — always exits 0, even
    on error, so a recorder problem can't wedge a session's SessionEnd hook.
    """
    import json as _json
    from pathlib import Path as _Path
    from . import ingest as _ingest
    from .recorder import Recorder

    try:
        if from_stdin:
            raw = sys.stdin.read()
            try:
                payload = _json.loads(raw) if raw.strip() else {}
            except Exception:
                payload = {}
            transcript_path = (
                _ingest.transcript_path_from_hook_payload(payload) or transcript_path
            )
        if not transcript_path:
            if not quiet:
                click.echo("No transcript path (pass a path or --stdin).", err=True)
            return  # exit 0 — the hook must not fail
        cfg = Config.from_env()
        base = _Path(cfg.record_dir) if cfg.record_dir else _Path.home() / ".inferroute"
        rec = Recorder(
            base, level=cfg.record_level,
            ttl_days=cfg.record_ttl_days, blob_cap_bytes=cfg.record_blob_cap_bytes,
        )
        wire = _load_wire(base, transcript_path)
        summary = _ingest.ingest_transcript(
            _Path(transcript_path), rec, wire=wire, force=force,
        )
        rec.flush()
        if not quiet:
            click.echo(_json.dumps(summary))
    except Exception as e:
        if not quiet:
            click.echo(f"ingest error (ignored): {e}", err=True)
        # Swallow: never break Claude Code's SessionEnd.


def _load_wire(base, transcript_path):
    """Mine the per-session OTEL raw-bodies file for the wire delta (system-prompt
    hash + tool list), then DELETE it so nothing is left behind. Returns a dict
    keyed by request_id (plus a `_session` fallback), or None. Implemented in
    wire.py; absent/empty wire is the normal case (pure-native sessions)."""
    try:
        from .wire import mine_and_consume
        return mine_and_consume(base, transcript_path)
    except Exception:
        return None
