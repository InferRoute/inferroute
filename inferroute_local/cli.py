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
import uvicorn

from . import credentials
from .config import Config
from .server import create_app

# Where the user creates / manages keys
KEYS_URL = "https://inferroute.ai/dashboard/api-keys"


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
    click.echo(f"minimax model:  {config.minimax_model}")
    if config.kimi_model:
        click.echo(f"kimi model:     {config.kimi_model} (legacy)")
    if config.glm_model:
        click.echo(f"glm model:      {config.glm_model} (legacy)")


@main.command()
@click.option("--watch", is_flag=True, help="Refresh every 2s")
@click.option("--reset", is_flag=True, help="Clear all counters before reporting")
def stats(watch, reset):
    """Show routing-decision counters from the running daemon."""
    config = Config.from_env()
    url = f"http://{config.host}:{config.port}/stats"
    if reset:
        try:
            httpx.get(url, params={"reset": 1}, timeout=2)
            click.echo("Counters reset.")
        except Exception as e:
            click.echo(f"Could not reach daemon: {e}", err=True); return

    import time as _t
    while True:
        try:
            data = httpx.get(url, timeout=2).json()
        except Exception as e:
            click.echo(f"Could not reach daemon: {e}", err=True); return
        click.clear() if watch else None
        click.echo(f"uptime: {data['uptime_seconds']:.0f}s   total: {data['total_requests']}   rate: {data['rate_per_min']}/min")
        click.echo("─" * 60)
        if not data["by_route"]:
            click.echo("  (no requests yet — send one through the daemon to see stats)")
        for route, info in sorted(data["by_route"].items(), key=lambda kv: -kv[1]["total"]):
            click.echo(f"  {route:20s} {info['total']:5d}")
            for reason, n in sorted(info["by_reason"].items(), key=lambda kv: -kv[1]):
                click.echo(f"      {reason:30s} {n}")
        comp = data.get("compression") or {}
        if comp.get("requests_compressed"):
            click.echo("─" * 60)
            click.echo(
                f"  compression: {comp['tokens_before']:,} → {comp['tokens_after']:,} tokens "
                f"(saved {comp['tokens_saved']:,} / {comp['reduction_ratio']*100:.1f}%) "
                f"over {comp['requests_compressed']:,} reqs"
            )
            by = comp.get("saved_by_route") or {}
            if by:
                click.echo("      saved by route: " + "  ".join(
                    f"{r}={n:,}" for r, n in sorted(by.items(), key=lambda kv: -kv[1])
                ))
        if data.get("recent"):
            click.echo("\n  Last 20 decisions:")
            for r in data["recent"]:
                ts = _t.strftime("%H:%M:%S", _t.localtime(r["ts"]))
                click.echo(f"    {ts}  {r['route']:18s} {r['reason']:25s} files={r['files']} ratio={r['context_ratio']}")
        if not watch:
            return
        _t.sleep(2)


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
    binary = shutil.which("inferroute") or str(Path.home() / ".local/bin/inferroute")
    unit_path.write_text(f"""[Unit]
Description=inferroute-local daemon (Claude Code proxy on :{port})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={binary}
Environment=INFERROUTE_HOST=127.0.0.1
Environment=INFERROUTE_PORT={port}
# INFERROUTE_API_KEY is read from ~/.inferroute/credentials.json by default;
# uncomment + set here if you'd rather pin it explicitly.
#Environment=INFERROUTE_API_KEY=inf_xxx
Restart=always
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
    """Diagnose common configuration issues."""
    config = Config.from_env()
    if not config.inferroute_api_key:
        config.inferroute_api_key = credentials.get_api_key()

    problems = []
    if not config.inferroute_api_key:
        problems.append("No INFERROUTE_API_KEY env or saved token. Run `inferroute login`.")
    try:
        httpx.get(f"{config.inferroute_base_url if hasattr(config,'inferroute_base_url') else config.inferroute_server_url}/", timeout=3)
    except Exception as e:
        problems.append(f"inferroute-server unreachable: {e}")
    try:
        httpx.get(f"{config.anthropic_base_url}/v1/models", timeout=3)
    except Exception:
        pass  # Anthropic doesn't expose /v1/models; fine

    if problems:
        for p in problems:
            click.echo(f"  ✗ {p}")
        sys.exit(1)
    click.echo("All checks passed.")
