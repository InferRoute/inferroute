"""`ir login` — paste an inferroute API key, save to disk."""

from __future__ import annotations

import sys
from urllib.parse import urlparse

import httpx

from . import config


SIGNUP_URL = "https://inferroute.ai/api-keys"

# inferroute keys (and legacy cdt_ keys) — used for a cheap local sanity check
# before we ever hit the network, so an accidental paste of random text is
# rejected as "invalid" instead of fired at the server.
KEY_PREFIXES = ("inf_", "cdt_")
MAX_ATTEMPTS = 3


def _mask(key: str) -> str:
    """Show enough of the key to confirm a paste registered, without dumping
    the whole secret to the terminal."""
    if len(key) <= 10:
        return (key[:2] + "…") if key else "…"
    return f"{key[:6]}…{key[-4:]}"


def _looks_like_key(key: str) -> bool:
    return key.startswith(KEY_PREFIXES) and len(key) >= 12 and key.isprintable()


def _prompt_key(prompt: str) -> str | None:
    """Read one API key from the terminal with masked, live feedback.

    We read one character at a time in cbreak mode and echo a mask glyph for
    each one, so a paste shows up immediately as a run of dots — the user sees
    that something registered — while the raw key never lands on screen. This
    threads the needle between three failure modes:

    1. *No feedback at all* (full echo-off): newbies think the paste didn't
       take. Here every character draws a ``•``.

    2. *Multi-line paste spilling into the shell*: a pasted blob with newlines
       would, with ``input()``, leave its tail in the terminal queue to be run
       by bash. We stop at the first newline and ``tcflush`` the rest, so it is
       discarded, never executed.

    3. *The secret in scrollback*: only mask glyphs are ever printed; the key
       itself is not echoed.

    Returns the first whitespace-delimited token of the line (the key),
    ``""`` for an empty line, or ``None`` on EOF / Ctrl-C.
    """
    stdin = sys.stdin
    if not stdin.isatty():
        # Piped / non-interactive: just read a line, no terminal tricks.
        line = stdin.readline()
        if not line:
            return None
        line = line.strip()
        return line.split()[0] if line else ""

    import os
    import termios
    import tty

    fd = stdin.fileno()
    mask = "•" if (sys.stdout.encoding or "").lower().startswith("utf") else "*"
    sys.stdout.write(prompt)
    sys.stdout.flush()

    buf: list[str] = []
    cancelled = False
    old = termios.tcgetattr(fd)
    try:
        # char-at-a-time, no echo; Ctrl-C still raises SIGINT. TCSANOW (not the
        # default TCSAFLUSH) so a paste that lands the instant the prompt prints
        # isn't discarded.
        tty.setcbreak(fd, termios.TCSANOW)
        try:
            while True:
                ch = os.read(fd, 1).decode("utf-8", "ignore")
                if ch == "":  # EOF (Ctrl-D on an empty line → cancel)
                    cancelled = not buf
                    break
                if ch in ("\n", "\r"):  # end of line
                    break
                if ch == "\x03":  # Ctrl-C
                    cancelled = True
                    break
                if ch == "\x04":  # Ctrl-D
                    if not buf:
                        cancelled = True
                        break
                    continue
                if ch in ("\x7f", "\b"):  # backspace / delete
                    if buf:
                        buf.pop()
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                    continue
                if ch == "\x1b":  # swallow an escape/CSI seq (arrows, paste markers)
                    if os.read(fd, 1).decode("utf-8", "ignore") == "[":
                        while True:
                            c2 = os.read(fd, 1).decode("utf-8", "ignore")
                            if c2 == "" or "@" <= c2 <= "~":
                                break
                    continue
                if not ch.isprintable():
                    continue
                buf.append(ch)
                if len(buf) <= 80:  # echo a dot; cap so a huge paste can't flood
                    sys.stdout.write(mask)
                    sys.stdout.flush()
        except KeyboardInterrupt:
            cancelled = True
    finally:
        # Drop the tail of a multi-line paste before restoring the terminal,
        # so it can never spill into the shell.
        termios.tcflush(fd, termios.TCIFLUSH)
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        sys.stdout.write("\n")
        sys.stdout.flush()

    if cancelled:
        return None
    line = "".join(buf).strip()
    return line.split()[0] if line else ""


def _verify(api_url: str, key: str) -> tuple[str, int | None]:
    """Probe /v1/models. Returns (status, n_models):
    status ∈ {"ok", "reject", "unreachable"}."""
    try:
        r = httpx.get(
            f"{api_url}/v1/models",
            headers={"x-api-key": key},
            timeout=10.0,
        )
        if r.status_code in (401, 403):
            return "reject", None
        r.raise_for_status()
        return "ok", len((r.json() or {}).get("data") or [])
    except httpx.HTTPError:
        return "unreachable", None


def run(args=None) -> int:
    print()
    print(f"  Sign up + get a key at {SIGNUP_URL}")
    print(f"  Pasting the key here saves it to {config.CREDS_FILE} (mode 600).")
    print()

    api_url = config.DEFAULT_API_URL
    if hasattr(args, "url") and args.url:
        api_url = args.url.rstrip("/")
        if not urlparse(api_url).scheme.startswith("http"):
            sys.stderr.write(f"  ERROR: bad URL: {api_url}\n")
            return 2

    for attempt in range(1, MAX_ATTEMPTS + 1):
        key = _prompt_key("  inferroute API key: ")
        if key is None:  # Ctrl-C / Ctrl-D / EOF
            return 130
        if not key:
            sys.stderr.write("  No key entered. Try again.\n")
            continue
        if not _looks_like_key(key):
            # Caught a fat-fingered paste before it ever touches the network.
            sys.stderr.write(
                "  ✗ invalid API key — expected something starting with "
                f"`inf_`. Try again.\n"
            )
            continue

        print(f"  Verifying key ({_mask(key)})…")
        status, n_models = _verify(api_url, key)

        if status == "reject":
            remaining = MAX_ATTEMPTS - attempt
            tail = f" ({remaining} attempt{'s' if remaining != 1 else ''} left)" if remaining else ""
            sys.stderr.write(f"  ✗ invalid API key — server rejected it.{tail}\n")
            if remaining:
                continue
            sys.stderr.write("  Re-run `ir login` once you have a valid key.\n")
            return 1

        # "ok" or "unreachable" → save. For unreachable we can't confirm the
        # key, but the user clearly has one in hand; persist and let them retry.
        path = config.save(api_key=key, api_url=api_url)
        print(f"  ✓ saved to {path}")
        if status == "ok":
            print(f"  ✓ {n_models} models available")
        else:
            sys.stderr.write(
                f"  ⚠ couldn't reach {api_url} to verify — saved anyway.\n"
            )
        print()
        print("  Try it:")
        print("    ir                   # open the model picker, then launch")
        print("    ir --model minimax   # pin to MiniMax")
        print("    ir status            # see your usage")
        return 0

    return 1
