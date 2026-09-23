"""`ir cline` — seal a Cline session, as far as Cline lets anyone.

Cline is the only agent besides Pi with a pre-request hook (`beforeModel`, which can abort), so it is the
only other one where we can refuse rather than merely report. But its OpenAI-compatible provider is a
settings-panel form: the published `cline` package carries CLINE_DIR, CLINE_DATA_DIR and CLINE_BIN_PATH
and no base-URL or provider variable, and the docs describe no file or flag for it. Writing that config
from here would mean guessing at internal state.

So the work is split the only way it can be. We hand over the two values Cline's form needs, and ship a
plugin that refuses every model request while the session is not sealed — so a wrong value fails closed
instead of quietly sending somewhere readable.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path


def plugin_path() -> Path:
    return Path(__file__).parent / "cline_attested" / "ir-attested-cline.ts"


def cmd_cline(rest: list[str]) -> int:
    from . import confidential_daemon as daemon

    st = daemon.running()
    if not st or not st.get("serving"):
        sys.stderr.write(
            "\n  No confidential daemon is running, and Cline cannot be pointed at a session that ends\n"
            "  with this command — its provider is configured in its own settings panel, which outlives\n"
            "  any one launch.\n\n"
            "      ir confidential daemon start\n\n"
            "  Then run this again.\n\n")
        return 2

    base = f"http://127.0.0.1:{st['port']}/v1"
    print("\n  🔒 Point Cline at this session\n")
    print("     Cline settings → API Provider: OpenAI Compatible\n")
    print(f"       Base URL   {base}")
    print(f"       API Key    {st['token']}")
    print(f"       Model      {st['model']}\n")
    print("     These are for this daemon only. Stopping it makes the key useless.\n")
    print("  Then install the guard, so a wrong value refuses instead of sending:\n")
    print(f"       cline plugin install {plugin_path()}\n")
    print("     It calls this endpoint before every model request and stops the request when the\n"
          "     session is not sealed. Cline has no way to send without passing it.\n")
    if not shutil.which("cline"):
        print("  (`cline` is not on PATH here — install it first: npm i -g cline)\n")
    return 0
