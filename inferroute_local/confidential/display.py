"""The screen the user sees — and can screenshot. Rendered from the receipt, so it cannot say
more than the receipt holds.

Design intent: calm, legible, a little educational. One green column of things THIS DEVICE
verified, one honest column of what it could not, a diagram of who can read the words, and a
pointer to the receipt file. No marketing adjectives: every line is a checked fact or a stated
limitation.
"""
from __future__ import annotations

from pathlib import Path

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import attest
from .receipt import Receipt

WIDTH = 96
FONT_STACK = "font-family: Menlo, DejaVu Sans Mono, Consolas, Noto Sans Mono, Fira Code, monospace"
ACCENT = "spring_green3"
DIM = "grey58"
AMBER = "dark_orange"


def _short(iid: str, n: int = 8) -> str:
    return (iid or "")[:n] + ("…" if len(iid or "") > n else "")


def _kb(n: int) -> str:
    return f"{n / 1024:.1f} KB" if n < 1024 * 1024 else f"{n / 1024 / 1024:.2f} MB"


def _when(r: Receipt) -> str:
    """'moments ago' only while it is true; a re-printed receipt names its time."""
    import datetime as dt
    try:
        t = dt.datetime.strptime(r.verified_at or r.started_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        return "at session start"
    age = (dt.datetime.now(dt.timezone.utc) - t).total_seconds()
    if age < 120:
        return "moments ago"
    if age < 3600:
        return f"{int(age // 60)} minutes ago"
    return "on " + t.strftime("%Y-%m-%d at %H:%M UTC")


def _width(console: Console) -> int:
    """The panel is designed at 96 columns; on a narrower terminal it folds rather than overflows."""
    return max(60, min(WIDTH, console.width))


def _home(path: str) -> str:
    h = str(Path.home())
    return "~" + path[len(h):] if path.startswith(h) else path


def _title_model(r: Receipt) -> str:
    """The catalog name only — the upstream model key is the provider's naming, and stays on the receipt."""
    fam = r.upstream_model.split("/")[-1].replace("-TEE", "")
    return f"{fam}  [{DIM}](ir --model {r.model_short})[/]"


def checks_table(r: Receipt) -> Table:
    t = Table(box=None, show_header=False, pad_edge=False, padding=(0, 1), expand=False)
    t.add_column(width=2)
    t.add_column(width=31)
    t.add_column(style=DIM)
    for name in attest.REQUIRED + attest.REQUIRED_ONLINE:
        c = r.checks.get(name)
        if c is None:
            continue                       # an older receipt without the online checks
        ok = bool(c.get("ok"))
        label, explain = attest.LABELS[name]
        t.add_row(Text("✓" if ok else "✗", style=ACCENT if ok else "red"),
                  Text(label, style="bold" if ok else "bold red"),
                  Text(explain if ok else f"FAILED — {c.get('why', 'not checked')}"))
    e = r.e2ee or {}
    t.add_row(Text("✓", style=ACCENT), Text("Post-quantum key exchange", style="bold"),
              Text(f"{e.get('kem', 'ML-KEM-768')} + {e.get('aead', 'ChaCha20-Poly1305')}, keys made here"))
    return t


def flow_diagram(r: Receipt) -> Text:
    direct = "direct" in (r.transport or "")
    line = Text()
    line.append("  you ", style="bold")
    line.append("──────▶ ", style=DIM)
    if not direct:
        line.append("InferRoute ", style="bold")
        line.append("──────▶ ", style=DIM)
    line.append("enclave operator ", style="bold")
    line.append("──────▶ ", style=DIM)
    line.append("🔒 enclave", style=f"bold {ACCENT}")
    line.append("\n  every arrow carries ciphertext only", style=DIM)
    line.append("\n  can read the words:  ", style=DIM)
    line.append("this device", style="bold")
    line.append(" · ")
    line.append("the enclave", style=f"bold {ACCENT}")
    line.append("\n  cannot:              ", style=DIM)
    parts = ([] if direct else ["InferRoute"]) + ["the enclave operator", "the cloud host", "the network"]
    line.append(" · ".join(parts), style=DIM)
    return line


def limitations_block(r: Receipt) -> Table:
    t = Table(box=None, show_header=False, pad_edge=False, padding=(0, 1), expand=False)
    t.add_column(width=2)
    t.add_column(style=DIM, overflow="fold")
    for lim in r.limitations:
        glyph, style = ("◐", AMBER) if lim["id"] == "attributed-key" else ("○", DIM)
        text = lim["text"]
        t.add_row(Text(glyph, style=style), Text(text))
    return t


def facts_table(r: Receipt) -> Table:
    t = Table(box=None, show_header=False, pad_edge=False, padding=(0, 2), expand=False)
    t.add_column(style=DIM, width=10)
    t.add_column()
    inst = r.instance or {}
    t.add_row("Model", Text.from_markup(_title_model(r)))
    gpus = inst.get("gpu_count") or 0
    per = inst.get("gpus") or {}
    model = "/".join(sorted({str(g.get("hwmodel") or "") for g in per.values()} - {""})) if per else ""
    t.add_row("Enclave", f"Intel TDX confidential VM · {gpus}× NVIDIA {model + ' ' if model else ''}GPU (confidential computing)")
    t.add_row("Instance", "one enclave, verified, then pinned for this whole session")
    t.add_row("Build", "the enclave's measured image matches the provider's published measurements")
    t.add_row("Carrier", r.transport)
    return t


def render_panel(r: Receipt, console: Console | None = None) -> None:
    console = console or Console()
    if r.verdict != "confidential":
        render_refusal(r, console)
        return
    head = Text("Your words are encrypted on this machine and can only be opened inside a hardware enclave "
                f"that this machine verified itself, {_when(r)} — not on anyone's word.", style="bold")
    body = Group(
        head, Text(""),
        facts_table(r), Text(""),
        Text("Verified from this device", style=f"bold {ACCENT}"),
        checks_table(r), Text(""),
        Text("Who can read your words", style="bold"),
        flow_diagram(r), Text(""),
        Text("What this does not prove — we would rather say it than let you assume it", style=f"bold {AMBER}"),
        limitations_block(r), Text(""),
        Text.assemble(("Receipt  ", DIM), (_home(str(r.path)), DIM)),
    )
    console.print(Panel(body, title="[bold]🔒 InferRoute · Confidential session[/]",
                        subtitle=f"[{DIM}]verified {r.verified_at or r.started_at} · session {r.session_id[:8]}[/]",
                        border_style=ACCENT, box=box.ROUNDED, width=_width(console), padding=(1, 2)))


def render_refusal(r: Receipt, console: Console | None = None) -> None:
    console = console or Console()
    body = Group(
        Text("This session was NOT opened. Nothing was sent.", style="bold red"),
        Text(""),
        Text(f"Reason: {r.refusal or r.verdict}", style="bold"),
        Text(""),
        Text("The confidential lane refuses rather than degrades: if the enclave cannot be verified from\n"
             "this device, no request leaves it. Try again in a minute; if it persists, tell us.", style=DIM),
        Text(""),
        Text.assemble(("Receipt  ", DIM), (_home(str(r.path)), DIM)),
    )
    console.print(Panel(body, title="[bold red]⛔ InferRoute · Confidential session refused[/]",
                        border_style="red", box=box.ROUNDED, width=_width(console), padding=(1, 2)))


def render_summary(r: Receipt, console: Console | None = None) -> None:
    console = console or Console()
    c = r.counters
    head = Text()
    head.append("🔒 Confidential session closed", style=f"bold {ACCENT}")
    head.append(f"  ·  {c['requests']} request{'s' if c['requests'] != 1 else ''}", style="bold")
    head.append(f"  ·  {_kb(c['plaintext_bytes_sealed_here'])} sealed here  ·  {_kb(c['response_bytes_opened_here'])} opened here", style=DIM)
    if c.get("instance_switches"):
        head.append(f"  ·  {c['instance_switches']} instance switch(es)", style=AMBER)
    if c.get("errors"):
        head.append(f"  ·  {c['errors']} error(s)", style="red")
    console.print(head, soft_wrap=True)
    console.print(Text("   plaintext that left this device: 0 bytes", style=DIM), soft_wrap=True)
    console.print(Text(f"   receipt: {_home(str(r.path))}", style=DIM), soft_wrap=True)


# Short column heads for the operator fleet table (offline | online), in check order.
FLEET_COLS = {"nonce_in_body": "nonce", "sig_ok": "sig", "spki_bound": "spki", "e2e_key_bound": "key", "tdx_shape": "tdx",
              "measurement_ok": "build", "chain_ok": "chain", "quote_sig": "qsig", "root_pinned": "root", "not_revoked": "crl",
              "tcb_current": "tcb", "qe_current": "qe", "gpu_in_signed_evidence": "gpu∈sig", "gpu_verified": "gpu"}


def render_fleet(fleet: attest.FleetReport, console: Console | None = None) -> None:
    console = console or Console()
    t = Table(title=f"Attestation — chute {fleet.chute_id[:8]}… · nonce {fleet.nonce[:8]}…", box=box.SIMPLE_HEAD,
              title_style="bold", header_style=DIM)
    t.add_column("instance")
    t.add_column("GPUs", justify="right")
    for name in attest.REQUIRED + attest.REQUIRED_ONLINE:
        t.add_column(FLEET_COLS.get(name, name), justify="center")
    t.add_column("verdict", no_wrap=True)
    for i in fleet.instances:
        cells = [(Text("✓", style=ACCENT) if i.checks[n].ok else Text("✗", style="red")) if n in i.checks else Text("·", style=DIM)
                 for n in attest.REQUIRED + attest.REQUIRED_ONLINE]
        if i.verified:
            verdict = Text("verified", style=f"bold {ACCENT}")
        elif i.failing == ["e2e_key_bound"] and "no encryption key" in i.checks["e2e_key_bound"].why:
            verdict = Text("no key offered", style=DIM)   # attested but not sealable — not a fault, just not usable
        else:
            verdict = Text("FAILED " + ",".join(i.failing), style="red")
        t.add_row(_short(i.instance_id, 8), str(i.gpu_count), *cells, verdict)
    console.print(t)
    console.print(Text("offline: nonce sig spki key tdx build chain · online: qsig root crl tcb qe gpu∈sig gpu · '·' = not run (no sealing key)", style=DIM))
    if fleet.failed_instance_ids:
        console.print(Text(f"instances the provider itself reports as failed: {fleet.failed_instance_ids}", style=DIM))


def save_svg(r: Receipt, path: Path) -> Path:
    """A shareable card: the panel, rendered into a self-contained SVG (terminal chrome included)."""
    import io
    console = Console(record=True, width=WIDTH, force_terminal=True, color_system="truecolor", file=io.StringIO())
    render_panel(r, console)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    console.save_svg(str(path), title="InferRoute · Confidential session")
    # rich's template names Fira Code alone; viewers without it fall back to a font that may lack
    # the box-drawing and check glyphs (rendered as boxes). Name common monospace faces that have
    # them on each platform so the card looks right wherever it is opened.
    svg = path.read_text()
    svg = svg.replace("font-family: Fira Code, monospace", FONT_STACK).replace('font-family="Fira Code, monospace"', f'font-family="{FONT_STACK.split(": ", 1)[1]}"')
    path.write_text(svg)
    return path
