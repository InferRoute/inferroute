"""What an attorney is told about a Surveyor session's protection — in plain words, derived from checks.

One summary, rendered twice: as the terminal card `ir surveyor open` shows before the agent starts, and as
the trust panel of the local browser page (`ir surveyor open --web`). Both read the dict `build()` returns,
so the two surfaces cannot say different things.

The rules this module keeps:

- Every ✓ comes from a check that ran for THIS launch: the model enclave's receipt, the search verifier's
  live `/enclave` result, the confinement label the launcher decided. No line is drawn from intent.
- A plain sentence may only claim what its check proves. Where the honest sentence is conditional (the AI
  machine's software; what any machine does with data it holds), the condition is on the page, not in a
  footnote the reader must go looking for.
- The operator of the AI machine is "its operator". The page never names a provider or prints a host.
- The technical detail is kept, one level down (`technical` rows, `ir surveyor proof`), for the reader who
  wants it. It is never the first thing a reader meets.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Item states. "info" is for lines that describe how the session works rather than a check.
OK, WARN, FAIL, OFF, INFO = "ok", "warn", "fail", "off", "info"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hhmm(iso: str) -> str:
    """Local wall-clock HH:MM for a UTC ISO stamp — the reader's clock, not UTC."""
    try:
        return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).astimezone().strftime("%H:%M")
    except (TypeError, ValueError):
        return (iso or "")[11:16]


def _check(receipt: Any, name: str) -> Optional[dict]:
    c = (getattr(receipt, "checks", None) or {}).get(name)
    return c if isinstance(c, dict) else None


def _ok(receipt: Any, name: str) -> bool:
    c = _check(receipt, name)
    return bool(c and c.get("ok"))


def ai_item(receipt: Any) -> Dict[str, Any]:
    from inferroute_local.confidential import attest
    names = [n for n in (*attest.REQUIRED, *attest.REQUIRED_ONLINE) if _check(receipt, n) is not None]
    technical = [{"label": (_check(receipt, n) or {}).get("label") or attest.LABELS.get(n, (n, ""))[0],
                  "ok": _ok(receipt, n), "value": str((_check(receipt, n) or {}).get("why", ""))} for n in names]
    verified = getattr(receipt, "verdict", "") == "confidential" and bool(names) and all(_ok(receipt, n) for n in names)
    if not verified:
        reason = getattr(receipt, "refusal", "") or "the checks did not pass"
        return {"key": "ai", "state": FAIL, "title": "AI assistant",
                "summary": "Could not be verified, so nothing was sent to it.",
                "points": [f"Reason: {reason}."], "more": [], "technical": technical}
    more = []
    if _ok(receipt, "tdx_shape"):
        gpus = " Its GPUs were checked by NVIDIA." if _ok(receipt, "gpu_verified") else ""
        more.append("Genuine sealed hardware (Intel TDX), with debugging switched off." + gpus)
    if _ok(receipt, "build_recorded"):
        more.append("It runs a software build InferRoute has on record, not only its operator's word.")
    if _ok(receipt, "e2e_key_bound"):
        more.append("Your text is encrypted on this computer to a key only that machine holds. "
                    "InferRoute, the network and the cloud host see scrambled data.")
    points = []
    if _ok(receipt, "tdx_shape") and _ok(receipt, "build_recorded"):
        points.append("Genuine sealed hardware, running a build InferRoute has on record.")
    if _ok(receipt, "e2e_key_bound"):
        points.append("Your text is encrypted here; only that machine can open it.")
    warn_ids = {"new-build", "pending-build"}
    caveats = [str(lim.get("text", "")) for lim in (getattr(receipt, "limitations", None) or [])
               if isinstance(lim, dict) and lim.get("id") in warn_ids]
    return {"key": "ai", "state": WARN if caveats else OK, "title": "AI assistant",
            "summary": "Sealed machine, checked at "
                       f"{_hhmm(getattr(receipt, 'verified_at', '') or getattr(receipt, 'started_at', ''))}.",
            "points": points + caveats, "more": more + caveats, "technical": technical}


def _plain_search_refusal(refusal: str) -> str:
    r = (refusal or "").lower()
    if any(m in r for m in ("did not answer", "unreachable", "connection", "timed out", "timeout", "refused to connect")):
        return "The search machine isn't answering; it may not be running right now."
    return f"Reason: {refusal or 'the checks did not pass'}."


IDENTITY_STEP = "enclave identity"


def search_is_inferroutes(search: Optional[dict]) -> bool:
    """Two facts, both required: the signed reference is authentic (signature and kind, checked by the
    verifier at startup) AND this enclave matches it (the identity step, run live). The first alone would
    assert an identity nobody compared against the machine."""
    if not search or not search.get("ok"):
        return False
    authentic = bool((search.get("reference") or {}).get("ok"))
    matched = any(isinstance(st, dict) and str(st.get("step", "")).startswith(IDENTITY_STEP) and st.get("ok")
                  for st in search.get("steps") or [])
    return authentic and matched


def search_item(search: Optional[dict], date_bound: str = "") -> Dict[str, Any]:
    if search is None:
        return {"key": "search", "state": OFF, "title": "Patent search",
                "summary": "Not set up on this computer, so the assistant can't search.",
                "points": [], "more": ["You can still work with the assistant on the disclosure."], "technical": []}
    steps = search.get("steps") or []
    technical = [{"label": str(s.get("step", "")), "ok": bool(s.get("ok")), "value": str(s.get("detail", ""))}
                 for s in steps if isinstance(s, dict)]
    if not search.get("ok"):
        return {"key": "search", "state": FAIL, "title": "Patent search",
                "summary": "Could not be verified, so no search will be sent.",
                "points": [_plain_search_refusal(str(search.get("refusal") or ""))], "more": [], "technical": technical}
    enclave = search.get("enclave") or {}
    ref = {"ok": search_is_inferroutes(search)}
    identity = ("running exactly the software InferRoute published (signed reference checked)" if ref.get("ok")
                else f"running exactly the software this computer expects (fingerprint {str(enclave.get('host_data', ''))[:8]})")
    points = [f"Genuine sealed hardware, {identity}."]
    if date_bound:
        points.append(f"Only documents published before {date_bound}; the assistant can't change that.")
    more = ["Genuine sealed hardware (AMD SEV-SNP on Microsoft Azure), confirmed with AMD's and Microsoft's own keys.",
            ("It runs exactly the software InferRoute published, checked against InferRoute's signed reference."
             if ref.get("ok") else
             "It runs exactly the software this computer is set up to expect. Once the signed reference is checked "
             "here, this line will say it is InferRoute's published software."),
            "Your search text is encrypted here and only that machine can open it; each answer comes back "
            "encrypted to this computer alone."]
    if date_bound:
        more.append(f"Only documents published before {date_bound} are returned. The limit is kept on this "
                    "computer, out of the assistant's reach.")
    if search.get("test_roots"):
        return {"key": "search", "state": WARN, "title": "Patent search",
                "summary": "TEST machine: checked against test keys, not a real verification.",
                "points": points, "more": more, "technical": technical}
    return {"key": "search", "state": OK, "title": "Patent search",
            # "run by InferRoute" is an identity claim: only the signed reference, checked here, earns it.
            "summary": (f"Sealed machine run by InferRoute, checked at {_hhmm(_now())}." if ref.get("ok")
                        else f"Sealed machine, checked at {_hhmm(_now())}."),
            "points": points, "more": more, "technical": technical}


BROWSER_POINT = ("This page is served by this computer alone. It loads nothing from the internet and never turns "
                 "what the assistant writes into a link.")


def computer_item(confinement: str, surface: str = "terminal") -> Dict[str, Any]:
    label = confinement or ""
    technical = [{"label": "confinement", "ok": True, "value": label}]
    browser = [BROWSER_POINT] if surface == "browser" else []
    if label.startswith("require, address-level"):
        return {"key": "computer", "state": OK, "title": "This computer",
                "summary": "The assistant works in a closed box.",
                "points": ["No internet, and no files beyond this matter's folder."] + browser,
                "more": ["It has no internet connection. Its only ways out are the two sealed machines above, "
                         "through this computer's own checks.",
                         "It sees only this matter's folder. Your other files don't exist inside the box."] + browser,
                "technical": technical}
    if label.startswith("unconfined") or label == "not confined":
        return {"key": "computer", "state": FAIL, "title": "This computer",
                "summary": "NOT boxed (developer mode). Don't use this with a client matter.",
                "points": ["The assistant could reach the internet and read other files."],
                "more": [], "technical": technical}
    return {"key": "computer", "state": WARN, "title": "This computer",
            "summary": "The assistant is only partly boxed.",
            "points": ["It can read other files here; the full box needs a one-time setup on this machine."],
            "more": ["Its network is limited by port number rather than by address, and file reads are not "
                     "confined. Run scripts/install-confine-profile.sh once (it needs an administrator)."],
            "technical": technical}


def control_item(matter: str) -> Dict[str, Any]:
    return {"key": "control", "state": INFO, "title": "You decide",
            "summary": "No search leaves without your OK. Marks and the record are yours.",
            "points": [],
            "more": ["The first search to each search machine waits for your approval, and shows you the text.",
                     "Relevance marks are yours alone: the assistant can't make or change them.",
                     "When you're done, export a record anyone can check without trusting InferRoute."],
            "technical": []}


EXPLAINER = ("A sealed machine encrypts its own memory with a key held by its chip, so even the people who run it "
             "can't look inside. This computer checks each machine's hardware signature before sending it anything.")


def limits(search_state: str, search_is_ours: bool = False, surface: str = "terminal") -> List[str]:
    search_sw = ("The search machine runs InferRoute's own published software; " if search_is_ours else
                 "The search machine runs the software this computer expects; ")
    out = ["The chips prove where your text can be read, not what the software there does with it. "
           + (search_sw + "the AI machine runs its operator's published software, which InferRoute re-checks in part."
              if search_state in (OK, WARN) else
              "The AI machine runs its operator's published software, which InferRoute re-checks in part."),
           "The services in between can see when you work and how much you send, never the words."]
    if search_state in (OK, WARN):
        out.append("A search finds related documents. It doesn't prove novelty, or that nothing else exists.")
    if surface == "browser":
        out.append("Browser extensions allowed to read every page can read this one too. For client matters, use "
                   "a browser profile without extensions.")
    return out


def build(receipt: Any, search: Optional[dict], confinement: str, *, matter: str = "", date_bound: str = "",
          surface: str = "terminal") -> Dict[str, Any]:
    """`surface`: "terminal" or "browser" — the browser page adds what it guarantees and what it can't."""
    items = [ai_item(receipt), search_item(search, date_bound), computer_item(confinement, surface), control_item(matter)]
    states = {i["key"]: i["state"] for i in items}
    if states["ai"] == FAIL:
        verdict, headline = "blocked", "Not opened: the AI machine could not be verified, so nothing was sent."
    elif any(states[k] in (FAIL, WARN) for k in ("ai", "search", "computer")) or states["search"] == OFF:
        verdict, headline = "limited", "Partly protected. Read the items marked below before using a client's invention."
    else:
        verdict, headline = "private", ("Private: your client's invention can be read only on this computer and "
                                        "inside two sealed machines, both checked just now.")
    return {"schema": "inferroute.surveyor-trust/1", "verdict": verdict, "headline": headline, "explainer": EXPLAINER,
            "items": items,
            "limits": limits(states["search"], search_is_inferroutes(search), surface), "surface": surface, "matter": matter, "date_bound": date_bound, "checked_at": _now()}


# ───────────────────────── terminal ─────────────────────────

_MARK = {OK: ("✓", "spring_green3"), WARN: ("◐", "dark_orange"), FAIL: ("✗", "red"), OFF: ("○", "grey58"), INFO: ("●", "grey70")}


def render_card(summary: Dict[str, Any], console: Any = None) -> None:
    from rich import box
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    console = console or Console()
    colour = {"private": "spring_green3", "limited": "dark_orange", "blocked": "red"}[summary["verdict"]]
    t = Table(box=None, show_header=False, pad_edge=False, padding=(0, 1), expand=False)
    t.add_column(width=2)
    t.add_column(width=15)
    t.add_column(overflow="fold")
    for it in summary["items"]:
        sym, style = _MARK[it["state"]]
        t.add_row(Text(sym, style=style), Text(it["title"], style="bold"), Text(it["summary"], style="bold" if it["state"] in (FAIL, WARN) else None))
        for w in it["points"]:
            t.add_row(Text(""), Text(""), Text(w, style="grey58"))
    lim = Table(box=None, show_header=False, pad_edge=False, padding=(0, 1), expand=False)
    lim.add_column(width=2)
    lim.add_column(overflow="fold", style="grey58")
    for line in summary["limits"]:
        lim.add_row(Text("○", style="grey58"), Text(line))
    title = "🔒 " + (summary.get("matter") or "Surveyor session").replace("/", " / ")
    body = Group(Text(summary["headline"], style=f"bold {colour}"), Text(summary["explainer"], style="grey58"), Text(""), t, Text(""),
                 Text("What this can't prove", style="bold"), lim, Text(""),
                 Text(f"Full technical proof: ir surveyor proof {summary.get('matter') or ''}".rstrip(), style="grey58"))
    width = min(console.width, 88)
    console.print(Panel(body, title=f"[bold]{title}[/]", subtitle=f"[grey58]checked {summary['checked_at']}[/]",
                        border_style=colour, box=box.ROUNDED, width=width, padding=(1, 2)))


def render_howto(matter: str, console: Any = None) -> None:
    from rich.console import Console
    from rich.text import Text
    console = console or Console()
    rows = [("In the session", "ask for a prior-art survey of the disclosure in this folder"),
            ("", "/relevant US-1234567-B2  mark a result (also /not-relevant, /known, /marks)"),
            ("", "/proof  show the checks again · Ctrl+C twice to leave"),
            ("Afterwards", f"ir surveyor export {matter}   the record to keep")]
    for head, text in rows:
        console.print(Text.assemble((f"  {head:<16}", "bold"), (text, "grey70")), soft_wrap=True)
    console.print("")
