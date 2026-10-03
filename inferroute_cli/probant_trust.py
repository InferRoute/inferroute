"""What the user is told about a Probant session's protection — in plain words, derived from checks.

One summary, rendered twice: as the terminal card `ir probant open` shows before the agent starts, and as
the trust panel of the local browser page (`ir probant open --web`). Both read the dict `build()` returns,
so the two surfaces cannot say different things.

The rules this module keeps:

- Every ✓ comes from a check that ran for THIS launch: the model enclave's receipt, the search verifier's
  live `/enclave` result, the confinement label the launcher decided. No line is drawn from intent.
- A plain sentence may only claim what its check proves. Where the honest sentence is conditional (the AI
  machine's software; what any machine does with data it holds), the condition is on the page, not in a
  footnote the reader must go looking for.
- The operator of the AI machine is "its operator". The page never names a provider or prints a host.
- The technical detail is kept, one level down (`technical` rows, `ir probant proof`), for the reader who
  wants it. It is never the first thing a reader meets.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Item states. "info" is for lines that describe how the session works rather than a check.
OK, WARN, FAIL, OFF, INFO = "ok", "warn", "fail", "off", "info"


def machines_served(receipt) -> int:
    """How many DISTINCT enclaves served this session, from the record rather than from intent.

    Not a continuity question. Measured across 955 receipts on one device, 20% of sessions were already
    served by more than one machine — up to five — because a session re-pins when its instance stops
    offering nonces or fails a re-check. "Only that machine can open it" was shown to those users too.
    """
    seen = set()
    for row in (getattr(receipt, "served_by", None) or []):
        iid = ((row or {}).get("instance") or {}).get("id")
        if iid:
            seen.add(iid)
    if not seen:
        inst = (getattr(receipt, "instance", None) or {}).get("id")
        return 1 if inst else 0
    return len(seen)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _hhmm(iso: str) -> str:
    """Local wall-clock HH:MM for a UTC ISO stamp — the reader's clock, not UTC."""
    try:
        return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).astimezone().strftime("%H:%M")
    except (TypeError, ValueError):
        return (iso or "")[11:16]


def _local_stamp(iso: str) -> str:
    try:
        return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).astimezone().strftime("%d %b %Y, %H:%M")
    except (TypeError, ValueError):
        return iso


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
    more = ["The assistant program runs on this computer; the AI model answers inside sealed hardware."]
    if _ok(receipt, "tdx_shape"):
        gpus = " Its GPUs were checked by NVIDIA." if _ok(receipt, "gpu_verified") else ""
        more.append("Genuine sealed hardware (Intel TDX), with debugging switched off." + gpus)
    if _ok(receipt, "build_recorded"):
        more.append("Its measured firmware and start-up match a build InferRoute has on record. "
                    "This does not measure all the software that handles your text.")
    # "IS ANYTHING KEPT?" — asked by four of five naive readers and answered on no screen. One of them:
    # "It says opened, never says deleted. Does it sit there?" It is the question a person with an
    # unfiled invention actually has, and the card talked about encryption instead.
    #
    # The honest answer differs by lane and the difference is the point. For the SEARCH machine there is
    # a signed, graded plaintext-handling contract: logging, crash dumps and unencrypted scratch are
    # denied by the policy the hardware signature covers. For the AI machine there is nothing
    # comparable — retention is its operator's claim, which is exactly what attest.LIMITATIONS
    # build-review already says in a parenthetical nobody reaches.
    # Where it belongs: a description of how the session behaves, beside the other descriptions, not
    # filed under Limitations where the word itself told four readers it was bad news.
    more.append("A session is not tied to one machine. If the one serving it stops responding, this "
                "computer checks another and the session continues there — which may mean a different "
                "model. Each is checked before anything is sent to it, and the receipt names them all.")
    if _ok(receipt, "e2e_key_bound"):
        more.append("Your text is encrypted on this computer to a key the machine's own hardware report "
                    "commits to. The network receives ciphertext; software inside the machine handles plaintext.")
    points = []
    if _ok(receipt, "tdx_shape") and _ok(receipt, "build_recorded"):
        # "SO WHICH IS IT — YOU CHECKED WHAT'S RUNNING, OR YOU CHECKED THE DOORFRAME AND NOT THE ROOM?"
        # A reader put that to the old tick, which said "running a build InferRoute has on record" while
        # the limitation underneath said the measurements cover firmware, boot chain and a short list of
        # configuration files, NOT the filesystem the model runs from. Both were written by us and they
        # do not agree; the tick was claiming the room.
        points.append("Genuine sealed hardware. The parts of its software that are measured — firmware "
                      "and start-up — match a build InferRoute has on record.")
    if _ok(receipt, "e2e_key_bound"):
        # THE CONDITION IS ON THE PAGE, which is this module's own rule and the one this sentence broke.
        # It read "only that machine can open it" — singular, unconditional. A session re-pins whenever
        # its machine stops offering nonces or fails a re-check, so across 955 receipts on one device
        # 20% were served by MORE THAN ONE machine, up to five. Those users were shown the singular
        # sentence too. This is a correction, not a concession to a new feature.
        #
        # What survives is the guarantee that was always the real one and is stronger than it sounds:
        # never an UNVERIFIED machine. The count is stated rather than hedged, so the ordinary
        # single-machine session still says something definite.
        # THE COUNT WAS NEVER THE GUARANTEE. Henry, 2026-09-30: "i dont understand why allowing
        # machines to switch has to weaken the claim." It does not, and four rounds of wording were
        # spent on a problem I invented.
        #
        # Every request is sealed to ONE machine's key (session.py: seal_request(pinned.pubkey_b64)),
        # and `e2e_key_bound` verifies that that machine's hardware quote commits to that key before
        # anything is sent. So for every request, exactly one machine can open it, and it proved it held
        # the key first. That is identical whether a session uses one machine or five.
        #
        # The old sentence conflated the guarantee — only verified hardware can open your text — with an
        # incidental fact about how many machines happened to be involved. Conditioning it meant
        # apologising for a number that was never the promise, and the readers reacted to the apology
        # rather than to any risk: "the effort is what worries me."
        #
        # So: the guarantee is stated unconditionally, and the count is reported as a fact, the way a
        # meter reading is. It is NOT a limitation — a limitation is something we cannot prove, and this
        # is something we do and can show.
        n = machines_served(receipt)
        points.append("Your text leaves this computer encrypted, and can be opened only inside hardware "
                      "this computer checked first.")
        # A COUNT UNDER A TICK READS AS A PROMISE. The fifth reader: "'One machine has opened it' up
        # top versus 'a session is not tied to one machine' — one, or several? Which is it?" Both were
        # true and they still fought, because a ✓ announces a guarantee and this is data. Written as a
        # field, which nobody reads as a promise.
        # ONE LINE, so there is no second statement to argue with. As a separate line the count kept
        # reading as a guarantee — "I read it as a guarantee the first time. It isn't" — because it sat
        # beside a description saying another machine may take over. Merged, it is plainly a running
        # count with its own condition attached.
        points.append(f"Machines that have opened it so far: {n}. If one stops responding another takes "
                      f"over, checked the same way first; the receipt names them all.")
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


def search_item(search: Optional[dict], date_bound: str = "", mode: str = "matter") -> Dict[str, Any]:
    if search is None and mode == "intake":
        # Reading a document is not searching, and saying "not set up" here would be false as well as
        # alarming: no search tool is offered in this mode, so none can be used.
        return {"key": "search", "state": INFO, "title": "Patent search",
                "summary": "Not used while reading a document.",
                "points": ["The assistant has no search tool in this mode, so nothing about the document can "
                           "leave for a search machine."],
                "more": ["Open a matter from what it proposes, and the search machine is checked then."],
                "technical": []}
    if search is None:
        return {"key": "search", "state": OFF, "title": "Patent search",
                "summary": "Not set up on this computer — nothing can leave for a search machine.",
                "points": ["The assistant cannot search, and cannot send any of this matter anywhere."],
                "more": ["You can still work with the assistant on the disclosure.",
                         "Set a search machine up when you want prior art; this computer will check it then."],
                "technical": []}
    steps = search.get("steps") or []
    technical = [{"label": str(s.get("step", "")), "ok": bool(s.get("ok")), "value": str(s.get("detail", ""))}
                 for s in steps if isinstance(s, dict)]
    if not search.get("ok"):
        return {"key": "search", "state": FAIL, "title": "Patent search",
                "summary": "Could not be verified, so no search will be sent.",
                "points": [_plain_search_refusal(str(search.get("refusal") or ""))], "more": [], "technical": technical}
    enclave = search.get("enclave") or {}
    ref = {"ok": search_is_inferroutes(search)}
    identity = ("with a deployment fingerprint matching InferRoute's signed reference" if ref.get("ok")
                else f"with the deployment fingerprint this computer expects ({str(enclave.get('host_data', ''))[:8]})")
    points = [f"Genuine sealed hardware, {identity}."]
    if date_bound:
        points.append(f"Only documents published before {date_bound}; the assistant can't change that.")
    more = ["Genuine sealed hardware (AMD SEV-SNP on Microsoft Azure), confirmed with AMD's and Microsoft's own keys.",
            ("Its deployment fingerprint matches InferRoute's signed reference. This is not an independent "
             "rebuild of the software that ran."
             if ref.get("ok") else
             "Its deployment fingerprint matches this computer's configuration. InferRoute's signed "
             "reference has not been verified here."),
            "Your search text is encrypted here and only that machine can open it; each answer comes back "
            "encrypted to this computer alone.",
            # The strong half of the retention answer, and it is ENFORCED rather than promised: those
            # three denials are in the container policy that the signed HOST_DATA is the hash of.
            "Hardware and fingerprint checks do not independently establish whether the software "
            "retains or discloses plaintext."]
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
    if label.startswith(("require, address-level", "require, Linux VM")):
        return {"key": "computer", "state": OK, "title": "This computer",
                "summary": "The assistant works in a closed box.",
                "points": ["No internet, and no files beyond this matter's folder."] + browser,
                "more": ["It has no internet connection. Its only ways out are the two sealed machines above, "
                         "through this computer's own checks.",
                         "It sees only this matter's folder. Your other files don't exist inside the box."] + browser,
                "technical": technical}
    # A PLATFORM WITHOUT OS CONFINEMENT IS NOT A DEVELOPER BYPASS. Those were one state, so a macOS
    # session — where Landlock never existed to disable — was told "developer mode, don't use this with a
    # client matter". That is wrong twice: the professional disabled nothing, and the sentence describes an
    # exposure that is not theirs. What is still enforced there is the tool set, and it covers the two
    # things that matter: the assistant cannot read files beyond this matter (no `read`, no `grep`, no
    # shell) and has no way to reach the internet (no fetch tool), with writes fenced to the matter folder
    # by the tool itself. What is missing is the kernel backstop UNDER those limits.
    if label.startswith("tool-level only"):
        return {"key": "computer", "state": WARN, "title": "This computer",
                "summary": "Limited by the assistant's own tools, not by this operating system.",
                "points": ["It has no way to reach the internet, and cannot read files beyond this matter.",
                           "Its writes are confined to this matter's folder."] + browser,
                "more": ["The assistant has no shell and no way to fetch anything: its only ways out are "
                         "the two sealed machines above, through this computer's own checks.",
                         "It cannot open your other files — the tool that reads is restricted to this "
                         "matter, and the general-purpose read and search tools are not given to it.",
                         "What is missing here, and present on Linux, is the operating system enforcing "
                         "those limits underneath. On Linux the kernel refuses the access as well as the "
                         "tool; here the tool refuses it alone. A fault in the assistant's own tools would "
                         "therefore have no second barrier behind it."] + browser,
                "technical": technical}
    if label.startswith("unconfined") or label == "not confined":
        return {"key": "computer", "state": FAIL, "title": "This computer",
                "summary": "NOT boxed — confinement was deliberately turned off here. Don't use this with a client matter.",
                "points": ["The assistant could reach the internet and read other files."],
                "more": [], "technical": technical}
    return {"key": "computer", "state": WARN, "title": "This computer",
            "summary": "The assistant is only partly boxed.",
            "points": ["It can read other files here; the full box needs a one-time setup on this machine."],
            "more": ["Its network is limited by port number rather than by address, and file reads are not "
                     "confined. Run scripts/install-confine-profile.sh once (it needs an administrator)."],
            "technical": technical}


# What the professional controls. NOT a fourth item in the chain (Henry, 20 Sep: "do we really need this? it
# doesn't look very positive"): among three verified checks it drew a hollow dot, which reads as something
# that did not pass, and "no search leaves without your OK" reads as a restriction rather than as control.
# One positive line under the chain instead — the facts are unchanged, and each is visible where it acts:
# the approval dialog, the marks panel, the exported record.
CONTROL_NOTE = "You approve the first search, your marks are yours alone, and the record is yours to export."


EXPLAINER = ("Sealed hardware protects its memory from the cloud host. This computer checks the hardware "
             "evidence before sending text encrypted to its key. Software inside the machine can read that text; "
             "these checks do not prove what it does with it.")


def limits(search_state: str, search_is_ours: bool = False, surface: str = "terminal") -> List[str]:
    out = ["These checks establish hardware and key bindings, not end-to-end confidentiality. "
           "They do not prove that software inside a machine cannot retain or disclose plaintext. "
           "Cloud platform components inside that boundary remain part of the trust set.",
           "The AI check measures firmware and start-up, not its whole filesystem.",
           "The network carries encrypted text, but timing and message sizes remain visible."]
    if search_state in (OK, WARN):
        out.append("The search deployment fingerprint "
                   + ("matches InferRoute's signed reference" if search_is_ours else
                      "matches this computer's configuration")
                   + "; an independent source-to-deployed-image proof is still missing.")
        out.append("A search finds related documents. It doesn't prove novelty, or that nothing else exists.")
    if surface == "browser":
        out.append("Browser extensions allowed to read every page can read this one too. For client matters, use "
                   "a browser profile without extensions.")
    return out


def build(receipt: Any, search: Optional[dict], confinement: str, *, matter: str = "", date_bound: str = "",
          surface: str = "terminal", mode: str = "matter") -> Dict[str, Any]:
    """`surface`: "terminal" or "browser" — the browser page adds what it guarantees and what it can't.
    `mode`: "matter" or "intake" (reading a document to propose matters; no search tool is offered)."""
    items = [ai_item(receipt), search_item(search, date_bound, mode), computer_item(confinement, surface)]
    states = {i["key"]: i["state"] for i in items}
    if states["ai"] == FAIL:
        verdict, headline = "blocked", "Not opened: the AI machine could not be verified, so nothing was sent."
    elif any(states[k] in (FAIL, WARN) for k in ("ai", "search", "computer")):
        verdict, headline = "limited", "Partly protected. Read the items marked below before using a client's invention."
    else:
        # A MISSING search is not a WEAKENED protection (Henry, 22 Sep: "if this is just the mcp not being up
        # why do we need to tell the user 'Partly protected'"). With no search there is no second machine and
        # no route off this computer at all — strictly MORE confidentiality, and reporting it as "Partly
        # protected" tells a professional their client's invention is at risk when the opposite is true.
        # The same reasoning is already written into search_item()'s intake branch; this path contradicted it.
        # What changes is the COUNT of sealed machines, which must not claim two when one was checked.
        verdict = "private"
        if states["search"] == OK:
            headline = ("Sealed hardware checked for this session: the AI model and the patent search service. "
                        "Text is encrypted before it leaves this computer.")
        else:
            missing = ("no patent search is set up on this computer" if states["search"] == OFF
                       else "no search tool is offered while reading a document")
            headline = ("Sealed hardware checked for this session: the AI model. Text is encrypted "
                        f"before it leaves this computer; {missing}, so nothing can leave this "
                        "computer for a search machine at all.")
    return {"schema": "inferroute.probant-trust/1", "verdict": verdict, "headline": headline, "explainer": EXPLAINER,
            "items": items, "control_note": CONTROL_NOTE,
            "limits": limits(states["search"], search_is_inferroutes(search), surface), "mode": mode, "surface": surface, "matter": matter, "date_bound": date_bound, "checked_at": _now()}


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
    title = "🔒 " + (summary.get("matter") or "Probant session").replace("/", " / ")
    body = Group(Text(summary["headline"], style=f"bold {colour}"), Text(summary["explainer"], style="grey58"), Text(""), t,
                 Text("  " + summary.get("control_note", ""), style="grey58"), Text(""),
                 Text("What this can't prove", style="bold"), lim, Text(""),
                 Text(f"Full technical proof: ir probant proof {summary.get('matter') or ''}".rstrip(), style="grey58"))
    width = min(console.width, 88)
    console.print(Panel(body, title=f"[bold]{title}[/]", subtitle=f"[grey58]checked {_local_stamp(summary['checked_at'])}[/]",
                        border_style=colour, box=box.ROUNDED, width=width, padding=(1, 2)))


def render_howto(matter: str, console: Any = None) -> None:
    from rich.console import Console
    from rich.text import Text
    console = console or Console()
    rows = [("In the session", "ask for a prior-art survey of the disclosure in this folder"),
            ("", "/relevant US-1234567-B2  mark a result (also /not-relevant, /known, /marks)"),
            ("", "/next 2  send the assistant's suggested next step number 2"),
            ("", "/proof  show the checks again · /quit  leave"),
            ("Afterwards", f"ir probant export {matter}   the record to keep")]
    for head, text in rows:
        console.print(Text.assemble((f"  {head:<16}", "bold"), (text, "grey70")), soft_wrap=True)
    console.print("")
