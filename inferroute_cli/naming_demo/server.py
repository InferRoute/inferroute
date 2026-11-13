"""Naming agent, quick demo (12 Nov 2026). Local only: serves one page on 127.0.0.1.

describe an idea -> ~60 names from the AI lane -> .com/.net checked against our own CZDS zone copy (no registrar,
no WHOIS) -> best ~16 searched in the trade mark index in parallel -> quick language check -> 10 shown with lights.

Every run is saved with its event timings, so it can be replayed for re-recording. A replay always says it is one.

Run:  python3 -m inferroute_cli.naming_demo.server --index <tm index .sqlite> --domains <dir with com.npy, net.npy>
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import hmac
import json
import os
import multiprocessing as mp
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
RUNS = Path.home() / ".local/share/naming-demo/runs"
MODEL = "deepseek-v4-flash"
SHORTLIST = 16
SHOW = 10

# Countries the page offers. Covered ones map to index registers; the rest are said to be "not checked".
COUNTRIES = {
    "EU": {"label": "EU (incl. France)", "registers": ["EU", "FR", "WO"]},
    "US": {"label": "United States", "registers": ["US"]},
    "AU": {"label": "Australia", "registers": ["AU"], "also": "AU"},
    "UK": {"label": "United Kingdom", "registers": None},
    "DE": {"label": "Germany (national)", "registers": None},
    "ES": {"label": "Spain (national)", "registers": None},
    "IT": {"label": "Italy (national)", "registers": None},
}
RED = {"same spelling", "sounds alike"}
AMBER = {"spelled closely", "sounds close", "has your whole name inside it", "is part of your name"}


def register_link(reg: str, number: str) -> str:
    n = str(number)
    if reg == "US":
        return f"https://tsdr.uspto.gov/#caseNumber={n}&caseType=SERIAL_NO&searchType=statusSearch"
    if reg == "EU":
        return f"https://euipo.europa.eu/eSearch/#details/trademarks/{n.zfill(9)}"
    if reg == "FR":
        return f"https://data.inpi.fr/marques/FR{n}"
    if reg == "WO":
        return f"https://www3.wipo.int/madrid/monitor/en/showData.jsp?ID=ROM.{n}"
    if reg == "AU":
        return f"https://search.ipaustralia.gov.au/trademarks/search/view/{n}"
    return ""


# ---------------------------------------------------------------- trade mark workers (one Index per process)
_IX = None


def _init_worker(index_path: str) -> None:
    global _IX
    from inferroute_cli import tm_search
    _IX = tm_search.Index(index_path)
    _IX.search("warmup", classes=["9"])


def _tm(args):
    name, classes, also = args
    t = time.time()
    r = _IX.search(name, classes=classes, limit=50, also=also)
    return name, r, time.time() - t


def judge(result: dict, registers: set, keep: int = 3, amber_at: float = 0.80) -> dict:
    """Light from the search result, counting only marks in the chosen registers with an overlapping class."""
    red, amber = [], []
    for h in result.get("hits", []):
        group = [h] + list(h.get("also", []))
        here = [m for m in group if m.get("register") in registers and m.get("overlapping_classes")]
        if not here:
            continue
        reasons = set(h.get("reasons", []))
        m = here[0]
        row = {"text": m.get("text"), "register": m.get("register"), "number": m.get("number"),
               "status": m.get("status"), "classes": m.get("classes"), "filed": m.get("filed"),
               "reasons": h.get("reasons", []), "link": register_link(m.get("register"), m.get("number"))}
        if reasons & RED:
            red.append(row)
        elif reasons & AMBER and h.get("score", 0) >= amber_at:  # page: 0.80; the watch passes its own (watch_bench)
            amber.append(row)
    light = "red" if red else "amber" if amber else "green"
    return {"light": light, "conflicts": (red + amber)[:keep], "n_conflicts": len(red) + len(amber)}


# ---------------------------------------------------------------- domains (local zone copy only)
class Domains:
    def __init__(self, d: Path):
        self.sets = {}
        for tld in ("com", "net"):
            p = d / f"{tld}.npy"
            if p.exists():
                self.sets[tld] = np.load(p, mmap_mode="r")

    def taken(self, label: str, tld: str):
        a = self.sets.get(tld)
        if a is None:
            return None
        h = np.uint64(int.from_bytes(hashlib.blake2b(label.lower().encode(), digest_size=8).digest(), "little"))
        i = int(np.searchsorted(a, h))
        return bool(i < len(a) and a[i] == h)


# ---------------------------------------------------------------- AI lane
BACKUP = "kimi-k3"
CREDIT = {"out_since": 0.0}  # set by a 402 from the proxy, cleared by the next successful call; shown on /health
_HEDGE = cf.ThreadPoolExecutor(8)


def _call(model: str, prompt: str, max_tokens: int, timeout: float) -> tuple[str, dict]:
    from inferroute_cli import config
    c = config.load()
    # Reasoning off: with it on, every model on the lane spends 60-100 s thinking (measured 12 Nov); off, 3.5-8 s.
    # deepseek honours reasoning.enabled; kimi honours reasoning_effort / chat_template_kwargs.
    body = {"model": model, "messages": [{"role": "user", "content": prompt}], "max_tokens": max_tokens,
            "reasoning": {"enabled": False}, "reasoning_effort": "none",
            "chat_template_kwargs": {"thinking": False, "enable_thinking": False}}
    req = urllib.request.Request(c.api_url + "/v1/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Authorization": "Bearer " + c.api_key, "Content-Type": "application/json"})
    try:
        d = json.load(urllib.request.urlopen(req, timeout=timeout))
    except urllib.error.HTTPError as e:
        if e.code == 402:  # the key's account is out of credit: every run will fail until it is topped up
            CREDIT["out_since"] = CREDIT["out_since"] or time.time()
        raise
    CREDIT["out_since"] = 0.0
    return d["choices"][0]["message"]["content"], d.get("usage") or {}


def llm(prompt: str, max_tokens: int = 4000, hedge_after: float = 7.0, deadline: float = 25.0) -> tuple[str, dict]:
    """The same prompt to MODEL, and to BACKUP if MODEL has not answered within `hedge_after` s; first answer wins.
    The lane's latency swings from ~4 s to ~100 s on identical calls (12 Nov), and a run has a 60 s promise."""
    t0 = time.time()
    futs = [_HEDGE.submit(_call, MODEL, prompt, max_tokens, deadline)]
    done, _ = cf.wait(futs, timeout=hedge_after)
    if not done or futs[0].exception():
        futs.append(_HEDGE.submit(_call, BACKUP, prompt, max_tokens, max(1.0, deadline - (time.time() - t0))))
    errors = []
    for f in cf.as_completed(futs, timeout=max(0.1, deadline - (time.time() - t0))):
        if f.exception() is None:
            return f.result()
        errors.append(f.exception())
    raise errors[-1] if errors else TimeoutError("no model answered")


def _json_in(text: str):
    m = re.search(r"[\[{].*[\]}]", text, re.S)
    return json.loads(m.group(0)) if m else None


RULES = (HERE / "naming_rules.md").read_text()
GEN = """You name new products and startups. Follow these rules:

{rules}

Idea: "{idea}". Tone: {tone}.
Give {n} brand name candidates, mostly in this style: {style}.
Each name: one word, 4 to 11 letters, A-Z only.
Also give the Nice classes (1-45) a trade mark for this product would be filed in, at most 4, most important first.
{classes_rule}Write in English. Answer with JSON only:
{{"classes": [{{"n": <class number>, "why": "<at most 5 English words>"}}], "names": ["..."]}}"""
STYLES = ["invented words that sound natural (like Spotify, Zalando, Kodak)",
          "two short real words or roots fused together (like Facebook, Airbnb, Mailchimp)"]

LANG = """For each brand name below, check English, French, German and Spanish: does it mean, sound like or
contain something rude, negative, embarrassing or confusing for a customer? Be strict but not paranoid.
Names: {names}
Answer with JSON only: {{"<name>": {{"ok": true|false, "note": "<at most 12 words, say which language if not ok>"}}}}"""


CLICHE = re.compile(r"(ly|ify|io|oo|sy|zy|hub|go|ster)$", re.I)


def cap_patterns(names: list[str], share: float = 0.25) -> list[str]:
    """naming_rules.md 2-3: at most `share` of the list may end in a cliche suffix or share one 4-letter root."""
    lim = max(2, int(len(names) * share))
    out, n_cl, roots = [], 0, {}
    for n in names:
        lo = n.lower()
        if CLICHE.search(lo):
            if n_cl >= lim:
                continue
            n_cl += 1
        r = lo[:4]
        if roots.get(r, 0) >= lim:
            continue
        roots[r] = roots.get(r, 0) + 1
        out.append(n)
    return out


def clean_names(xs) -> list[str]:
    out, seen = [], set()
    for x in xs or []:
        s = re.sub(r"[^A-Za-z]", "", str(x))
        if 4 <= len(s) <= 11 and s.lower() not in seen:
            seen.add(s.lower())
            out.append(s[0].upper() + s[1:])
    return out


# ---------------------------------------------------------------- a run
class Run:
    def __init__(self, app, q: dict):
        self.app, self.q = app, {k: v for k, v in q.items() if k not in ("device", "rec")}
        self.events, self.t0 = [], time.time()
        self.id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.usage = {"prompt_tokens": 0, "completion_tokens": 0}

    def emit(self, ev: dict):
        ev = dict(ev, ms=int((time.time() - self.t0) * 1000))
        self.events.append(ev)
        return ev

    def _add_usage(self, u):
        for k in self.usage:
            self.usage[k] += int(u.get(k) or 0)

    def go(self):
        q = self.q
        idea, tone = q.get("idea", "").strip()[:600], q.get("tone", "any")
        own = clean_names(re.split(r"[,\s]+", q.get("own", "")))[:5]
        countries = [c for c in q.get("countries", "EU,US").split(",") if c in COUNTRIES] or ["EU", "US"]
        registers = {r for c in countries for r in (COUNTRIES[c]["registers"] or [])}
        also = [COUNTRIES[c]["also"] for c in countries if COUNTRIES[c].get("also")]
        countries = [c for c in countries if COUNTRIES[c]["registers"] is not None] or ["EU", "US"]
        unchecked = ["United Kingdom", "national marks in Germany, Spain, Italy and other countries"]
        given = [c for c in re.findall(r"\d+", q.get("classes", "")) if 1 <= int(c) <= 45][:5]
        yield self.emit({"t": "start", "run": self.id, "idea": idea, "own": own, "countries": countries,
                         "unchecked": unchecked})

        # 1. names (and classes) from the AI lane; own names skip generation
        classes, why = given, {}
        names = list(own)
        if not own or not given:
            yield self.emit({"t": "phase", "text": "Inventing names" if not own else "Reading your idea"})
            rule = "" if not given else f"Use these Nice classes: {', '.join(given)}. "
            n = 45 if not own else 1
            styles = STYLES if not own else STYLES[:1]
            with cf.ThreadPoolExecutor(2) as ex:
                futs = [ex.submit(llm, GEN.format(rules=RULES, idea=idea or ", ".join(own), tone=tone, n=n, style=s,
                                                  classes_rule=rule)) for s in styles]
                for f in futs:
                    try:
                        text, u = f.result()
                        self._add_usage(u)
                        d = _json_in(text) or {}
                    except Exception as e:  # noqa: BLE001 - a failed leg is reported, the other may carry the run
                        yield self.emit({"t": "warn", "text": f"one name source failed: {type(e).__name__}"})
                        continue
                    if not own:
                        names += clean_names(d.get("names"))
                    if not given:
                        for c in d.get("classes", []):
                            try:
                                k = str(int(c.get("n")))
                            except (TypeError, ValueError):
                                continue
                            if 1 <= int(k) <= 45 and k not in classes and len(classes) < 4:
                                classes.append(k)
                                why[k] = str(c.get("why", ""))[:60]
        names = clean_names(names)
        if not own:
            names = cap_patterns(names)
        if not classes:
            classes = ["9", "42"]
        from .nice_classes import NICE
        yield self.emit({"t": "classes", "classes": classes, "why": {c: NICE.get(int(c), "") for c in classes}})
        if not names:
            yield self.emit({"t": "error", "text": "No names came back. Try again."})
            return

        # 2. domains, all candidates, our own zone copy
        dom = {n: {"com": self.app.domains.taken(n, "com"), "net": self.app.domains.taken(n, "net")} for n in names}
        free = [n for n in names if dom[n]["com"] is False]
        yield self.emit({"t": "screened", "n": len(names), "com_free": len(free),
                         "zone_names": int(len(self.app.domains.sets.get("com", [])))})
        short = own or (free + [n for n in names if n not in free])[:SHORTLIST]

        # 3. trade marks (parallel processes) and the language check (thread), at the same time
        yield self.emit({"t": "shortlist", "names": [{"name": n, "com": dom[n]["com"], "net": dom[n]["net"]}
                                                     for n in short]})
        yield self.emit({"t": "phase", "text": f"Searching {self.app.marks if also else self.app.marks_default:,} trade marks"})
        lang_box: dict = {}

        def lang():
            try:
                text, u = llm(LANG.format(names=", ".join(short)), 3000)
                self._add_usage(u)
                lang_box.update(_json_in(text) or {})
            except Exception as e:  # noqa: BLE001
                lang_box["__error__"] = type(e).__name__
        th = threading.Thread(target=lang)
        lang_t0 = time.time()
        th.start()
        results = {}
        for name, r, secs in self.app.pool.imap_unordered(_tm, [(n, classes, also) for n in short]):
            j = judge(r, registers)
            results[name] = j
            yield self.emit({"t": "name", "name": name, "com": dom[name]["com"], "net": dom[name]["net"],
                             "tm": j, "secs": round(secs, 1)})
        th.join(timeout=max(0.0, 20 - (time.time() - lang_t0)))  # the language check never holds the run past 20 s
        if th.is_alive() or "__error__" in lang_box or not lang_box:  # measured: ~1 run in 8 (13 Nov); log the cause
            why = "timeout" if th.is_alive() else lang_box.get("__error__", "unparsed reply")
            print(f"language check missing: {why} after {time.time() - lang_t0:.1f} s", flush=True)
        for n in short:
            v = lang_box.get(n) or next((v for k, v in lang_box.items() if k.lower() == n.lower()), None)
            yield self.emit({"t": "lang", "name": n,
                             "ok": None if v is None else bool(v.get("ok")),
                             "note": "" if v is None else str(v.get("note", ""))[:100]})
            results[n]["lang_ok"] = None if v is None else bool(v.get("ok"))

        # 4. the ten to show, best first
        order = {"green": 0, "amber": 1, "red": 2}
        ranked = sorted(short, key=lambda n: (order[results[n]["light"]], dom[n]["com"] is not False,
                                              results[n].get("lang_ok") is False, short.index(n)))
        top = ranked[:SHOW] if not own else ranked
        lang_ran = any(results[n].get("lang_ok") is not None for n in short)
        winners = [n for n in top if results[n]["light"] == "green" and dom[n]["com"] is False
                   and (results[n].get("lang_ok") is True or not lang_ran)]
        both = [n for n in top if results[n]["light"] == "green" and dom[n]["com"] is False]
        rest = [n for n in ranked if n not in top]  # checked but not in the ten: shown folded, never silently dropped
        yield self.emit({"t": "final", "top": top, "rest": rest, "winners": winners, "both": both, "lang_ran": lang_ran,
                         "usage": self.usage, "model": MODEL})

    def save(self):
        RUNS.mkdir(parents=True, exist_ok=True)
        (RUNS / f"{self.id}.json").write_text(json.dumps({"id": self.id, "q": self.q, "events": self.events}))


NEXT = {
    "red": "A mark with the same or very close name is live in a class you need. Using or filing this name risks an "
           "opposition or an infringement claim; choose another name, or ask an IP adviser before going further.",
    "amber": "Similar marks exist in your classes. Whether they block you depends on how close the goods and services "
             "are and how the names compare as a whole; an IP adviser can judge this before you file.",
    "green": "No close mark was found in the registers and classes searched. That is a good start, not clearance: file "
             "early, and check the countries marked not checked if you trade there.",
}


class Report(Run):
    """The paid report on up to 5 shortlisted names: every close mark in the chosen registers, no generation."""

    def go(self):
        q = self.q
        names = clean_names(re.split(r"[,\s]+", q.get("names", "")))[:5]
        countries = [c for c in q.get("countries", "EU,US").split(",") if c in COUNTRIES
                     and COUNTRIES[c]["registers"] is not None] or ["EU", "US"]
        registers = {r for c in countries for r in COUNTRIES[c]["registers"]}
        also = [COUNTRIES[c]["also"] for c in countries if COUNTRIES[c].get("also")]
        classes = [c for c in re.findall(r"\d+", q.get("classes", "")) if 1 <= int(c) <= 45][:6] or ["9", "42"]
        from .nice_classes import NICE
        yield self.emit({"t": "start", "kind": "report", "run": self.id, "names": names, "countries": countries,
                         "classes": {c: NICE[int(c)] for c in classes},
                         "data": self.app.data, "unchecked": ["United Kingdom",
                                                              "national marks in Germany, Spain, Italy and other countries"]})
        if not names:
            yield self.emit({"t": "error", "text": "No valid names (4 to 11 letters each)."})
            return
        lang_box: dict = {}

        def lang():
            try:
                text, u = llm(LANG.format(names=", ".join(names)), 2000)
                self._add_usage(u)
                lang_box.update(_json_in(text) or {})
            except Exception as e:  # noqa: BLE001
                lang_box["__error__"] = type(e).__name__
        th = threading.Thread(target=lang)
        th.start()
        rows = {}
        for name, r, _secs in self.app.pool.imap_unordered(_tm, [(n, classes, also) for n in names]):
            rows[name] = judge(r, registers, keep=25)
        th.join(timeout=20)
        for n in names:
            v = lang_box.get(n) or next((v for k, v in lang_box.items() if k.lower() == n.lower()), None)
            j = rows[n]
            yield self.emit({"t": "name_report", "name": n, "com": self.app.domains.taken(n, "com"),
                             "net": self.app.domains.taken(n, "net"), "tm": j,
                             "lang": {"ok": None if v is None else bool(v.get("ok")),
                                      "note": "" if v is None else str(v.get("note", ""))[:160]},
                             "next": NEXT[j["light"]]})
        yield self.emit({"t": "final", "kind": "report", "usage": self.usage, "model": MODEL})


# ---------------------------------------------------------------- http
class App:
    def __init__(self, index: str, domains: Path, workers: int):
        import sqlite3
        con = sqlite3.connect(f"file:{index}?mode=ro", uri=True)
        try:
            by = dict(con.execute("select register, count(*) from marks group by register").fetchall())
        except sqlite3.Error:
            by = {}
        self.marks = sum(by.values())
        self.marks_default = sum(v for k, v in by.items() if k != "AU")  # AU is opt-in
        try:
            meta = dict(con.execute("select k, v from meta").fetchall())
        except sqlite3.Error:
            meta = {}
        self.data = meta.get("data_date", "")
        h = hashlib.sha256()
        with open(index, "rb") as f:  # once at start (~3 s): /health names the exact index this host serves
            for chunk in iter(lambda: f.read(1 << 22), b""):
                h.update(chunk)
        self.index_sha = h.hexdigest()
        con.close()
        self.domains = Domains(domains)
        self.pool = mp.get_context("fork").Pool(workers, initializer=_init_worker, initargs=(index,))


class H(BaseHTTPRequestHandler):
    app: App = None
    secret = ""  # when set, POSTs must carry x-anteriora-names-secret (the site's proxy adds it; never the browser)
    record = ""  # the recording token; empty = public build, no saving and no replay routes

    def log_message(self, *a):
        pass

    def _sse_head(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

    def _send(self, ev):
        self.wfile.write(f"data: {json.dumps(ev)}\n\n".encode())
        self.wfile.flush()

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        # The idea and names travel in the POST body, never in the URL, so no access log can hold them.
        path = urllib.parse.urlparse(self.path).path
        if path not in ("/run", "/report"):
            self.send_error(404)
            return
        if self.secret and not hmac.compare_digest(self.headers.get("x-anteriora-names-secret", ""), self.secret):
            self.send_error(403)
            return
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > 4096:
            self.send_error(413)
            return
        try:
            q = {k: str(v) for k, v in json.loads(self.rfile.read(n)).items()}
        except (ValueError, AttributeError):
            self.send_error(400)
            return
        ip = self.headers.get("X-Forwarded-For", "").split(",")[0].strip() or self.client_address[0]
        if path == "/run" and not DAILY.take(q.get("device", "")[:64] or ip, ip):
            self._json({"error": "daily"}, 429)
            return
        if not BUDGET.take():
            self._json({"error": "busy"}, 429)
            return
        self._sse_head()
        run = (Report if path == "/report" else Run)(self.app, q)
        try:
            for ev in run.go():
                self._send(ev)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            BUDGET.give()
            if self.record and q.get("rec") == self.record and path == "/run":  # only the recording session's own runs; public build: never
                run.save()
            try:
                self._send({"t": "done"})
            except OSError:
                pass

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        if u.path == "/":
            body = (HERE / "page.html").read_text()
            if not (self.record and q.get("rec") == self.record):  # public build: the replay picker is not in the page at all
                body = re.sub(r"<!--rec-->.*?<!--/rec-->", "", body, flags=re.S)
            body = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
        elif u.path == "/health":
            # Used by the host watchdog: a hung pool or a missing zone must take this host out of the tunnel.
            ok, why = True, []
            try:
                self.app.pool.apply_async(_tm, (("Healthcheck", ["9"], []),)).get(timeout=15)
            except Exception as e:  # noqa: BLE001
                ok = False
                why.append("tm:" + type(e).__name__)
            if self.app.domains.taken("google", "com") is not True:
                ok = False
                why.append("com")
            # No model key (ft holds none): this host cannot make names, so it must not take /run traffic either.
            # The weekly rollout tolerates exactly this reason (it checks the index, not the key).
            try:
                from inferroute_cli import config
                if not config.load().api_key:
                    ok = False
                    why.append("model-key")
            except Exception:  # noqa: BLE001
                ok = False
                why.append("model-key")
            # Credit is reported, not gated: an empty account is the same on every host, so taking hosts out of the
            # tunnel would not help; the watchdog on mgld alerts Henry instead.
            credit = "out" if CREDIT["out_since"] else "ok"
            self._json({"ok": ok, "why": why, "index": self.app.index_sha, "data": self.app.data, "model_credit": credit},
                       200 if ok else 503)
        elif u.path == "/config":
            self._json({"record": bool(self.record) and q.get("rec") == self.record})
        elif u.path == "/runs" and self.record and q.get("rec") == self.record:
            RUNS.mkdir(parents=True, exist_ok=True)
            rows = []
            for p in sorted(RUNS.glob("*.json"), reverse=True)[:30]:
                d = json.loads(p.read_text())
                rows.append({"id": d["id"], "idea": d["q"].get("idea", ""), "own": d["q"].get("own", "")})
            self._json(rows)
        elif u.path == "/replay" and self.record and q.get("rec") == self.record:
            rid = re.sub(r"[^0-9A-Z]", "", q.get("id", ""))
            p = RUNS / f"{rid}.json"
            if not rid or not p.exists():
                self.send_error(404)
                return
            d = json.loads(p.read_text())
            self._sse_head()
            try:
                self._send({"t": "replay", "of": d["id"], "ms": 0})
                t0 = time.time()
                for ev in d["events"]:  # original timings kept
                    wait = ev["ms"] / 1000 - (time.time() - t0)
                    if wait > 0:
                        time.sleep(wait)
                    self._send(dict(ev, replay=d["id"]))
                self._send({"t": "done", "replay": d["id"]})
            except (BrokenPipeError, ConnectionResetError):
                pass
        else:
            self.send_error(404)


class Budget:
    """Keeps paid AI calls at demo volume: at most `parallel` runs at once and `per_hour` runs an hour."""

    def __init__(self, parallel: int = 2, per_hour: int = 60):
        self.lock, self.parallel, self.per_hour, self.live, self.starts = threading.Lock(), parallel, per_hour, 0, []

    def take(self) -> bool:
        with self.lock:
            now = time.time()
            self.starts = [t for t in self.starts if now - t < 3600]
            if self.live >= self.parallel or len(self.starts) >= self.per_hour:
                return False
            self.live += 1
            self.starts.append(now)
            return True

    def give(self) -> None:
        with self.lock:
            self.live -= 1


BUDGET = Budget()


class Daily:
    """Free tier: about `limit` runs a day per device, and 3x that per IP (a shared office or a cleared browser).
    Kept in memory only, keyed by salted hashes, and forgotten at midnight UTC; no search text is involved."""

    def __init__(self, limit: int = 3):
        self.limit, self.lock, self.day, self.seen = limit, threading.Lock(), "", {}
        self.salt = hashlib.sha256(str(time.time_ns()).encode()).hexdigest()

    def take(self, device: str, ip: str) -> bool:
        if self.limit <= 0:
            return True
        with self.lock:
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            if day != self.day:
                self.day, self.seen = day, {}
            keys = [("d", hashlib.sha256((self.salt + "d" + device).encode()).hexdigest(), self.limit),
                    ("i", hashlib.sha256((self.salt + "i" + ip).encode()).hexdigest(), self.limit * 3)]
            if any(self.seen.get(k, 0) >= lim for _, k, lim in keys):
                return False
            for _, k, _lim in keys:
                self.seen[k] = self.seen.get(k, 0) + 1
            return True


DAILY = Daily()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--index", required=True)
    ap.add_argument("--domains", required=True, type=Path)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8766)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--record", action="store_true",
                    help="save every run for replay (demo recording only; never on the web service)")
    ap.add_argument("--per-hour", type=int, default=60)
    ap.add_argument("--secret-env", default="", help="env var holding the shared secret the site proxy sends")
    ap.add_argument("--daily", type=int, default=3, help="free runs a day per device (0 = no cap)")
    a = ap.parse_args()
    H.secret = os.environ.get(a.secret_env, "") if a.secret_env else ""
    if a.secret_env and not H.secret:
        raise SystemExit(f"{a.secret_env} is empty")
    H.record = hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:16] if a.record else ""
    BUDGET.per_hour = a.per_hour
    DAILY.limit = a.daily
    H.app = App(a.index, a.domains, a.workers)
    print(f"naming demo on http://{a.host}:{a.port}  ({H.app.marks:,} marks, zones: {sorted(H.app.domains.sets)}, "
          f"record={'on: open /?rec=' + H.record if H.record else 'off'})",
          flush=True)
    ThreadingHTTPServer((a.host, a.port), H).serve_forever()


if __name__ == "__main__":
    main()
