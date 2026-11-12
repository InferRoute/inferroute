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
import json
import multiprocessing as mp
import re
import threading
import time
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


def judge(result: dict, registers: set) -> dict:
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
        elif reasons & AMBER and h.get("score", 0) >= 0.80:  # below 0.80 the resemblance is loose (seen 12 Nov)
            amber.append(row)
    light = "red" if red else "amber" if amber else "green"
    return {"light": light, "conflicts": (red + amber)[:3], "n_conflicts": len(red) + len(amber)}


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
def llm(prompt: str, max_tokens: int = 4000) -> tuple[str, dict]:
    from inferroute_cli import config
    c = config.load()
    # reasoning off: with it on, every model on the lane spends 60-100 s thinking (measured 12 Nov); off, 3.5-8 s
    body = {"model": MODEL, "messages": [{"role": "user", "content": prompt}], "max_tokens": max_tokens,
            "reasoning": {"enabled": False}, "chat_template_kwargs": {"thinking": False, "enable_thinking": False}}
    req = urllib.request.Request(c.api_url + "/v1/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Authorization": "Bearer " + c.api_key, "Content-Type": "application/json"})
    d = json.load(urllib.request.urlopen(req, timeout=120))
    return d["choices"][0]["message"]["content"], d.get("usage") or {}


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
        self.app, self.q = app, q
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
        unchecked = [COUNTRIES[c]["label"] for c in countries if COUNTRIES[c]["registers"] is None]
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
        yield self.emit({"t": "classes", "classes": classes, "why": why})
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
        winners = [n for n in top if results[n]["light"] == "green" and dom[n]["com"] is False
                   and results[n].get("lang_ok") is not False]
        yield self.emit({"t": "final", "top": top, "winners": winners, "usage": self.usage, "model": MODEL})

    def save(self):
        RUNS.mkdir(parents=True, exist_ok=True)
        (RUNS / f"{self.id}.json").write_text(json.dumps({"id": self.id, "q": self.q, "events": self.events}))


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
        con.close()
        self.domains = Domains(domains)
        self.pool = mp.get_context("fork").Pool(workers, initializer=_init_worker, initargs=(index,))


class H(BaseHTTPRequestHandler):
    app: App = None
    record = False

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
        if urllib.parse.urlparse(self.path).path != "/run":
            self.send_error(404)
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
        if not BUDGET.take():
            self._json({"error": "busy"}, 429)
            return
        self._sse_head()
        run = Run(self.app, q)
        try:
            for ev in run.go():
                self._send(ev)
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            BUDGET.give()
            if self.record:  # demo recording only; the web service is started without --record and keeps nothing
                run.save()
            try:
                self._send({"t": "done"})
            except OSError:
                pass

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        if u.path == "/":
            body = (HERE / "page.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(body)
        elif u.path == "/config":
            self._json({"record": self.record})
        elif u.path == "/runs" and self.record:
            RUNS.mkdir(parents=True, exist_ok=True)
            rows = []
            for p in sorted(RUNS.glob("*.json"), reverse=True)[:30]:
                d = json.loads(p.read_text())
                rows.append({"id": d["id"], "idea": d["q"].get("idea", ""), "own": d["q"].get("own", "")})
            self._json(rows)
        elif u.path == "/replay" and self.record:
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
    a = ap.parse_args()
    H.record = a.record
    BUDGET.per_hour = a.per_hour
    H.app = App(a.index, a.domains, a.workers)
    print(f"naming demo on http://{a.host}:{a.port}  ({H.app.marks:,} marks, zones: {sorted(H.app.domains.sets)}, "
          f"record={a.record})",
          flush=True)
    ThreadingHTTPServer((a.host, a.port), H).serve_forever()


if __name__ == "__main__":
    main()
