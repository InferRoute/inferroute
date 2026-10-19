"""INPI French trademark feed (ST.66 XML) to index rows (our side, not shipped).

The feed is a backlog snapshot (Dec 2024) followed by weekly files. A later record for the same application
number replaces the earlier one, and a record whose operation is "Delete" removes it, so files are read in
order: backlog, then weekly files sorted by year and week.
"""
import re
import zipfile
from html import unescape
from pathlib import Path
from typing import Dict, Iterator, Tuple
from xml.etree import ElementTree as ET

LIVE = {
    # Statuses under which a mark can still be relied on or is still being examined. Read from the feed's
    # own values (see `statuses()`); anything not listed here is treated as dead (expired, withdrawn, refused,
    # renounced, cancelled) and kept out of the index.
    "Marque enregistrée", "Marque renouvelée", "Demande déposée", "Demande publiée",
    "Marque publiée", "Demande en cours d'examen", "Demande ayant fait l'objet d'une opposition",
    "Opposition en cours", "Marque ayant fait l'objet d'une renonciation partielle",
    "Demande ayant fait l'objet d'une observation", "Marque inscrite", "Enregistrement en cours",
}


DEAD = {
    # Filled from the statuses the feed actually carries (see build_tm_index.py, which refuses to build while
    # any status is neither here nor in LIVE).
    "Marque expirée", "Marque ayant fait l'objet d'une renonciation totale", "Demande totalement rejetée",
    "Marque ayant fait l'objet d'un retrait total", "Marque déchue", "Marque annulée",
    "Demande irrecevable après publication",
}


def data_date(folder: Path) -> str:
    """The date of the newest weekly file: its year and week number, as the Friday of that ISO week."""
    import datetime as dt
    newest = (0, 0)
    for z in (folder / "weekly").glob("*.zip"):
        m = re.search(r"(\d{4})-(\d{2})", z.name)
        if m:
            newest = max(newest, (int(m.group(1)), int(m.group(2))))
    if newest == (0, 0):
        return "Dec 2024 backlog"
    return dt.date.fromisocalendar(newest[0], newest[1], 5).isoformat()


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _order(path: Path) -> Tuple:
    m = re.search(r"(\d{4})-(\d{2})", path.name)
    kind = 0 if path.name.startswith("BCK_") else 1
    return (kind, int(m.group(1)) if m else 0, int(m.group(2)) if m else 0, "UPD" in path.name, path.name)


BACKLOG_THROUGH = (2024, 50)     # backlog/readme.txt: "Backlog marques FR 2024-50 inclus"


def records(folder: Path) -> Iterator[Dict]:
    # Weekly files the backlog already includes are skipped: replayed after it, they would put back an older state.
    weekly = [z for z in (folder / "weekly").glob("*.zip") if _order(z)[1:3] > BACKLOG_THROUGH]
    files = sorted(list((folder / "backlog").glob("*.zip")) + weekly, key=_order)
    for zpath in files:
        try:
            z = zipfile.ZipFile(zpath)
        except zipfile.BadZipFile:
            print(f"skipping unreadable {zpath.name}")
            continue
        for member in sorted(n for n in z.namelist() if n.lower().endswith(".xml")):
            try:
                yield from _parse_member(z, member, zpath.name)
            except ET.ParseError as e:
                # One malformed record must not lose the file's other marks: parse record by record, and
                # skip, count and name only the records that do not parse.
                yield from _salvage(z.read(member), f"{zpath.name}/{member}", str(e))


SKIPPED: list = []
_BLOCK = re.compile(rb"<TradeMark\b.*?</TradeMark>", re.S)


def _salvage(raw: bytes, where: str, why: str) -> Iterator[Dict]:
    blocks = _BLOCK.findall(raw)
    lost = by_text = 0
    for block in blocks:
        try:
            yield from _records_in(ET.fromstring(block), where)
        except ET.ParseError:
            rec = _record_from_text(block, where)
            if rec is None:
                lost += 1
            else:
                by_text += 1
                yield rec
    SKIPPED.append(f"{where}: {why}; {len(blocks)} record(s): {by_text} read field by field, {lost} unreadable")


def _leaf(block: bytes, tag: str) -> list:
    return [unescape(m.decode("utf-8", "replace").strip())
            for m in re.findall(rb"<" + tag.encode() + rb"(?:\s[^>]*)?>([^<]*)</" + tag.encode() + rb">", block)]


def _record_from_text(block: bytes, source: str):
    """The fields the index uses are simple leaf elements, so a record whose OTHER parts are malformed (the
    feed has records with a missing opening <ClaimantIdentifier>) can still be read. None if even the
    application number is missing."""
    number = _leaf(block, "ApplicationNumber")
    if not number:
        return None
    op = re.search(rb'operationCode="([^"]*)"', block)
    rec = {"op": op.group(1).decode() if op else "Update", "classes": set(), "source": source, "number": number[0]}
    for tag, key in (("ApplicationDate", "filed"), ("MarkCurrentStatusCode", "status"),
                     ("MarkVerbalElementText", "text"), ("MarkFeature", "feature")):
        found = [v for v in _leaf(block, tag) if v]
        if found:
            rec[key] = found[0] if key != "status" else found[-1]
    rec["classes"] = {str(int(c)) for c in _leaf(block, "ClassNumber") if c.isdigit() and 1 <= int(c) <= 45}
    return rec


def _parse_member(z, member: str, source: str) -> Iterator[Dict]:
    pending = []
    with z.open(member) as fh:
                for _, el in ET.iterparse(fh, events=("end",)):
                    if _local(el.tag) != "TradeMark":
                        continue
                    rec = _record(el, source)
                    el.clear()
                    if rec.get("number"):
                        pending.append(rec)
    # Yielded only once the whole member parsed. A file that breaks half-way is re-read record by record by
    # _salvage instead, so its records are neither lost nor counted twice.
    yield from pending


def _record(el, source: str) -> Dict:
    rec = {"op": el.get("operationCode") or "Update", "classes": set(), "source": source}
    for child in el.iter():
        name = _local(child.tag)
        text = (child.text or "").strip()
        if name == "ApplicationNumber" and "number" not in rec:
            rec["number"] = text
        elif name == "ApplicationDate" and "filed" not in rec:
            rec["filed"] = text
        elif name == "MarkCurrentStatusCode":
            rec["status"] = text
        elif name == "MarkVerbalElementText" and text:
            rec["text"] = text
        elif name == "MarkFeature":
            rec["feature"] = text
        elif name == "ClassNumber" and text.isdigit() and 1 <= int(text) <= 45:
            rec["classes"].add(str(int(text)))
    return rec


def _records_in(el, source: str) -> Iterator[Dict]:
    rec = _record(el, source)
    if rec.get("number"):
        yield rec


def current(folder: Path) -> Dict[str, Dict]:
    """The latest state of every application, after every weekly file has been applied in order."""
    state: Dict[str, Dict] = {}
    for rec in records(folder):
        if rec["op"].lower().startswith("del"):
            state.pop(rec["number"], None)
            continue
        prior = state.get(rec["number"])
        if prior:
            # An update can omit what it does not change; keep what the earlier record knew.
            for key in ("text", "filed", "feature", "status"):
                rec.setdefault(key, prior.get(key))
            if not rec["classes"]:
                rec["classes"] = prior["classes"]
        state[rec["number"]] = rec
    return state


def statuses(state: Dict[str, Dict]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for rec in state.values():
        out[rec.get("status") or ""] = out.get(rec.get("status") or "", 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def rows(state: Dict[str, Dict], live: set = LIVE) -> Iterator[Tuple]:
    for number, rec in state.items():
        if rec.get("status") in live and rec.get("text"):
            label = "registered" if ("enregistrée" in rec["status"] or "renouvelée" in rec["status"]) else "pending"
            yield ("FR", number, rec["text"], label, sorted(rec["classes"]), rec.get("filed") or "")
