"""INPI French trademark feed (ST.66 XML) to index rows (our side, not shipped).

The feed is a backlog snapshot (Dec 2024) followed by weekly files. A later record for the same application
number replaces the earlier one, and a record whose operation is "Delete" removes it, so files are read in
order: backlog, then weekly files sorted by year and week.
"""
import re
import zipfile
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


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _order(path: Path) -> Tuple:
    m = re.search(r"(\d{4})-(\d{2})", path.name)
    kind = 0 if path.name.startswith("BCK_") else 1
    return (kind, int(m.group(1)) if m else 0, int(m.group(2)) if m else 0, "UPD" in path.name, path.name)


def records(folder: Path) -> Iterator[Dict]:
    files = sorted(list((folder / "backlog").glob("*.zip")) + list((folder / "weekly").glob("*.zip")), key=_order)
    for zpath in files:
        try:
            z = zipfile.ZipFile(zpath)
        except zipfile.BadZipFile:
            print(f"skipping unreadable {zpath.name}")
            continue
        for member in sorted(n for n in z.namelist() if n.lower().endswith(".xml")):
            with z.open(member) as fh:
                for _, el in ET.iterparse(fh, events=("end",)):
                    if _local(el.tag) != "TradeMark":
                        continue
                    rec = {"op": el.get("operationCode") or "Update", "classes": set(), "source": zpath.name}
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
                    el.clear()
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
