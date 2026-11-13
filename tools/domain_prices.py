"""Weekly per-ending domain price table for the naming page (shared/ANTERIORA-DOMAIN-PRICING-STRATEGY.md, Henry's go 13 Nov).

    python tools/domain_prices.py OUT_DIR [--prev PREV.json]

Three GETs with no domain name in them: Porkbun's public price list (USD), OVHcloud's public FR catalogue (EUR, excl.
VAT) and the ECB daily rate. Never called from a visitor's run. Writes prices-YYYYMMDD.json and, only when the gate
passes, prices.json next to it (the file the server reads). Gate: >= 500 endings; .com in both sources; .com renewal
between EUR 8 and 20; no shown ending moved > 40% unless both sources moved. On failure the old prices.json stays.
"""
import argparse
import datetime
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

PORKBUN = "https://api.porkbun.com/api/json/v3/pricing/get"
OVH = "https://eu.api.ovh.com/1.0/order/catalog/public/domain?ovhSubsidiary=FR"
ECB = "https://www.ecb.europa.eu/stats/eurofxref/eurofxref-daily.xml"
# Sources with a public, no-key, no-name price list. Spaceship and Cloudflare have none (13 Nov: their price pages refuse
# automated reads, and Spaceship's API needs an account key): they join the table as soon as one exists.
SHOWN = ["com", "net", "org", "app", "dev"]          # endings the page can show today (zone copies on disk)
PREMIUM = {"app", "dev"}                              # registry-premium names exist on these endings
UA = {"User-Agent": "anteriora-prices/1.0"}


def get(url: str, data: bytes | None = None, timeout: int = 120) -> bytes:
    with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=UA), timeout=timeout) as r:
        return r.read()


def usd_eur() -> tuple[float, str]:
    root = ET.fromstring(get(ECB))
    for c in root.iter():
        if c.get("currency") == "USD":
            day = next(x.get("time") for x in root.iter() if x.get("time"))
            return float(c.get("rate")), day
    raise SystemExit("ECB: no USD rate")


def porkbun(rate: float) -> dict:
    d = json.loads(get(PORKBUN, data=b"{}"))
    out = {}
    for tld, p in (d.get("pricing") or {}).items():
        if not re.fullmatch(r"[a-z0-9-]+", tld) or "renewal" not in p:
            continue
        try:
            out[tld] = {"first": round(float(p["registration"]) / rate, 2), "renew": round(float(p["renewal"]) / rate, 2)}
        except (TypeError, ValueError):
            continue
    return out


def ovh() -> dict:
    """First year = the phase-0 "create" pricing; renewal = the phase-1 "renew" pricing (both 12 months, excl. VAT)."""
    d = json.loads(get(OVH, timeout=300))
    out = {}
    for plan in d.get("plans", []):
        code = plan.get("planCode", "")
        if not re.fullmatch(r"[a-z0-9]+", code):
            continue  # second-level (com.fr) and suffixed plan codes
        first = renew = None
        for pr in plan.get("pricings", []):
            if not ((pr.get("interval"), pr.get("intervalUnit")) in ((12, "month"), (1, "year"))):
                continue
            price = round(pr.get("price", 0) / 1e8, 2)
            if pr.get("phase") == 0 and str(pr.get("mode", "")).startswith("create") and first is None:
                first = price
            if pr.get("phase") == 1 and "renew" in pr.get("capacities", []) and renew is None:
                renew = price
        if renew:
            out[code] = {"first": first or renew, "renew": renew}
    return out


def table(pb: dict, ov: dict) -> dict:
    t = {}
    for tld in sorted(set(pb) | set(ov)):
        src = {k: v[tld] for k, v in (("porkbun", pb), ("ovh", ov)) if tld in v}
        renews = [s["renew"] for s in src.values()]
        firsts = [s["first"] for s in src.values()]
        cheapest = min(src, key=lambda k: src[k]["renew"])
        t[tld] = {"renew": [round(min(renews)), round(max(renews))], "first": [round(min(firsts)), round(max(firsts))],
                  "renew_min": src[cheapest]["renew"], "cheapest": cheapest, "sources": src, "premium": tld in PREMIUM}
    return t


def gate(t: dict, pb: dict, ov: dict, prev: dict | None) -> list:
    bad = []
    if len(t) < 500:
        bad.append(f"only {len(t)} endings")
    if "com" not in pb or "com" not in ov:
        bad.append(".com missing from a source")
    elif not all(8 <= s["renew"] <= 20 for s in t["com"]["sources"].values()):
        bad.append(f".com renewal out of 8-20: {t['com']['sources']}")
    for tld in SHOWN:
        if tld not in t:
            bad.append(f".{tld} missing")
            continue
        old = (prev or {}).get("tlds", {}).get(tld)
        if not old:
            continue
        moved = [abs(t[tld]["sources"][s]["renew"] / old["sources"][s]["renew"] - 1) > 0.40
                 for s in t[tld]["sources"] if s in old["sources"]]
        if moved and any(moved) and not all(moved):
            bad.append(f".{tld} moved >40% in one source only")
    return bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out", type=Path)
    ap.add_argument("--prev", type=Path)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    rate, day = usd_eur()
    pb, ov = porkbun(rate), ovh()
    t = table(pb, ov)
    prev = json.loads(a.prev.read_text()) if a.prev and a.prev.exists() else None
    bad = gate(t, pb, ov, prev)
    today = datetime.date.today().isoformat()
    doc = {"checked": today, "usd_eur": rate, "ecb_day": day, "excl_vat": True, "basis": "renewal",
           "counts": {"porkbun": len(pb), "ovh": len(ov), "endings": len(t)}, "gate": bad or "pass", "tlds": t}
    dated = a.out / f"prices-{today.replace('-', '')}.json"
    dated.write_text(json.dumps(doc, separators=(",", ":")))
    for old in sorted(a.out.glob("prices-*.json"))[:-8]:
        old.unlink()
    print(json.dumps({k: doc[k] for k in ("checked", "usd_eur", "counts", "gate")}),
          {x: t[x]["renew"] for x in SHOWN if x in t})
    if bad:
        sys.exit("gate failed; prices.json left as it was: " + "; ".join(bad))
    tmp = a.out / ".prices.json.part"
    tmp.write_text(json.dumps(doc, separators=(",", ":")))
    tmp.rename(a.out / "prices.json")


if __name__ == "__main__":
    main()
