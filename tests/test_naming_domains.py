"""Domains: extra endings fill the top slots and the rest are listed under more(); stale lists are not shown."""
import hashlib
import json
import os
import time
from datetime import datetime, timezone

import numpy as np

from inferroute_cli.naming_demo.server import Domains


def _h(label):
    return int.from_bytes(hashlib.blake2b(label.encode(), digest_size=8).digest(), "little")


def _zone(d, tld, labels, age_days=0):
    p = d / f"{tld}.npy"
    np.save(p, np.unique(np.array([_h(x) for x in labels] or [], dtype=np.uint64)))
    t = time.time() - age_days * 86400
    os.utime(p, (t, t))


def test_more_endings_and_freshness(tmp_path):
    for t in ("com", "app", "dev", "net", "org"):
        _zone(tmp_path, t, ["taken"])
    _zone(tmp_path, "tech", ["other"])
    _zone(tmp_path, "xyz", [])
    _zone(tmp_path, "shop", [], age_days=30)  # stale: never shown
    (tmp_path / "prices.json").write_text(json.dumps({
        "checked": datetime.now(timezone.utc).date().isoformat(), "gate": "pass",
        "tlds": {"tech": {"renew_min": 40.2, "cheapest": "porkbun"}, "xyz": {"renew_min": 12.6, "cheapest": "ovh"}}}))
    d = Domains(tmp_path)
    # "fresh" is free on app/dev/net: those fill the top 3; tech/xyz go to more(), cheapest first; shop is stale
    assert [e["tld"] for e in d.endings("fresh")] == ["com", "app", "dev", "net"]
    assert [(m["tld"], m["eur"]) for m in d.more("fresh")] == [("xyz", 13), ("tech", 40)]
    # "taken" is taken on every EXTRA ending: the new endings fill the top slots instead
    assert [e["tld"] for e in d.endings("taken")] == ["com", "tech", "xyz"]
    assert d.more("taken") == []


def test_country_endings_mapping():
    import io
    import urllib.error

    from inferroute_cli.naming_demo.server import COUNTRY_RDAP, country_endings

    seen = []

    class R:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def opener(req, timeout):
        url = req.full_url
        seen.append(url)
        if url.endswith(".io"):
            return R()
        code = 429 if url.endswith(".de") else 404
        raise urllib.error.HTTPError(url, code, "x", {}, io.BytesIO())

    rs = country_endings(" Quillora ", opener)
    assert [r["tld"] for r in rs] == list(COUNTRY_RDAP)
    assert {r["tld"]: r["taken"] for r in rs} == {"io": True, "ai": False, "co": False, "fr": False, "de": None}
    assert len(seen) == 5 and all("quillora." in u for u in seen)
    assert country_endings("a.b") is None and country_endings("-x") is None and country_endings("") is None
