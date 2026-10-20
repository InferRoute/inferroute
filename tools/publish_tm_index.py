"""Refresh the trademark index and pin it in the client (our side; run before a release).

    python tools/publish_tm_index.py --uspto DIR --uspto-date YYYY-MM-DD --inpi DIR [--upload] [--pin]

1. builds the US+FR index (tools/build_tm_index.py),
2. compresses it with xz and hashes both files,
3. --upload: puts it in the anteriora-data R2 bucket under a dated name (wrangler; the file stays private
   to the bucket's public URL, which serves anyone who knows it — it holds public register data only),
4. --pin: rewrites INDEX in inferroute_cli/tm_install.py so the next signed release names the new file.

Nothing is pinned unless the download from the public URL hashes to what was built.
"""
import argparse
import hashlib
import json
import lzma
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
BUCKET = "anteriora-data"
PUBLIC = "https://pub-8584cfc5a9eb4f7c8f5f12885e9ec5c4.r2.dev"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--uspto", required=True); ap.add_argument("--uspto-date", required=True)
    ap.add_argument("--inpi", required=True)
    ap.add_argument("--out", default=str(Path.home() / "anteriora-tmdata"))
    ap.add_argument("--upload", action="store_true"); ap.add_argument("--pin", action="store_true")
    a = ap.parse_args()
    sys.path.insert(0, str(HERE))
    import tm_inpi
    fr_date = tm_inpi.data_date(Path(a.inpi))
    stamp = fr_date.replace("-", "")
    out = Path(a.out)
    db = out / f"index-us-fr-{stamp}.sqlite"
    xz = out / f"index-us-fr-{stamp}.sqlite.xz"
    if not db.exists():
        subprocess.run([sys.executable, str(HERE / "build_tm_index.py"), str(db), "--uspto", a.uspto,
                        "--uspto-date", a.uspto_date, "--inpi", a.inpi], check=True)
    if not xz.exists():
        subprocess.run(["xz", "-6", "-T0", "-k", "-c", str(db)], stdout=xz.open("wb"), check=True)
    info = {"url": f"{PUBLIC}/tm/{xz.name}", "xz_sha256": sha256(xz), "xz_bytes": xz.stat().st_size,
            "sha256": sha256(db), "bytes": db.stat().st_size,
            "data": f"US marks to {a.uspto_date}, French marks to {fr_date}",
            "sources": "USPTO (United States); INPI (France)"}
    print(json.dumps(info, indent=1))
    if a.upload:
        subprocess.run(["npx", "-y", "wrangler", "r2", "object", "put", f"{BUCKET}/tm/{xz.name}", "--file", str(xz),
                        "--content-type", "application/x-xz", "--remote"], check=True)
    if a.pin:
        req = urllib.request.Request(info["url"], headers={"User-Agent": "anteriora-client (inferroute)"})
        h = hashlib.sha256()
        with urllib.request.urlopen(req, timeout=120) as r:
            for block in iter(lambda: r.read(1 << 20), b""):
                h.update(block)
        if h.hexdigest() != info["xz_sha256"]:
            sys.exit("the public URL does not serve the file just built; nothing pinned")
        target = REPO / "inferroute_cli" / "tm_install.py"
        text = target.read_text()
        block = "INDEX = {\n" + "".join(
            f'    "{k}": {json.dumps(v) if isinstance(v, str) else f"{v:_}"},\n' for k, v in info.items()) + "}"
        new = re.sub(r"INDEX = \{\n.*?\n\}", lambda m: block, text, count=1, flags=re.S)
        if new == text:
            print("tm_install.py already pins this index")
        else:
            target.write_text(new)
            print(f"pinned in {target.relative_to(REPO)}; commit it with the release")


if __name__ == "__main__":
    main()
