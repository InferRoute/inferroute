"""Index provenance: the manifest a certificate can cite and a firm can re-verify offline.

STDLIB ONLY — same rule as verify.py, so this can ship inside the export bundle and be run by the
firm's own IT (or their expert) against the appliance without installing anything.

The corpus hash is a hash *of the shard listing*, not of a concatenation: it is stable under file
reordering, cheap to recompute incrementally, and names exactly which bytes were searched.

    corpus_sha256 = sha256( "".join(f"{sha256}  {relpath}\\n" for each shard, sorted by relpath) )

A certificate that states `openalex-npl@a1b2c3d4...` is therefore a claim the firm can falsify in one
command: `sealed-index-verify /path/to/index` recomputes every shard hash and the corpus hash.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, Iterable, List, Optional, Tuple

MANIFEST_NAME = "manifest.json"


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def corpus_hash(shards: Iterable[Dict[str, Any]]) -> str:
    """Hash of the canonical shard listing (sorted by path)."""
    lines = sorted(f"{s['sha256']}  {s['path']}\n" for s in shards)
    return hashlib.sha256("".join(lines).encode()).hexdigest()


def snapshot_id(manifest: Dict[str, Any], n: int = 16) -> str:
    """Short human-quotable id for a certificate: `openalex-npl@a1b2c3d4e5f60718`."""
    return f"{manifest.get('index', 'index')}@{manifest.get('corpus_sha256', '')[:n]}"


def load(index_dir: str) -> Dict[str, Any]:
    with open(os.path.join(index_dir, MANIFEST_NAME)) as fh:
        return json.load(fh)


def save(index_dir: str, manifest: Dict[str, Any]) -> str:
    path = os.path.join(index_dir, MANIFEST_NAME)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)
    return path


def scan_shards(index_dir: str, subdir: str = "works") -> List[str]:
    """Relative paths of every parquet shard, sorted — the canonical corpus listing."""
    root = os.path.join(index_dir, subdir)
    out: List[str] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            if fn.endswith(".parquet"):
                out.append(os.path.relpath(os.path.join(dirpath, fn), index_dir))
    return sorted(out)


def scan_files(index_dir: str, components: Dict[str, Dict[str, Any]]) -> List[str]:
    """`layout: files` — a search index is several artefacts (a paper store, an ANN index, dense shards,
    a patent corpus with its vectors, two encoders), each a component root under `index_dir` (symlinks
    allowed) with include globs. Everything matching is part of the searched bytes and is listed."""
    import fnmatch
    out: List[str] = []
    for name, comp in components.items():
        root = os.path.join(index_dir, comp.get("root", name))
        pats = comp.get("include", ["**/*"])
        for dirpath, _d, filenames in os.walk(root, followlinks=True):
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                rel_c = os.path.relpath(full, root)
                if any(fnmatch.fnmatch(rel_c, pat) or fnmatch.fnmatch(fn, pat) for pat in pats):
                    out.append(os.path.join(comp.get("root", name), rel_c))
    return sorted(set(out))


def build_files_manifest(index_dir: str, index_name: str, components: Dict[str, Dict[str, Any]],
                         extra: Optional[Dict[str, Any]] = None, progress: Optional[Any] = None) -> Dict[str, Any]:
    """Hash every listed file; write manifest.json with layout 'files'."""
    import time
    paths = scan_files(index_dir, components); shards = []
    for i, rel in enumerate(paths):
        full = os.path.join(index_dir, rel)
        shards.append({"path": rel, "bytes": os.path.getsize(full), "sha256": sha256_file(full)})
        if progress and (i + 1) % 25 == 0:
            progress(i + 1, len(paths))
    m = {"index": index_name, "layout": "files", "components": components, "shards": shards,
         "files": len(shards), "bytes": sum(s["bytes"] for s in shards),
         "built_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "corpus_sha256": corpus_hash(shards)}
    m.update(extra or {})
    save(index_dir, m)
    return m


def verify(index_dir: str, manifest: Optional[Dict[str, Any]] = None,
           progress: Optional[Any] = None) -> Tuple[bool, List[str]]:
    """Recompute every shard hash and the corpus hash. Returns (ok, problems).

    Detects: modified shard, missing shard, shard added since the build (an index that grew under the
    certificate's feet is exactly as disqualifying as one that shrank).
    """
    m = manifest if manifest is not None else load(index_dir)
    problems: List[str] = []
    recorded = {s["path"]: s for s in m.get("shards", [])}
    on_disk = set(scan_files(index_dir, m["components"]) if m.get("layout") == "files" else scan_shards(index_dir))
    for path in sorted(set(recorded) - on_disk):
        problems.append(f"missing shard: {path}")
    for path in sorted(on_disk - set(recorded)):
        problems.append(f"shard not in manifest (added after build): {path}")
    checked = []
    for i, path in enumerate(sorted(on_disk & set(recorded))):
        full = os.path.join(index_dir, path)
        digest = sha256_file(full)
        if digest != recorded[path]["sha256"]:
            problems.append(f"shard modified: {path}")
        else:
            checked.append({"path": path, "sha256": digest})
        if progress and (i + 1) % 250 == 0:
            progress(i + 1, len(on_disk & set(recorded)))
    if not problems:
        got = corpus_hash(checked)
        if got != m.get("corpus_sha256"):
            problems.append(f"corpus hash mismatch: manifest {m.get('corpus_sha256')} != recomputed {got}")
    return (not problems), problems


def main() -> int:  # `sealed-index-verify <index_dir>`
    import sys
    if len(sys.argv) < 2:
        print("usage: sealed-index-verify <index_dir>", file=sys.stderr)
        return 2
    index_dir = sys.argv[1]
    m = load(index_dir)
    print(f"index    : {snapshot_id(m)}")
    print(f"built    : {m.get('built_utc')}")
    rows = m.get('rows'); size = m.get('bytes')
    print(f"shards   : {len(m.get('shards', []))}  " + (f"rows: {rows:,}" if isinstance(rows, int) else f"bytes: {size/2**30:.1f} GB" if size else ""))
    ok, problems = verify(index_dir, m,
                          progress=lambda i, n: print(f"  ... {i}/{n} shards", flush=True))
    for p in problems[:50]:
        print(f"  PROBLEM: {p}")
    if len(problems) > 50:
        print(f"  ... and {len(problems) - 50} more")
    print("RESULT   : " + ("VERIFIED — every shard matches the manifest" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
