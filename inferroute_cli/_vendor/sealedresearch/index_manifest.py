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


def tree_sha256(root: str) -> str:
    """A deterministic hash over EVERY file under an index root, committed into REPORT_DATA so the client can pin the
    exact bytes that were searchable. Order-independent (sorted path+sha lines), like sha256 over a manifest.
    It is sha256 over exactly the text tree_lines() returns, so a saved lines file proves which root a hash names."""
    return hashlib.sha256("".join(tree_lines(root)).encode()).hexdigest()


def tree_lines(root: str) -> List[str]:
    """The sorted "sha256  relpath\n" lines tree_sha256 hashes, one per file under root (symlinks followed). The
    index delegate's tool reads them to check that a refreshed root changes data only, never models/."""
    # os.walk(followlinks=True), not Path.rglob: on Python 3.12 rglob does NOT descend symlinked
    # directories, and a pre-mounted path can be a symlink tree. rglob would then find zero files and this
    # would return sha256 of an empty list — e3b0c442…, identical for every index — a real-looking digest
    # committing to nothing while real files are served. Found by the attested session before the first
    # reference was signed.
    files = []
    for dirpath, _dirs, names in os.walk(root, followlinks=True):
        for name in names:
            files.append(os.path.join(dirpath, name))
    n_shards = sum(1 for _ in json.load(open(os.path.join(root, "ann", "layout.json")))["shards"])
    if len(files) < n_shards:
        raise SystemExit(f"manifest refuses: found {len(files)} files under {root} but the index declares "
                         f"{n_shards} shards. A short or empty manifest would commit to bytes that were not served.")
    lines = [f"{sha256_file(p)}  {os.path.relpath(p, root)}\n" for p in files]
    return sorted(lines)


def models_sha256(root: str) -> str:
    """v15's model_manifest_sha256: the same tree hash over root/models/ ONLY (the encoder's weights, tokenizer and
    config, and the stage-1/2 ranking models), paths relative to root. Before v15 it covered model.safetensors alone,
    so a different ranking model rode inside the index fingerprint (found by sealed-research, 8 Nov). Refuses an empty
    models/: a hash of nothing would commit to nothing."""
    return models_sha256_from_lines(tree_lines(root), where=root)


def models_sha256_from_lines(lines: List[str], where: str = "the root") -> str:
    """models_sha256 from lines tree_lines already produced, so the box hashes its 119 GiB root ONCE at boot for both
    fingerprints (sealed-research review, 8 Nov)."""
    lines = [l for l in lines if l.split("  ", 1)[1].startswith("models/")]
    if not any(l.rstrip("\n").endswith("/model.safetensors") for l in lines):
        raise SystemExit(f"models refuses: no models/…/model.safetensors under {where}")
    return hashlib.sha256("".join(lines).encode()).hexdigest()
