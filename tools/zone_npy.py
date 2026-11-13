"""Zone label sets for the naming backend: CZDS names_<tld>.parquet -> <tld>.npy (sorted unique blake2b-64 of the
lower-cased label, little-endian uint64), the format inferroute_cli.naming_demo.server.Domains reads.

    python tools/zone_npy.py OUT_DIR app dev org [--src DIR]

Only hashes are kept, so the served file holds no readable domain names.
"""
import argparse
import hashlib
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq

SRC = Path("/media/henry/Extreme SSD/open-data/czds")


def build(tld: str, src: Path, out: Path) -> int:
    f = pq.ParquetFile(src / f"names_{tld}.parquet")
    parts = []
    for i in range(f.num_row_groups):
        labels = f.read_row_group(i, columns=["label"]).column(0).to_pylist()
        parts.append(np.fromiter((int.from_bytes(hashlib.blake2b(s.lower().encode(), digest_size=8).digest(), "little")
                                  for s in labels if s), dtype=np.uint64))
    a = np.unique(np.concatenate(parts)) if parts else np.zeros(0, np.uint64)
    tmp = out / f".{tld}.npy.part"
    with open(tmp, "wb") as fh:
        np.save(fh, a)
    tmp.rename(out / f"{tld}.npy")
    return len(a)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out", type=Path)
    ap.add_argument("tlds", nargs="+")
    ap.add_argument("--src", type=Path, default=SRC)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    for t in a.tlds:
        print(t, build(t, a.src, a.out), "labels")


if __name__ == "__main__":
    main()
