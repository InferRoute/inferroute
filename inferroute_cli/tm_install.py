"""Download and install the trademark index the name check searches.

The file's address and BOTH hashes (the compressed download and the index itself) are pinned here, in the
signed release, so the host serving it is trusted for availability only: a file that does not hash to the
pinned value is deleted and nothing is installed. Downloading it tells the host only that this computer
fetched the same file every Anteriora user fetches; no name is involved.
"""
from __future__ import annotations

import hashlib
import lzma
import os
import sys
import urllib.request
from pathlib import Path
from typing import Callable, Optional

INDEX = {
    "url": "https://pub-8584cfc5a9eb4f7c8f5f12885e9ec5c4.r2.dev/tm/index-us-fr-20261016.sqlite.xz",
    "xz_sha256": "a81612a22bd16ad1ef6c4b04b9f8a302da84fbe139bd3c9b3f2a5b8409c27845",
    "xz_bytes": 249_760_808,
    "sha256": "d37b71fc64b974c97c47bddf834ac07ee50fcffbdff3ff76c314a1d4af5c5dca",
    "bytes": 804_175_872,
    "data": "US marks to 2026-09-30, French marks to 2026-10-16",
    "sources": "USPTO (United States); INPI (France)",
}
CHUNK = 1 << 20


class InstallError(Exception):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def installed(target: Path) -> bool:
    """True if the pinned index is the one installed (checked by size, then by hash once per file version)."""
    if not target.is_file() or target.stat().st_size != INDEX["bytes"]:
        return False
    stamp = target.with_suffix(".verified")
    mark = f"{INDEX['sha256']} {target.stat().st_mtime_ns}"
    try:
        if stamp.read_text().strip() == mark:
            return True
    except OSError:
        pass
    ok = _sha256(target) == INDEX["sha256"]
    if ok:
        stamp.write_text(mark)
    return ok


def install(target: Path, url: Optional[str] = None, progress: Optional[Callable[[str], None]] = None) -> Path:
    say = progress or (lambda m: None)
    target = Path(target)
    if installed(target):
        say("the trademark index is already installed and matches this release")
        return target
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    part = target.with_name(target.name + ".xz.part")
    tmp = target.with_name(target.name + ".tmp")
    try:
        say(f"downloading the trademark index ({INDEX['xz_bytes'] / 1e6:.0f} MB; {INDEX['data']})")
        h = hashlib.sha256()
        got = 0
        # A named agent: Cloudflare refuses Python's default one ("Python-urllib/…") with a 403.
        request = urllib.request.Request(url or INDEX["url"], headers={"User-Agent": "anteriora-client (inferroute)"})
        with urllib.request.urlopen(request, timeout=60) as r, part.open("wb") as out:
            while True:
                block = r.read(CHUNK)
                if not block:
                    break
                out.write(block)
                h.update(block)
                got += len(block)
                if got > INDEX["xz_bytes"]:
                    raise InstallError("the download is larger than the index this release names; stopped")
                if got % (25 * CHUNK) < CHUNK:
                    say(f"  {got / 1e6:.0f} / {INDEX['xz_bytes'] / 1e6:.0f} MB")
        if h.hexdigest() != INDEX["xz_sha256"]:
            raise InstallError("the downloaded file is not the one this release names; nothing was installed")
        say("unpacking")
        h = hashlib.sha256()
        with lzma.open(part) as src, tmp.open("wb") as out:
            for block in iter(lambda: src.read(CHUNK), b""):
                out.write(block)
                h.update(block)
        if h.hexdigest() != INDEX["sha256"]:
            raise InstallError("the unpacked index is not the one this release names; nothing was installed")
        os.chmod(tmp, 0o600)
        os.replace(tmp, target)
        target.with_suffix(".verified").write_text(f"{INDEX['sha256']} {target.stat().st_mtime_ns}")
        say(f"installed: {target}")
        return target
    except (OSError, lzma.LZMAError) as e:
        raise InstallError(f"could not install the trademark index: {e}")
    finally:
        part.unlink(missing_ok=True)
        tmp.unlink(missing_ok=True)


def main_install(target: Path) -> int:
    try:
        install(target, progress=lambda m: print(m, file=sys.stderr))
    except InstallError as e:
        print(f"ir: {e}", file=sys.stderr)
        return 1
    return 0
