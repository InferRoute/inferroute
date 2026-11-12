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
    "url": "https://pub-8584cfc5a9eb4f7c8f5f12885e9ec5c4.r2.dev/tm/index-us-fr-eu-wo-au-20261112.sqlite.xz.1",
    "parts": ["https://pub-8584cfc5a9eb4f7c8f5f12885e9ec5c4.r2.dev/tm/index-us-fr-eu-wo-au-20261112.sqlite.xz.1",
              "https://pub-8584cfc5a9eb4f7c8f5f12885e9ec5c4.r2.dev/tm/index-us-fr-eu-wo-au-20261112.sqlite.xz.2"],
    "xz_sha256": "2b9c321d65158b96b5b82ce7ff10a881f11651e2265c9539db66ffaeae547126",
    "xz_bytes": 384_040_924,
    "sha256": "1ee90bc6f9c70da794053fdfe7b31d9bfea5c0e74b719082c436d348d67a5de3",
    "bytes": 1_224_863_744,
    "data": ("US marks to 2026-09-30, French marks to 2026-10-16, EU marks to 2026-11-01, international "
             "registrations to 2026-10-22, Australian marks to 2026-11-08"),
    "sources": ("USPTO (United States); INPI (France); EUIPO (EU trade marks, from INPI's open-data copy); WIPO "
                "(international registrations designating France or the EU, from INPI's open-data copy); "
                "Australian trade marks: IP Australia, IP RAPID (data.gov.au), licensed CC BY 4.0 "
                "(creativecommons.org/licenses/by/4.0); filtered to live word marks."),
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


def install(target: Path, url: Optional[str] = None, progress: Optional[Callable[[str], None]] = None,
            on_connect: Optional[Callable[[], None]] = None) -> Path:
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
        # The file may be served in parts (R2 takes at most 300 MiB per upload from our side): they are fetched in
        # order into one file, and the size and both hashes are checked on the whole, exactly as for one part.
        urls = [url] if url else list(INDEX.get("parts") or [INDEX["url"]])
        with part.open("wb") as out:
            for i, u in enumerate(urls):
                # A named agent: Cloudflare refuses Python's default one ("Python-urllib/…") with a 403.
                request = urllib.request.Request(u, headers={"User-Agent": "anteriora-client (inferroute)"})
                with urllib.request.urlopen(request, timeout=60) as r:
                    if on_connect and i == 0:
                        on_connect()     # the server answered: from here a slow download is progress, not a dead line
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
