"""Put a built wheel where inferroute.ai serves it, and refuse to make one version mean two things.

On 1 Oct 2026 inferroute.ai was serving a 617 KB `inferroute-0.9.68-py3-none-any.whl` while this tree built
an 838 KB one under the same name. Two artifacts, one version string, and the smaller already downloadable.
That is not a cosmetic slip: `probant audit-client --url <that wheel>` exists so a client's own auditor can
show that what runs on their machine is what we published. Under a version collision that comparison FAILS,
and the honest reading of a failed comparison is tampering — we would have manufactured the exact evidence
the product is built to rule out.

So: a version is published once. Same bytes is a no-op; different bytes is a refusal that tells you to bump.

    python scripts/publish_client_wheel.py dist/inferroute-0.9.69-py3-none-any.whl \
        ../inferroute-site/public/client

Writes the wheel and a `.sha256` sidecar beside it. It does NOT deploy — the file still has to reach the
site, and that is a push someone does deliberately.
"""
import hashlib
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    wheel, dest = Path(argv[0]).resolve(), Path(argv[1]).resolve()
    if not wheel.is_file():
        print(f"no such wheel: {wheel}")
        return 1
    if not dest.is_dir():
        print(f"not a directory: {dest}")
        return 1

    raw = wheel.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    out = dest / wheel.name
    if out.exists():
        there = hashlib.sha256(out.read_bytes()).hexdigest()
        if there == digest:
            print(f"already published, byte for byte: {wheel.name}\n  sha256 {digest}")
            return 0
        print(f"REFUSED: {wheel.name} is already published with DIFFERENT bytes.\n"
              f"  published {there}  ({out.stat().st_size} bytes)\n"
              f"  building  {digest}  ({len(raw)} bytes)\n\n"
              "A version is published once. Anyone who installed the published one has a different product,\n"
              "and `audit-client --url` would report a mismatch that reads as tampering. Bump the version in\n"
              "pyproject.toml, rebuild, and publish that.")
        return 1

    out.write_bytes(raw)
    (dest / f"{wheel.name}.sha256").write_text(f"{digest}  {wheel.name}\n")
    print(f"published {wheel.name}\n  sha256 {digest}\n  {len(raw)} bytes -> {out}\n"
          "Not live yet: the site still has to be deployed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
