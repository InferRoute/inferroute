#!/usr/bin/env python3
"""Build the Probant macOS guest: a Linux kernel and an initrd holding everything a session runs.

What goes in, all pinned:

  * Alpine packages (busybox, musl, python3, nodejs, bubblewrap and their dependencies), installed by
    a pinned `apk.static` and VERIFIED against Alpine's own signing keys — never `--allow-untrusted`.
    The full resolved set is checked against the lock below; a drifted mirror fails the build.
  * Alpine's `linux-virt` kernel, by sha256. It ships as an EFI zboot wrapper; Apple's
    VZLinuxBootLoader wants the raw arm64 Image inside, which is extracted here and checked by magic.
  * Pi, from the committed `pi/package-lock.json` (`npm ci`), optional and install scripts omitted.
    Its only native dependency is an optional clipboard module the guest has no use for.
  * This repository's own `inferroute_cli` and `inferroute_local` trees: the guest supervisor, the
    confinement it applies, and the Pi extension.

What comes out, deterministically (sorted entries, zeroed owners, one fixed timestamp, gzip with no
name or mtime): `kernel`, `initrd`, and `guest-manifest.json` naming every input and both outputs by
hash. Nothing here signs anything. The vendor signature over the runtime manifest, and the Developer ID
on the runner, are separate gates and deliberately not this script's job.

    python3 native/macos/guest/build_guest.py --arch aarch64 --out /tmp/guest-arm64
    python3 native/macos/guest/build_guest.py --arch x86_64  --out /tmp/guest-x86   # Linux dev harness

No emulation is used and nothing foreign is executed: packages are unpacked with `--no-scripts`, and
busybox's applet links are made from the list the package itself ships.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]

ALPINE = "v3.24"
MIRROR = "https://dl-cdn.alpinelinux.org/alpine"
EPOCH = 1759449600                                  # 2025-10-03T00:00:00Z — one timestamp for every entry

# Fetched for the BUILD machine (x86_64), by sha256. apk.static does the installing; alpine-keys carries
# the per-architecture signing keys the installed packages are verified against.
APK_STATIC = ("apk-tools-static-3.0.8-r0.apk", "c8e2c88c13ba12a12269b79a3543e1190ff8c0ab0beb32b58cadfd5881c619e3")
ALPINE_KEYS = ("alpine-keys-2.6-r0.apk", "dd211936d544f4050924ce8aec078d24e7b1b036ae70b30bd07867349587c708")

KERNEL = {"aarch64": ("linux-virt-6.18.54-r0.apk", "9a4a6fa042b60b70f453dded99762810516b35793c64d776d75986b0b110b6e0")}
MODULES = ("net/vmw_vsock/vsock", "net/vmw_vsock/vmw_vsock_virtio_transport_common",
           "net/vmw_vsock/vmw_vsock_virtio_transport", "drivers/char/hw_random/rng-core",
           "drivers/char/hw_random/virtio-rng")

REQUESTED = ("busybox", "musl", "python3", "nodejs", "bubblewrap")
# The complete resolved set. Anything else — a new dependency, a bumped revision — is a failed build
# until someone looks at it and updates this table on purpose.
LOCK = {
    "ada-libs": "3.3.0-r0", "brotli-libs": "1.2.0-r1", "bubblewrap": "0.12.0-r0", "busybox": "1.37.0-r31",
    "busybox-binsh": "1.37.0-r31", "c-ares": "1.34.8-r0", "ca-certificates": "20260909-r0", "gdbm": "1.26-r0",
    "icu-data-en": "78.1-r0", "icu-libs": "78.1-r0", "libbz2": "1.0.8-r6", "libcap2": "2.78-r0",
    "libcrypto3": "3.5.9-r0", "libexpat": "2.8.5-r0", "libffi": "3.5.2-r1", "libgcc": "15.2.0-r5",
    "libncursesw": "6.6_p20260516-r0", "libpanelw": "6.6_p20260516-r0", "libssl3": "3.5.9-r0",
    "libstdc++": "15.2.0-r5", "mpdecimal": "4.0.1-r0", "musl": "1.2.6-r2",
    "ncurses-terminfo-base": "6.6_p20260516-r0", "nghttp2-libs": "1.70.0-r0", "nodejs": "24.18.1-r0",
    "pyc": "3.14.8-r0", "python3": "3.14.8-r0", "python3-pyc": "3.14.8-r0",
    "python3-pycache-pyc0": "3.14.8-r0", "readline": "8.3.3-r1", "simdjson": "4.2.4-r0",
    "simdutf": "9.0.0-r0", "sqlite-libs": "3.53.4-r0", "ssl_client": "1.37.0-r31", "xz-libs": "5.8.4-r0",
    "zlib": "1.3.2-r0", "zstd-libs": "1.5.7-r2",
}
PI_VERSION = "0.84.1"


def die(msg: str) -> "NoReturn":            # noqa: F821
    print(f"build_guest: {msg}", file=sys.stderr)
    raise SystemExit(1)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def fetch(url: str, dest: Path, want: str) -> Path:
    """Download once, and refuse anything whose hash is not the pinned one — a cached copy included."""
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(url, timeout=300) as r, dest.open("wb") as out:
            shutil.copyfileobj(r, out)
    got = sha256(dest)
    if got != want:
        dest.unlink()
        die(f"{dest.name}: sha256 {got} is not the pinned {want}")
    return dest


def unpack_apk(apk: Path, into: Path) -> None:
    into.mkdir(parents=True, exist_ok=True)
    with tarfile.open(apk, "r:gz") as t:
        t.extractall(into, filter="tar")


def install_packages(arch: str, work: Path) -> Path:
    tools = work / "tools"
    apk_static = tools / "apk-static" / "sbin" / "apk.static"
    keys = tools / "keys" / "usr" / "share" / "apk" / "keys" / arch
    if not apk_static.exists():
        unpack_apk(fetch(f"{MIRROR}/{ALPINE}/main/x86_64/{APK_STATIC[0]}", tools / APK_STATIC[0], APK_STATIC[1]),
                   tools / "apk-static")
    if not keys.is_dir():
        unpack_apk(fetch(f"{MIRROR}/{ALPINE}/main/x86_64/{ALPINE_KEYS[0]}", tools / ALPINE_KEYS[0], ALPINE_KEYS[1]),
                   tools / "keys")
    root = work / f"rootfs-{arch}"
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True)
    wanted = [f"{name}={LOCK[name]}" for name in REQUESTED]
    r = subprocess.run(
        [str(apk_static), "--arch", arch, "--root", str(root), "--initdb", "--usermode",
         "--keys-dir", str(keys), "-X", f"{MIRROR}/{ALPINE}/main", "-X", f"{MIRROR}/{ALPINE}/community",
         "--no-scripts", "--no-cache", "add", *wanted],
        capture_output=True, text=True)
    if r.returncode != 0:
        die("apk failed:\n" + (r.stdout + r.stderr)[-2000:])
    installed = {}
    for block in (root / "lib/apk/db/installed").read_text(errors="replace").split("\n\n"):
        fields = {}
        for line in block.splitlines():
            if len(line) > 1 and line[1] == ":":
                fields.setdefault(line[0], line[2:])
        if "P" in fields:
            installed[fields["P"]] = fields["V"]
    if installed != LOCK:
        extra = {k: v for k, v in installed.items() if LOCK.get(k) != v}
        gone = sorted(set(LOCK) - set(installed))
        die(f"resolved packages differ from the lock. changed/new: {extra}; missing: {gone}")
    # apk's own log of this install carries wall-clock timestamps and is the one file that differed between
    # two otherwise identical builds (measured 3 Oct). It records nothing the lock above does not.
    (root / "var/log/apk.log").unlink(missing_ok=True)
    # The applet links busybox's own install script would have made. The package ships the list.
    for line in (root / "etc/busybox-paths.d/busybox").read_text().split():
        link = root / line.lstrip("/")
        if not link.exists() and not link.is_symlink():
            link.parent.mkdir(parents=True, exist_ok=True)
            link.symlink_to("/bin/busybox")
    return root


def extract_kernel(arch: str, work: Path, root: Path) -> tuple[Path, dict]:
    """The raw Image out of Alpine's EFI zboot wrapper, and the handful of modules the guest loads."""
    name, want = KERNEL[arch]
    apk = fetch(f"{MIRROR}/{ALPINE}/main/{arch}/{name}", work / "tools" / name, want)
    pkg = work / f"kernel-{arch}"
    shutil.rmtree(pkg, ignore_errors=True)
    unpack_apk(apk, pkg)
    raw = (pkg / "boot/vmlinuz-virt").read_bytes()
    if raw[:2] != b"MZ" or raw[4:8] != b"zimg":
        die("kernel is not an EFI zboot image; the packaging changed")
    offset, size = struct.unpack_from("<II", raw, 8)
    compression = raw[0x18:0x38].split(b"\0")[0].decode()
    if compression != "gzip":
        die(f"kernel payload compression {compression!r} is not handled")
    image = gzip.decompress(raw[offset:offset + size])
    if image[56:60] != b"ARM\x64":
        die("extracted kernel does not carry the arm64 Image magic")
    out = work / f"kernel-{arch}.Image"
    out.write_bytes(image)
    moddir = next((pkg / "lib/modules").iterdir())
    dest = root / "lib/probant-modules"
    dest.mkdir(parents=True)
    for rel in MODULES:
        src = moddir / "kernel" / (rel + ".ko.gz")
        (dest / (Path(rel).name + ".ko")).write_bytes(gzip.decompress(src.read_bytes()))
    return out, {"package": name, "sha256": want, "release": moddir.name}


def install_pi(work: Path, root: Path) -> None:
    """`npm ci` from the committed lock: the same tree every time, no install scripts, no optional natives."""
    stage = work / "pi"
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)
    for name in ("package.json", "package-lock.json"):
        shutil.copy2(HERE / "pi" / name, stage / name)
    r = subprocess.run(["npm", "ci", "--omit=optional", "--ignore-scripts", "--no-audit", "--no-fund",
                        "--loglevel=error"], cwd=stage, capture_output=True, text=True)
    if r.returncode != 0:
        die("npm ci failed:\n" + (r.stdout + r.stderr)[-2000:])
    got = json.loads((stage / "node_modules/@earendil-works/pi-coding-agent/package.json").read_text())["version"]
    if got != PI_VERSION:
        die(f"Pi resolved to {got}, not {PI_VERSION}")
    modules = stage / "node_modules"
    for path in sorted(modules.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        # Source maps are a third of the tree and nothing at runtime reads them; the prebuilt binaries are
        # for other operating systems. Any OTHER native binary is unexpected and stops the build.
        if path.suffix == ".map":
            path.unlink()
        elif path.suffix == ".node":
            if any(part in ("darwin", "win32") or part.startswith(("darwin-", "win32-")) for part in path.parts):
                path.unlink()
            else:
                die(f"unexpected native module in the Pi tree: {path.relative_to(modules)}")
    dest = root / "opt/pi"
    dest.mkdir(parents=True)
    shutil.copytree(modules, dest / "node_modules", symlinks=True)


def install_client(root: Path) -> None:
    dest = root / "opt/probant/client"
    dest.mkdir(parents=True)
    for package in ("inferroute_cli", "inferroute_local"):
        shutil.copytree(REPO / package, dest / package,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "macos_runtime", "node_modules"))
    for required in ("inferroute_local/macos_vm/guest.py", "inferroute_local/macos_vm/guard.py",
                     "inferroute_cli/pi_attested/ir-attested.ts"):
        if not (dest / required).is_file():
            die(f"client tree is missing {required}")


def install_init(root: Path) -> None:
    for name in ("init", "init2"):
        shutil.copy2(HERE / name, root / name)
        (root / name).chmod(0o755)
    for d in ("proc", "sys", "dev", "tmp", "run", "root", "matter", "config", "newroot"):
        (root / d).mkdir(exist_ok=True)


def write_cpio(root: Path, out: Path) -> None:
    """newc cpio, written here rather than by cpio(1) so ownership, order and time are all fixed."""
    buf = io.BytesIO()

    def entry(name: str, mode: int, data: bytes, nlink: int = 1) -> None:
        encoded = name.encode() + b"\0"
        header = "070701" + "".join(f"{v:08X}" for v in (
            0, mode, 0, 0, nlink, EPOCH, len(data), 0, 0, 0, 0, len(encoded), 0))
        buf.write(header.encode() + encoded)
        buf.write(b"\0" * (-(110 + len(encoded)) % 4))
        buf.write(data)
        buf.write(b"\0" * (-len(data) % 4))

    paths = sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix())
    for path in paths:
        rel = path.relative_to(root).as_posix()
        st = path.lstat()
        if stat.S_ISLNK(st.st_mode):
            entry(rel, 0o120777, os.readlink(path).encode())
        elif stat.S_ISDIR(st.st_mode):
            entry(rel, 0o040000 | (stat.S_IMODE(st.st_mode) or 0o755), b"", nlink=2)
        elif stat.S_ISREG(st.st_mode):
            mode = 0o755 if st.st_mode & 0o111 else 0o644
            entry(rel, 0o100000 | mode, path.read_bytes())
        else:
            die(f"unexpected file type in the guest tree: {rel}")
    entry("TRAILER!!!", 0, b"")
    with out.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as gz:
        gz.write(buf.getvalue())


def write_tar(root: Path, out: Path) -> None:
    """The same tree as a tarball — what the Linux development harness imports as a container image."""
    def clean(info: tarfile.TarInfo) -> tarfile.TarInfo:
        info.uid = info.gid = 0
        info.uname = info.gname = "root"
        info.mtime = EPOCH
        return info
    with tarfile.open(out, "w") as t:
        for path in sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix()):
            t.add(path, arcname=path.relative_to(root).as_posix(), recursive=False, filter=clean)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--arch", choices=("aarch64", "x86_64"), required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--work", default="")
    a = ap.parse_args()
    out = Path(a.out).resolve()
    work = Path(a.work).resolve() if a.work else out / "work"
    out.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)

    root = install_packages(a.arch, work)
    manifest = {"schema": "inferroute.macos-vm-guest/1", "arch": a.arch, "alpine": ALPINE,
                "packages": dict(sorted(LOCK.items())), "pi_version": PI_VERSION,
                "pi_lock_sha256": sha256(HERE / "pi/package-lock.json"),
                "apk_static": APK_STATIC[1], "alpine_keys": ALPINE_KEYS[1], "source_date_epoch": EPOCH}
    kernel = None
    if a.arch in KERNEL:
        kernel, manifest["kernel_source"] = extract_kernel(a.arch, work, root)
    install_pi(work, root)
    install_client(root)
    install_init(root)

    if kernel is not None:
        shutil.copy2(kernel, out / "kernel")
        write_cpio(root, out / "initrd")
        manifest["artifacts"] = {n: {"bytes": (out / n).stat().st_size, "sha256": sha256(out / n)}
                                 for n in ("kernel", "initrd")}
    else:
        write_tar(root, out / "rootfs.tar")
        manifest["artifacts"] = {"rootfs.tar": {"bytes": (out / "rootfs.tar").stat().st_size,
                                                "sha256": sha256(out / "rootfs.tar")}}
    (out / "guest-manifest.json").write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    for name, rec in manifest["artifacts"].items():
        print(f"{name:11} {rec['bytes'] / 1e6:7.1f} MB  sha256 {rec['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
