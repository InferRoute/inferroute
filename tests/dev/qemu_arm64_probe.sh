#!/bin/sh
# DEVELOPMENT ONLY — run tests/dev/guest_confinement_probe.py inside the REAL arm64 guest, emulated by QEMU.
#
#   sh tests/dev/qemu_arm64_probe.sh <dir with kernel + initrd from build_guest.py --arch aarch64>
#
# The shipped initrd is not modified: the kernel unpacks concatenated archives in order, so a second small
# archive holding the probe and an /init2 that runs it instead of the supervisor is appended to a COPY.
# Everything before that point — the kernel, stage-1 init, the module loads, the userland — is the image
# as built. Needs docker, the image `probant-qemu-dev:arm64` (alpine + qemu-system-aarch64) and cpio.
set -eu
GUEST=$(cd "$1" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/overlay/opt/dev" "$WORK/rt"
cp "$HERE/guest_confinement_probe.py" "$WORK/overlay/opt/dev/probe.py"
sed 's|^python3 -m inferroute_local.macos_vm.guest$|echo PROBE_BEGIN; python3 /opt/dev/probe.py; echo "PROBE_END rc=$?"|' \
  "$HERE/../../native/macos/guest/init2" > "$WORK/overlay/init2"
grep -q PROBE_BEGIN "$WORK/overlay/init2" || { echo "init2 no longer has the line this replaces" >&2; exit 1; }
chmod 755 "$WORK/overlay/init2"
( cd "$WORK/overlay" && find . -mindepth 1 | sort | cpio -o -H newc --owner 0:0 2>/dev/null | gzip -n ) > "$WORK/overlay.gz"
cat "$GUEST/initrd" "$WORK/overlay.gz" > "$WORK/rt/initrd"
cp "$GUEST/kernel" "$WORK/rt/kernel"
chmod -R a+rX "$WORK"
NAME=probant-qemu-probe-$$
timeout 240 docker run --rm --name "$NAME" --network none --device /dev/vhost-vsock -v "$WORK/rt:/rt:ro" \
  probant-qemu-dev:arm64 qemu-system-aarch64 -M virt -cpu max -smp 2 -m 1024 -display none -serial none \
  -monitor none -no-reboot -nic none -kernel /rt/kernel -initrd /rt/initrd \
  -append "console=hvc0 rdinit=/init panic=0 probant.session=00000000-0000-4000-8000-000000000001" \
  -device virtio-serial-pci -chardev stdio,id=con,signal=off -device virtconsole,chardev=con \
  -device vhost-vsock-pci,guest-cid=4243 -device virtio-rng-pci < /dev/null 2>&1 | {
    seen=1
    while IFS= read -r line; do
      case "$line" in
        *PROBE_BEGIN*) show=1 ;;
        *PROBE_END*) echo "$line"; case "$line" in *"rc=0"*) seen=0 ;; esac; docker kill "$NAME" >/dev/null 2>&1 || true; break ;;
      esac
      [ "${show:-0}" = 1 ] && echo "$line"
    done
    exit $seen
  }
