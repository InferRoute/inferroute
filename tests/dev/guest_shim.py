"""DEVELOPMENT ONLY — plays the guest's PID 1 (`native/macos/guest/init2`) inside a container.

Two things a container cannot give the real supervisor are supplied here and nowhere else:

  * the session id, which the real guest reads from the kernel command line the runner sets;
  * the host's vsock address: a guest reaches its host at VMADDR_CID_HOST, a container on the same
    kernel reaches it over the vsock loopback transport at VMADDR_CID_LOCAL.

Everything after that is the product's own `guest.main()`, unmodified. Like init2, this never exits on
its own: the host stops the machine, and a guest that stopped first is reported as a failure.
"""
import pathlib
import socket
import sys
import time

session = sys.argv[1]
socket.VMADDR_CID_HOST = socket.VMADDR_CID_LOCAL

_read_text = pathlib.Path.read_text


def read_text(self, *args, **kwargs):
    if str(self) == "/proc/cmdline":
        return f"console=hvc0 rdinit=/init panic=0 probant.session={session}\n"
    return _read_text(self, *args, **kwargs)


pathlib.Path.read_text = read_text

from inferroute_local.macos_vm import guest  # noqa: E402

try:
    code = guest.main()
except BaseException as e:                                  # noqa: BLE001
    import traceback
    traceback.print_exc()
    code = 78
print(f"PROBANT_GUEST_SUPERVISOR_EXIT {code}", flush=True)
while True:
    time.sleep(3600)
