"""DEVELOPMENT ONLY — makes the PRODUCT take its macOS VM path on a Linux machine.

Python imports a module named `sitecustomize` at startup if one is on its path. tests/dev/run_product_vm.py
puts this directory on PYTHONPATH, so every process the product starts (the home page starts each session as
a child) gets the same two substitutions:

  * `macos_vm.required_for` answers as it would on a Mac;
  * `runtime.locate` hands back the Linux stand-in runner (tests/dev/linux_vm_runner.py) instead of
    authenticating a vendor bundle — with a container guest, or with the REAL arm64 kernel and initrd under
    QEMU when PROBANT_DEV_VM_STANDIN names the directory holding them.

Everything else is the product, unmodified: confidential.py's Mac branch, Backend, Broker, the search
verifier, the session page, the export. It is the only way to run that code before a Mac is at hand.

This is not a bypass the product can be talked into. The product has no hook that reads this; it works by
replacing the product's functions from OUTSIDE, which anyone who controls PYTHONPATH can already do to any
Python program. Nothing here is installed by the wheel.
"""
import os
import shutil
import tempfile
from pathlib import Path

_standin = os.environ.get("PROBANT_DEV_VM_STANDIN")
if _standin:
    import inferroute_local.macos_vm as _vm
    from inferroute_local.macos_vm import backend as _backend
    from inferroute_local.macos_vm import runtime as _runtime

    _dev = Path(__file__).resolve().parents[1]
    _qemu = None if _standin == "container" else Path(_standin).resolve()

    def _required_for(agent, probant=None):
        return agent == "pi" and probant is not None

    def _locate():
        directory = Path(tempfile.mkdtemp(prefix="probant-vm-standin-"))
        shutil.copy2(_dev / "linux_vm_runner.py", directory / "ProbantVM")
        (directory / "ProbantVM").chmod(0o755)
        shutil.copy2(_dev / "guest_shim.py", directory / "guest_shim.py")
        (directory / "boot.json").write_text("{}")
        if _qemu is not None:
            for name in ("kernel", "initrd"):
                shutil.copy2(_qemu / name, directory / name)
        return _runtime.Runtime(directory, {})

    _vm.required_for = _required_for
    _runtime.locate = _locate
    if _qemu is not None:
        _backend.Backend.READY_SECONDS = 300
