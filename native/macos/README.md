A Mac Anteriora session runs its agent inside a small Linux virtual machine. This directory holds what
builds it. Missing or unauthenticated runtime means refusal before Pi or any model session starts; no
environment variable enables an unsigned payload.

What a client needs, and where each piece comes from:

| piece | built by | shipped as |
|---|---|---|
| `ProbantVM` (the runner) | `build_runner.sh`, on a Mac | `inferroute-macos-vm-runtime` wheel |
| `kernel`, `initrd` (the guest) | `guest/build_guest.py --arch aarch64`, anywhere, reproducibly | the same wheel |
| `runtime.json` (hashes of the three, signed) | `scripts/sign_macos_runtime.py build` | the same wheel |
| `macos-vm-policy.json` (the key that must have signed it, and the runner tier) | `docs/trust/`, committed | inside the `inferroute` client wheel |

The runtime wheel installs `inferroute_macos_vm_runtime/` beside the client's packages; that is the one
place `runtime.locate()` looks. Where the files sit is not a trust decision: the signature is.

Two tiers for the runner executable, fixed by the policy inside the client:

* `adhoc-pinned` (current). The runner is ad-hoc signed — which grants it the virtualization entitlement
  and says nothing about who built it. Its bytes are pinned by the vendor-signed manifest. One factor:
  the vendor key (`sign_macos_runtime.py keygen`; private half mode 600, outside every repo).
* `developer-id`. Additionally requires Apple's Developer ID chain for a named team and identifier, so a
  stolen vendor key alone cannot bless a runner. Needs an Apple Developer account; not provisioned.

A development runner (`DEV_CONSOLE=1 build_runner.sh`) copies the guest's console to stderr. It carries a
marker string and the signing script refuses it.

Checked without a Mac (see `tests/dev/`): the guest image boots and runs a whole session under QEMU
emulation, the confinement probe gives the expected refusals on arm64, and the product itself has run a
real session through its Mac branch with a stand-in runner. Checked on a Mac (ADE, 3 Oct): the runner
compiles, Virtualization.framework boots the image, and an installed client ran a real session — see
`RELEASE.md`.

`ProbantVM.swift` is the Virtualization.framework runner. Its guest has no NIC,
shares or persistent disks. Python verifies the signed manifest and privately
copies all artifacts before passing boot URLs. Agent RPC uses separate anonymous
pipes; the guest supervisor owns the virtio broker channels. The runner must
prove the VM stopped before the host commits workspace outputs.

`AppMain.swift` and `app_entry.py` keep the browser UI behind a small signed app
shell. Vendor CI must bundle standalone Python and all host dependencies, client
code, pinned trust resources, the runner, Linux kernel/initrd, guest Python,
Node and pinned Pi. End users need no installed developer tools or runtimes.
`install.sh.in` is an installation template that refuses until vendor pins are
rendered. It verifies Developer ID and Gatekeeper assessment, verifies a private
copy again, and installs a versioned app without replacing prior versions.
The template has not been used to install a client on any test Mac.

Vendor build/signing must cover nested Mach-O binaries and Python libraries,
then the outer app with hardened runtime; notarize and staple the final bundle.
The guest manifest signature covers kernel and initrd (including Pi, extension,
Python, Node, confinement and broker code), protocol, architecture, minimum OS
and Pi version. Do not embed private signing keys in app, VM or reports.
Vendor identity/key provisioning, reproducible authenticated guest construction,
clean-Mac installation, minimum-OS and Intel support are release gates.
Currently only arm64 is accepted. Compilation targeting macOS 12 is not proof
that every macOS 12 machine supports the shipped workload.

Development test drivers may construct an explicit Runtime object in a separate
synthetic harness. They must not add a production verification bypass. An inner
boot manifest's `development_only:false` is not authentication: production also
requires the independent signed outer manifest and Developer ID check.

## Ad-hoc app (`build_app_adhoc.sh`): a .dmg for a stock Mac, without an Apple Developer ID

    sh native/macos/build_app_adhoc.sh INPUTS OUT        # on an Apple-silicon Mac; Command Line Tools only

`INPUTS` holds the four files named in `pins.json`, each refused unless its sha256 matches: a
python-build-standalone CPython 3.12 (arm64, install_only), and the signed release's client wheel, runtime
wheel and hash lock (the lock `install-probant.sh` pins). Output: `Anteriora.app` and `Anteriora-<V>.dmg`
(the app, an Applications link, and a French/English `README.txt` about the Gatekeeper warning).

Names: a person sees **Anteriora** (app folder, menu, window, dmg/pkg file and volume names). The technical
identifiers keep the earlier name on purpose, because installed copies, the signed runtime and existing matters
depend on them: bundle identifier `ai.inferroute.probant`, pkg identifier `ai.inferroute.probant.pkg`, runner
`ProbantVM`, data folder `~/Probant`, the `probant` / `ir probant` commands and `IR_PROBANT_*` variables. An
earlier `/Applications/Probant.app` is not removed by installing `Anteriora.app`; delete it by hand.

* The runtime wheel goes in unchanged. Its runner, kernel, initrd and `runtime.json` are never re-signed or
  modified; the build checks the runner's sha256 against the pin before and after signing, and runs
  `runtime.locate()` on the bundled copy, so the signed manifest verifies in place.
* Libraries: `pip install --require-hashes --only-binary=:all:` from the lock, then the two wheels by hash,
  `--no-deps`. pip is removed afterwards; nothing is installed at run time. Bytecode is compiled at build
  time and the app never writes inside its own bundle (`-B`, `PYTHONDONTWRITEBYTECODE`): a new file there
  would break the bundle's seal.
* Signatures, all ad-hoc: every Mach-O in the bundled Python except the runner; `python3.12` with the
  hardened runtime and ONE entitlement, `disable-library-validation` (ad-hoc libraries have no Team ID, and
  library validation refuses them otherwise); the outer app with the hardened runtime and none.
* `AppMain.swift` starts `probant home` (which opens the page in the browser), shows a Dock icon, reopens
  the page on a Dock click, and on Quit / Cmd-Q / SIGTERM sends SIGINT to the service's process group, which
  is what Ctrl-C does in a terminal, then waits (up to 90 s) for the sessions to end.

What this does NOT give: Apple has not notarized the app, so Gatekeeper blocks the first open of a
downloaded copy and the person must use System Settings > Privacy & Security > Open Anyway. That says
nothing about who built it; trust rests on the vendor-signed runtime manifest and the hash-pinned inputs.
The bundle is not reproducible byte for byte (the dmg differs on each build) and only arm64 is built.
`assemble_app.py` and `install.sh.in` are the separate Developer-ID path and are not used here.

## Installer .pkg (no Developer ID)

`build_pkg_from_dmg.sh Anteriora-<V>.dmg OUTDIR` (on a Mac) wraps the ad-hoc `Anteriora.app` from the .dmg, bytes unchanged, into an
unsigned `.pkg`. A copy out of a quarantined .dmg also quarantines the bundled `python3`, which Gatekeeper then kills; files the
Installer places carry no quarantine. Measured on a second Mac by sealed-research (2026-10-15, CLI install only): python3 runs at once,
codesign valid, service check passes. The GUI path (Open Anyway on the pkg, then Installer.app) is not yet measured.
