A Mac Probant session runs its agent inside a small Linux virtual machine. This directory holds what
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
real session through its Mac branch with a stand-in runner. NOT yet checked anywhere: that the Swift runner
compiles and that Virtualization.framework boots the image.

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
