This is an unreleased, gated source integration. Production launch requires an
independently pinned vendor policy in `inferroute_cli/trust/macos-vm-policy.json`,
a signed `inferroute_cli/macos_runtime/runtime.json`, and a Developer ID signed
runner. None are provisioned here. Missing runtime means refusal before Pi or
model-session startup. No environment variable enables an unsigned payload.

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
