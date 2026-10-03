# Releasing Probant for a Mac — the runbook

State on 2026-10-03, evening. Steps 1, 2, 3 and 5 have been done once, on ADE (Apple M1, macOS 26.5,
Swift 6.3.2), with nothing published:

* the runner compiled at the first attempt and both builds booted the guest under Virtualization.framework
  — kernel to guest supervisor in about 2.4 s, a whole synthetic session in about 10 s;
* release runner sha256 `e2021618fc7f3eff0c8c407538d7bd0bf78559c115737266fc9051412960d80e`;
* client 0.9.100 and the signed runtime wheel, installed with the uv lines in step 5 into a fresh venv on a
  Mac with no Pi and no Node: `runtime.locate()` authenticated and staged the runtime in 1.1 s, and a real
  session ran — sealed model, approval dialog, sealed search, a file written in the guest and exported at
  the end, 7 turns, 0 faults; the record exported, `verify-export` exit 0, "closed box" and the VM
  sentence in it.

Not done: step 4 (nothing is published), a person using the page in a browser on a Mac, a second Mac, and
any Intel Mac (refused by design).

## 1. On an Apple-silicon Mac: compile the runner and prove the image boots

On Linux, make the bundle and send it over:

    python3 native/macos/guest/build_guest.py --arch aarch64 --out /tmp/guest-arm64
    sh tests/dev/make_mac_bundle.sh /tmp/guest-arm64 /tmp/probant-vm-dev.tgz

On the Mac (needs the Xcode Command Line Tools; everything else it fetches or builds itself):

    tar -xzf probant-vm-dev.tgz && cd probant-vm-dev && sh tests/dev/mac_bringup.sh

It ends with `RESULT: passed with: dev release` or says what failed; either way `bringup.log` holds
everything. Bring back `runtime-release/ProbantVM` — that binary, and no development build, is what ships.

## 2. On Linux: build the guest again from the tree being released, and sign

The guest image contains the client's own code, so build it from the commit you are releasing.

    python3 native/macos/guest/build_guest.py --arch aarch64 --out /tmp/guest-arm64
    python3 scripts/sign_macos_runtime.py build \
        --key ~/inferroute-publication/macos-vm-runtime-signing.key \
        --runner /path/to/ProbantVM --guest /tmp/guest-arm64 --version <V> --out /tmp/runtime-dist
    python3 scripts/sign_macos_runtime.py verify /tmp/runtime-dist/*.whl

`build` refuses a development runner, a non-arm64 binary, and a kernel or image that is not the output of
one `build_guest.py` run. `verify` checks the wheel against `docs/trust/macos-vm-policy.json`, which is the
policy the client wheel carries.

## 3. Build the client wheel

Bump `version` in `pyproject.toml` (a published version is never republished with different bytes), then:

    uv build --wheel -o /tmp/client-dist
    python3 scripts/check_probant_wheel.py /tmp/client-dist/*.whl
    unzip -l /tmp/client-dist/*.whl | grep trust/macos-vm-policy.json      # must be there

## 4. Publish both

    python3 scripts/publish_client_wheel.py ...          # the client wheel, as for every release
    cp /tmp/runtime-dist/inferroute_macos_vm_runtime-<V>-py3-none-macosx_11_0_arm64.whl* <site>/public/client/
    (cd <site> && vercel --prod --yes)                   # a git push does NOT deploy
    curl -sL https://inferroute.ai/client/<each file> | sha256sum      # compare with the .sha256 beside it

The runtime wheel is about 69 MB. Vercel's CLI upload limit is 100 MB on Hobby and 1 GB on Pro for the whole
source; if the deploy refuses, the wheel needs another home and the install line below a different URL.

## 5. What a Mac user runs

A stock Mac has Python 3.9 or none, and the client needs 3.10+. `uv` brings its own Python and touches
nothing of the system's:

    curl -LsSf https://astral.sh/uv/install.sh | sh
    ~/.local/bin/uv venv --python 3.12 ~/probant
    ~/.local/bin/uv pip install --python ~/probant/bin/python \
        "inferroute[confidential] @ https://inferroute.ai/client/inferroute-<V>-py3-none-any.whl" \
        "inferroute-macos-vm-runtime @ https://inferroute.ai/client/inferroute_macos_vm_runtime-<V>-py3-none-macosx_11_0_arm64.whl"
    ~/probant/bin/ir probant home

No Xcode tools, no Node, no Pi: the assistant and everything it needs are inside the guest image.
An Intel Mac is refused with a sentence saying so.

## What differs from Linux, for the person using it

* Files the assistant writes appear in the matter folder when the session ENDS, not while it runs. A session
  that is killed rather than ended loses them.
* A file the assistant changes is never replaced: its version appears under `vm-session-output-…/` in the
  matter folder, beside the untouched original. The same happens to its version of any file you changed
  while the session ran.
* The assistant works on a copy of the folder taken when the session starts. A disclosure edited in the page
  mid-session is not seen until the next session.
* Files over 4 MB are not brought into the session; a line at the start names them.

## The signing key

`~/inferroute-publication/macos-vm-runtime-signing.key` (mode 600), public half in
`docs/trust/macos-vm-policy.json`. Whoever holds it decides what runs in the VM on every client Mac. The tier
is `adhoc-pinned`: there is no Apple Developer ID behind the runner, so this key is the only factor. To move
to `developer-id`, sign and notarise the runner with one and write a schema-1 policy naming the team and
identifier; `runtime.py` already enforces it.
