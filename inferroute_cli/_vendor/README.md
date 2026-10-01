# Vendored, not forked

`sealedresearch/` is a byte-for-byte copy of sealed-research's open client set — the list in that
project's `client-dist/WHITELIST`, which is its own publication decision. `search_service.py`, the
enclave-side half, is deliberately not in it and must never be copied here.

## Why it is here at all

Probant launches the search verifier as a separate process: `python -m sealedresearch.search_verifier`.
That module is not part of the `inferroute` package, so a machine with no sealed-research checkout
installed Probant successfully and then could not start a search at all — measured 2026-10-01 on a clean
venv on another machine, where `pip install inferroute[confidential]` gave a working client with a search
lane that could never run.

A thing the product cannot function without is part of the product. The alternative — a second install
plus a config file pointing at wherever it landed — puts a path that must be right on a machine we cannot
see, and its failure mode is "the search panel never starts", which reads as our product being broken.

## Why a copy and not a dependency

A declared dependency would be better: pip would install one source and nothing could drift. That needs a
package index, and these wheels are served from inferroute.ai rather than PyPI, so a dependency could not
be resolved by a plain `pip install <url>`.

The drift this costs is managed the way the existing single-file copy already was: a byte-identity test
pins every module here against the canonical copy, and fails if either side moves. That test caught a real
change on 2026-10-01 within minutes of it being made.

## What is NOT this

`inferroute_cli/pi_attested/verify_record.py` is a different copy with a different purpose: the standalone
file a STRANGER runs against an exported record, with no InferRoute code and no imports from this package.
It must stay standalone, because an auditor must never have to install Probant to check a record.
