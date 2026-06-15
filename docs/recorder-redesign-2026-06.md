# Recorder redesign + safety fixes (2026-06, v0.3.25)

Two things shipped together: (1) the daemon/recorder is now a thin, opt-in,
metadata-only sidecar over native Claude Code transcripts, and (2) the install
path can no longer endanger native `claude`. This doc is the upstream-bug
writeup + the rationale, suitable as a PR description.

## Incident that motivated this

On a fleet machine, native `claude` stopped working entirely. Root cause was
inferroute, in two compounding layers:

1. A stale systemd user unit with `ExecStart=… serve --port 5005` — but the
   daemon CLI has **no `serve` subcommand** — crash-looped (observed
   NRestarts > 268,000). On another machine the same unit failed even earlier
   with `ModuleNotFoundError: No module named 'click'` (a venv without the
   `[local]` extra), which *masks* the `serve` error.
2. `ir add recording` had appended `export ANTHROPIC_BASE_URL=http://localhost:5005`
   to the user's shell rc, so **every** `claude` depended on the daemon being
   up. With the daemon crash-looping, native Claude Code had no fallback.

## Bugs fixed

### B1 — stale managed units were never regenerated
`add.py::_install_systemd_unit` only wrote the base unit `if not unit_path.exists()`,
so a broken unit from an old version survived upgrades forever.
**Fix:** units we created (carry `# Managed-by: ir add recording`) are now
**regenerated** on install; only genuinely hand-crafted units (no marker) are
preserved. The template also adds a crash-loop guard
(`StartLimitIntervalSec=60`, `StartLimitBurst=5`) so a broken unit fails fast
instead of looping indefinitely.

### B2 — `doctor` didn't validate the unit
The old `doctor` only checked for an API key, so the crash-loop was invisible to
the tool's own diagnostics. **Fix:** `doctor` now parses the unit's `ExecStart`
(flags the nonexistent `serve` subcommand and a wrong/missing binary), checks
`systemctl --user show` for `failed`/`auto-restart`/high `NRestarts`, and verifies
the recorder deps import.

### B3 — install edited the global shell rc with no fail-open
`ir add recording` wrote `ANTHROPIC_BASE_URL` into the shell rc by default.
**Fix:** it **never** edits the shell rc now. The `ir` launcher already injects
the base URL into only the process it spawns (`launch.py`); native `claude`
always reaches Anthropic directly. `ir remove recording` still strips any legacy
block a prior version left behind. (`--no-shell-edit` is accepted as a no-op.)

### B4 — `click` was an optional dep, so the console scripts crash-looped
`inferroute-daemon` / `inferroute-scrub` are always registered but imported
`click` (and `uvicorn`/`fastapi`) at module load, so a venv without `[local]`
died with an `ImportError` on every systemd restart. **Fix:** `click` is now a
core dep, and `uvicorn`/`fastapi` are imported lazily — a missing `[local]`
extra yields a clean `exit 3` with a one-line fix instead of a traceback loop.

### B5 — `install-service` pointed at a nonexistent binary
`inferroute-daemon install-service` resolved `shutil.which("inferroute")` — not a
real console script — writing a broken `ExecStart`. **Fix:** it resolves
`inferroute-daemon` and adds the same crash-loop guard.

## Architecture: native transcripts are the spine

Claude Code already writes a complete per-session transcript
(`~/.claude/projects/**/<sessionId>.jsonl`) for **native and routed** sessions —
including the served model (routing substitution shows up), token `usage`,
`requestId`/`sessionId`/`cwd`/`gitBranch`/`version`, and full content. It lacks
only per-turn `costUSD`, and the wire `system`/`tools` params.

So the recorder no longer needs the proxy for content:

- **Content** is ingested out-of-band by a Claude Code **`SessionEnd` hook**
  (`inferroute-daemon ingest --stdin`) → one `turn` event per assistant message,
  at level `metadata`, **never a blob** (content stays in the transcript; zero
  duplication). Idempotent via a per-transcript line marker. Dep-light: runs even
  without `[local]` and even when the daemon is down.
- **Cost** follows a strict rule: **persist only numbers a system reported.**
  Routed turns keep the real server `usage.cost` (daemon). Native-turn cost is a
  **read-time estimate** (`ir data cost`) from recorded tokens × a *dated* price
  table (`pricing.py`), flagged `is_estimate` and recomputable — we never solidify
  a self-computed estimate into the corpus.
- **Wire delta** (system hash + tool list) is **opt-in** (`IR_CAPTURE_WIRE=1`):
  the launcher points CC's per-process OTEL `OTEL_LOG_RAW_API_BODIES=file:` sink
  at a scratch dir; ingest mines the delta then **deletes** it ("nothing left
  behind"). Default OFF until the raw-body file format is verified on a live CC
  run.

The router-era surface that no longer ran (local classifier, compactor, session
router, tool-output compression, `/stats`, the `minimax/kimi/glm` model config,
the hardcoded `/v1/models` list) was removed; `/v1/models` is now a real upstream
passthrough.

## Remaining follow-up
- `outcome` events don't carry the Anthropic `request_id`, so daemon cost can't
  yet be joined to a transcript turn at request granularity (session-level only).
  Threading `x-request-id` into `record_outcome` would enable a per-turn join.
- The `pricing.py` rates are placeholders — verify against anthropic.com/pricing.
- Verify CC's `OTEL_LOG_RAW_API_BODIES=file:` format, then consider default-on
  wire capture.
