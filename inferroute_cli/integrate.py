"""`ir integrate-deferral-gate` — wire an existing autonomous-agent loop to
inferroute's economy (deferred / discounted) lane, using an agent.

Instead of handing the user docs, we launch Claude Code *in their repo*, pre-prompted
to find their loop(s), insert the economy gate at the right point, and set up per-role
model routing — with explicit confirmation and a backup before any file is changed.

Design: future-tasks-impl-plan.md §5b. The agent itself runs on a tier-2 model
(Kimi/GLM, the cheap backend) — onboarding dogfoods the product on first contact.
"""

from __future__ import annotations

from . import config, models
from .launch import launch_through_inferroute

# The model the integration agent runs on. Tier-2 (cheap) by deliberate choice —
# this is a bounded code task, and running onboarding on our own cheap backend
# is the dogfood. Override with `ir integrate-deferral-gate --model glm`.
DEFAULT_AGENT_MODEL = "kimi"


def _build_prompt(api_url: str) -> str:
    """The agent's standing instruction. `api_url` is the user's inferroute base
    URL; the agent reads the API key from the user's existing inferroute creds /
    env — we never paste the secret into the prompt."""
    return f"""\
Wire THIS repo's autonomous-agent loop to inferroute's economy lane (cheap off-peak runs).
You are in PLAN MODE: research the repo, then present a concise implementation plan and STOP
for approval. Do not edit files until the plan is approved.

HARD RULES:
- Use the installed `ir` CLI (it's on PATH — this agent was launched via it). Do NOT read or
  import inferroute's source / Python package to reverse-engineer it — `ir` already wraps it.
- Claude Code CANNOT set arbitrary HTTP headers. Do NOT look for a way to send an `IR-Lane`
  header — there is none. The economy lane is selected by the BASE URL (step 3).
- Time-box discovery: a few greps, then plan. Keep the plan short and concrete (exact files,
  exact lines, exact edits).

STEP 1 — Find the loop: the repeating driver (`run-loop.sh`, `while true`, cron, systemd
`*.service`) and any existing pace/gate line (e.g. `pace-gate`). That line is the seam.

STEP 2 — Gate the cycle with `ir gate` (it owns poll + fail-open + jitter; exit 0=run/1=skip):
```bash
if ir gate; then <run one cycle>; else sleep 30; fi
```
Compose with an existing pace-gate rather than replace it: `pace-gate … && ir gate && <cycle>`.
PATH note: if the loop runs under systemd/cron with a stripped PATH, use `ir`'s absolute path
(`command -v ir`). Raw-curl fallback only if `ir` truly isn't reachable at loop runtime.

STEP 3 — Make the discount apply: the gated cycle's LLM calls must hit the ECONOMY base URL.
Find how this repo invokes the model TODAY and MIRROR its existing idiom — do NOT add export/
tmux gymnastics. Most loops build an env-prefixed command string, e.g.
`NATIVE_ENV="env -u ANTHROPIC_BASE_URL …"; CMD="$NATIVE_ENV claude …"`. The clean economy
counterpart is one variable reused across roles, sourced from `ir`:
```bash
IR_ECON="env $(ir gate --print-env --inline)"   # → env ANTHROPIC_BASE_URL={api_url}/economy ANTHROPIC_AUTH_TOKEN=…
CMD="$IR_ECON claude …"                          # replaces the native env prefix
```
(`ir gate --print-env --inline` resolves the key at runtime from the user's creds — never
hardcode it.) If the cycle genuinely can't be pointed at inferroute, say so — don't pretend.

STEP 4 — Model routing: leave invocations on `auto` (inferroute routes per turn). If the loop
pins per-role models (e.g. opus/sonnet), note that economy will route them via inferroute; you
MAY suggest per-role tier hints, as hints not hard pins. Orthogonal to the gate.

STEP 5 — Present the PLAN: exact files + lines + edits, how to test one gated cycle, how to
revert. Then stop for approval (plan mode). After approval, apply the edits and `bash -n` each
changed script.
"""


def cmd_integrate(args: list[str]) -> int:
    """Entry point for `ir integrate-deferral-gate`."""
    model = DEFAULT_AGENT_MODEL
    rest: list[str] = []
    i = 0
    while i < len(args):
        if args[i] == "--model" and i + 1 < len(args):
            model = args[i + 1]
            i += 2
        else:
            rest.append(args[i])
            i += 1

    creds = config.load()
    if not creds.is_valid:
        print("No inferroute API key found. Run `ir login` first.")
        return 2

    alias = models.get(model)
    if alias is None:
        print(f"Unknown model '{model}'. Try: kimi, glm, auto.")
        return 2

    prompt = _build_prompt(creds.api_url)
    print("⚡ Launching the inferroute integration agent (model: %s)…" % alias.short)
    print("   Plan mode: it scans this repo, proposes a plan, and waits for your approval.\n")
    # Launch in PLAN MODE — the agent researches and presents a plan before touching
    # files; the plan-approval is the gate (replaces manual per-file y/n). The prompt
    # is the initial positional arg. execvpe replaces the process, so this never returns.
    launch_through_inferroute(
        alias.model_id, creds, extra_args=[prompt, *rest], permission_mode="plan"
    )
    return 0
