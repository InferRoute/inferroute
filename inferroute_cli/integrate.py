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
You're in plan mode: research, then present ONE concise plan and stop. Be minimal and concrete.

EFFICIENCY: this is a tiny task — grep + read a couple of files DIRECTLY. Do NOT spawn Explore
or Task subagents; do NOT read the whole repo. Find the loop driver, read just it, then plan.

The `ir` CLI is installed (you were launched via it). Use it directly; do NOT read inferroute's
source. For RESEARCH you may ONLY run: `ir help`, `ir gate`, `ir gate --print-env`. NEVER run
bare `ir` or `ir --model …` — those LAUNCH a Claude session (a nested agent); they belong in the
loop you're editing, not in your research. Two commands do everything:
  • `ir gate`            → exit 0 = cheap window now, 1 = skip. Gates one cycle (like pace-gate).
  • `IR_LANE=economy ir` → launches Claude Code on the economy lane; inferroute auto-routes the
                          model per turn. This REPLACES a `claude --model …` call — the native
                          models (opus/sonnet) do NOT exist on the economy backend, so DROP the
                          `--model` pin and let `ir` auto-route. Keep flags like --effort. For a
                          specific tier use `IR_LANE=economy ir --model kimi` (or glm).

Plan to:
1. Find the loop's driver (run-loop.sh / while-true / cron / systemd / pace-gate line) and how it
   invokes the model today (e.g. `claude --model opus --effort X …`, possibly behind an `env …` prefix).
2. Gate each cycle: `if ir gate; then <cycle>; else sleep 30; fi` (compose with any existing
   pace-gate: `pace-gate && ir gate && <cycle>`). If the loop runs under systemd/cron with a
   stripped PATH, use ir's absolute path (`command -v ir`).
3. Make the cycle run economy: replace its model invocation with `IR_LANE=economy ir --effort X …`
   (bare `ir` auto-routes; or per-role `IR_LANE=economy ir --model kimi`/`glm` only if the loop
   clearly separates roles). Drop the native `--model opus/sonnet` pin and any hand-rolled
   ANTHROPIC_BASE_URL/token env — `ir` handles all of it.
4. Present the plan: exact files + lines + edits, how to test one gated cycle, how to revert.
   On approval, apply the edits and `bash -n` each changed script.
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
    # Launch in PLAN MODE with the research tools PRE-APPROVED so the user is never
    # interrupted with permission prompts on the way to the plan. Read-only + the two
    # safe `ir` research commands only (NOT bare `ir`/`ir auto`, which would launch a
    # nested session — also blocked by the CLAUDECODE guard in launch.py). The prompt
    # is the first positional; --allowedTools is variadic so it goes last.
    launch_through_inferroute(
        alias.model_id, creds,
        extra_args=[
            prompt, *rest,
            # Block subagent spawning — it's a tiny task; Explore/Task subagents
            # burn minutes + tokens and bloat context (slows Kimi). Grep+read directly.
            "--disallowedTools", "Task",
            "--allowedTools", *_RESEARCH_TOOLS,
        ],
        permission_mode="plan",
    )
    return 0


# Read-only research tools pre-approved for the planning phase (no approval prompts).
# Deliberately scoped: `ir gate`/`ir help` only — never bare `ir`/`ir auto` (nested launch).
_RESEARCH_TOOLS = [
    "Read", "Grep", "Glob",
    "Bash(ir gate:*)", "Bash(ir help)", "Bash(ir --help)", "Bash(ir -h)",
    "Bash(grep:*)", "Bash(rg:*)", "Bash(ls:*)", "Bash(cat:*)", "Bash(sed:*)",
    "Bash(head:*)", "Bash(tail:*)", "Bash(wc:*)", "Bash(find:*)", "Bash(command:*)",
]
