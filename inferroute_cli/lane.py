"""Which lane a session takes, decided in ONE place.

Three audits on 23 Sep found three separate silent drops to the plaintext lane — `_fallback`, a missing
launch-index row, and `ir cowork`. None was a wrong default: the default has been "confidential for
enclave-backed models" for a long time. The fault was that the lane was re-derived at six call sites and
each had to remember. One of them never did.

So the decision lives here, and `launch.launch_through_inferroute` will not run without one. Forgetting is
a TypeError the suite catches, not a downgrade a law firm discovers. The announcement is made BY the
launcher rather than by its callers, for the same reason: a future entry point cannot forget to warn.

Henry, 23 Sep, asked for warn-and-continue rather than refuse. That puts the whole weight on the notice
actually being read, which is why it is a block rather than the one-line stderr notice it replaces — and
why it is NOT suppressed on resume, which is exactly where the silent case lived.
"""
from __future__ import annotations

import sys
import textwrap
from dataclasses import dataclass

from . import models

# Every reason the plaintext lane still exists. Henry's goal is to delete that lane, so this tuple is the
# backlog: when a reason stops being needed, remove it here and the call site that cited it. When the tuple
# is empty, removing the lane is a deletion rather than an investigation.
NO_ENCLAVE = "this model has no enclave, so there is nothing to seal to"
USER_ASKED = "you asked for the standard lane with --plain"
COWORK = ("ir cowork launches the desktop app detached, and a sealed session's local endpoint cannot "
          "outlive this command")
INTEGRATE = "ir integrate does not have a confidential lane yet"
REASONS = (NO_ENCLAVE, USER_ASKED, COWORK, INTEGRATE)

CONFIDENTIAL = "confidential"
STANDARD = "standard"
NATIVE = "native"


@dataclass(frozen=True)
class Lane:
    """What was decided, and why — `why` is shown to the user, so it is written for them."""
    kind: str
    model: str
    why: str

    @property
    def readable_by_inferroute(self) -> bool:
        return self.kind == STANDARD


# The catalog that marks a model "-TEE" is fetched from InferRoute's own server and cached on this
# machine, so the server can stop marking a model and move a user to the readable lane. It can only ever
# DOWNGRADE — attestation still has to pass, so it cannot make a plain model look sealed — but downgrade
# is the direction that matters. These were enclave-backed in this release: the catalog may ADD to this
# set and may never take from it. Same problem and same shape as `builds.BUNDLED`.
ENCLAVE_FLOOR = frozenset({"kimi-k2.6", "kimi-k3", "deepseek-v4-flash", "glm-5.2", "glm-5.1"})


def enclave_backed(model: str | None) -> bool:
    """Whether this model runs in an enclave: the published catalog, with a floor it cannot go under."""
    if not model:
        return False
    m = str(model).strip()
    if m.lower() in ENCLAVE_FLOOR:
        return True
    short = models.short_for_model_id(m) or ""
    if short.lower() in ENCLAVE_FLOOR:
        return True
    a = models.get(m)
    return bool(a and (getattr(a, "ref_key", "") or "").endswith("-TEE"))


def decide(model: str | None, *, plain: bool, enclave_backed=None) -> Lane:
    if enclave_backed is None:
        enclave_backed = globals()["enclave_backed"]
    m = model or ""
    if plain:
        return Lane(STANDARD, m, USER_ASKED)
    if m and enclave_backed(m):
        return Lane(CONFIDENTIAL, m, "this model runs in an enclave")
    return Lane(STANDARD, m, NO_ENCLAVE)


def announce(lane: Lane, out=None) -> None:
    """Said once, by the launcher, for every path that reaches the readable lane."""
    if not lane.readable_by_inferroute:
        return
    out = out or sys.stderr
    width = 62
    lines = ["STANDARD LANE — InferRoute can read this session."]
    lines += textwrap.wrap(lane.why, width - 6) or [lane.why]
    if lane.why != USER_ASKED:
        lines.append("Sealed models: ir confidential models")
    out.write("\n  ╔" + "═" * width + "╗\n")
    for text in lines:
        out.write("  ║  " + text.ljust(width - 4) + "  ║\n")
    out.write("  ╚" + "═" * width + "╝\n\n")


def why_standard(model: str | None, enclave_backed=None) -> str:
    """The reason a launch that has ALREADY been routed to the plaintext lane is there. If the model runs
    in an enclave then the only way to arrive here is that the user opted out; if it does not, there was
    never a lane to take. Saves threading `--plain` down through every caller to say the same thing."""
    if enclave_backed is None:
        enclave_backed = globals()["enclave_backed"]
    return USER_ASKED if (model and enclave_backed(model)) else NO_ENCLAVE
