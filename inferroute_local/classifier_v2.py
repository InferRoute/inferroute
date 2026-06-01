"""Local ONNX classifier for tier-routing decisions.

This is the v0 production classifier — a 3-class softmax model that predicts
the ideal routing tier for a given Claude Code request.

Architecture context
--------------------
- TRAINED at `inferroute/inferroute-local-experiments/train_classifier.py`
  on ~2K labeled records from `~/.claude/projects/`. Best v0 model is the
  `longer` config (ModernBERT-base, 12 epochs, macro F1 0.71, frontier F1 0.54).
- DESIGN doc: `shared-docs/inferroute/stability-and-routing.md`.
- This module is the STATELESS PER-TURN PREDICTOR. Session stickiness,
  switch thresholds, deferred commitment, and compaction all live in a
  separate `router.py` (Phase 2 of the rollout) that consumes the probs
  this classifier returns.

Phase 1 scope (this file): just load the ONNX, classify a request, return
calibrated probs. No stickiness, no compaction. The proxy collapses the
3-class output to binary for routing in Phase 1; full 3-class routing
comes in Phase 2 when middle-tier wiring lands.

Fail-soft policy
----------------
If the ONNX model can't be located or loaded (missing on disk, version
mismatch, onnxruntime not installed), `RoutingClassifier.available` is
False and `classify()` returns None. The proxy then falls back to the
legacy server `/inferroute/route` call. This is critical: we MUST NOT
break the daemon when the classifier isn't deployed yet.
"""
from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger("inferroute_local.classifier_v2")

LABEL_NAMES = ("minimax_ok", "middle_tier", "frontier")


def _next_pow2_bounded(n: int, lo: int, hi: int) -> int:
    """Smallest power of 2 in [lo, hi] that is >= n. Caps at hi if n > hi."""
    p = lo
    while p < n and p < hi:
        p *= 2
    return min(p, hi)


# Default classifier dir locations to search if config doesn't specify one.
# Order: explicit env var > user-config dir > XDG data dir > /opt > built-in.
DEFAULT_SEARCH_PATHS = (
    Path.home() / ".inferroute" / "models" / "classifier-v0",
    Path.home() / ".local" / "share" / "inferroute" / "models" / "classifier-v0",
    Path("/opt/inferroute/models/classifier-v0"),
)


@dataclass
class ClassifierResult:
    """A single classify() output, with all the data the daemon needs."""
    probs: dict[str, float]              # {minimax_ok: 0.7, middle_tier: 0.25, frontier: 0.05}
    argmax_label: str                    # the highest-probability tier name
    max_prob: float                      # the value of probs[argmax_label]
    inference_ms: float                  # how long the ONNX run took (for logging / SLO)


# ──────────────────────────────────────────────────────────────────────────
# Input assembly — MUST match prepare_training_set.py:assemble_text() shape
# ──────────────────────────────────────────────────────────────────────────

_CLAUDE_MD_HEADER_RE = re.compile(
    r"Contents of\s+([^\n)]+CLAUDE\.md)[^\n]*\n+",
    re.IGNORECASE,
)

_NONASCII_DECIMALS = 4


def extract_claude_md_from_system(system_text: str, max_chars: int = 800) -> str:
    """Pull the first CLAUDE.md content block out of a CC system prompt.

    CC injects CLAUDE.md as a `<system-reminder>` block in the system prompt,
    starting with a line like "Contents of /path/to/CLAUDE.md (user's instructions):".
    We look for that marker, slice from there forward to the next `</system-reminder>`
    or the end, and return the first `max_chars` of body. This mirrors how
    prepare_training_set.py:assemble_text() reads CLAUDE.md from disk at
    training time, so train/inference distributions match.

    Returns an empty string if no CLAUDE.md block is found.
    """
    if not system_text:
        return ""
    match = _CLAUDE_MD_HEADER_RE.search(system_text)
    if not match:
        return ""
    body_start = match.end()
    body_end_marker = system_text.find("</system-reminder>", body_start)
    if body_end_marker == -1:
        body = system_text[body_start:]
    else:
        body = system_text[body_start:body_end_marker]
    return body.strip()[:max_chars]


def extract_last_user_message_text(body: dict, max_chars: int = 4000) -> str:
    """Return the verbatim text of the most recent user message in the request.

    User messages can be strings or lists of content blocks (text + tool_result
    + image). We concatenate the text blocks and ignore other types, since the
    classifier was trained on text-only user_message extracts.
    """
    messages = body.get("messages") or []
    for msg in reversed(messages):
        if msg.get("role") != "user":
            continue
        content = msg.get("content")
        if isinstance(content, str):
            return content[:max_chars]
        if isinstance(content, list):
            parts = []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    txt = block.get("text") or ""
                    if isinstance(txt, str):
                        parts.append(txt)
            if parts:
                return "\n".join(parts)[:max_chars]
    return ""


def extract_recent_tools(body: dict, window: int = 6) -> list[str]:
    """Distinct tool names used in the last `window` assistant messages."""
    messages = body.get("messages") or []
    out: list[str] = []
    seen = 0
    for msg in reversed(messages):
        if seen >= window:
            break
        if msg.get("role") != "assistant":
            continue
        seen += 1
        content = msg.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if isinstance(block, dict) and block.get("type") == "tool_use":
                name = block.get("name")
                if isinstance(name, str) and name not in out:
                    out.append(name)
    return sorted(out)


def total_content_chars(body: dict) -> int:
    """Approximate context_chars: sum of all message-content lengths."""
    messages = body.get("messages") or []
    total = 0
    for msg in messages:
        content = msg.get("content")
        if isinstance(content, str):
            total += len(content)
        elif isinstance(content, list):
            for block in content:
                if not isinstance(block, dict):
                    continue
                for k in ("text", "content", "input"):
                    v = block.get(k)
                    if isinstance(v, str):
                        total += len(v)
                    elif isinstance(v, (dict, list)):
                        try:
                            total += len(json.dumps(v))
                        except Exception:
                            pass
    return total


def nonascii_ratio(text: str) -> float:
    if not text:
        return 0.0
    n = sum(1 for ch in text if ord(ch) > 127)
    return round(n / len(text), _NONASCII_DECIMALS)


def system_prompt_text(body: dict) -> str:
    """Flatten CC's system field (string or list of blocks) into a single string."""
    system = body.get("system") or ""
    if isinstance(system, list):
        return "\n".join(
            b.get("text", "") for b in system if isinstance(b, dict)
        )
    return str(system)


def assemble_text(body: dict, max_user_chars: int = 4000) -> str:
    """Build the classifier's input string from a Claude Code request body.

    MUST match `prepare_training_set.py:assemble_text()` exactly. The format is:

        [PROJECT] <CLAUDE.md excerpt, first ~800 chars>      (omitted if empty)
        [FEATURES] message_index=N context_chars=N tools_recent=A,B,C nonascii_ratio=0.0
        [USER] <verbatim user message>

    Block order matters: under truncation, [USER] is closest to [CLS] which is
    where the classifier head reads. Don't reorder without retraining.
    """
    messages = body.get("messages") or []
    sys_text = system_prompt_text(body)
    claude_md = extract_claude_md_from_system(sys_text)

    last_user = extract_last_user_message_text(body, max_user_chars)
    tools = extract_recent_tools(body)
    context_chars = total_content_chars(body)
    n_ratio = nonascii_ratio(last_user)

    tools_str = ", ".join(tools) if tools else "(none)"
    features_line = (
        f"[FEATURES] message_index={len(messages)} "
        f"context_chars={context_chars} "
        f"tools_recent={tools_str} "
        f"nonascii_ratio={n_ratio}"
    )

    parts: list[str] = []
    if claude_md:
        parts.append(f"[PROJECT] {claude_md}")
    parts.append(features_line)
    parts.append(f"[USER] {last_user}")
    return "\n".join(parts)


# ──────────────────────────────────────────────────────────────────────────
# RoutingClassifier — lazy-loaded, fail-soft, ONNX-backed
# ──────────────────────────────────────────────────────────────────────────

class RoutingClassifier:
    """ONNX-backed 3-class routing classifier.

    Construction is cheap (no disk reads, no model load). The first classify()
    call triggers lazy loading. If loading fails, `available` becomes False
    and classify() returns None for the rest of the daemon's life. The proxy
    treats None as "fall back to legacy server-side routing."
    """

    def __init__(self, model_dir: Optional[Path] = None, max_length: int = 512):
        self.model_dir: Optional[Path] = None
        self.max_length = max_length
        self._session = None
        self._tokenizer = None
        self._temperature: float = 1.0
        self._labels_ordered: list[str] = list(LABEL_NAMES)
        self._loaded = False
        self._load_attempted = False
        self._load_error: Optional[str] = None
        self._init_load_path(model_dir)

    @property
    def available(self) -> bool:
        """True if the classifier loaded successfully and can serve predictions."""
        if not self._load_attempted:
            self._lazy_load()
        return self._loaded

    @property
    def load_error(self) -> Optional[str]:
        return self._load_error

    def _init_load_path(self, model_dir: Optional[Path]) -> None:
        """Pick the model dir to use, but don't actually load yet."""
        if model_dir is not None:
            self.model_dir = Path(model_dir)
            return
        for path in DEFAULT_SEARCH_PATHS:
            if path.exists() and (path / "onnx" / "model.onnx").exists():
                self.model_dir = path
                return
        # No path found yet — _lazy_load will mark unavailable

    def _lazy_load(self) -> None:
        """Try to load the ONNX session and tokenizer. Idempotent."""
        if self._load_attempted:
            return
        self._load_attempted = True

        if self.model_dir is None:
            self._load_error = (
                "no classifier model dir found; searched: "
                + ", ".join(str(p) for p in DEFAULT_SEARCH_PATHS)
            )
            logger.info(f"classifier_v2 disabled — {self._load_error}")
            return

        onnx_path = self.model_dir / "onnx" / "model.onnx"
        if not onnx_path.exists():
            self._load_error = f"ONNX not found at {onnx_path}"
            logger.info(f"classifier_v2 disabled — {self._load_error}")
            return

        try:
            import onnxruntime as ort
            from tokenizers import Tokenizer
        except ImportError as e:
            # Either dep missing → classifier disabled, daemon falls back to
            # the legacy server route. The [local] extra installs both.
            self._load_error = f"missing dep: {e}"
            logger.warning(f"classifier_v2 disabled — {self._load_error}")
            return

        try:
            # Graph optimizations matter: ORT_ENABLE_ALL fuses attention subgraphs
            # that ORT_ENABLE_BASIC leaves alone, shaving ~15% off inference. One-
            # time cost at load.
            sess_opts = ort.SessionOptions()
            sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            self._session = ort.InferenceSession(
                str(onnx_path),
                sess_options=sess_opts,
                providers=["CPUExecutionProvider"],
            )
            # Load tokenizer directly from tokenizer.json (Rust `tokenizers` lib,
            # ~10 MB) instead of through transformers (~50 MB + heavy transitive
            # graph that risks pulling torch). The tokenizer.json is all we need;
            # transformers was wrapping it anyway.
            self._tokenizer = Tokenizer.from_file(str(self.model_dir / "tokenizer.json"))
            # The saved tokenizer.json bakes in padding=max_length=512. We do our
            # own adaptive pow-2 padding (see classify()) so disable the built-in
            # one. Truncation cap stays at max_length.
            self._tokenizer.no_padding()
            self._tokenizer.enable_truncation(max_length=self.max_length)
            # Resolve [PAD] id once at load. ModernBERT's tokenizer uses "[PAD]";
            # fall back to 0 only if the vocabulary is somehow missing it.
            self._pad_token_id = self._tokenizer.token_to_id("[PAD]")
            if self._pad_token_id is None:
                self._pad_token_id = 0
        except Exception as e:
            self._load_error = f"failed to load model: {e}"
            logger.warning(f"classifier_v2 disabled — {self._load_error}")
            return

        # Load calibration temperature
        calib_path = self.model_dir / "calibration.json"
        if calib_path.exists():
            try:
                self._temperature = float(
                    json.loads(calib_path.read_text())["temperature"]
                )
            except Exception:
                self._temperature = 1.0

        # Load label mapping (override defaults if file present)
        label_path = self.model_dir / "label_to_int.json"
        if label_path.exists():
            try:
                lm = json.loads(label_path.read_text())
                int_to_label = {int(v): k for k, v in lm.items()}
                self._labels_ordered = [int_to_label[i] for i in range(len(int_to_label))]
            except Exception:
                pass

        self._loaded = True
        logger.info(
            f"classifier_v2 loaded from {self.model_dir} "
            f"(T={self._temperature:.3f}, labels={self._labels_ordered})"
        )

    def classify(self, text: str) -> Optional[ClassifierResult]:
        """Return calibrated probabilities for the assembled text.

        Returns None if the classifier isn't available (fail-soft path).
        Caller must check for None and fall back to legacy routing.
        """
        if not self.available:
            return None

        import numpy as np

        t0 = time.perf_counter()
        # Adaptive power-of-2 padding (Phase 4 optimization).
        # The ONNX graph has dynamic seq dims so we don't have to pad every call
        # up to max_length=512. We tokenize WITHOUT padding to find the actual
        # length, then pad up to the next power of 2 in [64, max_length]. On
        # real CC inputs (p50 ≈ 286 tokens, many far shorter) this drops median
        # inference from ~700ms to 50-200ms. Power-of-2 keeps the number of
        # distinct shapes ORT sees small so its kernel-selection cache stays hot.
        enc = self._tokenizer.encode(text)
        actual_len = len(enc.ids)
        pad_to = _next_pow2_bounded(actual_len, lo=64, hi=self.max_length)
        ids = enc.ids + [self._pad_token_id] * (pad_to - actual_len)
        mask = enc.attention_mask + [0] * (pad_to - actual_len)
        try:
            import numpy as _np
            (logits,) = self._session.run(
                None,
                {
                    "input_ids": _np.array([ids], dtype=_np.int64),
                    "attention_mask": _np.array([mask], dtype=_np.int64),
                },
            )
        except Exception as e:
            logger.warning(f"classifier_v2 inference error: {e}")
            return None

        # Temperature-scaled softmax (numerically stable)
        z = logits[0] / self._temperature
        z = z - z.max()
        exp_z = np.exp(z)
        probs_arr = exp_z / exp_z.sum()
        probs = {name: float(probs_arr[i]) for i, name in enumerate(self._labels_ordered)}
        argmax_label = max(probs.items(), key=lambda kv: kv[1])[0]
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return ClassifierResult(
            probs=probs,
            argmax_label=argmax_label,
            max_prob=probs[argmax_label],
            inference_ms=elapsed_ms,
        )

    def classify_body(self, body: dict) -> Optional[ClassifierResult]:
        """Convenience: assemble text from a CC request body, then classify."""
        return self.classify(assemble_text(body))
