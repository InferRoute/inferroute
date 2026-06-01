"""Local request classifier for Option C fast-path.

Two conditions that bypass the server metadata round-trip:
1. system prompt contains compaction keywords  (reliable signal)
2. context_ratio > threshold  (optional heuristic — magic number, tune or remove)

Everything else sends a tiny metadata payload to /inferroute/route and waits
~50-80ms for the decision.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .config import Config


# Anthropic model context windows (tokens). Used for ratio calculation.
_CONTEXT_WINDOWS = {
    "claude-opus-4": 200_000,
    "claude-sonnet-4": 200_000,
    "claude-haiku-4": 200_000,
    "claude-opus-4-5": 200_000,
    "claude-sonnet-4-5": 200_000,
    "claude-haiku-4-5": 200_000,
    "claude-3-5-sonnet": 200_000,
    "claude-3-5-haiku": 200_000,
    "claude-3-opus": 200_000,
}
_DEFAULT_CONTEXT_WINDOW = 200_000


@dataclass
class RequestMeta:
    context_ratio: float
    has_planning_keywords: bool
    file_count_estimate: int
    is_simple_task: bool
    model: str
    user_agent: str
    # Kimi-vs-GLM archetype signals (see shared-docs/inferroute/model-selection-policy.md)
    has_frontend_signals: bool = False
    has_backend_signals: bool = False
    tools_count: int = 0
    message_count: int = 0


def _context_window(model: str) -> int:
    for prefix, size in _CONTEXT_WINDOWS.items():
        if model.startswith(prefix):
            return size
    return _DEFAULT_CONTEXT_WINDOW


def _estimate_tokens(messages: list[dict]) -> int:
    """Rough token count from message content lengths. ~4 chars/token heuristic."""
    total_chars = 0
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            total_chars += len(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    total_chars += len(str(block.get("text", "") or block.get("source", "")))
    return total_chars // 4


def _count_files(messages: list[dict]) -> int:
    """Estimate number of distinct files referenced in tool result messages."""
    file_patterns = [
        re.compile(r"<file_path>(.*?)</file_path>"),
        re.compile(r'"file_path"\s*:\s*"([^"]+)"'),
        re.compile(r"(?:^|\n)(?:/[\w./\-]+\.[\w]+)"),
    ]
    text = " ".join(
        str(m.get("content", "")) for m in messages if m.get("role") == "tool"
    )
    paths: set[str] = set()
    for pat in file_patterns:
        paths.update(pat.findall(text))
    return len(paths)


def _has_keywords(text: str, keywords: list[str]) -> bool:
    text_lower = text.lower()
    return any(kw.lower() in text_lower for kw in keywords)


def _has_planning_intent(text: str, keywords: list[str]) -> bool:
    """Word-boundary match each keyword against `text`.

    Used only on the latest user message so we don't trip on Claude Code's
    ambient system prompt mentioning "architect"/"plan"/"think" generically.
    A keyword that's a multi-word phrase is matched literally; a single-word
    keyword is wrapped in \\b so "architect" doesn't match "architecture".
    """
    if not text:
        return False
    lower = text.lower()
    for kw in keywords:
        kw_lower = kw.lower()
        if " " in kw_lower:
            if kw_lower in lower:
                return True
        else:
            if re.search(r"\b" + re.escape(kw_lower) + r"\b", lower):
                return True
    return False


# Word-boundary patterns so "api" matches "api endpoint" but not "rapid"
_FRONTEND_KEYWORD_RE = re.compile(
    r"\b(?:react|vue|svelte|nextjs|next\.js|tailwind|jsx|tsx|html|css|scss|"
    r"frontend|front-end|component|storybook|figma|ui/ux|"
    r"vite|webpack|prettier)\b",
    re.IGNORECASE,
)
_FRONTEND_EXTS = (".tsx", ".jsx", ".vue", ".svelte", ".css", ".scss", ".less", ".html")

_BACKEND_KEYWORD_RE = re.compile(
    r"\b(?:api|endpoint|database|sql|migration|schema|backend|back-end|"
    r"server|worker|cron|queue|orm|fastapi|django|flask|gunicorn|uvicorn|"
    r"postgres|postgresql|mysql|mongodb|redis|kafka|rabbitmq)\b",
    re.IGNORECASE,
)
_BACKEND_EXTS = (".sql", ".go", ".rs", ".proto")
_BACKEND_PATH_HINTS = ("/server/", "/api/", "/backend/", "/db/", "/migrations/", "/handlers/")


def _has_frontend_signals(text: str) -> bool:
    if _FRONTEND_KEYWORD_RE.search(text):
        return True
    return any(ext in text.lower() for ext in _FRONTEND_EXTS)


def _has_backend_signals(text: str) -> bool:
    if _BACKEND_KEYWORD_RE.search(text):
        return True
    lower = text.lower()
    if any(ext in lower for ext in _BACKEND_EXTS):
        return True
    return any(hint in lower for hint in _BACKEND_PATH_HINTS)


def _system_text(body: dict) -> str:
    system = body.get("system", "")
    if isinstance(system, list):
        return " ".join(b.get("text", "") for b in system if isinstance(b, dict))
    return system or ""


def classify(body: dict, config: Config, user_agent: str = "") -> RequestMeta:
    """Extract routing metadata from a raw Anthropic request body."""
    model = body.get("model", "")
    messages = body.get("messages", [])
    system = _system_text(body)

    estimated_tokens = _estimate_tokens(messages)
    context_window = _context_window(model)
    context_ratio = estimated_tokens / context_window if context_window else 0.0

    # Planning intent is a property of the latest user ask, not of Claude Code's
    # ambient system prompt / tool descriptions (which mention "architect",
    # "plan", "think" in agent meta-instructions unrelated to the user task).
    # Looking at the full transcript also caused false positives on long sessions
    # where any earlier message happened to contain a keyword.
    last_user_for_intent = next(
        (m.get("content", "") for m in reversed(messages) if m.get("role") == "user"),
        "",
    )
    last_user_intent_text = (
        last_user_for_intent if isinstance(last_user_for_intent, str)
        else " ".join(b.get("text", "") for b in last_user_for_intent if isinstance(b, dict))
    )
    has_planning = _has_planning_intent(last_user_intent_text, config.planning_keywords)

    file_count = _count_files(messages)

    # Simple task heuristics: short conversation, no tool results, no files
    last_user = next(
        (m["content"] for m in reversed(messages) if m.get("role") == "user"),
        "",
    )
    last_user_text = last_user if isinstance(last_user, str) else str(last_user)
    is_simple = (
        len(messages) <= 3
        and len(last_user_text) < 500
        and file_count == 0
        and not any(m.get("role") == "tool" for m in messages)
    )

    # Kimi-vs-GLM signals from last user message + tool results (where file paths
    # and recent context live). Skip system prompt — it's identical across requests
    # and would bias every classification toward whatever Claude Code happens to
    # mention in its prompt.
    domain_text_parts = [last_user_text]
    for m in messages:
        if m.get("role") == "tool":
            domain_text_parts.append(str(m.get("content", ""))[:4000])
    domain_text = " ".join(domain_text_parts)
    has_frontend = _has_frontend_signals(domain_text)
    has_backend = _has_backend_signals(domain_text)

    tools_count = len(body.get("tools") or [])
    message_count = len(messages)

    return RequestMeta(
        context_ratio=round(context_ratio, 3),
        has_planning_keywords=has_planning,
        file_count_estimate=file_count,
        is_simple_task=is_simple,
        model=model,
        user_agent=user_agent,
        has_frontend_signals=has_frontend,
        has_backend_signals=has_backend,
        tools_count=tools_count,
        message_count=message_count,
    )


def is_fast_path_anthropic(meta: RequestMeta, config: Config, system_text: str) -> bool:
    """Return True if we can skip the server round-trip and go direct to Anthropic.

    Two conditions (Option C):
    1. Context ratio above threshold (compaction or large context)
    2. System prompt contains compaction keywords
    """
    if meta.context_ratio > config.fast_path_context_ratio:
        return True
    if _has_keywords(system_text, config.compaction_keywords):
        return True
    return False
