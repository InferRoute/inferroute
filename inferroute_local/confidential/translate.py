"""Anthropic Messages API ⇄ OpenAI Chat Completions, performed ON THIS DEVICE.

Why this lives in the client: a Chutes TEE chute exposes OpenAI-shaped cords only
(``/chat``, ``/chat_stream``… — no ``/v1/messages``), and on the confidential lane the
InferRoute proxy sees ciphertext, so the translation the proxy normally does must happen
before encryption — here.

Scope: exactly what Claude Code sends and reads. Request: ``system`` (string or blocks),
``messages`` with text / image / tool_use / tool_result / thinking blocks, ``tools`` with
``input_schema``, ``tool_choice``, sampling params, ``stream``, ``thinking``. Response: text,
tool calls (with streamed ``input_json_delta``), reasoning (``reasoning_content`` deltas or
``<think>`` tags) as ``thinking`` blocks, usage with cache-read accounting, stop reasons.

Deliberate choices, each a privacy or fidelity decision:
  * ``metadata`` (Claude Code's ``user_id``) is DROPPED — it identifies the user and the model
    does not need it.
  * ``cache_control`` markers are stripped (meaningless upstream; the enclave's own prefix
    cache still works within the session because the instance is pinned).
  * Assistant ``thinking`` blocks are sent back as ``reasoning_content`` (what vLLM/SGLang
    chat templates for these model families read), not folded into the text.
  * Extended thinking is switched by the chat-template key each family actually uses —
    Kimi: ``chat_template_kwargs.enable_thinking``; GLM: ``chat_template_kwargs.thinking``
    (``enable_thinking=false`` makes GLM hang — a probed fact, not a preference).
  * Message ids are forced into ``msg_…`` shape: Claude Code's resume path requires it.
"""
from __future__ import annotations

import json
import secrets
from typing import Iterator

FAMILY_THINKING_KEY = {"kimi": "enable_thinking", "glm": "thinking", "deepseek": "thinking"}


def thinking_key_for(model_name: str) -> str | None:
    m = model_name.lower()
    for fam, key in FAMILY_THINKING_KEY.items():
        if fam in m:
            return key
    return None


# ───────────────────────────── request: Anthropic → OpenAI ─────────────────────────────

def _text_of(content) -> str:
    if isinstance(content, str):
        return content
    parts = []
    for b in content or []:
        if isinstance(b, str):
            parts.append(b)
        elif isinstance(b, dict):
            if b.get("type") == "text":
                parts.append(b.get("text") or "")
            elif b.get("type") == "image":
                parts.append("[image omitted: not representable inside a tool result]")
            else:
                parts.append(json.dumps(b, ensure_ascii=False))
    return "\n".join(p for p in parts if p is not None)


def _image_url(block: dict) -> str | None:
    src = block.get("source") or {}
    if src.get("type") == "base64" and src.get("data"):
        return f"data:{src.get('media_type') or 'image/png'};base64,{src['data']}"
    if src.get("type") == "url" and src.get("url"):
        return src["url"]
    return None


def _user_message(msg: dict, out: list) -> None:
    """tool_result blocks become ``tool`` messages FIRST (they must follow the assistant's
    tool_calls directly); any text/images become one ``user`` message after them."""
    content = msg.get("content")
    if isinstance(content, str):
        out.append({"role": "user", "content": content})
        return
    texts, parts, has_image = [], [], False
    for b in content or []:
        if isinstance(b, str):
            texts.append(b)
            parts.append({"type": "text", "text": b})
        elif not isinstance(b, dict):
            continue
        elif b.get("type") == "text":
            texts.append(b.get("text") or "")
            parts.append({"type": "text", "text": b.get("text") or ""})
        elif b.get("type") == "image":
            url = _image_url(b)
            if url:
                has_image = True
                parts.append({"type": "image_url", "image_url": {"url": url}})
        elif b.get("type") == "tool_result":
            text = _text_of(b.get("content"))
            if b.get("is_error") and not text.lower().startswith("error"):
                text = "Error: " + text
            out.append({"role": "tool", "content": text, "tool_call_id": b.get("tool_use_id") or ""})
        elif b.get("type") == "document":
            texts.append("[document omitted: not supported on the confidential lane]")
            parts.append({"type": "text", "text": texts[-1]})
    if has_image:
        out.append({"role": "user", "content": parts})
    elif texts:
        out.append({"role": "user", "content": "\n".join(texts)})


def _assistant_message(msg: dict, out: list) -> None:
    content = msg.get("content")
    if isinstance(content, str):
        out.append({"role": "assistant", "content": content})
        return
    text, reasoning, calls = [], [], []
    for b in content or []:
        if not isinstance(b, dict):
            continue
        t = b.get("type")
        if t == "text":
            text.append(b.get("text") or "")
        elif t == "thinking" and b.get("thinking"):
            reasoning.append(b["thinking"])
        elif t == "tool_use":
            args = b.get("input")
            calls.append({"id": b.get("id") or _tool_id(), "type": "function",
                          "function": {"name": b.get("name") or "", "arguments":
                                       args if isinstance(args, str) else json.dumps(args or {}, ensure_ascii=False)}})
    m: dict = {"role": "assistant", "content": "".join(text)}
    if reasoning:
        m["reasoning_content"] = "\n".join(reasoning)
    if calls:
        m["tool_calls"] = calls
    out.append(m)


def _tool_id() -> str:
    return "call_" + secrets.token_hex(8)


def to_openai(body: dict, upstream_model: str, system_prefix: str = "") -> dict:
    """Anthropic Messages request → OpenAI Chat Completions request for ``upstream_model``.

    ``system_prefix`` is prepended to the system prompt (the lane preamble: the model is told,
    truthfully, where it is running and what was verified, so it can answer "is this private?"
    from facts instead of guessing it is talking to a vendor's cloud)."""
    messages: list = []
    system = body.get("system")
    if isinstance(system, str):
        s = system
    elif isinstance(system, list):
        s = "\n".join((b.get("text") or "") for b in system if isinstance(b, dict) and b.get("type") == "text")
    else:
        s = ""
    s = (system_prefix.rstrip() + "\n\n" + s.lstrip()) if system_prefix.strip() else s
    if s.strip():
        messages.append({"role": "system", "content": s.strip()})
    for msg in body.get("messages") or []:
        if not isinstance(msg, dict):
            continue
        if msg.get("role") == "user":
            _user_message(msg, messages)
        elif msg.get("role") == "assistant":
            _assistant_message(msg, messages)

    req: dict = {"model": upstream_model, "messages": messages, "stream": bool(body.get("stream"))}
    if req["stream"]:
        req["stream_options"] = {"include_usage": True}
    for k in ("max_tokens", "temperature", "top_p", "top_k"):
        if body.get(k) is not None:
            req[k] = body[k]
    if body.get("stop_sequences"):
        req["stop"] = body["stop_sequences"]

    tools = [t for t in (body.get("tools") or []) if isinstance(t, dict) and t.get("name") and "input_schema" in t]
    if tools:
        req["tools"] = [{"type": "function", "function": {
            "name": t["name"], "description": t.get("description") or "",
            "parameters": t.get("input_schema") or {"type": "object", "properties": {}}}} for t in tools]
        tc = body.get("tool_choice")
        if isinstance(tc, dict):
            kind = tc.get("type")
            if kind == "any":
                req["tool_choice"] = "required"
            elif kind == "none":
                req["tool_choice"] = "none"
            elif kind == "tool" and tc.get("name"):
                req["tool_choice"] = {"type": "function", "function": {"name": tc["name"]}}
            elif kind == "auto":
                req["tool_choice"] = "auto"
            if tc.get("disable_parallel_tool_use"):
                req["parallel_tool_calls"] = False

    key = thinking_key_for(upstream_model)
    th = body.get("thinking")
    if key and isinstance(th, dict):
        req["chat_template_kwargs"] = {key: th.get("type") == "enabled"}
    return req


# ───────────────────────────── response: OpenAI → Anthropic ─────────────────────────────

def _stop_reason(finish_reason, has_tools: bool) -> str:
    if has_tools or finish_reason in ("tool_calls", "function_call"):
        return "tool_use"
    if finish_reason == "length":
        return "max_tokens"
    return "end_turn"


def _usage(u: dict | None) -> dict:
    u = u or {}
    prompt = int(u.get("prompt_tokens") or 0)
    cached = int(((u.get("prompt_tokens_details") or {}).get("cached_tokens")) or 0)
    out = {"input_tokens": max(prompt - cached, 0), "output_tokens": int(u.get("completion_tokens") or 0)}
    if cached:
        out["cache_read_input_tokens"] = cached
        out["cache_creation_input_tokens"] = 0
    return out


def _msg_id(raw) -> str:
    s = str(raw or "").strip() or secrets.token_hex(12)
    return s if s.startswith("msg_") else "msg_" + s.replace("chatcmpl-", "")


def _split_think(text: str) -> tuple[str, str]:
    if text.startswith("<think>"):
        end = text.find("</think>")
        if end != -1:
            return text[7:end], text[end + 8:]
    return "", text


def from_openai(resp: dict, model: str) -> dict:
    choice = (resp.get("choices") or [{}])[0]
    m = choice.get("message") or {}
    blocks: list = []
    reasoning = m.get("reasoning_content") or m.get("reasoning") or ""
    think, text = _split_think(m.get("content") or "")
    reasoning = reasoning or think
    if reasoning:
        blocks.append({"type": "thinking", "thinking": reasoning, "signature": ""})
    if text:
        blocks.append({"type": "text", "text": text})
    calls = m.get("tool_calls") or []
    for tc in calls:
        fn = tc.get("function") or {}
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except json.JSONDecodeError:
            args = {"_raw": fn.get("arguments")}
        blocks.append({"type": "tool_use", "id": tc.get("id") or _tool_id(), "name": fn.get("name") or "",
                       "input": args if isinstance(args, dict) else {"value": args}})
    if not blocks:
        blocks.append({"type": "text", "text": ""})
    return {"id": _msg_id(resp.get("id")), "type": "message", "role": "assistant", "model": model,
            "content": blocks, "stop_reason": _stop_reason(choice.get("finish_reason"), bool(calls)),
            "stop_sequence": None, "usage": _usage(resp.get("usage"))}


def error_body(message: str, kind: str = "api_error") -> dict:
    return {"type": "error", "error": {"type": kind, "message": message}}


def sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


class StreamTranslator:
    """OpenAI SSE lines in → Anthropic SSE events out. One instance per response.

    Blocks are opened lazily and closed when the content type changes, so any order the
    model produces (reasoning → text → tool calls, or text after tools) renders as a valid
    Anthropic block sequence. Tool calls are keyed by OpenAI's ``index``; a call whose id
    never arrives gets one minted here so Claude Code can still reference it.
    """

    def __init__(self, model: str):
        self.model = model
        self.started = False
        self.index = -1
        self.cur: str | None = None            # "thinking" | "text" | "tool"
        self.cur_tool: int | None = None       # OpenAI tool index of the open block
        self.tools: dict[int, dict] = {}       # oai index → {id, name, block, started, pending}
        self.usage: dict = {"input_tokens": 0, "output_tokens": 0}
        self.finish: str | None = None
        self.saw_tool = False
        self.think_probe = ""                  # first bytes of text, to detect a <think> prefix
        self.probing = True
        self.in_think_tag = False
        self.closed: set[int] = set()          # block indexes whose stop has been emitted
        self.done = False
        self.events = 0
        self.text_chars = 0

    # -- block helpers --
    def _open(self, kind: str, block: dict) -> str:
        self.index += 1
        self.cur = kind
        return sse("content_block_start", {"type": "content_block_start", "index": self.index, "content_block": block})

    def _close(self) -> list[str]:
        if self.cur is None:
            return []
        ev = sse("content_block_stop", {"type": "content_block_stop", "index": self.index})
        self.closed.add(self.index)
        self.cur, self.cur_tool = None, None
        return [ev]

    def _delta(self, delta: dict) -> str:
        return sse("content_block_delta", {"type": "content_block_delta", "index": self.index, "delta": delta})

    def _ensure(self, kind: str) -> list[str]:
        if self.cur == kind:
            return []
        out = self._close()
        block = {"type": "thinking", "thinking": ""} if kind == "thinking" else {"type": "text", "text": ""}
        out.append(self._open(kind, block))
        return out

    # -- public --
    def feed_line(self, line: str) -> list[str]:
        line = line.strip()
        if not line.startswith("data:"):
            return []
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            return []
        try:
            chunk = json.loads(payload)
        except json.JSONDecodeError:
            return []
        if not isinstance(chunk, dict):
            return []
        if "error" in chunk and "choices" not in chunk:
            err = chunk["error"] if isinstance(chunk["error"], dict) else {"message": str(chunk["error"])}
            return [sse("error", {"type": "error", "error": {"type": "api_error", "message": err.get("message") or "upstream error"}})]
        out: list[str] = []
        if chunk.get("usage"):
            self.usage = _usage(chunk["usage"])
        if not self.started:
            self.started = True
            if chunk.get("model"):
                self.model = self.model or chunk["model"]
            out.append(sse("message_start", {"type": "message_start", "message": {
                "id": _msg_id(chunk.get("id")), "type": "message", "role": "assistant", "model": self.model,
                "content": [], "stop_reason": None, "stop_sequence": None,
                "usage": {**self.usage, "output_tokens": 0}}}))
        choice = (chunk.get("choices") or [None])[0]
        if not choice:
            self.events += len(out)
            return out
        delta = choice.get("delta") or {}
        if choice.get("finish_reason"):
            self.finish = choice["finish_reason"]

        reasoning = delta.get("reasoning_content") or delta.get("reasoning")
        if reasoning:
            self.probing = False
            out += self._ensure("thinking")
            out.append(self._delta({"type": "thinking_delta", "thinking": reasoning}))

        content = delta.get("content")
        if content:
            out += self._text(content)

        for tc in delta.get("tool_calls") or []:
            out += self._tool(tc)
        self.events += len(out)
        return out

    def _text(self, content: str) -> list[str]:
        out: list[str] = []
        if self.probing:
            self.think_probe += content
            if len(self.think_probe) < 7 and "<think>".startswith(self.think_probe):
                return out
            self.probing = False
            if self.think_probe.startswith("<think>"):
                out += self._ensure("thinking")
                content = self.think_probe[7:]
                self.in_think_tag = True
            else:
                content = self.think_probe
        if getattr(self, "in_think_tag", False):
            end = content.find("</think>")
            if end == -1:
                out.append(self._delta({"type": "thinking_delta", "thinking": content}))
                return out
            before, content = content[:end], content[end + 8:]
            if before:
                out.append(self._delta({"type": "thinking_delta", "thinking": before}))
            self.in_think_tag = False
            if not content:
                return out
        out += self._ensure("text")
        self.text_chars += len(content)
        out.append(self._delta({"type": "text_delta", "text": content}))
        return out

    def _tool(self, tc: dict) -> list[str]:
        out: list[str] = []
        idx = int(tc.get("index") or 0)
        fn = tc.get("function") or {}
        st = self.tools.get(idx)
        if st is None:
            st = self.tools[idx] = {"id": tc.get("id"), "name": fn.get("name"), "block": None, "started": False, "pending": ""}
        if tc.get("id"):
            st["id"] = tc["id"]
        if fn.get("name"):
            st["name"] = fn["name"]
        if fn.get("arguments"):
            st["pending"] += fn["arguments"]
        if not st["started"] and st["name"]:
            out += self._close()
            st["id"] = st["id"] or _tool_id()
            out.append(self._open("tool", {"type": "tool_use", "id": st["id"], "name": st["name"], "input": {}}))
            st["block"], st["started"], self.cur_tool, self.saw_tool = self.index, True, idx, True
        if st["started"] and st["pending"]:
            if self.cur_tool != idx:            # interleaved calls: reopen is not allowed; route by index
                self.cur_tool = idx
                self.index = st["block"]
            out.append(self._delta({"type": "input_json_delta", "partial_json": st["pending"]}))
            st["pending"] = ""
        return out

    def finish_events(self) -> list[str]:
        if self.done:
            return []
        self.done = True
        out: list[str] = []
        if not self.started:
            out.append(sse("message_start", {"type": "message_start", "message": {
                "id": _msg_id(None), "type": "message", "role": "assistant", "model": self.model, "content": [],
                "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 0, "output_tokens": 0}}}))
        if self.probing and self.think_probe:
            self.probing = False
            out += self._ensure("text")
            out.append(self._delta({"type": "text_delta", "text": self.think_probe}))
        # every opened block, in index order, gets exactly one stop
        opened = {st["block"] for st in self.tools.values() if st["started"]}
        if self.cur in ("text", "thinking"):
            opened.add(self.index)
        for i in sorted(opened - self.closed):
            out.append(sse("content_block_stop", {"type": "content_block_stop", "index": i}))
            self.closed.add(i)
        self.cur = None
        if self.index < 0:
            out.append(sse("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}))
            out.append(sse("content_block_stop", {"type": "content_block_stop", "index": 0}))
        out.append(sse("message_delta", {"type": "message_delta",
                                         "delta": {"stop_reason": _stop_reason(self.finish, self.saw_tool), "stop_sequence": None},
                                         "usage": dict(self.usage)}))
        out.append(sse("message_stop", {"type": "message_stop"}))
        self.events += len(out)
        return out


def iter_sse_lines(chunks: Iterator[bytes]) -> Iterator[str]:
    """Reassemble arbitrary byte chunks into complete lines (the decrypted stream is chunked
    however the enclave chunked it, not at line boundaries)."""
    buf = b""
    for c in chunks:
        buf += c
        while True:
            i = buf.find(b"\n")
            if i == -1:
                break
            yield buf[:i].decode("utf-8", "replace")
            buf = buf[i + 1:]
    if buf.strip():
        yield buf.decode("utf-8", "replace")
