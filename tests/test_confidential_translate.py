"""Anthropic ⇄ OpenAI translation on Claude Code–shaped traffic."""
import json

from inferroute_local.confidential import translate as T

KIMI = "moonshotai/Kimi-K2.6-TEE"


def _cc_request(**over):
    body = {
        "model": "kimi-k2.6", "max_tokens": 32000, "stream": True,
        "metadata": {"user_id": "user_abc_session_xyz"},
        "system": [{"type": "text", "text": "You are Claude Code.", "cache_control": {"type": "ephemeral"}}],
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "list files", "cache_control": {"type": "ephemeral"}}]},
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "I should run ls", "signature": "sig"},
                {"type": "text", "text": "Running ls."},
                {"type": "tool_use", "id": "call_1", "name": "Bash", "input": {"command": "ls"}}]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "call_1", "content": [{"type": "text", "text": "a.py\nb.py"}]},
                {"type": "text", "text": "thanks"}]},
        ],
        "tools": [{"name": "Bash", "description": "run", "input_schema": {"type": "object", "properties": {"command": {"type": "string"}}},
                   "cache_control": {"type": "ephemeral"}},
                  {"type": "web_search_20250305", "name": "web_search"}],
        "tool_choice": {"type": "auto"},
        "thinking": {"type": "enabled", "budget_tokens": 4096},
    }
    body.update(over)
    return body


def test_request_shape_for_claude_code_traffic():
    r = T.to_openai(_cc_request(), KIMI)
    assert r["model"] == KIMI and r["stream"] is True and r["stream_options"] == {"include_usage": True}
    assert "metadata" not in r, "user_id must not leave the device"
    assert "cache_control" not in json.dumps(r)
    roles = [m["role"] for m in r["messages"]]
    assert roles == ["system", "user", "assistant", "tool", "user"]
    a = r["messages"][2]
    assert a["reasoning_content"] == "I should run ls" and a["content"] == "Running ls."
    assert a["tool_calls"] == [{"id": "call_1", "type": "function", "function": {"name": "Bash", "arguments": '{"command": "ls"}'}}]
    assert r["messages"][3] == {"role": "tool", "content": "a.py\nb.py", "tool_call_id": "call_1"}
    assert [t["function"]["name"] for t in r["tools"]] == ["Bash"], "server tools without a schema are dropped"
    assert r["tool_choice"] == "auto"
    assert r["chat_template_kwargs"] == {"enable_thinking": True}


def test_thinking_key_follows_the_model_family_and_is_absent_when_unknown():
    assert T.to_openai(_cc_request(thinking={"type": "disabled"}), "zai-org/GLM-5.2-TEE")["chat_template_kwargs"] == {"thinking": False}
    assert "chat_template_kwargs" not in T.to_openai(_cc_request(), "Qwen/Qwen3-32B-TEE")
    assert "chat_template_kwargs" not in T.to_openai(_cc_request(thinking=None), KIMI)


def test_tool_choice_any_and_specific_and_error_results():
    r = T.to_openai(_cc_request(tool_choice={"type": "any", "disable_parallel_tool_use": True}), KIMI)
    assert r["tool_choice"] == "required" and r["parallel_tool_calls"] is False
    r = T.to_openai(_cc_request(tool_choice={"type": "tool", "name": "Bash"}), KIMI)
    assert r["tool_choice"] == {"type": "function", "function": {"name": "Bash"}}
    body = _cc_request()
    body["messages"][2]["content"][0] = {"type": "tool_result", "tool_use_id": "call_1", "content": "boom", "is_error": True}
    assert T.to_openai(body, KIMI)["messages"][3]["content"] == "Error: boom"


def test_images_become_data_urls_only_when_present():
    body = _cc_request(messages=[{"role": "user", "content": [
        {"type": "text", "text": "what is this"},
        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}}]}])
    m = T.to_openai(body, KIMI)["messages"][-1]
    assert m["content"][1] == {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}


def test_non_stream_response_with_reasoning_text_and_tools():
    resp = {"id": "chatcmpl-abc", "choices": [{"finish_reason": "tool_calls", "message": {
        "content": "I'll list them.", "reasoning_content": "plan",
        "tool_calls": [{"id": "call_9", "function": {"name": "Bash", "arguments": '{"command":"ls"}'}}]}}],
        "usage": {"prompt_tokens": 120, "completion_tokens": 30, "prompt_tokens_details": {"cached_tokens": 100}}}
    out = T.from_openai(resp, "kimi-k2.6")
    assert out["id"] == "msg_abc" and out["stop_reason"] == "tool_use"
    assert [b["type"] for b in out["content"]] == ["thinking", "text", "tool_use"]
    assert out["content"][2]["input"] == {"command": "ls"}
    assert out["usage"] == {"input_tokens": 20, "output_tokens": 30, "cache_read_input_tokens": 100, "cache_creation_input_tokens": 0}
    think = T.from_openai({"id": "x", "choices": [{"finish_reason": "stop", "message": {"content": "<think>hmm</think>answer"}}]}, "m")
    assert [(b["type"], b.get("thinking") or b.get("text")) for b in think["content"]] == [("thinking", "hmm"), ("text", "answer")]


def _events(lines, model="kimi-k2.6"):
    st = T.StreamTranslator(model)
    evs = []
    for ln in lines:
        evs += st.feed_line(ln)
    evs += st.finish_events()
    parsed = []
    for e in evs:
        head, data = e.split("\n", 1)
        parsed.append(json.loads(data[len("data: "):].strip()))
    return parsed


def _chunk(delta=None, finish=None, usage=None, id="chatcmpl-1"):
    c = {"id": id, "model": "moonshotai/Kimi-K2.6-TEE", "choices": [{"index": 0, "delta": delta or {}, "finish_reason": finish}]}
    if usage:
        c["usage"] = usage
    return "data: " + json.dumps(c)


def test_stream_reasoning_then_text_then_tool_call_is_a_valid_block_sequence():
    ev = _events([
        _chunk({"reasoning_content": "think "}, usage={"prompt_tokens": 50, "completion_tokens": 0}),
        _chunk({"reasoning_content": "more"}),
        _chunk({"content": "Sure."}),
        _chunk({"tool_calls": [{"index": 0, "id": "call_1", "function": {"name": "Bash", "arguments": ""}}]}),
        _chunk({"tool_calls": [{"index": 0, "function": {"arguments": '{"command":'}}]}),
        _chunk({"tool_calls": [{"index": 0, "function": {"arguments": '"ls"}'}}]}),
        _chunk(finish="tool_calls", usage={"prompt_tokens": 50, "completion_tokens": 12}),
        "data: [DONE]",
    ])
    types = [e["type"] for e in ev]
    assert types[0] == "message_start" and ev[0]["message"]["id"] == "msg_1"
    assert ev[0]["message"]["usage"]["input_tokens"] == 50
    starts = [(e["index"], e["content_block"]["type"]) for e in ev if e["type"] == "content_block_start"]
    assert starts == [(0, "thinking"), (1, "text"), (2, "tool_use")]
    stops = sorted(e["index"] for e in ev if e["type"] == "content_block_stop")
    assert stops == [0, 1, 2]
    args = "".join(e["delta"]["partial_json"] for e in ev if e["type"] == "content_block_delta" and e["delta"]["type"] == "input_json_delta")
    assert json.loads(args) == {"command": "ls"}
    md = [e for e in ev if e["type"] == "message_delta"][0]
    assert md["delta"]["stop_reason"] == "tool_use" and md["usage"]["output_tokens"] == 12
    assert types[-1] == "message_stop"
    # each block's stop comes after its start and before the next start
    order = [(e["type"], e.get("index")) for e in ev if e["type"] in ("content_block_start", "content_block_stop")]
    assert order == [("content_block_start", 0), ("content_block_stop", 0), ("content_block_start", 1),
                     ("content_block_stop", 1), ("content_block_start", 2), ("content_block_stop", 2)]


def test_stream_think_tags_split_across_chunks_become_a_thinking_block():
    ev = _events([_chunk({"content": "<th"}), _chunk({"content": "ink>plan"}), _chunk({"content": "ning</think>Hello"}),
                  _chunk({"content": " world"}), _chunk(finish="stop")])
    starts = [e["content_block"]["type"] for e in ev if e["type"] == "content_block_start"]
    assert starts == ["thinking", "text"]
    think = "".join(e["delta"]["thinking"] for e in ev if e["type"] == "content_block_delta" and e["delta"]["type"] == "thinking_delta")
    text = "".join(e["delta"]["text"] for e in ev if e["type"] == "content_block_delta" and e["delta"]["type"] == "text_delta")
    assert (think, text) == ("planning", "Hello world")


def test_stream_short_text_that_merely_looks_like_a_tag_is_flushed_at_the_end():
    ev = _events([_chunk({"content": "<t"}), _chunk(finish="stop")])
    text = "".join(e["delta"]["text"] for e in ev if e["type"] == "content_block_delta")
    assert text == "<t"
    assert [e["delta"]["stop_reason"] for e in ev if e["type"] == "message_delta"] == ["end_turn"]


def test_stream_tool_call_without_an_id_gets_one_minted_and_parallel_calls_keep_their_blocks():
    ev = _events([
        _chunk({"tool_calls": [{"index": 0, "function": {"name": "Read", "arguments": '{"a":1}'}}]}),
        _chunk({"tool_calls": [{"index": 1, "id": "call_b", "function": {"name": "Bash", "arguments": '{"b":'}}]}),
        _chunk({"tool_calls": [{"index": 1, "function": {"arguments": '2}'}}]}),
        _chunk(finish="tool_calls"),
    ])
    starts = [e for e in ev if e["type"] == "content_block_start"]
    assert [s["content_block"]["name"] for s in starts] == ["Read", "Bash"]
    assert starts[0]["content_block"]["id"].startswith("call_") and starts[1]["content_block"]["id"] == "call_b"
    deltas = [(e["index"], e["delta"]["partial_json"]) for e in ev if e["type"] == "content_block_delta"]
    assert deltas == [(0, '{"a":1}'), (1, '{"b":'), (1, '2}')]
    assert sorted(e["index"] for e in ev if e["type"] == "content_block_stop") == [0, 1]


def test_stream_with_no_content_at_all_still_yields_a_complete_message():
    ev = _events([_chunk(finish="stop", usage={"prompt_tokens": 3, "completion_tokens": 0})])
    types = [e["type"] for e in ev]
    assert types == ["message_start", "content_block_start", "content_block_stop", "message_delta", "message_stop"]


def test_stream_upstream_error_frame_becomes_an_anthropic_error_event():
    ev = _events(['data: {"error": {"message": "instance busy", "code": 503}}'])
    assert ev[0] == {"type": "error", "error": {"type": "api_error", "message": "instance busy"}}


def test_sse_line_reassembly_across_arbitrary_chunks():
    raw = b"data: {\"a\":1}\n\ndata: {\"b\":2}\n\n"
    assert [line for line in T.iter_sse_lines([raw[:3], raw[3:17], raw[17:]]) if line.startswith("data:")] == ['data: {"a":1}', 'data: {"b":2}']


def test_lane_preamble_is_prepended_to_the_system_prompt_for_both_shapes():
    pre = "# Confidential session\nYou are inside an enclave."
    r = T.to_openai(_cc_request(), KIMI, system_prefix=pre)
    assert r["messages"][0]["role"] == "system"
    assert r["messages"][0]["content"].startswith(pre) and r["messages"][0]["content"].endswith("You are Claude Code.")
    r = T.to_openai(_cc_request(system="plain string"), KIMI, system_prefix=pre)
    assert r["messages"][0]["content"] == pre + "\n\nplain string"
    r = T.to_openai(_cc_request(system=None), KIMI, system_prefix=pre)
    assert r["messages"][0] == {"role": "system", "content": pre}
    r = T.to_openai(_cc_request(system=None), KIMI)
    assert r["messages"][0]["role"] == "user", "no preamble, no system → no system message"
