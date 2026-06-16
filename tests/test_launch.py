"""Regression tests for permission-flag resolution (launch._resolve_flags).

Background: `--dangerously-skip-permissions` HARD-WINS over `--permission-mode` when both
are passed to `claude` (verified empirically — skip-permissions bypasses the allow-list).
So when a caller manages permissions (param or CLI passthrough) we must drop the forced
skip-permissions; bare invocations keep it so unattended agents don't stall on prompts.
"""
from inferroute_cli.launch import _resolve_flags, _DEFAULT_FLAGS


def test_bare_invocation_keeps_skip_permissions():
    assert _resolve_flags(None, []) == _DEFAULT_FLAGS
    assert _resolve_flags(None, ["-p", "hi", "--allowedTools", "Read(*)"]) == _DEFAULT_FLAGS


def test_permission_mode_param_drops_skip_permissions():
    assert _resolve_flags("plan", []) == ["--permission-mode", "plan"]
    assert "--dangerously-skip-permissions" not in _resolve_flags("plan", [])


def test_cli_passthrough_permission_mode_drops_skip_permissions():
    # caller passes their own --permission-mode (+ allow-list) → we add NO permission
    # flags, so skip-permissions never appears and the caller's allow-list is enforced.
    assert _resolve_flags(None, ["--permission-mode", "default", "--allowedTools", "Read(*)"]) == []
    assert _resolve_flags(None, ["--permission-mode=default"]) == []
    assert "--dangerously-skip-permissions" not in _resolve_flags(
        None, ["--permission-mode", "default"]
    )


def test_does_not_match_unrelated_args():
    # a flag that merely contains the substring must not trigger the opt-out
    assert _resolve_flags(None, ["--permission-mode-extra"]) == _DEFAULT_FLAGS


# --- auto-compact window injection (launch._auto_compact_window / _apply_autocompact_env) ---
# CC can't auto-detect the context window for our custom model ids, so its native
# auto-compact never fires (verified 2026-06-09: long sessions grew unbounded, 0
# compactions at 100% context → eventual hard overflow). The launcher sets
# CLAUDE_CODE_AUTO_COMPACT_WINDOW so auto-compact triggers at ~92% of it.
from inferroute_cli.launch import _auto_compact_window, _apply_autocompact_env


def test_auto_compact_window_per_model():
    # 2026-06-16: 200K-class lowered to 180K so CC's auto-compact fires earlier
    # despite the proxy's compression masking the reported context count.
    assert _auto_compact_window("moonshotai/Kimi-K2.6-TEE") == 180_000
    assert _auto_compact_window("zai-org/GLM-5.1-TEE") == 180_000
    assert _auto_compact_window("minimax/minimax-m2.5") == 180_000
    assert _auto_compact_window("deepseek-ai/DeepSeek-V3.2") == 120_000
    assert _auto_compact_window("some/unknown-model") == 150_000
    assert _auto_compact_window("") == 150_000  # never crashes on empty


def test_apply_autocompact_env_sets_when_absent():
    env = {}
    _apply_autocompact_env(env, "moonshotai/Kimi-K2.6-TEE")
    assert env["CLAUDE_CODE_AUTO_COMPACT_WINDOW"] == "180000"


def test_apply_autocompact_env_respects_user_override():
    env = {"CLAUDE_CODE_AUTO_COMPACT_WINDOW": "90000"}
    _apply_autocompact_env(env, "moonshotai/Kimi-K2.6-TEE")
    assert env["CLAUDE_CODE_AUTO_COMPACT_WINDOW"] == "90000"  # user value untouched


# --- product-strip status line (launch._product_strip_settings_args et al.) ---
# CC's fullscreen TUI (the DEFAULT in 2.1.170) hides the pre-launch banner and the
# inline renderer scrolls it away; post-session printing is impossible (we execvp
# claude). So the durable home for ir's session info — dashboard link AND the
# relaunch hint — is CC's status line, injected via the per-invocation --settings
# flag. The strip is two lines (CC supports multi-line statusLine output). Cost is
# the REAL server-computed figure: the recorder daemon writes a per-session .cost
# file and the status line reads it (NOT CC's own mis-priced cost.total_cost_usd).
import json
import subprocess
from pathlib import Path

from inferroute_cli.launch import (
    _session_url,
    _product_strip_settings_args,
    _gate_strip_prefix,
    _native_strip_prefix,
    _model_for_statusline,
    _strip_command,
)


def _run_statusline(cmd: str, stdin: str = "{}") -> subprocess.CompletedProcess:
    """Run an injected statusLine command the way CC does: in a shell, session
    JSON on stdin, stdout is the rendered strip."""
    return subprocess.run(cmd, shell=True, input=stdin, capture_output=True, text=True)


def test_session_url_strips_api_subdomain():
    assert _session_url("https://api.inferroute.ai", "abc") == "https://inferroute.ai/session/abc"
    assert _session_url("http://api.localhost:8000", "x") == "http://localhost:8000/session/x"
    # non-api host left alone
    assert _session_url("https://example.test", "x") == "https://example.test/session/x"


def test_gate_strip_prefix_one_line_with_friendly_short():
    # One line; Kimi's canonical id reverse-maps to the friendly short in the header.
    prefix = _gate_strip_prefix("https://api.inferroute.ai", "sess123",
                                "moonshotai/Kimi-K2.6-TEE", False)
    assert "\n" not in prefix
    assert prefix == "⚡ kimi · standard │ https://inferroute.ai/session/sess123"


def test_gate_strip_prefix_economy_lane():
    prefix = _gate_strip_prefix("https://api.inferroute.ai", "s", "MiniMax-M2.7", True)
    assert "\n" not in prefix
    assert prefix.startswith("⚡ minimax · economy │ ")


def test_gate_strip_prefix_unknown_model_passes_through_verbatim():
    prefix = _gate_strip_prefix("https://api.inferroute.ai", "s", "claude-opus-4-8", False)
    assert prefix.startswith("⚡ claude-opus-4-8 · standard │ ")


def test_native_strip_prefix_one_line_with_and_without_model():
    assert _native_strip_prefix(["--model", "sonnet", "hi"]) == "⚡ sonnet · native"
    assert _native_strip_prefix(["--model=opus"]) == "⚡ opus · native"
    assert _native_strip_prefix(["hello"]) == "⚡ claude · native"


def test_model_for_statusline_extraction():
    assert _model_for_statusline(["--model", "kimi"]) == "kimi"
    assert _model_for_statusline(["--model=glm"]) == "glm"
    assert _model_for_statusline(["--foo", "--model-extra"]) is None
    assert _model_for_statusline([]) is None


def test_statusline_command_renders_one_line_and_ignores_stdin():
    # No cost_file → static one-line strip; CC's piped session JSON is ignored.
    args = _product_strip_settings_args(_gate_strip_prefix(
        "https://api.inferroute.ai", "sess123", "moonshotai/Kimi-K2.6-TEE", False), [])
    assert args[0] == "--settings"
    cmd = json.loads(args[1])["statusLine"]["command"]  # must be valid JSON for CC
    out = _run_statusline(cmd, '{"cost":{"total_cost_usd":99.99}}')  # CC's number — ignored
    assert out.returncode == 0
    assert out.stderr == ""
    assert out.stdout == "⚡ kimi · standard │ https://inferroute.ai/session/sess123"


def test_statusline_appends_real_cost_from_daemon_file(tmp_path):
    cost_file = tmp_path / "sess123.cost"
    cost_file.write_text("0.423700")  # full-precision USD, as the recorder writes it
    cmd = _strip_command("⚡ kimi · standard │ link", cost_file)["command"]
    out = _run_statusline(cmd)
    assert out.returncode == 0
    # Cost lands at the very end, printf-formatted to cents.
    assert out.stdout == "⚡ kimi · standard │ link │ $0.42"


def test_statusline_no_cost_when_file_missing_empty_or_garbage(tmp_path):
    prefix = "⚡ x · native"
    # missing file
    cmd = _strip_command(prefix, tmp_path / "nope.cost")["command"]
    out = _run_statusline(cmd)
    assert out.returncode == 0 and out.stdout == prefix
    # empty file → -s is false → no cost, still exits 0
    empty = tmp_path / "e.cost"; empty.write_text("")
    out = _run_statusline(_strip_command(prefix, empty)["command"])
    assert out.returncode == 0 and out.stdout == prefix
    # garbage content → printf can't format → guarded by `|| true`, still exits 0
    junk = tmp_path / "j.cost"; junk.write_text("not-a-number")
    out = _run_statusline(_strip_command(prefix, junk)["command"])
    assert out.returncode == 0
    assert out.stdout.startswith(prefix)  # never crashes the line


def test_statusline_backs_off_when_user_passes_own_settings():
    assert _product_strip_settings_args("p", ["--settings", "{}"]) == []
    assert _product_strip_settings_args("p", ["--settings={}"]) == []


def test_statusline_opt_out_env(monkeypatch):
    monkeypatch.setenv("IR_NO_STATUSLINE", "1")
    assert _product_strip_settings_args("p", []) == []


def test_statusline_backs_off_when_user_has_statusline(monkeypatch, tmp_path):
    # A statusLine in ~/.claude/settings.json must not be clobbered.
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / "settings.json").write_text(
        json.dumps({"statusLine": {"type": "command", "command": "echo mine"}})
    )
    monkeypatch.setattr("pathlib.Path.home", lambda: home)
    monkeypatch.chdir(tmp_path)  # cwd has no .claude, so only the home one matches
    monkeypatch.delenv("IR_NO_STATUSLINE", raising=False)
    assert _product_strip_settings_args("p", []) == []


# --- `ir --resume` like `claude --resume`: reuse the last model, no picker ---
# `claude --resume` never asks which model to use. To match that, ir remembers the
# model of each launch (launch._persist_last_model) and `ir --resume` reuses it
# (main._is_resume + launch.last_model) instead of popping the model picker.
from inferroute_cli.launch import _persist_last_model, last_model
from inferroute_cli.main import _is_resume


def test_last_model_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    assert last_model() is None                       # nothing launched yet
    _persist_last_model("moonshotai/Kimi-K2.6-TEE")
    assert last_model() == "moonshotai/Kimi-K2.6-TEE"
    _persist_last_model("MiniMax-M2.7")               # later launch overwrites
    assert last_model() == "MiniMax-M2.7"
    _persist_last_model("")                           # empty is a no-op
    assert last_model() == "MiniMax-M2.7"


def test_is_resume_detection():
    assert _is_resume(["--resume"])
    assert _is_resume(["-r"])
    assert _is_resume(["--continue"])
    assert _is_resume(["-c"])
    assert _is_resume(["--resume", "abc123"])         # `--resume <id>`
    assert _is_resume(["--resume=abc123"])            # `--resume=<id>`
    assert _is_resume(["hi", "--continue"])
    assert not _is_resume([])
    assert not _is_resume(["--model", "kimi", "say hi"])
    assert not _is_resume(["--resume-foo"])           # not a real resume flag


# --- minted session id must be a valid UUID (claude --session-id rejects hex) ---
import uuid as _uuid
from inferroute_cli.launch import _new_session_id


def test_new_session_id_is_a_valid_hyphenated_uuid():
    sid = _new_session_id()
    # claude --session-id validates this as a UUID; a bare .hex (no hyphens) is
    # rejected with "Invalid session ID. Must be a valid UUID."
    assert _uuid.UUID(sid)          # parses as a UUID (raises otherwise)
    assert sid.count("-") == 4      # canonical 8-4-4-4-12 form
    assert _new_session_id() != sid # fresh each call


# --- goal-loop economy session (`ir --economy-loop` / IR_LANE=economy-loop) ---
# The patient per-iteration economy mode. It routes like economy (base URL + ir-lane
# header) but, unlike plain economy, (a) does NOT grab an open-gate grant at launch and
# (b) tags the session `ir-mode: goal-loop` so the backend can gate each /goal turn from
# within (deferred). See shared-docs/inferroute/goal-loop-economy-session-spec.md §5.
import os as _os

from inferroute_cli import gate as _gate_mod
from inferroute_cli import launch as _launch_mod
from inferroute_cli.config import Credentials
from inferroute_cli.main import main as _ir_main


def _headers_from_env(env: dict) -> dict:
    """Parse the newline-joined ANTHROPIC_CUSTOM_HEADERS into a {name: value} dict."""
    out: dict[str, str] = {}
    for line in env.get("ANTHROPIC_CUSTOM_HEADERS", "").split("\n"):
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def _capture_launch(monkeypatch, tmp_path, *, lane=None, ir_grant=None):
    """Run launch_through_inferroute with execvpe + the claude binary + gate stubbed,
    returning (captured_env, grab_calls). grab_calls counts open-gate grant polls."""
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)           # config writes → tmp
    monkeypatch.setattr(_launch_mod, "_require_claude_binary", lambda: "claude")
    monkeypatch.delenv("CLAUDECODE", raising=False)                       # not nested
    monkeypatch.delenv("IR_NO_STATUSLINE", raising=False)
    if lane is None:
        monkeypatch.delenv("IR_LANE", raising=False)
    else:
        monkeypatch.setenv("IR_LANE", lane)
    if ir_grant is None:
        monkeypatch.delenv("IR_GRANT", raising=False)
    else:
        monkeypatch.setenv("IR_GRANT", ir_grant)

    grab_calls = {"n": 0}

    def _fake_grab(creds, timeout=10.0):
        grab_calls["n"] += 1
        return "GRABBED-AT-OPEN"

    monkeypatch.setattr(_gate_mod, "grab_grant", _fake_grab)

    captured = {}

    def _fake_execvpe(binary, argv, env):
        captured["env"] = env
        captured["argv"] = argv

    monkeypatch.setattr("os.execvpe", _fake_execvpe)

    creds = Credentials(api_url="https://api.inferroute.ai", api_key="k")
    _launch_mod.launch_through_inferroute("moonshotai/Kimi-K2.6-TEE", creds)
    return captured["env"], grab_calls["n"]


def test_economy_loop_tags_mode_and_skips_open_gate(monkeypatch, tmp_path):
    env, grab_n = _capture_launch(monkeypatch, tmp_path, lane="economy-loop")
    # routes economy
    assert env["ANTHROPIC_BASE_URL"] == "https://api.inferroute.ai/economy"
    hdrs = _headers_from_env(env)
    assert hdrs.get("ir-lane") == "economy"
    assert hdrs.get("ir-mode") == "goal-loop"
    # (a) no open-gate grant grabbed, and none injected
    assert grab_n == 0
    assert "ir-grant" not in hdrs


def test_economy_loop_honors_presupplied_grant(monkeypatch, tmp_path):
    env, grab_n = _capture_launch(monkeypatch, tmp_path, lane="economy-loop",
                                  ir_grant="PRESET-GRANT")
    hdrs = _headers_from_env(env)
    assert hdrs.get("ir-mode") == "goal-loop"
    assert grab_n == 0                              # still never polls the gate at open
    assert hdrs.get("ir-grant") == "PRESET-GRANT"  # but honors a pre-issued grant


def test_plain_economy_grabs_grant_and_has_no_mode_tag(monkeypatch, tmp_path):
    env, grab_n = _capture_launch(monkeypatch, tmp_path, lane="economy")
    hdrs = _headers_from_env(env)
    assert hdrs.get("ir-lane") == "economy"
    assert "ir-mode" not in hdrs                    # mode tag is loop-only
    assert grab_n == 1                              # plain economy DOES grab at open
    assert hdrs.get("ir-grant") == "GRABBED-AT-OPEN"


def test_economy_loop_strip_lane_label():
    prefix = _gate_strip_prefix("https://api.inferroute.ai", "s", "moonshotai/Kimi-K2.6-TEE",
                                True, True)
    assert prefix.startswith("⚡ kimi · economy·loop │ ")


def test_main_consumes_economy_loop_flag(monkeypatch):
    # `ir --economy-loop --model kimi -p hi` sets IR_LANE=economy-loop, strips the flag,
    # and does NOT pass it through to claude.
    monkeypatch.setenv("IR_LANE", "")  # tracked → restored on teardown
    captured = {}

    def _fake_launch(model_id, creds, extra_args=(), **kw):
        captured["model"] = model_id
        captured["extra"] = list(extra_args)

    monkeypatch.setattr("inferroute_cli.launch.launch_through_inferroute", _fake_launch)
    monkeypatch.setattr("inferroute_cli.config.load",
                        lambda: Credentials(api_url="https://api.inferroute.ai", api_key="k"))
    rc = _ir_main(["--economy-loop", "--model", "kimi", "-p", "hi"])
    assert rc == 0
    assert _os.environ["IR_LANE"] == "economy-loop"
    assert "--economy-loop" not in captured["extra"]
    assert captured["extra"] == ["-p", "hi"]


def test_is_premium_anthropic_auto_route_decision():
    """sonnet/opus pins → NATIVE path (user's Anthropic creds, no proxy routing);
    everything else → routed through inferroute as normal. Prevents the proxy from
    substituting a premium model to a depleted tier-2 (sonnet→MiniMax 402)."""
    from inferroute_cli.main import _is_premium_anthropic
    # premium → native
    assert _is_premium_anthropic("sonnet")
    assert _is_premium_anthropic("opus")
    assert _is_premium_anthropic("claude-sonnet-4-6")
    assert _is_premium_anthropic("claude-opus-4-8")
    assert _is_premium_anthropic("Sonnet")          # case-insensitive
    # NOT premium → routed (economy/other models, haiku background, empty)
    assert not _is_premium_anthropic("kimi")
    assert not _is_premium_anthropic("moonshotai/Kimi-K2.6-TEE")
    assert not _is_premium_anthropic("haiku")
    assert not _is_premium_anthropic("claude-haiku-4-5")
    assert not _is_premium_anthropic("")
