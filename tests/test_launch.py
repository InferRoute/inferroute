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
    assert _auto_compact_window("moonshotai/Kimi-K2.6-TEE") == 200_000
    assert _auto_compact_window("zai-org/GLM-5.1-TEE") == 200_000
    assert _auto_compact_window("minimax/minimax-m2.5") == 200_000
    assert _auto_compact_window("deepseek-ai/DeepSeek-V3.2") == 120_000
    assert _auto_compact_window("some/unknown-model") == 150_000
    assert _auto_compact_window("") == 150_000  # never crashes on empty


def test_apply_autocompact_env_sets_when_absent():
    env = {}
    _apply_autocompact_env(env, "moonshotai/Kimi-K2.6-TEE")
    assert env["CLAUDE_CODE_AUTO_COMPACT_WINDOW"] == "200000"


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


def test_gate_strip_prefix_two_lines_with_friendly_short_and_hint():
    # Kimi's canonical id reverse-maps to the friendly short in the relaunch hint.
    prefix = _gate_strip_prefix("https://api.inferroute.ai", "sess123",
                                "moonshotai/Kimi-K2.6-TEE", False)
    line1, line2 = prefix.split("\n")
    assert line1 == "⚡ kimi · standard │ https://inferroute.ai/session/sess123"
    assert line2 == "↻ ir --model kimi"


def test_gate_strip_prefix_economy_lane_and_hint():
    prefix = _gate_strip_prefix("https://api.inferroute.ai", "s", "MiniMax-M2.7", True)
    line1, line2 = prefix.split("\n")
    assert line1.startswith("⚡ minimax · economy │ ")
    assert line2 == "↻ ir --model minimax --economy"


def test_gate_strip_prefix_unknown_model_passes_through_verbatim():
    prefix = _gate_strip_prefix("https://api.inferroute.ai", "s", "claude-opus-4-8", False)
    assert "⚡ claude-opus-4-8 · standard" in prefix
    assert prefix.endswith("↻ ir --model claude-opus-4-8")


def test_native_strip_prefix_with_and_without_model():
    assert _native_strip_prefix(["--model", "sonnet", "hi"]) == "⚡ sonnet · native\n↻ ir anthropic --model sonnet"
    assert _native_strip_prefix(["--model=opus"]) == "⚡ opus · native\n↻ ir anthropic --model opus"
    assert _native_strip_prefix(["hello"]) == "⚡ claude · native\n↻ ir anthropic"


def test_model_for_statusline_extraction():
    assert _model_for_statusline(["--model", "kimi"]) == "kimi"
    assert _model_for_statusline(["--model=glm"]) == "glm"
    assert _model_for_statusline(["--foo", "--model-extra"]) is None
    assert _model_for_statusline([]) is None


def test_statusline_command_renders_both_lines_and_ignores_stdin():
    # No cost_file → static two-line strip; CC's piped session JSON is ignored.
    args = _product_strip_settings_args(_gate_strip_prefix(
        "https://api.inferroute.ai", "sess123", "moonshotai/Kimi-K2.6-TEE", False), [])
    assert args[0] == "--settings"
    cmd = json.loads(args[1])["statusLine"]["command"]  # must be valid JSON for CC
    out = _run_statusline(cmd, '{"cost":{"total_cost_usd":99.99}}')  # CC's number — ignored
    assert out.returncode == 0
    assert out.stderr == ""
    assert out.stdout == (
        "⚡ kimi · standard │ https://inferroute.ai/session/sess123\n"
        "↻ ir --model kimi"
    )


def test_statusline_appends_real_cost_from_daemon_file(tmp_path):
    cost_file = tmp_path / "sess123.cost"
    cost_file.write_text("0.423700")  # full-precision USD, as the recorder writes it
    cmd = _strip_command("⚡ kimi · standard │ link\n↻ ir --model kimi", cost_file)["command"]
    out = _run_statusline(cmd)
    assert out.returncode == 0
    # Cost lands at the very end (last line), printf-formatted to cents.
    assert out.stdout == "⚡ kimi · standard │ link\n↻ ir --model kimi │ $0.42"


def test_statusline_no_cost_when_file_missing_empty_or_garbage(tmp_path):
    prefix = "⚡ x · native\n↻ ir anthropic"
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
