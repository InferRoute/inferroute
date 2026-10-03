"""Bounded protocol and active-workspace capability tests for the macOS VM bridge."""

from __future__ import annotations

import hashlib
from pathlib import Path
import os
import socket
import threading

import pytest

from inferroute_local.macos_vm import wire
from inferroute_local.macos_vm.workspace import (
    MAX_FILE_BYTES,
    MAX_WORKSPACE_BYTES,
    WorkspaceError,
    WorkspaceSnapshot,
    valid_path,
)


def test_snapshot_is_flat_hashed_and_excludes_host_state_and_neighbors(tmp_path):
    active = tmp_path / "active"
    active.mkdir()
    (active / "src").mkdir()
    (active / "src" / "main.py").write_bytes(b"print('hi')\n")
    (active / "notes.txt").write_bytes(b"notes")
    (active / ".env").write_text("SECRET=never-copy")
    (active / "auth.json").write_text('{"token":"never-copy"}')
    (active / ".inferroute").mkdir()
    (active / ".inferroute" / "confidential.json").write_text("host state")
    (active / ".ssh").mkdir()
    (active / ".ssh" / "id_ed25519").write_text("private key")
    (active / ".pi").mkdir()
    (active / ".pi" / "settings.json").write_text("agent configuration")
    (active / ".aws").mkdir()
    (active / ".aws" / "credentials").write_text("cloud credentials")
    (active / ".npmrc").write_text("//registry: token")
    neighbor = tmp_path / "neighbor"
    neighbor.mkdir()
    (neighbor / "secret.txt").write_text("outside active workspace")

    with WorkspaceSnapshot(active) as snap:
        assert dict(snap.files) == {
            "notes.txt": b"notes",
            "src/main.py": b"print('hi')\n",
        }
        assert snap.manifest["src/main.py"] == {
            "sha256": hashlib.sha256(b"print('hi')\n").hexdigest(),
            "size": 12,
        }
        assert "../neighbor/secret.txt" not in snap.files
        assert all(
            b"SECRET" not in data
            and b"private key" not in data
            and b"agent configuration" not in data
            and b"cloud credentials" not in data
            and b"registry: token" not in data
            for data in snap.files.values()
        )


def test_snapshot_refuses_git_workspace_and_output_paths_refuse_host_state(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    (root / ".git").mkdir()
    with pytest.raises(WorkspaceError, match=".git"):
        WorkspaceSnapshot(root)

    for path in (
        ".git/config",
        ".ssh/id_ed25519",
        ".pi/settings.json",
        ".env.local",
        "src/credentials.json",
        "nested/.npmrc/token",
        ".inferroute/state.json",
    ):
        with pytest.raises(WorkspaceError):
            valid_path(path)
    assert valid_path("src/main.py") == "src/main.py"


def test_snapshot_refuses_symlinks_hardlinks_and_special_files(tmp_path):
    symlink_root = tmp_path / "symlink-case"
    symlink_root.mkdir()
    (symlink_root / "outside-link").symlink_to(
        tmp_path / "outside", target_is_directory=True
    )
    with pytest.raises(WorkspaceError, match="symlink"):
        WorkspaceSnapshot(symlink_root)

    hardlink_root = tmp_path / "hardlink-case"
    hardlink_root.mkdir()
    original = hardlink_root / "shared.txt"
    original.write_text("same inode outside")
    os.link(original, tmp_path / "outside-hardlink")
    with pytest.raises(WorkspaceError, match="hard-linked"):
        WorkspaceSnapshot(hardlink_root)

    fifo_root = tmp_path / "special-case"
    fifo_root.mkdir()
    os.mkfifo(fifo_root / "pipe")
    with pytest.raises(WorkspaceError, match="special file"):
        WorkspaceSnapshot(fifo_root)


@pytest.mark.parametrize(
    "path", ["../escape", "/absolute", "a/../b", "./x", "a//b", r"a\b", ""]
)
def test_commit_refuses_non_normalized_or_traversal_paths(tmp_path, path):
    root = tmp_path / "workspace"
    root.mkdir()
    (tmp_path / "escape").write_text("must stay unchanged")
    with WorkspaceSnapshot(root) as snap:
        with pytest.raises(WorkspaceError):
            snap.commit({path: b"not written"})
    assert (tmp_path / "escape").read_text() == "must stay unchanged"


def test_commit_updates_and_adds_only_explicit_paths(tmp_path):
    root = tmp_path / "workspace"
    (root / "src").mkdir(parents=True)
    (root / "src" / "main.py").write_bytes(b"before")
    with WorkspaceSnapshot(root) as snap:
        committed = snap.commit(
            {"src/main.py": b"after", "new/sub/result.txt": b"created"}
        )
    assert committed[0] == "new/sub/result.txt"
    assert committed[1].startswith("vm-session-output-")
    assert committed[1].endswith("/src/main.py")
    assert (root / committed[1]).read_bytes() == b"after"
    assert (root / "src" / "main.py").read_bytes() == b"before"
    assert (root / "new" / "sub" / "result.txt").read_bytes() == b"created"
    assert not (root / ".inferroute-vm-export-stage").exists()


def test_any_conflict_aborts_all_workspace_writes_before_commit(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "a.txt").write_bytes(b"a0")
    (root / "b.txt").write_bytes(b"b0")
    with WorkspaceSnapshot(root) as snap:
        (root / "b.txt").write_bytes(b"host edit")
        with pytest.raises(WorkspaceError, match="changed since snapshot"):
            snap.commit({"a.txt": b"guest edit", "b.txt": b"guest overwrite"})
    assert (root / "a.txt").read_bytes() == b"a0"
    assert (root / "b.txt").read_bytes() == b"host edit"
    assert not (root / ".inferroute-vm-export-stage").exists()


def test_commit_refuses_symlink_ancestor_without_touching_target(tmp_path):
    root = tmp_path / "workspace"
    (root / "safe").mkdir(parents=True)
    (root / "safe" / "result.txt").write_text("before")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "result.txt").write_text("outside")
    with WorkspaceSnapshot(root) as snap:
        (root / "safe").rename(root / "safe-old")
        (root / "safe").symlink_to(outside, target_is_directory=True)
        with pytest.raises(WorkspaceError, match="symlink ancestor"):
            snap.commit({"safe/result.txt": b"guest output"})
    assert (outside / "result.txt").read_text() == "outside"
    assert (root / "safe-old" / "result.txt").read_text() == "before"


def test_snapshot_limits_are_enforced(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "large.bin").write_bytes(b"x" * (MAX_FILE_BYTES + 1))
    with pytest.raises(WorkspaceError, match="file limit"):
        WorkspaceSnapshot(root)

    (root / "large.bin").unlink()
    (root / "a.bin").write_bytes(b"x" * 8)
    monkeypatch.setattr("inferroute_local.macos_vm.workspace.MAX_WORKSPACE_BYTES", 7)
    with pytest.raises(WorkspaceError, match="byte limit"):
        WorkspaceSnapshot(root)


def test_bounded_framed_request_and_stream_response_use_ack_backpressure():
    client, server = socket.socketpair()
    observed = {}

    def serve():
        try:
            header, body = wire.receive_request(server)
            observed["header"] = header
            observed["body"] = body
            wire.send_response(
                server, header["seq"], [b"one", b"two"], vm_complete=True
            )
        finally:
            server.close()

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        payload = {"prompt": "P" * 7000}
        chunks = list(wire.request(client, "test-session", 4, "model.stream", payload))
        assert chunks == [b"one", b"two"]
        assert observed["header"]["op"] == "model.stream"
        assert observed["header"]["bytes"] <= wire.MAX_REQUEST_BYTES
        assert (
            observed["body"]
            == __import__("json")
            .dumps(payload, separators=(",", ":"), ensure_ascii=False)
            .encode()
        )
        assert wire.decode(wire.encode(b"wire bytes\x00")) == b"wire bytes\x00"
    finally:
        client.close()
        thread.join(timeout=5)


def test_wire_rejects_oversized_request_before_sending(tmp_path):
    client, server = socket.socketpair()
    try:
        with pytest.raises(wire.ProtocolError, match="payload exceeds limit"):
            wire.send_request(
                client, "test", 0, "x", b"x" * (wire.MAX_REQUEST_BYTES + 1)
            )
        server.settimeout(0.05)
        with pytest.raises(TimeoutError):
            server.recv(1)
    finally:
        client.close()
        server.close()


def test_wire_rejects_nonboolean_vm_completion_marker():
    client, server = socket.socketpair()
    try:
        wire.send_frame(
            server,
            {"v": wire.VERSION, "seq": 8, "end": True, "ok": True, "vm_complete": 1},
        )
        with pytest.raises(wire.ProtocolError, match="terminator"):
            list(wire.receive_response(client, 8))
    finally:
        client.close()
        server.close()


@pytest.mark.parametrize(
    "name",
    [
        ".SSH/key",
        ".InferRoute/state",
        ".GIT/config",
        "Auth.JSON",
        ".ENV.local",
        "ID_RSA",
    ],
)
def test_case_aliases_cannot_export_host_state(name):
    from inferroute_local.macos_vm.workspace import valid_path

    with pytest.raises(WorkspaceError):
        valid_path(name)


def test_host_edit_after_last_preflight_is_never_overwritten(tmp_path, monkeypatch):
    (tmp_path / "document.txt").write_bytes(b"original")
    with WorkspaceSnapshot(tmp_path) as snap:
        preflight = snap._preflight
        calls = 0

        def race(updated):
            nonlocal calls
            writes = preflight(updated)
            calls += 1
            if calls == 2:
                (tmp_path / "document.txt").write_bytes(b"concurrent host edit")
            return writes

        monkeypatch.setattr(snap, "_preflight", race)
        output = snap.commit({"document.txt": b"guest edit"})
    assert (tmp_path / "document.txt").read_bytes() == b"concurrent host edit"
    assert (tmp_path / output[0]).read_bytes() == b"guest edit"


@pytest.mark.parametrize(
    "name", [".SSH", ".InferRoute", ".PI", ".ENV.local", "Auth.JSON", "ID_RSA"]
)
def test_case_aliases_are_excluded_from_snapshot(tmp_path, name):
    (tmp_path / "disclosure.md").write_bytes(b"active synthetic disclosure")
    (tmp_path / name).write_bytes(b"SYNTHETIC HOST STATE MUST NOT TRANSFER")
    with WorkspaceSnapshot(tmp_path) as snapshot:
        assert dict(snapshot.files) == {"disclosure.md": b"active synthetic disclosure"}


def test_case_alias_git_directory_refuses_snapshot(tmp_path):
    (tmp_path / ".GIT").mkdir()
    with pytest.raises(WorkspaceError, match="git metadata"):
        WorkspaceSnapshot(tmp_path)


def test_regular_file_to_fifo_race_refuses_without_hanging(tmp_path):
    import subprocess
    import sys
    import textwrap

    (tmp_path / "document.txt").write_bytes(b"synthetic regular file")
    program = textwrap.dedent("""
        import os, sys
        sys.path.insert(0, sys.argv[2])
        from inferroute_local.macos_vm.workspace import WorkspaceSnapshot, WorkspaceError
        original = WorkspaceSnapshot._open_file
        def substitute(dir_fd, name, before, rel):
            os.unlink(name, dir_fd=dir_fd)
            os.mkfifo(name, mode=0o600, dir_fd=dir_fd)
            return original(dir_fd, name, before, rel)
        WorkspaceSnapshot._open_file = staticmethod(substitute)
        try:
            WorkspaceSnapshot(sys.argv[1])
        except WorkspaceError:
            print("SYNTHETIC_FIFO_RACE_REFUSED")
        else:
            raise SystemExit(78)
    """)
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            program,
            str(tmp_path),
            str(Path(__file__).resolve().parents[1]),
        ],
        capture_output=True,
        text=True,
        timeout=3,
        check=True,
    )
    assert completed.stdout.strip() == "SYNTHETIC_FIFO_RACE_REFUSED"
    assert not completed.stderr
