"""Read-only snapshot and explicit safe export capability for one active workspace.

The object retains an open directory descriptor for the selected root. All
walks and writes are descriptor-relative; entries below that root are opened
without following symlinks. This does not grant access to a neighboring
workspace or the caller's home directory.
"""

from __future__ import annotations

import errno
import hashlib
import os
import secrets
import stat
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Optional

MAX_WORKSPACE_BYTES = 32 * 1024 * 1024
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_WORKSPACE_ENTRIES = 2048
_STAGE_NAME = ".inferroute-vm-export-stage"
_REFUSED_DIRS = frozenset({".git"})
_EXCLUDED_DIRS = frozenset(
    {
        ".inferroute",
        ".ssh",
        ".pi",
        ".claude",
        ".codex",
        ".aws",
        ".azure",
        ".docker",
        ".kube",
        ".gnupg",
    }
)
_CREDENTIAL_FILES = frozenset(
    {
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".git-credentials",
        "auth.json",
        "credentials",
        "credentials.json",
        "secrets",
        "secrets.json",
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "id_ed25519_sk",
        "access_token",
        "token",
        "token.json",
    }
)


class WorkspaceError(ValueError):
    """The active workspace cannot be safely snapshotted or reconciled."""


class TargetOccupied(WorkspaceError):
    """Something this session did not put there now sits at an output path — and it is not a file the
    snapshot could have carried (too large, a directory, a link). A conflict, not a reason to stop."""


def _safe_relative(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise WorkspaceError("workspace path must be normalized relative POSIX text")
    if value.startswith("/"):
        raise WorkspaceError("absolute workspace path refused")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise WorkspaceError("workspace path traversal or empty component refused")
    if any(any(ord(ch) < 32 or ord(ch) == 127 for ch in part) for part in parts):
        raise WorkspaceError("control characters in workspace path refused")
    return value


def valid_path(value: object) -> str:
    """Validate a workspace-relative output path before accepting guest bytes."""
    rel = _safe_relative(value)
    parts = [part.casefold() for part in rel.split("/")]
    if any(part in _REFUSED_DIRS for part in parts):
        raise WorkspaceError("git metadata path refused")
    if any(part in _EXCLUDED_DIRS or part == _STAGE_NAME for part in parts[:-1]):
        raise WorkspaceError("excluded host-state path refused")
    if (
        parts[-1] in _EXCLUDED_DIRS
        or parts[-1] in _REFUSED_DIRS
        or parts[-1] == _STAGE_NAME
    ):
        raise WorkspaceError("excluded host-state path refused")
    if any(_excluded_file(part) for part in parts):
        raise WorkspaceError("credential or host-state path refused")
    return rel


def _excluded_file(name: str) -> bool:
    lower = name.lower()
    return (
        lower in _CREDENTIAL_FILES
        or lower.startswith(".env")
        or lower.startswith("credentials.")
        or lower.endswith((".pem", ".p12", ".pfx", ".key"))
    )


def _same_file(a: os.stat_result, b: os.stat_result) -> bool:
    return (a.st_dev, a.st_ino, stat.S_IFMT(a.st_mode)) == (
        b.st_dev,
        b.st_ino,
        stat.S_IFMT(b.st_mode),
    )


def _file_version(st: os.stat_result) -> tuple[int, ...]:
    """Metadata that detects replacement, chmod, link, and in-place edit races."""
    return (
        st.st_dev,
        st.st_ino,
        stat.S_IMODE(st.st_mode),
        st.st_size,
        st.st_mtime_ns,
        st.st_ctime_ns,
        st.st_nlink,
    )


class WorkspaceSnapshot:
    """Snapshot one already-existing active workspace and reconcile explicit updates.

    `.files` maps safe POSIX-relative names to the exact initial bytes. `.manifest`
    maps those names to SHA-256 and size. `commit({path: bytes, ...})` updates or
    adds only the named files; it never deletes files. Existing-file updates are
    preserved in a fresh output directory, never replaced in place — and so is the
    session's version of any file the host changed or created meanwhile. `.withheld`
    names files that were in the folder and too large to bring into the session.
    """

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(os.path.abspath(os.fspath(path)))
        try:
            root_st = os.lstat(self.path)
        except OSError as exc:
            raise WorkspaceError("active workspace is unavailable") from exc
        if not stat.S_ISDIR(root_st.st_mode) or stat.S_ISLNK(root_st.st_mode):
            raise WorkspaceError("active workspace root must be a real directory")
        flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            self._root_fd = os.open(self.path, flags)
        except OSError as exc:
            raise WorkspaceError("could not open active workspace root safely") from exc
        self._closed = False
        try:
            files: dict[str, bytes] = {}
            file_versions: dict[str, tuple[int, ...]] = {}
            self._entry_count = 0
            # Files that exist in the folder and were NOT brought into the session, with the reason.
            self.withheld: dict[str, str] = {}
            self._walk(self._root_fd, "", files, file_versions)
            self.total_bytes = sum(map(len, files.values()))
            self.files = MappingProxyType(files)
            self._file_versions = MappingProxyType(file_versions)
            self.manifest = MappingProxyType(
                {
                    name: MappingProxyType(
                        {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
                    )
                    for name, data in files.items()
                }
            )
            self.initial_hashes = MappingProxyType(
                {name: item["sha256"] for name, item in self.manifest.items()}
            )
        except BaseException:
            self.close()
            raise

    def _walk(
        self,
        dir_fd: int,
        prefix: str,
        files: dict[str, bytes],
        file_versions: dict[str, tuple[int, ...]],
    ) -> None:
        try:
            names = os.listdir(dir_fd)
        except OSError as exc:
            raise WorkspaceError("could not enumerate active workspace") from exc
        for name in sorted(names):
            self._entry_count += 1
            if self._entry_count > MAX_WORKSPACE_ENTRIES:
                raise WorkspaceError("active workspace entry limit exceeded")
            rel = f"{prefix}/{name}" if prefix else name
            _safe_relative(rel)
            if name.casefold() in _REFUSED_DIRS:
                raise WorkspaceError(
                    "active workspace containing .git metadata is refused"
                )
            if name.casefold() in _EXCLUDED_DIRS:
                continue
            if name.casefold() == _STAGE_NAME:
                raise WorkspaceError("reserved export staging path already exists")
            if _excluded_file(name):
                continue
            try:
                before = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            except OSError as exc:
                raise WorkspaceError("workspace entry changed during snapshot") from exc
            if stat.S_ISLNK(before.st_mode):
                raise WorkspaceError(f"symlink refused in active workspace: {rel}")
            if stat.S_ISDIR(before.st_mode):
                flags = (
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                try:
                    child_fd = os.open(name, flags, dir_fd=dir_fd)
                except OSError as exc:
                    raise WorkspaceError(
                        f"workspace directory changed during snapshot: {rel}"
                    ) from exc
                try:
                    opened = os.fstat(child_fd)
                    if not _same_file(before, opened):
                        raise WorkspaceError(
                            f"workspace directory changed during snapshot: {rel}"
                        )
                    self._walk(child_fd, rel, files, file_versions)
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(before.st_mode):
                raise WorkspaceError(f"special file refused in active workspace: {rel}")
            if before.st_nlink != 1:
                raise WorkspaceError(
                    f"hard-linked file refused in active workspace: {rel}"
                )
            if before.st_size > MAX_FILE_BYTES:
                # Left on the host, by name. A matter folder is a professional's folder: a scanned PDF of
                # drawings is the ordinary case, and refusing the whole session over one is the wrong
                # answer to it. The agent has no tool that reads such a file anyway; what it loses is
                # the file's NAME in the folder listing. If it writes that name, commit() keeps both.
                self.withheld[rel] = "larger than the per-file limit"
                continue
            fd = self._open_file(dir_fd, name, before, rel)
            try:
                data = bytearray()
                while True:
                    block = os.read(
                        fd, min(1024 * 1024, MAX_FILE_BYTES + 1 - len(data))
                    )
                    if not block:
                        break
                    data.extend(block)
                    if len(data) > MAX_FILE_BYTES:
                        raise WorkspaceError(f"workspace file limit exceeded: {rel}")
                after = os.fstat(fd)
                if (
                    not _same_file(before, after)
                    or before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns
                    or len(data) != after.st_size
                ):
                    raise WorkspaceError(
                        f"workspace file changed during snapshot: {rel}"
                    )
            finally:
                os.close(fd)
            if sum(map(len, files.values())) + len(data) > MAX_WORKSPACE_BYTES:
                self.withheld[rel] = "the folder is over the session's size budget"
                continue
            files[rel] = bytes(data)
            file_versions[rel] = _file_version(after)

    @staticmethod
    def _open_file(dir_fd: int, name: str, before: os.stat_result, rel: str) -> int:
        flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(name, flags, dir_fd=dir_fd)
        except OSError as exc:
            raise WorkspaceError(
                f"workspace file changed during snapshot: {rel}"
            ) from exc
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or not _same_file(before, opened)
        ):
            os.close(fd)
            raise WorkspaceError(f"workspace file changed during snapshot: {rel}")
        return fd

    def _open_parent(
        self, rel: str, *, create: bool = False
    ) -> Optional[tuple[int, str]]:
        parts = rel.split("/")
        current = os.dup(self._root_fd)
        for component in parts[:-1]:
            try:
                before = os.stat(component, dir_fd=current, follow_symlinks=False)
            except FileNotFoundError:
                if not create:
                    os.close(current)
                    return None
                try:
                    os.mkdir(component, 0o700, dir_fd=current)
                except FileExistsError:
                    pass
                except OSError as exc:
                    os.close(current)
                    raise WorkspaceError(
                        "could not create export parent directory"
                    ) from exc
                try:
                    before = os.stat(component, dir_fd=current, follow_symlinks=False)
                except OSError as exc:
                    os.close(current)
                    raise WorkspaceError("export parent directory changed") from exc
            except OSError as exc:
                os.close(current)
                raise WorkspaceError(
                    "could not inspect export parent directory"
                ) from exc
            if not stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode):
                os.close(current)
                raise WorkspaceError(
                    "export path contains a non-directory or symlink ancestor"
                )
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                nxt = os.open(component, flags, dir_fd=current)
            except OSError as exc:
                os.close(current)
                raise WorkspaceError("export parent directory changed") from exc
            if not _same_file(before, os.fstat(nxt)):
                os.close(nxt)
                os.close(current)
                raise WorkspaceError("export parent directory changed")
            os.close(current)
            current = nxt
        return current, parts[-1]

    def _read_current(self, rel: str) -> Optional[tuple[bytes, tuple[int, ...]]]:
        parent = self._open_parent(rel)
        if parent is None:
            return None
        parent_fd, name = parent
        try:
            try:
                before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None
            except OSError as exc:
                raise WorkspaceError("could not inspect export target") from exc
            if (
                not stat.S_ISREG(before.st_mode)
                or stat.S_ISLNK(before.st_mode)
                or before.st_nlink != 1
                or before.st_size > MAX_FILE_BYTES
            ):
                raise TargetOccupied(
                    "export target is no longer a regular unlinked file"
                )
            fd = self._open_file(parent_fd, name, before, rel)
            try:
                out = bytearray()
                while True:
                    block = os.read(fd, min(1024 * 1024, MAX_FILE_BYTES + 1 - len(out)))
                    if not block:
                        break
                    out.extend(block)
                    if len(out) > MAX_FILE_BYTES:
                        raise WorkspaceError("export target exceeds file limit")
                after = os.fstat(fd)
                if (
                    not _same_file(before, after)
                    or before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns
                    or len(out) != after.st_size
                ):
                    raise WorkspaceError("export target changed while being checked")
                return bytes(out), _file_version(after)
            finally:
                os.close(fd)
        finally:
            os.close(parent_fd)

    def _validate_updates(self, updated: Mapping[str, bytes]) -> dict[str, bytes]:
        if not isinstance(updated, Mapping):
            raise WorkspaceError("updates must map relative paths to bytes")
        if len(updated) > MAX_WORKSPACE_ENTRIES:
            raise WorkspaceError("updated workspace entry limit exceeded")
        normalized: dict[str, bytes] = {}
        for raw_path, data in updated.items():
            rel = valid_path(raw_path)
            if not isinstance(data, bytes):
                raise WorkspaceError("updated file content must be bytes")
            if len(data) > MAX_FILE_BYTES:
                raise WorkspaceError("updated file exceeds per-file limit")
            normalized[rel] = data
        final_total = self.total_bytes
        final_count = len(self.files)
        for rel, data in normalized.items():
            previous = self.files.get(rel)
            if previous is None:
                final_count += 1
                final_total += len(data)
            else:
                final_total += len(data) - len(previous)
        if final_count > MAX_WORKSPACE_ENTRIES or final_total > MAX_WORKSPACE_BYTES:
            raise WorkspaceError("updated workspace exceeds snapshot limits")
        return normalized

    def _preflight(self, updated: Mapping[str, bytes]) -> dict[str, bytes]:
        """The strict form: any conflict raises. Used for the recheck just before files are placed."""
        writes, conflicts = self._classify(updated)
        if conflicts:
            raise WorkspaceError(
                "host workspace changed since snapshot: " + ", ".join(sorted(conflicts))
            )
        return writes

    def _classify(self, updated: Mapping[str, bytes]) -> tuple[dict[str, bytes], list[str]]:
        """(what can be placed as planned, what the host changed or created since the snapshot)."""
        writes: dict[str, bytes] = {}
        conflicts: list[str] = []
        for rel, data in updated.items():
            before = self.files.get(rel)
            if before == data:
                continue
            try:
                current_info = self._read_current(rel)
            except TargetOccupied:
                conflicts.append(rel)
                continue
            if before is None:
                if current_info is not None:
                    conflicts.append(rel)
                else:
                    writes[rel] = data
            elif (
                current_info is None
                or current_info[0] != before
                or current_info[1] != self._file_versions[rel]
            ):
                conflicts.append(rel)
            else:
                writes[rel] = data
        return writes, conflicts

    def commit(self, updated: Mapping[str, bytes]) -> tuple[str, ...]:
        """Exclusively add outputs; preserve updates separately without overwriting.

        There is no portable compare-and-swap replacement of host files. Existing
        updates therefore go to a fresh directory, keeping concurrent edits safe.
        Multi-file export is not an atomic transaction.
        """
        if self._closed:
            raise WorkspaceError("workspace capability is closed")
        normalized = self._validate_updates(updated)
        planned, conflicts = self._classify(normalized)
        # A conflict is a file the HOST changed, or created, while the session ran — the professional
        # edited the disclosure in the page, or the agent wrote a name that a file left on the host
        # already has. Aborting here used to discard every file the session wrote, to protect one. The
        # agent's version goes to the fresh output directory instead: nothing of the host's is touched
        # and nothing of the session's is lost.
        diverted = {rel: normalized[rel] for rel in conflicts}
        writes = {**planned, **diverted}
        if not writes:
            return ()
        preserved = {}
        if diverted or any(rel in self.files for rel in planned):
            output_dir = "vm-session-output-" + secrets.token_hex(16)
            os.mkdir(output_dir, 0o700, dir_fd=self._root_fd)
            preserved = {
                rel: output_dir + "/" + rel for rel in writes if rel in self.files or rel in diverted
            }
        try:
            os.mkdir(_STAGE_NAME, 0o700, dir_fd=self._root_fd)
        except FileExistsError as exc:
            raise WorkspaceError("reserved export staging path already exists") from exc
        except OSError as exc:
            raise WorkspaceError(
                "could not create private export staging directory"
            ) from exc
        stage_flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        stage_fd = os.open(_STAGE_NAME, stage_flags, dir_fd=self._root_fd)
        staged: dict[str, str] = {}
        committed: list[str] = []
        try:
            for index, (rel, data) in enumerate(sorted(writes.items())):
                stage_name = f"{index:04x}-{secrets.token_hex(4)}"
                fd = os.open(
                    stage_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=stage_fd,
                )
                try:
                    mode = self._file_versions[rel][2] if rel in self.files else 0o600
                    os.fchmod(fd, mode)
                    view = memoryview(data)
                    while view:
                        written = os.write(fd, view)
                        view = view[written:]
                    os.fsync(fd)
                finally:
                    os.close(fd)
                staged[rel] = stage_name

            # Recheck after staging and before modifying targets. Only what was planned to go in
            # place can newly conflict; the diverted files go to a directory created a moment ago.
            self._preflight(planned)
            for rel, data in sorted(writes.items()):
                destination = preserved.get(rel, rel)
                parent = self._open_parent(destination, create=True)
                if parent is None:
                    raise WorkspaceError("could not resolve export parent directory")
                parent_fd, name = parent
                stage_name = staged[rel]
                try:
                    # Exclusive creation also covers preserved existing-file updates.
                    os.link(
                        stage_name,
                        name,
                        src_dir_fd=stage_fd,
                        dst_dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
                    os.unlink(stage_name, dir_fd=stage_fd)
                    os.fsync(parent_fd)
                    committed.append(destination)
                except FileExistsError as exc:
                    raise WorkspaceError(
                        f"new export path appeared during commit: {rel}"
                    ) from exc
                except OSError as exc:
                    raise WorkspaceError(
                        f"could not commit workspace path: {rel}"
                    ) from exc
                finally:
                    os.close(parent_fd)
            os.fsync(self._root_fd)
            return tuple(committed)
        finally:
            for name in os.listdir(stage_fd):
                try:
                    os.unlink(name, dir_fd=stage_fd)
                except OSError:
                    pass
            os.close(stage_fd)
            try:
                os.rmdir(_STAGE_NAME, dir_fd=self._root_fd)
            except OSError:
                pass

    def close(self) -> None:
        if not getattr(self, "_closed", True):
            self._closed = True
            os.close(self._root_fd)

    def __enter__(self) -> "WorkspaceSnapshot":
        if self._closed:
            raise WorkspaceError("workspace capability is closed")
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass


__all__ = [
    "MAX_FILE_BYTES",
    "MAX_WORKSPACE_BYTES",
    "MAX_WORKSPACE_ENTRIES",
    "WorkspaceError",
    "WorkspaceSnapshot",
    "valid_path",
]
