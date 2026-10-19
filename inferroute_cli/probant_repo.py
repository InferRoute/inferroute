"""A source-code repository as an intake source: one commit, staged as one document the reading session can quote.

The reading itself is probant_intake's, unchanged: a sealed session with no search tools, drafts kept only when
their quote is verbatim in the staged text, a host-only archive copy, human review of disclosure and date. What
this module adds is everything that is specific to code, and all of it runs on this computer:

* **One commit, tracked files only.** Content comes from `git show <commit>:<path>`, never the working tree, so
  the staged text is exactly what that commit holds and untracked or ignored files can never be included.
  History is read only for DATES (below), never for content: an old commit can hold a secret that was removed.
* **What is left out, and why, is listed.** A deny-list (keys, credential files, environment files, vendored
  dependencies, lock files, build output, binaries, very large files) and a secret scan. A file with a secret
  is left out whole, and the listing names the rule, never the secret.
* **The person approves the file list** before anything is staged (`anteriora intake --repo`).
* **Dates come from git on this computer, never from the model.** For a draft's quoted lines: when the file
  first appeared at its path, and the range of dates on which those lines took their present form (`git
  blame`). Commit dates are written by whoever made the commit and can be set to anything, so these are shown
  as what the repository records, not as proof of when anything was invented.
* **Public repositories.** A repository with a remote may be public; if it is, its first push was a public
  disclosure. Whether it is public is not checked over the network (that would tell the host which repository
  is being read); the person is told what to check.
"""
from __future__ import annotations

import fnmatch
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import probant as S

MAX_FILE_BYTES = 600_000      # a large hand-written module is often the heart of the repo; whole-repo size is capped by intake
HEADER = "REPOSITORY SNAPSHOT"
FILE_MARK = "===== FILE "

# Matched against the path's basename (and, for directory rules, against every path component).
DENY_DIRS = {"node_modules", "vendor", "third_party", "third-party", "dist", "build", "out", "target",
             ".venv", "venv", "env", "__pycache__", ".git", ".next", ".nuxt", "coverage", "Pods",
             "DerivedData", ".gradle", ".idea", ".vscode", "site-packages", "bower_components"}
DENY_NAMES = [
    (".env", "environment file"), (".env.*", "environment file"), ("*.env", "environment file"),
    ("*.pem", "key or certificate"), ("*.key", "key or certificate"), ("*.p12", "key or certificate"),
    ("*.pfx", "key or certificate"), ("*.jks", "key or certificate"), ("*.keystore", "key or certificate"),
    ("*.crt", "key or certificate"), ("*.der", "key or certificate"), ("*.ovpn", "key or certificate"),
    ("id_rsa*", "SSH key"), ("id_ed25519*", "SSH key"), ("id_ecdsa*", "SSH key"), ("*.ppk", "SSH key"),
    ("credentials", "credential file"), ("credentials.*", "credential file"), ("*credentials*.json", "credential file"),
    ("secrets.*", "credential file"), ("*secret*.json", "credential file"), ("*.tfvars", "credential file"),
    (".npmrc", "credential file"), (".pypirc", "credential file"), (".netrc", "credential file"),
    (".htpasswd", "credential file"), ("service-account*.json", "credential file"),
    ("*.lock", "lock file"), ("package-lock.json", "lock file"), ("pnpm-lock.yaml", "lock file"),
    ("yarn.lock", "lock file"), ("Cargo.lock", "lock file"), ("poetry.lock", "lock file"), ("go.sum", "lock file"),
    ("*.min.js", "minified code"), ("*.min.css", "minified code"), ("*.map", "minified code"),
]
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".icns", ".bmp", ".tiff", ".psd", ".pdf",
              ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".whl", ".egg",
              ".so", ".dylib", ".dll", ".exe", ".bin", ".o", ".a", ".class", ".pyc", ".wasm",
              ".mp3", ".mp4", ".mov", ".wav", ".ogg", ".webm", ".ttf", ".otf", ".woff", ".woff2",
              ".sqlite", ".db", ".parquet", ".npy", ".npz", ".pt", ".onnx", ".safetensors", ".ckpt", ".h5"}

# Each is a shape a real credential has. A file with any match is left out entirely.
SECRET_PATTERNS = [
    ("private key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("API key", re.compile(r"\bsk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9_-]{20,}\b")),
    ("Stripe key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("JSON web token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("connection string with password", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@'\"]+:[^\s@'\"]{3,}@[^\s'\"]+")),
    ("assigned secret", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|passw(?:or)?d|auth)[A-Za-z0-9_]*\s*[:=]\s*['\"][A-Za-z0-9/+_=-]{16,}['\"]")),
]


# A repository's own config can make git run programs (core.fsmonitor, a pager, a diff driver). None of the
# commands here should need any of that, so each runs with them switched off.
GIT_SAFE = ["-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat",
            "-c", "diff.external=", "-c", "blame.ignoreRevsFile=", "--no-pager"]


def _git(repo: Path, *args: str, text: bool = True) -> Any:
    r = subprocess.run(["git", *GIT_SAFE, "-C", str(repo), *args], capture_output=True, text=text,
                       env={**__import__("os").environ, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"})
    if r.returncode != 0:
        err = (r.stderr if text else r.stderr.decode(errors="replace")).strip()
        raise S.ProbantError(f"git {args[0]} failed: {err[-300:] or 'no message'}")
    return r.stdout


def repo_root(path: str) -> Path:
    p = Path(path).expanduser().resolve()
    if not p.is_dir():
        raise S.ProbantError(f"{p} is not a folder")
    try:
        top = _git(p, "rev-parse", "--show-toplevel").strip()
    except S.ProbantError:
        raise S.ProbantError(f"{p} is not inside a git repository")
    return Path(top)


def deny_reason(path: str) -> Optional[str]:
    """Why a tracked path is left out by name alone, or None. Content checks come later."""
    parts = path.split("/")
    for part in parts[:-1]:
        if part in DENY_DIRS:
            return "dependency or build folder"
    name = parts[-1]
    for pattern, why in DENY_NAMES:
        if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(name.lower(), pattern):
            return why
    if Path(name).suffix.lower() in BINARY_EXT:
        return "binary file"
    return None


def secret_kind(text: str) -> Optional[str]:
    for kind, pattern in SECRET_PATTERNS:
        if pattern.search(text):
            return kind
    return None


def _remotes(repo: Path) -> List[str]:
    out = []
    for line in _git(repo, "remote", "-v").splitlines():
        bits = line.split()
        if len(bits) >= 2:
            # Never keep credentials someone embedded in a remote URL.
            url = re.sub(r"://[^@/]+@", "://", bits[1])
            if url not in out:
                out.append(url)
    return out


def snapshot(path: str, ref: str = "HEAD", only: Optional[List[str]] = None) -> Tuple[str, Dict[str, Any]]:
    """The commit as one text, and what was taken and left out. Stages nothing.

    `only` limits the reading to some folders or files (paths relative to the repository root), for a
    repository larger than one reading holds."""
    prefixes = [p.strip("/") for p in (only or []) if p.strip("/")]
    repo = repo_root(path)
    commit = _git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}").strip()
    tree = _git(repo, "rev-parse", f"{commit}^{{tree}}").strip()
    listing = _git(repo, "ls-tree", "-r", "-l", "-z", commit)
    included: List[Dict[str, Any]] = []
    excluded: List[Dict[str, str]] = []
    pieces: List[str] = []
    first = _git(repo, "log", "--reverse", "--format=%aI", commit).splitlines()
    remotes = _remotes(repo)
    head = (f"{HEADER}\nRepository: {repo.name}\nCommit: {commit}\nTree: {tree}\n"
            f"First commit recorded: {first[0] if first else 'unknown'}\n\n")
    pieces.append(head)
    offset = len(head)
    for entry in listing.split("\0"):
        if not entry:
            continue
        meta, _, fpath = entry.partition("\t")
        mode, kind, obj, size = meta.split()
        if kind != "blob" or mode == "120000":           # submodules and symlinks: nothing to read here
            continue
        if prefixes and not any(fpath == p or fpath.startswith(p + "/") for p in prefixes):
            continue
        why = deny_reason(fpath)
        if why is None and size != "-" and int(size) > MAX_FILE_BYTES:
            why = "larger than 600 kB"
        if why:
            excluded.append({"path": fpath, "reason": why})
            continue
        raw = _git(repo, "cat-file", "blob", obj, text=False)
        if b"\0" in raw[:8192]:
            excluded.append({"path": fpath, "reason": "binary file"})
            continue
        body = raw.decode("utf-8", errors="replace").replace("\r\n", "\n")
        found = secret_kind(body)
        if found:
            excluded.append({"path": fpath, "reason": f"contains what looks like a {found}"})
            continue
        if not body.strip():
            continue
        if not body.endswith("\n"):
            body += "\n"
        mark = f"{FILE_MARK}{fpath} =====\n"
        start = offset + len(mark)
        pieces.append(mark + body + "\n")
        included.append({"path": fpath, "start": start, "end": start + len(body), "chars": len(body)})
        offset += len(mark) + len(body) + 1
    text = "".join(pieces)
    info = {"kind": "repo", "repo_path": str(repo), "repo_name": repo.name, "commit": commit, "tree": tree,
            "first_commit": first[0] if first else "", "remotes": remotes,
            "files": included, "excluded": excluded, "only": prefixes}
    return text, info


def describe(info: Dict[str, Any], text: str) -> List[str]:
    """What the person approves: plain lines, no file contents."""
    lines = [f"{info['repo_name']} at commit {info['commit'][:12]}: {len(info['files'])} file(s) to read, "
             f"{len(text):,} characters."]
    if info.get("only"):
        lines.append(f"Only: {', '.join(info['only'])}")
    from .probant_intake import MAX_CHARS
    if len(text) > MAX_CHARS:
        lines.append(f"That is more than one reading holds ({MAX_CHARS:,} characters). Choose folders with --only.")
    by_reason: Dict[str, List[str]] = {}
    for row in info["excluded"]:
        by_reason.setdefault(row["reason"], []).append(row["path"])
    if by_reason:
        lines.append(f"Left out: {len(info['excluded'])} file(s).")
        for reason, paths in sorted(by_reason.items(), key=lambda kv: -len(kv[1])):
            shown = ", ".join(paths[:4]) + (f" and {len(paths) - 4} more" if len(paths) > 4 else "")
            lines.append(f"  {reason}: {shown}")
    lines.extend(public_notice(info))
    return lines


def public_notice(info: Dict[str, Any]) -> List[str]:
    if not info.get("remotes"):
        return ["No remote is configured, so nothing suggests this code was published."]
    return [f"This repository has a remote ({', '.join(info['remotes'][:2])}).",
            "If it is public, its first push was a public disclosure of what it contained. Public disclosure "
            "can count against novelty: the US allows one year after it, Europe essentially no time. "
            f"The first commit is dated {info.get('first_commit') or 'unknown'}; check when the repository "
            "was first made public."]


def file_at(info: Dict[str, Any], position: int) -> Optional[Dict[str, Any]]:
    for row in info.get("files") or []:
        if row["start"] <= position < row["end"]:
            return row
    return None


def quote_dates(info: Dict[str, Any], body: str, start: int, end: int) -> Optional[Dict[str, Any]]:
    """Where a quote sits in the repository, and what git records about the dates of those lines.

    `start`/`end` are offsets in the staged text. A quote that crosses a file boundary is placed in the file it
    starts in and clipped there. Nothing here is the model's: it is computed on this computer from the commit.
    """
    row = file_at(info, start)
    if row is None:
        return None
    end = min(end, row["end"])
    first_line = body.count("\n", row["start"], start) + 1
    last_line = first_line + body.count("\n", start, max(start, end - 1))
    repo, commit, fpath = Path(info["repo_path"]), info["commit"], row["path"]
    out: Dict[str, Any] = {"file": fpath, "lines": [first_line, last_line], "commit": commit}
    try:
        added = _git(repo, "log", "--diff-filter=A", "--format=%aI", commit, "--", fpath).splitlines()
        out["file_added"] = added[-1] if added else ""
        blame = _git(repo, "blame", "--porcelain", "-L", f"{first_line},{last_line}", commit, "--", fpath)
        times = sorted({int(line.split()[1]) for line in blame.splitlines() if line.startswith("author-time ")})
        if times:
            import datetime as dt
            iso = lambda t: dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%d")
            out["lines_dated"] = [iso(times[0]), iso(times[-1])]
    except S.ProbantError:
        out["dates_unavailable"] = True          # a shallow clone or a rewritten history: say so, never guess
    return out


def date_note(where: Dict[str, Any]) -> str:
    """The disclosure's line about dates: what git records, and what that does not prove."""
    bits = [f"{where['file']}, lines {where['lines'][0]}–{where['lines'][1]}, commit {where['commit'][:12]}."]
    if where.get("dates_unavailable"):
        bits.append("This repository's history could not be read for dates (a shallow clone?).")
    else:
        if where.get("file_added"):
            bits.append(f"The repository records this file as added on {where['file_added'][:10]}.")
        if where.get("lines_dated"):
            a, b = where["lines_dated"]
            bits.append(f"These lines took their present form on {a}" + (f" to {b}." if b != a else "."))
    bits.append("Commit dates are whatever the committer's computer said; they are not proof of an invention date.")
    return " ".join(bits)
