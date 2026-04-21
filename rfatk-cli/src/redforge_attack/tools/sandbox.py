"""Scope-bounded tool implementations.

Why this exists
---------------
Specialist agents receive `read_file`, `glob`, `grep`, and optionally
`run_bash` as tools. Agents are instructed by their prompt to stay inside
`target/intake/`, but prompt-level instructions aren't a security boundary —
code-level containment is. This module is that boundary. Every tool resolves
every path against `target/intake/` and REJECTS any path that escapes, with
the rejection returned to the model as a `ToolResult(is_error=True, ...)` so
the model self-corrects instead of the agent crashing.

Containment strategy
--------------------
- Reject paths with null bytes, absolute paths, paths containing `..` that
  walk out of `intake/`, and symlinks pointing outside `intake/`.
- Use `Path.resolve(strict=True)` for final canonicalization, then
  `Path.is_relative_to(intake_root.resolve())` as the containment assertion.
- Treat all errors (ENOENT, permission denied, oversize, binary) as
  tool-level errors (tool_result with is_error=true) — never exceptions
  leaking to the agent loop.

run_bash notes
--------------
- Disabled by default; enabled only when `ToolContext(allow_shell=True)`.
- Executes with `cwd=target_dir` (NOT intake/ — bash may need to read its
  own scripts from `evidence/`), restricted PATH, timeout, output byte cap.
- The operator is explicitly warned in the CLI help: "only on disposable VMs."
"""

from __future__ import annotations

import fnmatch
import json
import os
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass

MAX_FILE_BYTES = 2 * 1024 * 1024           # 2 MiB per file
MAX_GLOB_RESULTS = 500
MAX_GREP_MATCHES = 1000
MAX_GREP_MATCHES_PER_FILE = 100
SHELL_TIMEOUT_SECONDS = 30                 # overridable via ToolContext
SHELL_MAX_OUTPUT_BYTES = 64 * 1024
SHELL_PATH = "/usr/bin:/bin"
SHELL_HOME = "/tmp/redforge-home"


@dataclass(frozen=True)
class ToolContext:
    """Per-agent container for sandbox parameters.

    The orchestrator creates one ToolContext per specialist agent and passes
    it to dispatch.dispatch() alongside each ToolCall.
    """
    target_dir: pathlib.Path        # .../targets/<slug>-<ts>/
    intake_dir: pathlib.Path        # .../targets/<slug>-<ts>/intake/
    agent_id: str = ""              # required for submit_finding / write_notes
    allow_shell: bool = False
    shell_timeout_seconds: int = SHELL_TIMEOUT_SECONDS
    shell_max_output_bytes: int = SHELL_MAX_OUTPUT_BYTES


class SandboxViolation(Exception):
    """Raised when a path escapes intake/. Caught by dispatch and turned into a tool_result error."""


# -----------------------------------------------------------------------------
# Path containment (the single critical safety piece)
# -----------------------------------------------------------------------------


def _resolve_inside_intake(ctx: ToolContext, user_path: str) -> pathlib.Path:
    """Resolve `user_path` inside `ctx.intake_dir`, rejecting any escape.

    Check order is security-critical:
      1. NUL byte check — reject early.
      2. Absolute-path check — catches both POSIX `/etc/...` and Windows `C:/...`
         regardless of the current platform (agents may emit either shape).
      3. Lexical containment check — `resolve(strict=False)` canonicalizes
         `..` segments without hitting the filesystem. If the lexical target
         is outside intake_dir, raise SandboxViolation immediately — we do
         NOT want to leak file-existence info by letting FileNotFoundError
         bubble up differently for in-scope vs out-of-scope paths.
      4. Existence check — `resolve(strict=True)` raises FileNotFoundError.
      5. Post-strict containment re-check — belt-and-suspenders against any
         symlink resolution that only materializes under strict mode.
    """
    if "\x00" in user_path:
        raise SandboxViolation("path contains NUL byte")

    # (2) Absolute-path detection, both POSIX and Windows flavors.
    normalized = user_path.replace("\\", "/")
    posix_candidate = pathlib.PurePosixPath(normalized)
    windows_candidate = pathlib.PureWindowsPath(user_path)
    if posix_candidate.is_absolute() or windows_candidate.is_absolute():
        raise SandboxViolation(f"absolute paths are not allowed: {user_path!r}")

    intake_root = ctx.intake_dir.resolve()
    joined = ctx.intake_dir / user_path

    # (3) Lexical containment — resolve .. without requiring existence.
    lexical = joined.resolve(strict=False)
    if not _is_relative_to(lexical, intake_root):
        raise SandboxViolation(
            f"path escapes intake/ (resolves to {lexical}, outside {intake_root})"
        )

    # (4) Existence check. Propagates FileNotFoundError for legit in-scope
    # misses (caller handles that).
    resolved = joined.resolve(strict=True)

    # (5) Post-strict containment — a symlink in intake/ pointing outside
    # would be caught here (strict resolve follows symlinks).
    if not _is_relative_to(resolved, intake_root):
        raise SandboxViolation(
            f"path escapes intake/ via symlink (strict-resolved to {resolved})"
        )
    return resolved


def _is_relative_to(child: pathlib.Path, parent: pathlib.Path) -> bool:
    """Python 3.9+ backport of `Path.is_relative_to()` for belt-and-suspenders."""
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _validate_glob_pattern(pattern: str) -> None:
    if "\x00" in pattern:
        raise SandboxViolation("pattern contains NUL byte")
    if pattern.startswith("/") or pattern.startswith("\\"):
        raise SandboxViolation(f"absolute glob patterns are not allowed: {pattern!r}")
    # A pattern like '../../**' walks out before glob resolution happens.
    # We block any pattern with '..' as a path component.
    parts = pattern.replace("\\", "/").split("/")
    if ".." in parts:
        raise SandboxViolation(f"'..' is not allowed in glob patterns: {pattern!r}")


# -----------------------------------------------------------------------------
# Tool impls
# -----------------------------------------------------------------------------


def read_file(ctx: ToolContext, path: str) -> str:
    """Read a UTF-8 text file from intake/. Returns file content as string."""
    resolved = _resolve_inside_intake(ctx, path)
    if resolved.is_dir():
        raise SandboxViolation(f"path is a directory, not a file: {path!r}")
    size = resolved.stat().st_size
    if size > MAX_FILE_BYTES:
        raise SandboxViolation(
            f"file is {size:,} bytes, exceeds {MAX_FILE_BYTES:,} byte cap: {path!r}"
        )
    # Binary sniff — reject if first 8 KiB contains a NUL byte.
    with resolved.open("rb") as fh:
        head = fh.read(8192)
    if b"\x00" in head:
        raise SandboxViolation(f"file appears to be binary (NUL in first 8 KiB): {path!r}")
    return resolved.read_text(encoding="utf-8", errors="replace")


def glob(ctx: ToolContext, pattern: str) -> list[str]:
    """List intake/-relative paths matching `pattern`. Capped at MAX_GLOB_RESULTS."""
    _validate_glob_pattern(pattern)
    intake_root = ctx.intake_dir.resolve()
    results: list[str] = []
    for p in intake_root.glob(pattern):
        try:
            resolved = p.resolve(strict=True)
        except FileNotFoundError:
            continue
        if not _is_relative_to(resolved, intake_root):
            # Defense-in-depth: skip anything that resolves outside.
            continue
        rel = resolved.relative_to(intake_root)
        results.append(str(rel).replace("\\", "/"))
        if len(results) >= MAX_GLOB_RESULTS:
            break
    results.sort()
    return results


def grep(
    ctx: ToolContext,
    pattern: str,
    path_glob: str = "**/*",
    case_insensitive: bool = False,
) -> list[str]:
    """Grep across intake/. Returns list of 'path:line:match' strings."""
    _validate_glob_pattern(path_glob)
    flags = re.IGNORECASE if case_insensitive else 0
    try:
        regex = re.compile(pattern, flags)
    except re.error as e:
        raise SandboxViolation(f"invalid regex: {e}") from e

    intake_root = ctx.intake_dir.resolve()
    out: list[str] = []
    total = 0
    for p in sorted(intake_root.glob(path_glob)):
        if total >= MAX_GREP_MATCHES:
            break
        try:
            resolved = p.resolve(strict=True)
        except FileNotFoundError:
            continue
        if not _is_relative_to(resolved, intake_root):
            continue
        if resolved.is_dir():
            continue
        try:
            if resolved.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        # Skip binary files.
        try:
            with resolved.open("rb") as fh:
                if b"\x00" in fh.read(8192):
                    continue
        except OSError:
            continue
        rel = resolved.relative_to(intake_root)
        try:
            text = resolved.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        per_file = 0
        for i, line in enumerate(text.splitlines(), start=1):
            if regex.search(line):
                out.append(f"{str(rel).replace(chr(92), '/')}:{i}:{line.rstrip()}")
                per_file += 1
                total += 1
                if per_file >= MAX_GREP_MATCHES_PER_FILE:
                    break
                if total >= MAX_GREP_MATCHES:
                    break
    return out


def run_bash(ctx: ToolContext, cmd: str) -> str:
    """Run `bash -c <cmd>` with restricted PATH, cwd=target_dir, timeout."""
    if not ctx.allow_shell:
        raise SandboxViolation(
            "run_bash is disabled. Re-run the trial with --allow-shell "
            "(and only on a disposable VM)."
        )
    if "\x00" in cmd:
        raise SandboxViolation("command contains NUL byte")

    # Windows doesn't have /bin/bash. Default to WSL if available, else reject.
    if sys.platform.startswith("win"):
        bash_exe = _find_bash_on_windows()
        if bash_exe is None:
            raise SandboxViolation(
                "run_bash on Windows requires WSL (bash.exe) on PATH. "
                "Install WSL or run the trial on Linux/macOS."
            )
        argv: list[str] = [bash_exe, "-c", cmd]
    else:
        argv = ["/bin/bash", "-c", cmd]

    try:
        proc = subprocess.run(
            argv,
            cwd=str(ctx.target_dir.resolve()),
            env={"PATH": SHELL_PATH, "HOME": SHELL_HOME, "LANG": "C.UTF-8"},
            capture_output=True,
            timeout=ctx.shell_timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return (
            f"[run_bash] TIMEOUT after {ctx.shell_timeout_seconds}s. "
            "Command exceeded the per-call limit."
        )
    except FileNotFoundError as e:
        raise SandboxViolation(f"could not invoke bash: {e}") from e

    stdout = proc.stdout.decode("utf-8", errors="replace")
    stderr = proc.stderr.decode("utf-8", errors="replace")
    combined = f"[exit {proc.returncode}]\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    if len(combined) > ctx.shell_max_output_bytes:
        combined = combined[: ctx.shell_max_output_bytes] + f"\n[truncated to {ctx.shell_max_output_bytes} bytes]"
    return combined


# -----------------------------------------------------------------------------
# Output tools — write findings / notes to the agent's own dir (NOT intake/).
# -----------------------------------------------------------------------------


def _agent_dir(ctx: ToolContext) -> pathlib.Path:
    if not ctx.agent_id:
        raise SandboxViolation(
            "internal: ToolContext has no agent_id — cannot route output tool"
        )
    p = ctx.target_dir.resolve() / "agents" / ctx.agent_id
    # Sanity — confirm the resolved agent dir is under target_dir.
    if not _is_relative_to(p, ctx.target_dir.resolve()):
        raise SandboxViolation(f"agent dir escapes target_dir: {p}")
    p.mkdir(parents=True, exist_ok=True)
    return p


def submit_finding(ctx: ToolContext, finding: dict) -> str:
    """Append one finding object to `agents/<agent_id>/findings.json`."""
    if not isinstance(finding, dict):
        raise TypeError(f"finding must be an object, got {type(finding).__name__}")
    path = _agent_dir(ctx) / "findings.json"
    existing: list = []
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            existing = []
        if not isinstance(existing, list):
            existing = []
    existing.append(finding)
    path.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")
    fid = finding.get("id", "?")
    return f"saved finding {fid!r}. total findings so far: {len(existing)}"


def write_notes(ctx: ToolContext, content: str, *, append: bool = True) -> str:
    """Write (or append to) `agents/<agent_id>/notes.md`."""
    if not isinstance(content, str):
        raise TypeError(f"content must be a string, got {type(content).__name__}")
    path = _agent_dir(ctx) / "notes.md"
    mode = "a" if append and path.exists() else "w"
    with path.open(mode, encoding="utf-8") as fh:
        if mode == "a":
            fh.write("\n")
        fh.write(content)
    return f"wrote {len(content)} chars to notes.md (mode={mode})"


def _find_bash_on_windows() -> str | None:
    """Locate a bash.exe on Windows (WSL preferred)."""
    for candidate in ("bash.exe", "C:/Windows/System32/bash.exe", "C:/Program Files/Git/bin/bash.exe"):
        expanded = os.path.expandvars(candidate)
        if os.path.isfile(expanded):
            return expanded
    # PATH lookup
    for dirpath in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(dirpath, "bash.exe")
        if os.path.isfile(candidate):
            return candidate
    return None
