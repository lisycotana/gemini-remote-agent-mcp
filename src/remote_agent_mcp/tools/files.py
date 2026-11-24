from __future__ import annotations

import contextlib
import difflib
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from ..auth import require_tool_scope
from ..circuit_breaker import circuit_breaker
from ..config import settings
from ..security import (
    SandboxError,
    audit_log,
    file_sha256,
    is_sensitive_relative,
    redact_secrets,
    resolve_safe_path,
)

IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
}
READ_ONLY = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
EDIT = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False
)
WRITE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False
)


def _relative_path(target: Path) -> str:
    return target.relative_to(settings.resolved_workspace).as_posix()


def _read_utf8_file(target: Path) -> str:
    if target.stat().st_size > settings.max_file_bytes:
        raise ValueError(f"File exceeds the {settings.max_file_bytes}-byte tool limit")
    raw = target.read_bytes()
    if b"\x00" in raw[:8192]:
        raise ValueError("Binary files cannot be edited with text tools")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Only UTF-8 text files are supported") from exc


def _atomic_write(target: Path, content: str) -> None:
    if target.is_symlink():
        raise SandboxError("Symlink targets are not allowed")
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.parent.resolve().is_relative_to(settings.resolved_workspace):
        raise SandboxError("The destination directory escapes the workspace")
    previous_mode = stat.S_IMODE(target.stat().st_mode) if target.exists() else None
    descriptor, temporary_name = tempfile.mkstemp(dir=target.parent, prefix=".mcp-write-")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as file_handle:
            file_handle.write(content)
            file_handle.flush()
            os.fsync(file_handle.fileno())
        if previous_mode is not None:
            os.chmod(temporary_name, previous_mode)
        os.replace(temporary_name, target)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary_name)
        raise


def _make_diff(path: str, original: str, updated: str) -> str:
    return redact_secrets(
        "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                updated.splitlines(keepends=True),
                fromfile=f"a/{path}",
                tofile=f"b/{path}",
                n=3,
            )
        )
    )


def _walk_entries(base: Path, max_depth: int, limit: int) -> tuple[list[str], bool]:
    root = settings.resolved_workspace
    entries: list[str] = []
    truncated = False

    def walk(directory: Path, depth: int) -> None:
        nonlocal truncated
        if depth > max_depth or truncated:
            return
        try:
            children = sorted(directory.iterdir(), key=lambda item: (not item.is_dir(), item.name))
        except OSError:
            return
        for child in children:
            if child.name in IGNORE_DIRS or child.is_symlink():
                continue
            resolved = child.resolve(strict=False)
            if not resolved.is_relative_to(root):
                continue
            relative = _relative_path(child)
            if is_sensitive_relative(relative):
                continue
            if len(entries) >= limit:
                truncated = True
                return
            is_directory = child.is_dir()
            entries.append(f"{relative}/" if is_directory else relative)
            if is_directory:
                walk(child, depth + 1)

    walk(base, 1)
    return entries, truncated


def register_file_tools(mcp: FastMCP) -> None:
    @mcp.tool(annotations=READ_ONLY)
    def list_directory(
        path: str = ".", max_depth: int = 2, max_entries: int = 300
    ) -> dict[str, Any]:
        """List directories recursively; omit ignored, sensitive, and symlinked entries."""
        require_tool_scope("list_directory")
        circuit_breaker.check("list_directory")
        target = resolve_safe_path(path, check_sensitive=False)
        if not target.is_dir():
            raise ValueError(f"Not a directory: {path}")
        entries, truncated = _walk_entries(
            target, max(1, min(max_depth, 4)), max(1, min(max_entries, 500))
        )
        audit_log("list_directory", {"path": path, "max_depth": max_depth}, "ok")
        return {"path": path, "entries": entries, "count": len(entries), "truncated": truncated}

    @mcp.tool(annotations=READ_ONLY)
    def find_files(pattern: str, path: str = ".", max_results: int = 100) -> dict[str, Any]:
        """Find files using a relative glob such as '**/*.py'; results stay inside the workspace."""
        require_tool_scope("find_files")
        circuit_breaker.check("find_files")
        if PurePosixPath(pattern).is_absolute() or ".." in PurePosixPath(pattern).parts:
            raise ValueError("The glob must be workspace-relative and cannot contain '..'")
        base = resolve_safe_path(path, check_sensitive=False)
        limit = max(1, min(max_results, 300))
        matches: list[str] = []
        for item in base.glob(pattern):
            if any(part in IGNORE_DIRS for part in item.parts) or item.is_symlink():
                continue
            resolved = item.resolve(strict=False)
            if not resolved.is_relative_to(settings.resolved_workspace) or not item.is_file():
                continue
            relative = _relative_path(item)
            if is_sensitive_relative(relative):
                continue
            matches.append(relative)
            if len(matches) >= limit:
                break
        audit_log("find_files", {"pattern": pattern, "path": path}, "ok")
        return {"matches": matches, "count": len(matches), "truncated": len(matches) >= limit}

    @mcp.tool(annotations=READ_ONLY)
    def grep_search(
        pattern: str,
        path: str = ".",
        file_glob: str | None = None,
        max_matches: int = 50,
    ) -> dict[str, Any]:
        """Search with ripgrep. Matches include workspace-relative paths and line numbers."""
        require_tool_scope("grep_search")
        circuit_breaker.check("grep_search")
        target = resolve_safe_path(path, check_sensitive=False)
        ripgrep = shutil.which("rg")
        if not ripgrep:
            raise RuntimeError("ripgrep (rg) is required for grep_search")
        limit = max(1, min(max_matches, 200))
        if file_glob and (
            "\x00" in file_glob
            or PurePosixPath(file_glob).is_absolute()
            or ".." in PurePosixPath(file_glob).parts
        ):
            raise ValueError("file_glob must be workspace-relative and cannot contain '..'")
        command = [
            ripgrep,
            "--line-number",
            "--no-heading",
            "--with-filename",
            "--no-follow",
            "--glob-case-insensitive",
            "--color",
            "never",
            "--max-count",
            str(limit),
            "--max-columns",
            "500",
            "--max-columns-preview",
            "--no-messages",
        ]
        if file_glob:
            command.extend(["--glob", file_glob])
        for directory in IGNORE_DIRS:
            command.extend(["--glob", f"!**/{directory}/**"])
        for denied in settings.denied_globs:
            command.extend(["--glob", f"!{denied}"])
        command.extend(["--", pattern, "."])
        completed = subprocess.run(
            command,
            cwd=target,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
        if completed.returncode not in {0, 1}:
            raise RuntimeError(redact_secrets(completed.stderr)[:1000])
        base_rel = _relative_path(target)
        filtered_lines: list[str] = []
        for line in completed.stdout.splitlines():
            matched_file = line.split(":", 1)[0].replace("\\", "/").lstrip("./")
            rel_file = f"{base_rel}/{matched_file}" if base_rel != "." else matched_file
            if is_sensitive_relative(rel_file):
                continue
            filtered_lines.append(line)
        matches = redact_secrets("\n".join(filtered_lines[:limit]))
        audit_log("grep_search", {"pattern": pattern, "path": path}, "ok")
        return {
            "matches": matches,
            "match_count": len(filtered_lines[:limit]),
            "truncated": len(filtered_lines) > limit,
        }

    @mcp.tool(annotations=READ_ONLY)
    def read_file(
        path: str,
        start_line: int = 1,
        end_line: int | None = None,
        tail_lines: int | None = None,
    ) -> dict[str, Any]:
        """Read UTF-8 lines (or tail_lines from EOF); pass returned sha256 to edit_file."""
        require_tool_scope("read_file")
        circuit_breaker.check("read_file")
        target = resolve_safe_path(path)
        if not target.is_file():
            raise FileNotFoundError(f"File not found: {path}")
        text = _read_utf8_file(target)
        lines = text.splitlines()
        if tail_lines is not None:
            count = max(1, min(tail_lines, settings.max_read_lines))
            start = max(1, len(lines) - count + 1)
            end = len(lines)
        else:
            start = max(1, start_line)
            requested_end = end_line if end_line is not None else start + 199
            end = min(len(lines), requested_end, start + settings.max_read_lines - 1)
        if start > len(lines) and lines:
            raise ValueError(f"start_line exceeds the {len(lines)}-line file")
        numbered = [f"{number:>6} | {lines[number - 1]}" for number in range(start, end + 1)]
        audit_log("read_file", {"path": path, "start_line": start, "end_line": end}, "ok")
        return {
            "path": path,
            "total_lines": len(lines),
            "range": [start, end],
            "truncated": end < len(lines),
            "sha256": file_sha256(target),
            "content": redact_secrets("\n".join(numbered)),
        }

    @mcp.tool(annotations=EDIT)
    def edit_file(
        path: str,
        old_string: str,
        new_string: str,
        expected_occurrences: int = 1,
        expected_sha256: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Replace exact text, optionally preview only. Existing files require expected_sha256."""
        require_tool_scope("edit_file")
        circuit_breaker.check(
            "edit_file",
            mutating=not dry_run,
            fingerprint={"path": path, "old": old_string, "new": new_string},
        )
        target = resolve_safe_path(path)
        if not target.is_file():
            raise FileNotFoundError(f"File not found: {path}")
        if not expected_sha256:
            raise ValueError("expected_sha256 is required; call read_file first")
        if expected_occurrences < 1:
            raise ValueError("expected_occurrences must be positive")
        original = _read_utf8_file(target)
        if file_sha256(target) != expected_sha256.lower():
            raise ValueError("The file changed since it was read; re-read before editing")
        occurrences = original.count(old_string)
        if occurrences != expected_occurrences:
            raise ValueError(
                f"old_string occurs {occurrences} times, expected {expected_occurrences}"
            )
        updated = original.replace(old_string, new_string, expected_occurrences)
        diff = _make_diff(path, original, updated)
        if not dry_run:
            _atomic_write(target, updated)
        audit_log("edit_file", {"path": path, "dry_run": dry_run}, "ok")
        return {
            "path": path,
            "applied": not dry_run,
            "sha256": file_sha256(target) if not dry_run else expected_sha256.lower(),
            "diff": diff,
        }

    @mcp.tool(annotations=WRITE)
    def write_file(
        path: str,
        content: str,
        overwrite: bool = False,
        expected_sha256: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Create a UTF-8 file or explicitly overwrite one with expected_sha256; returns a diff."""
        require_tool_scope("write_file")
        circuit_breaker.check(
            "write_file",
            mutating=not dry_run,
            fingerprint={"path": path, "len": len(content)},
        )
        target = resolve_safe_path(path)
        if target.exists() and not target.is_file():
            raise ValueError("The target is not a regular file")
        original = _read_utf8_file(target) if target.exists() else ""
        if target.exists() and not overwrite:
            raise FileExistsError("File exists; use edit_file or explicitly set overwrite=true")
        if target.exists() and (
            not expected_sha256 or file_sha256(target) != expected_sha256.lower()
        ):
            raise ValueError("Overwriting requires the current expected_sha256 from read_file")
        diff = _make_diff(path, original, content)
        if not dry_run:
            _atomic_write(target, content)
        audit_log(
            "write_file",
            {"path": path, "overwrite": overwrite, "bytes": len(content.encode("utf-8"))},
            "ok",
        )
        return {
            "path": path,
            "applied": not dry_run,
            "written_bytes": len(content.encode("utf-8")),
            "sha256": file_sha256(target) if not dry_run else None,
            "diff": diff,
        }
