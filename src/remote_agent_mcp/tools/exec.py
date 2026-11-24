from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from ..auth import require_tool_scope
from ..config import settings
from ..jobs import job_manager
from ..processes import spawn_command, terminate_process_tree
from ..security import (
    SandboxError,
    audit_log,
    redact_secrets,
    redacted_command_for_audit,
    resolve_safe_path,
    sanitized_env,
    truncate_head_tail,
    validate_command,
)

EXECUTE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)
READ_ONLY = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
KILL = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False
)


def _run_git(arguments: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "--no-pager", *arguments],
        cwd=cwd or settings.resolved_workspace,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=sanitized_env(),
        timeout=30,
        check=False,
    )


def _git_checked(arguments: list[str]) -> str:
    completed = _run_git(arguments)
    if completed.returncode != 0:
        raise RuntimeError(redact_secrets(completed.stderr or completed.stdout)[:2000])
    return redact_secrets(completed.stdout)


def register_exec_and_git_tools(mcp: FastMCP) -> None:
    @mcp.tool(annotations=EXECUTE)
    def run_command(
        command: str,
        cwd: str = ".",
        timeout_sec: int = settings.default_cmd_timeout,
        max_output_chars: int = settings.default_output_chars,
    ) -> dict[str, Any]:
        """Run a non-interactive shell command. OS isolation is required for untrusted callers."""
        require_tool_scope("run_command")
        try:
            validate_command(command)
        except SandboxError as exc:
            audit_log(
                "run_command",
                {"command": redacted_command_for_audit(command), "cwd": cwd},
                "denied",
                str(exc),
            )
            raise
        work_dir = resolve_safe_path(cwd, check_sensitive=False)
        if not work_dir.is_dir():
            raise ValueError(f"Working directory does not exist: {cwd}")
        timeout = max(1, min(timeout_sec, settings.max_cmd_timeout))
        process = spawn_command(
            command,
            work_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        timed_out = False
        try:
            output_bytes, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            terminate_process_tree(process, force=True)
            output_bytes, _ = process.communicate()
        output_limit_reached = len(output_bytes) > settings.max_command_output_bytes
        output_bytes = output_bytes[: settings.max_command_output_bytes]
        cleaned = redact_secrets(output_bytes.decode("utf-8", errors="replace"))
        output, truncated, _ = truncate_head_tail(cleaned, max(500, min(max_output_chars, 20000)))
        audit_log(
            "run_command",
            {"command": redacted_command_for_audit(command), "cwd": cwd},
            "timeout" if timed_out else "ok",
        )
        return {
            "exit_code": process.returncode,
            "timed_out": timed_out,
            "truncated": truncated,
            "output_limit_reached": output_limit_reached,
            "output": output,
        }

    @mcp.tool(annotations=EXECUTE)
    def start_bg_job(command: str, cwd: str = ".") -> dict[str, Any]:
        """Start a non-interactive long-running job; poll with the returned job_id."""
        require_tool_scope("start_bg_job")
        try:
            validate_command(command)
        except SandboxError as exc:
            audit_log(
                "start_bg_job",
                {"command": redacted_command_for_audit(command), "cwd": cwd},
                "denied",
                str(exc),
            )
            raise
        work_dir = resolve_safe_path(cwd, check_sensitive=False)
        if not work_dir.is_dir():
            raise ValueError(f"Working directory does not exist: {cwd}")
        result = job_manager.start(command, work_dir)
        audit_log(
            "start_bg_job",
            {
                "command": redacted_command_for_audit(command),
                "cwd": cwd,
                "job_id": result["job_id"],
            },
            "ok",
        )
        return result

    @mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    def poll_bg_job(job_id: str, offset_bytes: int = 0, max_bytes: int = 8192) -> dict[str, Any]:
        """Poll job status and incremental output. Use next_offset for the next request."""
        require_tool_scope("poll_bg_job")
        return job_manager.poll(job_id, offset_bytes, max_bytes)

    @mcp.tool(annotations=KILL)
    def kill_bg_job(job_id: str, signal_name: str = "SIGTERM") -> dict[str, Any]:
        """Terminate a background job and its child process tree."""
        require_tool_scope("kill_bg_job")
        result = job_manager.kill(job_id, signal_name)
        audit_log("kill_bg_job", {"job_id": job_id, "signal": signal_name}, "ok")
        return result

    @mcp.tool(annotations=READ_ONLY)
    def git_status_diff(include_diff: bool = True, max_diff_chars: int = 8000) -> dict[str, Any]:
        """Return branch/status and both diffs. Untracked files are listed, not dumped."""
        require_tool_scope("git_status_diff")
        status = _git_checked(["status", "--short", "--branch"])
        diff = ""
        staged_diff = ""
        truncated = False
        if include_diff:
            diff, tracked_truncated, _ = truncate_head_tail(
                _git_checked(["diff", "--no-ext-diff", "--"]),
                max(500, min(max_diff_chars, 20000)),
            )
            staged_diff, staged_truncated, _ = truncate_head_tail(
                _git_checked(["diff", "--cached", "--no-ext-diff", "--"]),
                max(500, min(max_diff_chars, 20000)),
            )
            truncated = tracked_truncated or staged_truncated
        audit_log("git_status_diff", {"include_diff": include_diff}, "ok")
        return {
            "status": status,
            "diff": diff,
            "staged_diff": staged_diff,
            "diff_truncated": truncated,
        }

    @mcp.tool(annotations=KILL)
    def git_restore(
        paths: list[str] | None = None,
        restore_all: bool = False,
        source_ref: str = "HEAD",
        confirm_destructive: bool = False,
    ) -> dict[str, Any]:
        """Discard tracked edits only. Untracked files are preserved. Disabled by default."""
        require_tool_scope("git_restore")
        if not settings.enable_git_restore:
            raise RuntimeError(
                "git_restore is disabled; set MCP_ENABLE_GIT_RESTORE=true explicitly"
            )
        if not confirm_destructive:
            raise ValueError("Set confirm_destructive=true after reviewing git_status_diff")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/@{}^~:-]{0,199}", source_ref):
            raise ValueError("Invalid source_ref")
        if not paths and not restore_all:
            raise ValueError("Provide paths or explicitly set restore_all=true")
        if paths and restore_all:
            raise ValueError("Choose paths or restore_all, not both")
        arguments = ["restore", "--worktree", f"--source={source_ref}"]
        restored_paths = ["."]
        if not restore_all:
            restored_paths = [
                resolve_safe_path(path, check_sensitive=False)
                .relative_to(settings.resolved_workspace)
                .as_posix()
                for path in paths or []
            ]
        arguments.extend(["--", *restored_paths])
        output = _git_checked(arguments)
        audit_log(
            "git_restore",
            {"paths": restored_paths, "restore_all": restore_all, "source_ref": source_ref},
            "ok",
        )
        return {"restored": True, "paths": restored_paths, "output": output or "OK"}
