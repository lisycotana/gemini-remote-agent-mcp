from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shlex
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .auth_context import current_user_sub
from .config import settings


class SandboxError(ValueError):
    pass


_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), "[REDACTED_GOOGLE_KEY]"),
    (re.compile(r"\bAKIA[A-Z0-9]{16}\b"), "[REDACTED_AWS_ACCESS_KEY]"),
    (
        re.compile(
            r"(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key)"
            r"(\s*[:=]\s*)(['\"]?)([^\s'\"`,;]{4,})\3"
        ),
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]",
    ),
    (
        re.compile(r"(https?://)([^:\s/@]+):([^@\s/]+)@"),
        r"\1[REDACTED_USER]:[REDACTED_PASS]@",
    ),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*", re.IGNORECASE), "Bearer [REDACTED]"),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "[REDACTED_JWT]",
    ),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED_SLACK_TOKEN]"),
    (re.compile(r"\b(?:npm|pypi)-[A-Za-z0-9_-]{16,}\b"), "[REDACTED_PKG_TOKEN]"),
)


_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)


def _is_reparse_or_symlink(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(os.path, "isjunction", None)
    if is_junction is not None:
        try:
            if is_junction(path):
                return True
        except OSError:
            return True
    return False


def is_sensitive_relative(relative: str) -> bool:
    rel_lower = relative.lower()
    name_lower = PurePosixPath(rel_lower).name
    for pattern in settings.denied_globs:
        pat_lower = pattern.lower()
        if fnmatch.fnmatchcase(rel_lower, pat_lower) or fnmatch.fnmatchcase(name_lower, pat_lower):
            return True
    return False


def resolve_safe_path(rel_path: str, *, check_sensitive: bool = True) -> Path:
    if not rel_path or not rel_path.strip():
        rel_path = "."
    if "\x00" in rel_path or any(ord(ch) < 32 for ch in rel_path):
        raise SandboxError("Paths cannot contain NUL or control characters")
    if ":" in rel_path:
        raise SandboxError("Drive letters and alternate data streams are not allowed")

    raw = PureWindowsPath(rel_path)
    posix = PurePosixPath(rel_path)
    if raw.is_absolute() or raw.drive or posix.is_absolute():
        raise SandboxError("Use a workspace-relative path, not an absolute path")
    if any(part == ".." for part in raw.parts) or any(part == ".." for part in posix.parts):
        raise SandboxError("Parent-directory traversal is not allowed")

    for part in Path(rel_path).parts:
        if part in {"", "."}:
            continue
        if part.rstrip(" .") != part:
            raise SandboxError("Trailing spaces or dots in path segments are not allowed")
        stem = part.split(".", 1)[0].upper()
        if stem in _WINDOWS_RESERVED_NAMES:
            raise SandboxError(f"Reserved device name is not allowed: {part}")

    root = settings.resolved_workspace
    current = root
    for part in Path(rel_path).parts:
        if part in {"", "."}:
            continue
        current = current / part
        if (current.exists() or current.is_symlink()) and _is_reparse_or_symlink(current):
            raise SandboxError("Symlinks and directory junctions are not allowed")

    target = (root / Path(rel_path)).resolve(strict=False)
    if not target.is_relative_to(root):
        raise SandboxError("The resolved path escapes the workspace")

    if check_sensitive:
        relative = target.relative_to(root).as_posix()
        if is_sensitive_relative(relative):
            raise SandboxError(f"Access to sensitive file is denied: {relative}")
    return target


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def redact_secrets(text: str) -> str:
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def truncate_head_tail(text: str, max_chars: int) -> tuple[str, bool, int]:
    if len(text) <= max_chars:
        return text, False, 0
    marker_budget = 100
    content_budget = max(1, max_chars - marker_budget)
    head_length = content_budget // 5
    tail_length = content_budget - head_length
    omitted = len(text) - head_length - tail_length
    marker = f"\n\n... [omitted {omitted} characters] ...\n\n"
    return f"{text[:head_length]}{marker}{text[-tail_length:]}", True, omitted


def redacted_command_for_audit(command: str, platform: str = os.name) -> str:
    try:
        tokens = shlex.split(command, posix=platform != "nt")
    except ValueError:
        return redact_secrets(command)[:2000]
    sensitive = ("token", "secret", "password", "passwd", "api_key", "apikey", "authorization")
    redacted_tokens = []
    redact_next = False
    for token in tokens:
        lowered = token.lower()
        if redact_next:
            redacted_tokens.append("[REDACTED]")
            redact_next = False
        elif any(key in lowered for key in sensitive) and "=" in token:
            redacted_tokens.append(f"{token.split('=', 1)[0]}=[REDACTED]")
        else:
            redacted_tokens.append(token)
        if token in {"--token", "--password", "--api-key", "--authorization"}:
            redact_next = True
    result = " ".join(redacted_tokens)
    return redact_secrets(result)[:2000]


def _rotate_audit_log_if_needed(log_path: Path) -> None:
    if not log_path.exists() or log_path.stat().st_size < settings.audit_log_max_bytes:
        return
    for index in range(settings.audit_log_backups, 0, -1):
        source = log_path if index == 1 else Path(f"{log_path}.{index - 1}")
        dest = Path(f"{log_path}.{index}")
        if source.exists():
            source.replace(dest)


def audit_log(tool: str, args: dict[str, Any], status: str, detail: str = "") -> None:
    record = {
        "timestamp": datetime.now(UTC).isoformat(),
        "user": current_user_sub.get(),
        "tool": tool,
        "arguments": redact_secrets(json.dumps(args, ensure_ascii=False, default=str)),
        "status": status,
        "detail": redact_secrets(detail)[:500],
    }
    try:
        settings.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        _rotate_audit_log_if_needed(settings.audit_log_path)
        with settings.audit_log_path.open("a", encoding="utf-8") as file_handle:
            file_handle.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    except OSError:
        pass


def build_sandbox_argv(command: str, cwd: Path) -> list[str]:
    if settings.sandbox_mode == "bwrap":
        if os.name != "posix":
            raise RuntimeError("bubblewrap is supported only on Linux")
        root = str(settings.resolved_workspace)
        argv = [
            "bwrap",
            "--die-with-parent",
            "--new-session",
            "--unshare-pid",
            "--unshare-uts",
            "--unshare-ipc",
            "--unshare-cgroup",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/bin",
            "/bin",
            "--ro-bind",
            "/lib",
            "/lib",
            "--ro-bind",
            "/etc",
            "/etc",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            "--bind",
            root,
            root,
            "--chdir",
            str(cwd),
        ]
        library_arguments = []
        for library_path in ("/lib64", "/lib32"):
            if Path(library_path).exists():
                library_arguments.extend(["--ro-bind", library_path, library_path])
        argv[1:1] = library_arguments
        if settings.sandbox_disable_net:
            argv.append("--unshare-net")
        argv.extend(["--", "bash", "-lc", command])
        return argv
    if os.name == "posix":
        return ["bash", "-lc", command]
    return f'{os.environ.get("COMSPEC", "cmd.exe")} /d /s /c "{command}"'


_SENSITIVE_ENV_EXACT = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "NPM_TOKEN",
        "PYPI_TOKEN",
    }
)
_SENSITIVE_ENV_SUBSTRINGS = (
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "API_KEY",
    "PRIVATE_KEY",
    "CREDENTIAL",
)
_SHELL_META_RE = re.compile(r"[;&|`$<>\n\r]")


def sanitized_env() -> dict[str, str]:
    if not settings.strip_sensitive_env:
        return dict(os.environ)
    clean: dict[str, str] = {}
    for key, value in os.environ.items():
        upper = key.upper()
        if upper.startswith("MCP_") or upper in _SENSITIVE_ENV_EXACT:
            continue
        if any(sub in upper for sub in _SENSITIVE_ENV_SUBSTRINGS):
            continue
        clean[key] = value
    return clean


def validate_command(command: str) -> None:
    if not command or not command.strip():
        raise SandboxError("Command cannot be empty")
    if "\x00" in command:
        raise SandboxError("Command cannot contain NUL bytes")
    if len(command) > settings.max_command_chars:
        raise SandboxError(f"Command exceeds {settings.max_command_chars}-character limit")
    for pattern in settings.denied_command_patterns:
        if re.search(pattern, command):
            raise SandboxError("Command blocked by security policy")
    if settings.allowed_commands:
        if _SHELL_META_RE.search(command):
            raise SandboxError("Shell chaining and redirection are disabled in allowlist mode")
        try:
            tokens = shlex.split(command, posix=os.name != "nt")
        except ValueError as exc:
            raise SandboxError(f"Invalid command syntax: {exc}") from exc
        if not tokens:
            raise SandboxError("Command cannot be empty")
        exe = Path(tokens[0]).name.lower()
        if exe.endswith(".exe"):
            exe = exe[:-4]
        allowed = {item.lower().removesuffix(".exe") for item in settings.allowed_commands}
        if exe not in allowed:
            raise SandboxError(f"Command '{tokens[0]}' is not in MCP_ALLOWED_COMMANDS")
