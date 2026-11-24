from __future__ import annotations

import os
from pathlib import Path

import pytest

from remote_agent_mcp.config import Settings, settings
from remote_agent_mcp.security import (
    SandboxError,
    build_sandbox_argv,
    redact_secrets,
    redacted_command_for_audit,
    resolve_safe_path,
    truncate_head_tail,
)


@pytest.mark.parametrize(
    "path",
    ["../outside", "folder/../../outside", "/etc/passwd", "C:/Windows/win.ini", r"C:\secret"],
)
def test_rejects_absolute_and_traversing_paths(path: str) -> None:
    with pytest.raises(SandboxError):
        resolve_safe_path(path)


def test_symlink_escape_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = settings.resolved_workspace / "escape.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("Creating symlinks requires permission on this Windows host")
    with pytest.raises(SandboxError):
        resolve_safe_path("escape.txt")


@pytest.mark.parametrize(
    "path", [".env", "nested/.env.production", "keys/server.pem", ".git/config"]
)
def test_sensitive_files_are_rejected(path: str) -> None:
    with pytest.raises(SandboxError):
        resolve_safe_path(path)


def test_workspace_file_is_allowed() -> None:
    assert resolve_safe_path("src/app.py") == (settings.resolved_workspace / "src/app.py").resolve()


def test_redacts_common_secrets() -> None:
    raw = (
        "OPENAI_API_KEY=sk-1234567890abcdefghijklmnop\n"
        "url=https://admin:MySuperPass@db.internal/app\n"
        "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
    )
    cleaned = redact_secrets(raw)
    assert "sk-1234567890abcdefghijklmnop" not in cleaned
    assert "MySuperPass" not in cleaned
    assert "REDACTED" in cleaned


def test_audit_command_redacts_flag_values() -> None:
    cleaned = redacted_command_for_audit("deploy --token very-secret-value --verbose")
    assert "very-secret-value" not in cleaned
    assert "--verbose" in cleaned


def test_truncation_keeps_head_and_tail() -> None:
    text = "HEAD" * 200 + "MIDDLE" * 1000 + "TAIL" * 200
    output, truncated, omitted = truncate_head_tail(text, 1000)
    assert truncated and omitted > 0
    assert output.startswith("HEAD") and output.endswith("TAIL")
    assert "omitted" in output
    assert len(output) <= 1100


def test_bwrap_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "sandbox_mode", "bwrap")

    class PortablePath:
        def __init__(self, path: str) -> None:
            self.path = path

        def exists(self) -> bool:
            return False

    monkeypatch.setattr("remote_agent_mcp.security.Path", PortablePath)
    with monkeypatch.context() as patch:
        patch.setattr("remote_agent_mcp.security.os.name", "posix")
        command = build_sandbox_argv("pytest", settings.resolved_workspace)
        assert command[0] == "bwrap"
        assert "--unshare-net" in command
        assert command[-3:] == ["bash", "-lc", "pytest"]


def test_windows_command_preserves_nested_quotes() -> None:
    command = 'python -c "print(123)"'
    argv = build_sandbox_argv(command, settings.resolved_workspace)
    assert argv.endswith(' /d /s /c "python -c "print(123)""')


def test_non_loopback_unauthenticated_server_is_rejected() -> None:
    config = Settings(host="0.0.0.0", auth_enabled=False)  # noqa: S104
    with pytest.raises(ValueError, match="non-loopback"):
        config.validate_public_security()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_workspace_permissions_are_not_changed_by_path_checks() -> None:
    target = settings.resolved_workspace / "script.sh"
    target.write_text("echo ok\n", encoding="utf-8")
    target.chmod(0o750)
    assert target.stat().st_mode & 0o777 == 0o750
