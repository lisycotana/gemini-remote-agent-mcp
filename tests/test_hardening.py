from __future__ import annotations

import json
import shutil

import pytest
from mcp.server.fastmcp import FastMCP
from starlette.testclient import TestClient

from remote_agent_mcp.config import Settings, settings
from remote_agent_mcp.oauth_provider import load_or_create_credentials, oauth_state
from remote_agent_mcp.security import (
    SandboxError,
    resolve_safe_path,
    sanitized_env,
    validate_command,
)
from remote_agent_mcp.server import create_asgi_app
from remote_agent_mcp.tools.files import register_file_tools


@pytest.mark.parametrize(
    "path",
    [
        ".ENV",
        ".Env.Local",
        ".GIT/CONFIG",
        "keys/Secret.PEM",
        "CON",
        "nul.txt",
        "a.txt:ads",
        "bad.txt ",
    ],
)
def test_hardened_path_checks_reject_bypass_attempts(path: str) -> None:
    with pytest.raises(SandboxError):
        resolve_safe_path(path)


def test_grep_search_cannot_override_denied_globs_with_file_glob() -> None:
    if not shutil.which("rg"):
        pytest.skip("ripgrep (rg) is not installed")
    (settings.resolved_workspace / ".env").write_text(
        "SECRET_VALUE=topsecret123\n", encoding="utf-8"
    )
    (settings.resolved_workspace / "app.py").write_text("VALUE = 'ok'\n", encoding="utf-8")
    mcp = FastMCP("test")
    register_file_tools(mcp)
    grep = mcp._tool_manager._tools["grep_search"].fn
    result = grep(pattern="topsecret123", file_glob=".env")
    assert result["match_count"] == 0
    assert result["matches"] == ""


def test_sanitized_env_strips_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_LOCAL_OAUTH_CLIENT_SECRET", "super-secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_12345678901234567890")
    monkeypatch.setenv("SAFE_TEST_VAR", "hello")
    env = sanitized_env()
    assert "MCP_LOCAL_OAUTH_CLIENT_SECRET" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "GITHUB_TOKEN" not in env
    assert env.get("SAFE_TEST_VAR") == "hello"


def test_validate_command_policies() -> None:
    with pytest.raises(SandboxError, match="blocked by security policy"):
        validate_command("rm -rf /")
    with pytest.raises(SandboxError, match="blocked by security policy"):
        validate_command("diskpart")
    settings.allowed_commands = ["python", "pytest"]
    validate_command("python -V")
    with pytest.raises(SandboxError, match="allowlist mode"):
        validate_command("python -V && whoami")
    with pytest.raises(SandboxError, match="MCP_ALLOWED_COMMANDS"):
        validate_command("powershell -Command dir")


def test_wildcard_allowed_hosts_rejected_when_auth_enabled() -> None:
    cfg = Settings(
        auth_enabled=True,
        oauth_issuer="https://idp.example",
        oauth_audience="https://mcp.example",
        allowed_user_subs="u1",
        transport_allowed_hosts=["*"],
    )
    with pytest.raises(ValueError, match="Wildcard"):
        cfg.validate_public_security()


def test_security_headers_payload_limit_and_auth_audit() -> None:
    settings.auth_enabled = True
    settings.local_oauth_provider = True
    settings.resource_url = "https://mcp.example.com/mcp"
    settings.max_request_bytes = 128
    oauth_state.failed_attempts_by_key.clear()
    load_or_create_credentials()
    with TestClient(create_asgi_app()) as client:
        health = client.get("/healthz")
        assert health.status_code == 200
        assert health.headers["x-content-type-options"] == "nosniff"
        assert health.headers["x-frame-options"] == "DENY"
        assert health.headers["referrer-policy"] == "no-referrer"

        denied = client.post("/mcp", json={"jsonrpc": "2.0", "method": "ping", "id": 1})
        assert denied.status_code == 401
        audit_text = settings.audit_log_path.read_text(encoding="utf-8")
        assert '"status": "denied"' in audit_text

        oversized = client.post(
            "/mcp",
            content=json.dumps({"pad": "x" * 300}),
            headers={"content-type": "application/json"},
        )
        assert oversized.status_code == 413

        for _ in range(10):
            r = client.post(
                "/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": "bad",
                    "client_secret": "bad",
                },
            )
            assert r.status_code == 401
        limited = client.post(
            "/oauth/token",
            data={"grant_type": "authorization_code", "client_id": "bad", "client_secret": "bad"},
        )
        assert limited.status_code == 429
    oauth_state.failed_attempts_by_key.clear()


def test_audit_log_rotation() -> None:
    from remote_agent_mcp.security import audit_log

    settings.audit_log_max_bytes = 200
    settings.audit_log_backups = 2
    for idx in range(10):
        audit_log("test_tool", {"idx": idx, "pad": "x" * 60}, "ok")
    assert settings.audit_log_path.exists()
    assert settings.audit_log_path.with_name(settings.audit_log_path.name + ".1").exists()


def test_consent_page_ui_and_csp() -> None:
    import base64
    import hashlib
    import secrets

    settings.auth_enabled = True
    settings.local_oauth_provider = True
    settings.resource_url = "https://mcp.example.com/mcp"
    credentials = load_or_create_credentials()
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    with TestClient(create_asgi_app()) as client:
        resp = client.get(
            "/oauth/authorize",
            params={
                "client_id": credentials["client_id"],
                "redirect_uri": "https://oauth-redirect.googleusercontent.com/r/test-gemini",
                "state": "state123",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": "mcp:read mcp:write",
            },
        )
        assert resp.status_code == 200
        assert "OAuth 2.1" in resp.text
        assert "mcp:read" in resp.text
        assert "mcp:write" in resp.text
        assert "content-security-policy" in resp.headers
