from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp.server.fastmcp.exceptions import ToolError
from starlette.responses import JSONResponse
from starlette.testclient import TestClient

from remote_agent_mcp.auth import (
    JWTValidator,
    OAuthResourceMiddleware,
    caller_context,
    require_tool_scope,
)
from remote_agent_mcp.config import settings


async def dummy_app(scope, receive, send) -> None:  # noqa: ANN001, ARG001
    await JSONResponse({"ok": True})(scope, receive, send)


@pytest.fixture
def rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def configure_auth() -> None:
    settings.auth_enabled = True
    settings.resource_url = "https://mcp.example.com/mcp"
    settings.oauth_issuer = "https://auth.example.com/"
    settings.oauth_audience = "https://mcp.example.com/mcp"
    settings.allowed_user_subs = "user-allowed"


def issue_token(private_key, *, subject: str = "user-allowed", scope: str = "mcp:read") -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": subject,
            "iss": settings.oauth_issuer,
            "aud": settings.oauth_audience,
            "scope": scope,
            "iat": now,
            "exp": now + timedelta(minutes=5),
        },
        private_key,
        algorithm="RS256",
    )


def test_oauth_discovery_and_authentication(rsa_keys) -> None:
    private_key, public_key = rsa_keys
    configure_auth()
    client = TestClient(
        OAuthResourceMiddleware(dummy_app, validator=JWTValidator(public_key=public_key))
    )
    metadata = client.get("/.well-known/oauth-protected-resource/mcp")
    assert metadata.status_code == 200
    assert metadata.json()["resource"] == settings.resource_url
    assert metadata.json()["scopes_supported"] == ["mcp:read", "mcp:write", "mcp:exec"]
    unauthorized = client.post("/mcp")
    assert unauthorized.status_code == 401
    assert "/.well-known/oauth-protected-resource/mcp" in unauthorized.headers["www-authenticate"]
    allowed = client.post("/mcp", headers={"Authorization": f"Bearer {issue_token(private_key)}"})
    assert allowed.status_code == 200
    forbidden = client.post(
        "/mcp",
        headers={"Authorization": f"Bearer {issue_token(private_key, subject='intruder')}"},
    )
    assert forbidden.status_code == 403


def test_each_tool_scope_is_enforced(rsa_keys) -> None:
    private_key, public_key = rsa_keys
    configure_auth()
    validator = JWTValidator(public_key=public_key)
    read_caller = validator.verify(issue_token(private_key, scope="mcp:read"))
    token = caller_context.set(read_caller)
    try:
        require_tool_scope("read_file")
        with pytest.raises(ToolError, match="mcp:exec"):
            require_tool_scope("run_command")
        with pytest.raises(ToolError, match="mcp:write"):
            require_tool_scope("edit_file")
    finally:
        caller_context.reset(token)
    full_caller = validator.verify(issue_token(private_key, scope="mcp:read mcp:write mcp:exec"))
    assert full_caller.has_scope("mcp:exec")


def test_token_with_wrong_audience_is_rejected(rsa_keys) -> None:
    private_key, public_key = rsa_keys
    configure_auth()
    token = issue_token(private_key)
    settings.oauth_audience = "https://different.example.com/mcp"
    from remote_agent_mcp.auth import AuthError

    with pytest.raises(AuthError) as error:
        JWTValidator(public_key=public_key).verify(token)
    assert error.value.status_code == 401


def test_oauth_metadata_is_unavailable_when_auth_is_disabled() -> None:
    client = TestClient(OAuthResourceMiddleware(dummy_app))
    response = client.get("/.well-known/oauth-protected-resource/mcp")
    assert response.status_code == 404
