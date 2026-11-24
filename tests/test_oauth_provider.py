from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import UTC, datetime

from starlette.testclient import TestClient

from remote_agent_mcp.config import settings
from remote_agent_mcp.oauth_provider import (
    load_or_create_credentials,
    oauth_state,
    refresh_tokens_path,
)
from remote_agent_mcp.server import create_asgi_app


def test_single_user_oauth_authorization_pkce_and_refresh() -> None:
    settings.auth_enabled = True
    settings.local_oauth_provider = True
    settings.resource_url = "https://mcp.example.com/mcp"
    oauth_state.codes.clear()
    oauth_state.refresh_tokens.clear()
    refresh_tokens_path().unlink(missing_ok=True)
    credentials = load_or_create_credentials()
    with TestClient(create_asgi_app()) as client:
        metadata = client.get("/.well-known/oauth-authorization-server").json()
        assert metadata["code_challenge_methods_supported"] == ["S256"]
        assert metadata["issuer"] == "https://mcp.example.com"
        assert client.get("/oauth/jwks").json()["keys"][0]["alg"] == "RS256"

        verifier = secrets.token_urlsafe(64)
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        redirect_uri = "https://oauth-redirect.googleusercontent.com/r/test-gemini"
        authorization = {
            "client_id": credentials["client_id"],
            "redirect_uri": redirect_uri,
            "state": secrets.token_urlsafe(16),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "mcp:read mcp:write mcp:exec",
        }
        consent = client.get("/oauth/authorize", params=authorization)
        assert consent.status_code == 200
        assert "Local setup passcode" in consent.text
        rejected = client.get(
            "/oauth/authorize", params={**authorization, "redirect_uri": "https://evil.example/cb"}
        )
        assert rejected.status_code == 400
        granted = client.post(
            "/oauth/authorize",
            data={**authorization, "passcode": credentials["passcode"]},
            follow_redirects=False,
        )
        assert granted.status_code == 302, granted.text
        code = granted.headers["location"].split("code=", 1)[1].split("&", 1)[0]
        token = client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": credentials["client_id"],
                "client_secret": credentials["client_secret"],
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": verifier,
            },
        )
        assert token.status_code == 200, token.text
        issued = token.json()
        assert issued["expires_in"] == 3600
        refresh_token = issued["refresh_token"]
        protected = client.post(
            "/mcp", headers={"Authorization": f"Bearer {issued['access_token']}"}
        )
        assert protected.status_code != 401
        refreshed = client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": credentials["client_id"],
                "client_secret": credentials["client_secret"],
                "refresh_token": refresh_token,
            },
        )
        assert refreshed.status_code == 200
        assert refreshed.json()["refresh_token"] == refresh_token
        stored = refresh_tokens_path().read_text(encoding="utf-8")
        assert refresh_token not in stored
        oauth_state.refresh_tokens.clear()
        after_restart = client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": credentials["client_id"],
                "client_secret": credentials["client_secret"],
                "refresh_token": refresh_token,
            },
        )
        assert after_restart.status_code == 200
        assert datetime.now(UTC).timestamp() > 0
