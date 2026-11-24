from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_state_dir() -> Path:
    if os.name == "nt":
        return Path(tempfile.gettempdir()) / "remote-agent-mcp"
    return Path("/tmp/remote-agent-mcp")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MCP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    workspace_root: Path = Field(default_factory=Path.cwd)
    host: str = "127.0.0.1"
    port: int = 8000
    stateless_http: bool = True
    json_response: bool = True
    session_idle_timeout: float | None = Field(default=90 * 86400, gt=0)
    sse_retry_interval: int = Field(default=15000, ge=1000)
    transport_allowed_hosts: list[str] = Field(
        default_factory=lambda: ["127.0.0.1:*", "localhost:*"]
    )
    transport_allowed_origins: list[str] = Field(
        default_factory=lambda: ["http://127.0.0.1:*", "http://localhost:*"]
    )

    sandbox_mode: Literal["none", "bwrap"] = "none"
    sandbox_disable_net: bool = True
    audit_log_path: Path = Field(default_factory=lambda: _default_state_dir() / "audit.jsonl")
    jobs_dir: Path = Field(default_factory=lambda: _default_state_dir() / "jobs")
    max_concurrent_jobs: int = Field(default=8, ge=1, le=64)
    job_retention_seconds: int = Field(default=86400, ge=60)

    max_read_lines: int = Field(default=400, ge=1, le=1000)
    max_file_bytes: int = Field(default=5 * 1024 * 1024, ge=1024)
    default_cmd_timeout: int = Field(default=30, ge=1)
    max_cmd_timeout: int = Field(default=120, ge=1, le=120)
    default_output_chars: int = Field(default=8000, ge=500)
    max_command_output_bytes: int = Field(default=10 * 1024 * 1024, ge=65536)
    denied_globs: list[str] = Field(
        default_factory=lambda: [
            ".env",
            ".env.*",
            "**/.env",
            "**/.env.*",
            "*.pem",
            "*.key",
            "id_rsa*",
            "id_ed25519*",
            ".git/config",
            ".git/credentials",
            "**/.git/config",
            "**/.git/credentials",
        ]
    )

    auth_enabled: bool = False
    resource_url: str = "http://127.0.0.1:8000/mcp"
    oauth_issuer: str = ""
    oauth_jwks_url: str = ""
    oauth_audience: str = ""
    allowed_user_subs: str = ""
    local_oauth_provider: bool = False
    local_oauth_client_id: str = ""
    local_oauth_client_secret: str = ""
    require_oauth_scopes: bool = True
    oauth_leeway_seconds: int = Field(default=30, ge=0, le=300)
    enable_git_restore: bool = False
    strip_sensitive_env: bool = True
    max_command_chars: int = Field(default=8192, ge=64, le=65536)
    max_request_bytes: int = Field(default=10 * 1024 * 1024, ge=1024)
    audit_log_max_bytes: int = Field(default=10 * 1024 * 1024, ge=65536)
    audit_log_backups: int = Field(default=3, ge=1, le=10)
    allowed_commands: list[str] = Field(default_factory=list)
    denied_command_patterns: list[str] = Field(
        default_factory=lambda: [
            r"(?i)\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+/(\s|$)",
            r"(?i)\bmkfs\.[a-z0-9]+",
            r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",
            r"(?i)\bdiskpart\b",
            r"(?i)\bvssadmin\s+delete\s+shadows\b",
            r"(?i)\breg\s+save\s+hklm\\(sam|security|system)\b",
            r"(?i)\b(mimikatz|sekurlsa)\b",
        ]
    )
    rotate_refresh_tokens: bool = False

    @property
    def resolved_workspace(self) -> Path:
        return self.workspace_root.expanduser().resolve()

    @property
    def jwks_uri(self) -> str:
        if self.oauth_jwks_url:
            return self.oauth_jwks_url
        return f"{self.oauth_issuer.rstrip('/')}/.well-known/jwks.json"

    @property
    def allowed_subs_set(self) -> set[str]:
        return {item.strip() for item in self.allowed_user_subs.split(",") if item.strip()}

    def validate_public_security(self) -> None:
        if self.local_oauth_provider:
            if not self.resource_url.startswith("https://"):
                raise ValueError("The self-hosted OAuth provider requires an HTTPS resource URL")
            self.oauth_issuer = self.resource_url.rsplit("/", 1)[0]
            self.oauth_audience = self.resource_url
            self.oauth_jwks_url = f"{self.oauth_issuer}/oauth/jwks"
            self.allowed_user_subs = "local-owner"
        if self.auth_enabled:
            missing = []
            if not self.oauth_issuer:
                missing.append("MCP_OAUTH_ISSUER")
            if not self.oauth_audience:
                missing.append("MCP_OAUTH_AUDIENCE")
            if not self.allowed_subs_set:
                missing.append("MCP_ALLOWED_USER_SUBS")
            if missing:
                raise ValueError(f"Missing required OAuth settings: {', '.join(missing)}")
        if self.host not in {"127.0.0.1", "localhost", "::1"} and not self.auth_enabled:
            raise ValueError("Refusing a non-loopback listener without MCP_AUTH_ENABLED=true")
        if (self.auth_enabled or self.host not in {"127.0.0.1", "localhost", "::1"}) and any(
            h.strip() == "*" for h in self.transport_allowed_hosts
        ):
            raise ValueError("Wildcard '*' in MCP_TRANSPORT_ALLOWED_HOSTS is not allowed")


settings = Settings()
