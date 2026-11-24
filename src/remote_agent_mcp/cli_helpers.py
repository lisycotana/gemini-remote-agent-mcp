from __future__ import annotations

import json
import os
import shutil
from typing import Any

from .config import settings


def run_preflight_check() -> dict[str, Any]:
    workspace = settings.resolved_workspace
    checks: dict[str, Any] = {
        "workspace_root": str(workspace),
        "workspace_exists": workspace.is_dir(),
        "transport": settings.transport,
        "auth_enabled": settings.auth_enabled,
        "local_oauth_provider": settings.local_oauth_provider,
        "sandbox_mode": settings.sandbox_mode,
        "read_only_mode": settings.read_only_mode,
        "strip_sensitive_env": settings.strip_sensitive_env,
        "allowed_commands_enabled": bool(settings.allowed_commands),
        "max_tool_calls_per_minute": settings.max_tool_calls_per_minute,
        "max_repeat_mutations": settings.max_repeat_mutations,
        "ripgrep_available": shutil.which("rg") is not None,
        "git_available": shutil.which("git") is not None,
        "bwrap_available": shutil.which("bwrap") is not None if os.name == "posix" else False,
    }
    warnings: list[str] = []
    if not checks["workspace_exists"]:
        warnings.append(f"Workspace directory does not exist: {workspace}")
    if not checks["ripgrep_available"]:
        warnings.append("ripgrep (rg) not found in PATH; grep_search will fail")
    if settings.transport == "http":
        try:
            settings.validate_public_security()
        except ValueError as exc:
            warnings.append(f"Security configuration error: {exc}")
        if settings.sandbox_mode == "none":
            warnings.append("MCP_SANDBOX_MODE=none provides no OS shell isolation")
    checks["warnings"] = warnings
    checks["ok"] = checks["workspace_exists"] and not any(
        w.startswith("Security configuration error") for w in warnings
    )
    return checks


def generate_client_config(client: str) -> str:
    workspace = str(settings.resolved_workspace)
    stdio_entry = {
        "command": "uv",
        "args": [
            "run",
            "--project",
            workspace,
            "remote-agent-mcp",
            "--transport",
            "stdio",
        ],
        "env": {
            "MCP_WORKSPACE_ROOT": workspace,
            "MCP_AUTH_ENABLED": "false",
        },
    }
    if client == "gemini-cli":
        payload = {
            "mcpServers": {
                "gemini-remote-agent": {
                    **stdio_entry,
                    "trust": False,
                }
            }
        }
        return json.dumps(payload, indent=2)
    if client == "gemini-cli-http":
        payload = {
            "mcpServers": {
                "gemini-remote-agent": {
                    "httpUrl": settings.resource_url,
                    "trust": False,
                }
            }
        }
        return json.dumps(payload, indent=2)
    if client in {"claude-desktop", "cursor"}:
        payload = {"mcpServers": {"gemini-remote-agent": stdio_entry}}
        return json.dumps(payload, indent=2)
    if client == "gemini-web":
        payload = {
            "connector_url": settings.resource_url,
            "recommended_env": {
                "MCP_TRANSPORT": "http",
                "MCP_STATELESS_HTTP": "true",
                "MCP_JSON_RESPONSE": "true",
                "MCP_AUTH_ENABLED": "true",
                "MCP_MAX_TOOL_CALLS_PER_MINUTE": "60",
                "MCP_MAX_REPEAT_MUTATIONS": "5",
            },
            "companion_browser_helper": "https://github.com/ngiken/KenEasy-Gemini-MCP-Auto-Helper",
        }
        return json.dumps(payload, indent=2)
    raise ValueError(
        "Unsupported client. Choose from: gemini-cli, gemini-cli-http, "
        "claude-desktop, cursor, gemini-web"
    )
