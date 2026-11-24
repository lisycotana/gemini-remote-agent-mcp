from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.types import ASGIApp
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from . import oauth_provider
from .auth import JWTValidator, OAuthResourceMiddleware
from .cli_helpers import generate_client_config, run_preflight_check
from .config import settings
from .tools.exec import register_exec_and_git_tools
from .tools.files import register_file_tools


def create_mcp(*, read_only: bool = False, streamable_http_path: str = "/mcp") -> FastMCP:
    mcp = FastMCP(
        name="gemini-remote-agent-mcp-readonly" if read_only else "gemini-remote-agent-mcp",
        host=settings.host,
        port=settings.port,
        streamable_http_path=streamable_http_path,
        stateless_http=settings.stateless_http,
        json_response=settings.json_response,
        retry_interval=settings.sse_retry_interval,
        session_idle_timeout=settings.session_idle_timeout,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=settings.transport_allowed_hosts,
            allowed_origins=settings.transport_allowed_origins,
        ),
        instructions=(
            "Operate only within this remote workspace. Read files before editing. "
            "For existing files, pass the sha256 returned by read_file to edit_file or write_file. "
            "Prefer edit_file for local changes and review the returned unified diff. "
            "Use start_bg_job and poll_bg_job for commands that may exceed 30 seconds. "
            "Commands are non-interactive. Do not request or print credentials. "
            "git_restore is destructive, may be disabled, and requires explicit confirmation."
        ),
    )
    effective_ro = read_only or settings.read_only_mode
    register_file_tools(mcp, read_only=effective_ro)
    register_exec_and_git_tools(mcp, read_only=effective_ro)
    return mcp


logger = logging.getLogger(__name__)


def create_asgi_app(*, validator: JWTValidator | None = None) -> ASGIApp:
    settings.validate_public_security()
    logger.info(
        "Security posture: auth=%s sandbox=%s strip_env=%s allowlist=%s rotate_refresh=%s",
        settings.auth_enabled,
        settings.sandbox_mode,
        settings.strip_sensitive_env,
        bool(settings.allowed_commands),
        settings.rotate_refresh_tokens,
    )
    if validator is None and settings.local_oauth_provider:
        validator = JWTValidator(public_key=oauth_provider.signing_key().public_key())
    mcp = create_mcp()
    mcp_ro = create_mcp(read_only=True, streamable_http_path="/mcp/readonly")
    mcp_app = mcp.streamable_http_app()
    mcp_ro_app = mcp_ro.streamable_http_app()

    @asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        async with mcp.session_manager.run(), mcp_ro.session_manager.run():
            yield

    application = Starlette(
        routes=[],
        lifespan=lifespan,
        middleware=[Middleware(ProxyHeadersMiddleware, trusted_hosts=["127.0.0.1", "::1"])],
    )
    if settings.local_oauth_provider:
        from starlette.routing import Route

        oauth_provider.load_or_create_credentials()
        oauth_provider.secure_credentials_permissions()
        application.router.routes.extend(
            [
                Route(
                    "/.well-known/oauth-authorization-server",
                    oauth_provider.authorization_metadata,
                    methods=["GET"],
                ),
                Route(
                    "/.well-known/openid-configuration",
                    oauth_provider.authorization_metadata,
                    methods=["GET"],
                ),
                Route("/oauth/jwks", oauth_provider.jwks_endpoint, methods=["GET"]),
                Route(
                    "/oauth/authorize",
                    oauth_provider.authorize,
                    methods=["GET", "POST"],
                ),
                Route("/oauth/token", oauth_provider.token, methods=["POST"]),
                Route("/oauth/revoke", oauth_provider.revoke, methods=["POST"]),
                Route("/oauth/register", oauth_provider.register, methods=["POST"]),
            ]
        )
    application.router.routes.extend(mcp_ro_app.routes)
    application.mount("/", mcp_app)
    return OAuthResourceMiddleware(application, validator=validator)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="remote-agent-mcp",
        description="Workspace-scoped MCP server for Gemini Web, Gemini CLI, and desktop clients.",
    )
    parser.add_argument(
        "--transport",
        choices=["http", "stdio"],
        default=settings.transport,
        help="Transport mode: 'http' (Streamable HTTP for web/remote) or 'stdio' (desktop/CLI).",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Run preflight security and environment checks and exit.",
    )
    parser.add_argument(
        "--print-client-config",
        choices=["gemini-cli", "gemini-cli-http", "claude-desktop", "cursor", "gemini-web"],
        help="Print ready-to-paste client configuration JSON and exit.",
    )
    args = parser.parse_args(argv)
    settings.transport = args.transport

    if args.check:
        report = run_preflight_check()
        print(json.dumps(report, indent=2, ensure_ascii=False))
        sys.exit(0 if report["ok"] else 1)

    if args.print_client_config:
        print(generate_client_config(args.print_client_config))
        return

    if settings.transport == "stdio":
        settings.auth_enabled = False
        create_mcp().run(transport="stdio")
        return

    uvicorn.run(
        create_asgi_app(),
        host=settings.host,
        port=settings.port,
        log_level="info",
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
