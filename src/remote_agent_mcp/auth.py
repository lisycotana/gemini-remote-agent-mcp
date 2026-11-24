from __future__ import annotations

import json
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import jwt
from jwt import PyJWKClient
from starlette.types import ASGIApp, Receive, Scope, Send

from .auth_context import current_user_sub
from .config import settings
from .security import audit_log

READ_SCOPE = "mcp:read"
WRITE_SCOPE = "mcp:write"
EXEC_SCOPE = "mcp:exec"
TOOL_SCOPES = {
    "list_directory": READ_SCOPE,
    "find_files": READ_SCOPE,
    "grep_search": READ_SCOPE,
    "read_file": READ_SCOPE,
    "edit_file": WRITE_SCOPE,
    "write_file": WRITE_SCOPE,
    "run_command": EXEC_SCOPE,
    "start_bg_job": EXEC_SCOPE,
    "poll_bg_job": EXEC_SCOPE,
    "kill_bg_job": EXEC_SCOPE,
    "git_status_diff": READ_SCOPE,
    "git_restore": WRITE_SCOPE,
}


@dataclass(frozen=True)
class Caller:
    subject: str
    scopes: frozenset[str]

    def has_scope(self, required: str) -> bool:
        return not settings.require_oauth_scopes or required in self.scopes


caller_context: ContextVar[Caller | None] = ContextVar("mcp_caller", default=None)


class AuthError(Exception):
    def __init__(self, status_code: int, error: str, description: str) -> None:
        super().__init__(description)
        self.status_code = status_code
        self.error = error
        self.description = description


class _PayloadTooLargeError(Exception):
    pass


class JWTValidator:
    def __init__(self, *, jwks_uri: str | None = None, public_key: Any = None) -> None:
        self._public_key = public_key
        self._jwk_client = (
            None
            if public_key or not settings.auth_enabled
            else PyJWKClient(jwks_uri or settings.jwks_uri, cache_keys=True, lifespan=300)
        )

    def verify(self, token: str) -> Caller:
        try:
            key = self._public_key
            if key is None:
                if self._jwk_client is None:
                    self._jwk_client = PyJWKClient(settings.jwks_uri, cache_keys=True, lifespan=300)
                key = self._jwk_client.get_signing_key_from_jwt(token).key
            payload = jwt.decode(
                token,
                key,
                algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "EdDSA"],
                audience=settings.oauth_audience,
                issuer=settings.oauth_issuer,
                leeway=settings.oauth_leeway_seconds,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthError(401, "invalid_token", "Bearer token validation failed") from exc

        subject = str(payload["sub"])
        if subject not in settings.allowed_subs_set:
            raise AuthError(403, "access_denied", "This user is not allowed to use the MCP server")
        raw_scopes = payload.get("scope", "")
        if isinstance(raw_scopes, str):
            scopes = frozenset(raw_scopes.split())
        elif isinstance(raw_scopes, list) and all(isinstance(item, str) for item in raw_scopes):
            scopes = frozenset(raw_scopes)
        else:
            scopes = frozenset()
        return Caller(subject=subject, scopes=scopes)


def _metadata_url(resource_url: str) -> str:
    parsed = urlsplit(resource_url)
    path = parsed.path.rstrip("/")
    return f"{parsed.scheme}://{parsed.netloc}/.well-known/oauth-protected-resource{path}"


def _bearer_challenge(error: str | None = None, required_scope: str | None = None) -> str:
    values = [f'resource_metadata="{_metadata_url(settings.resource_url)}"']
    if error:
        values.insert(0, f'error="{error}"')
    if required_scope:
        values.append(f'scope="{required_scope}"')
    return "Bearer " + ", ".join(values)


async def _json_response(
    send: Send,
    status_code: int,
    payload: dict[str, Any],
    headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    body = json.dumps(payload).encode("utf-8")
    response_headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
        (b"cache-control", b"no-store"),
        (b"x-content-type-options", b"nosniff"),
        (b"x-frame-options", b"DENY"),
        (b"referrer-policy", b"no-referrer"),
    ]
    response_headers.extend(headers or [])
    await send({"type": "http.response.start", "status": status_code, "headers": response_headers})
    await send({"type": "http.response.body", "body": body})


class OAuthResourceMiddleware:
    def __init__(self, app: ASGIApp, validator: JWTValidator | None = None) -> None:
        self.app = app
        self.validator = validator or JWTValidator()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_security_headers(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers_list = list(message.get("headers", []))
                existing = {name.lower() for name, _ in headers_list}
                defaults = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                ]
                for name, value in defaults:
                    if name not in existing:
                        headers_list.append((name, value))
                message = {**message, "headers": headers_list}
            await send(message)

        req_headers = dict(scope.get("headers", []))
        content_length_raw = req_headers.get(b"content-length")
        if content_length_raw:
            try:
                if int(content_length_raw.decode("ascii")) > settings.max_request_bytes:
                    await _json_response(
                        send_with_security_headers,
                        413,
                        {
                            "error": "payload_too_large",
                            "error_description": "Request body too large",
                        },
                    )
                    return
            except ValueError:
                await _json_response(
                    send_with_security_headers,
                    400,
                    {"error": "invalid_request", "error_description": "Invalid Content-Length"},
                )
                return

        received_bytes = 0

        async def limited_receive() -> dict[str, Any]:
            nonlocal received_bytes
            message = await receive()
            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > settings.max_request_bytes:
                    raise _PayloadTooLargeError
            return message

        path = scope.get("path", "")
        if path == "/healthz":
            await _json_response(
                send_with_security_headers,
                200,
                {"status": "ok", "auth_enabled": settings.auth_enabled},
            )
            return
        if settings.local_oauth_provider and (
            path.startswith("/oauth/")
            or path
            in {"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"}
        ):
            await self.app(scope, limited_receive, send_with_security_headers)
            return
        metadata_paths = {
            "/.well-known/oauth-protected-resource",
            _metadata_url(settings.resource_url).removeprefix(
                f"{urlsplit(settings.resource_url).scheme}://{urlsplit(settings.resource_url).netloc}"
            ),
        }
        if path in metadata_paths:
            if not settings.auth_enabled:
                await _json_response(
                    send,
                    404,
                    {"error": "not_found", "error_description": "OAuth is not enabled"},
                )
                return
            await _json_response(
                send_with_security_headers,
                200,
                {
                    "resource": settings.resource_url,
                    "authorization_servers": [settings.oauth_issuer.rstrip("/")],
                    "bearer_methods_supported": ["header"],
                    "scopes_supported": [READ_SCOPE, WRITE_SCOPE, EXEC_SCOPE],
                },
            )
            return
        if not settings.auth_enabled:
            try:
                await self.app(scope, limited_receive, send_with_security_headers)
            except _PayloadTooLargeError:
                await _json_response(
                    send_with_security_headers,
                    413,
                    {"error": "payload_too_large", "error_description": "Request body too large"},
                )
            return

        headers = dict(scope.get("headers", []))
        authorization = headers.get(b"authorization", b"").decode("latin-1")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            audit_log("auth", {"path": path}, "denied", "missing_bearer")
            await _json_response(
                send_with_security_headers,
                401,
                {"error": "invalid_token", "error_description": "A Bearer token is required"},
                [(b"www-authenticate", _bearer_challenge().encode("latin-1"))],
            )
            return
        try:
            caller = self.validator.verify(token.strip())
        except AuthError as exc:
            audit_log("auth", {"path": path, "error": exc.error}, "denied", exc.description)
            response_headers = []
            if exc.status_code == 401:
                response_headers.append(
                    (b"www-authenticate", _bearer_challenge(exc.error).encode("latin-1"))
                )
            await _json_response(
                send_with_security_headers,
                exc.status_code,
                {"error": exc.error, "error_description": exc.description},
                response_headers,
            )
            return

        reset_subject = current_user_sub.set(caller.subject)
        reset_caller = caller_context.set(caller)
        try:
            await self.app(scope, limited_receive, send_with_security_headers)
        except _PayloadTooLargeError:
            await _json_response(
                send_with_security_headers,
                413,
                {"error": "payload_too_large", "error_description": "Request body too large"},
            )
        finally:
            caller_context.reset(reset_caller)
            current_user_sub.reset(reset_subject)


def require_tool_scope(tool_name: str) -> None:
    if not settings.auth_enabled:
        return
    caller = caller_context.get()
    required_scope = TOOL_SCOPES[tool_name]
    if caller is None or not caller.has_scope(required_scope):
        audit_log("auth_scope", {"tool": tool_name, "required": required_scope}, "denied")
        from mcp.server.fastmcp.exceptions import ToolError

        raise ToolError(f"OAuth scope required for {tool_name}: {required_scope}")
