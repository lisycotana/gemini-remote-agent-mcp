from __future__ import annotations

import base64
import contextlib
import hashlib
import html
import json
import secrets
import time
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from starlette.datastructures import FormData
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from .config import settings

SCOPES = ("mcp:read", "mcp:write", "mcp:exec")
GOOGLE_REDIRECTS = (
    "https://oauth-redirect.googleusercontent.com/r/",
    "https://oauth-redirect.googleusercontent.com/a/",
    "https://oauth-redirect-sandbox.googleusercontent.com/r/",
    "https://oauth-redirect-sandbox.googleusercontent.com/a/",
    "https://oauth-redirect-test.googleusercontent.com/r/",
    "https://oauth-redirect-test.googleusercontent.com/a/",
)


def oauth_error(description: str, status_code: int = 400) -> JSONResponse:
    return JSONResponse(
        {"error": "invalid_request", "error_description": description},
        status_code=status_code,
        headers={"cache-control": "no-store"},
    )


def public_origin() -> str:
    parsed = urlsplit(settings.resource_url)
    return f"{parsed.scheme}://{parsed.netloc}"


def valid_redirect(uri: str) -> bool:
    parsed = urlsplit(uri)
    return (
        parsed.scheme == "https"
        and not parsed.username
        and not parsed.password
        and not parsed.fragment
        and any(uri.startswith(prefix) for prefix in GOOGLE_REDIRECTS)
    )


def valid_code_verifier(value: str) -> bool:
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    return 43 <= len(value) <= 128 and set(value) <= allowed


class OAuthState:
    def __init__(self) -> None:
        self.codes: dict[str, dict[str, Any]] = {}
        self.refresh_tokens: dict[str, dict[str, Any]] = {}
        self.failed_passcodes: list[float] = []
        self.failed_attempts_by_key: dict[str, list[float]] = defaultdict(list)
        self.credentials_cache: dict[str, str] | None = None
        self.key_cache: Any = None

    def prune(self) -> None:
        now = time.time()
        self.codes = {key: value for key, value in self.codes.items() if value["expires"] > now}
        self.refresh_tokens = {
            key: value for key, value in self.refresh_tokens.items() if value["expires"] > now
        }
        self.failed_passcodes = [
            timestamp for timestamp in self.failed_passcodes if now - timestamp < 900
        ]
        for key in list(self.failed_attempts_by_key):
            self.failed_attempts_by_key[key] = [
                timestamp for timestamp in self.failed_attempts_by_key[key] if now - timestamp < 900
            ]
            if not self.failed_attempts_by_key[key]:
                del self.failed_attempts_by_key[key]


oauth_state = OAuthState()


def credentials_path() -> Path:
    return settings.jobs_dir.parent / "oauth"


def refresh_tokens_path() -> Path:
    return credentials_path() / "refresh-tokens.json"


def token_hash(token_value: str) -> str:
    return hashlib.sha256(token_value.encode()).hexdigest()


def persist_refresh_tokens() -> None:
    path = refresh_tokens_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_suffix(".tmp")
    temporary_path.write_text(
        json.dumps(oauth_state.refresh_tokens, separators=(",", ":")), encoding="utf-8"
    )
    with contextlib.suppress(OSError):
        temporary_path.chmod(0o600)
    temporary_path.replace(path)
    with contextlib.suppress(OSError):
        path.chmod(0o600)


def load_refresh_tokens() -> None:
    path = refresh_tokens_path()
    if not path.exists():
        return
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(stored, dict):
            return
        now = time.time()
        for key, grant in stored.items():
            if (
                isinstance(key, str)
                and len(key) == 64
                and isinstance(grant, dict)
                and isinstance(grant.get("client_id"), str)
                and isinstance(grant.get("scope"), str)
                and isinstance(grant.get("expires"), int | float)
                and grant["expires"] > now
            ):
                oauth_state.refresh_tokens[key] = grant
    except (OSError, ValueError, TypeError):
        return


def load_or_create_credentials() -> dict[str, str]:
    if oauth_state.credentials_cache is not None:
        return oauth_state.credentials_cache
    path = credentials_path()
    path.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        path.chmod(0o700)
    client_path = path / "client.json"
    passcode_path = path / "passcode.txt"
    key_path = path / "jwt-private.pem"
    if not client_path.exists():
        client_path.write_text(
            json.dumps(
                {
                    "client_id": f"gemini-{secrets.token_urlsafe(18)}",
                    "client_secret": secrets.token_urlsafe(36),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    if not passcode_path.exists():
        passcode_path.write_text(secrets.token_urlsafe(18) + "\n", encoding="utf-8")
    if not key_path.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    client = json.loads(client_path.read_text(encoding="utf-8"))
    if settings.local_oauth_client_id:
        client["client_id"] = settings.local_oauth_client_id
    if settings.local_oauth_client_secret:
        client["client_secret"] = settings.local_oauth_client_secret
    if not key_path.exists():
        raise RuntimeError("OAuth signing key could not be created")
    oauth_state.credentials_cache = {
        **client,
        "passcode": passcode_path.read_text(encoding="utf-8").strip(),
        "private_key": key_path.read_text(encoding="utf-8"),
    }
    return oauth_state.credentials_cache


def secure_credentials_permissions() -> None:
    path = credentials_path()
    for file_path in (path / "client.json", path / "passcode.txt", path / "jwt-private.pem"):
        with contextlib.suppress(OSError):
            file_path.chmod(0o600)


def signing_key() -> Any:
    if oauth_state.key_cache is None:
        oauth_state.key_cache = serialization.load_pem_private_key(
            load_or_create_credentials()["private_key"].encode("utf-8"), password=None
        )
    return oauth_state.key_cache


def public_jwks() -> dict[str, list[dict[str, str]]]:
    private_key = signing_key()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    return {
        "keys": [
            {
                **jwk,
                "kid": hashlib.sha256(public_key).hexdigest()[:24],
                "use": "sig",
                "alg": "RS256",
            }
        ]
    }


def issue_access_token(client_id: str, scope: str) -> str:
    now = int(time.time())
    private_key = signing_key()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return jwt.encode(
        {
            "iss": public_origin(),
            "sub": "local-owner",
            "aud": settings.oauth_audience,
            "client_id": client_id,
            "scope": scope,
            "iat": now,
            "nbf": now,
            "exp": now + 3600,
            "jti": secrets.token_urlsafe(18),
        },
        private_key,
        algorithm="RS256",
        headers={"kid": hashlib.sha256(public_key).hexdigest()[:24]},
    )


_SCOPE_LABELS = {
    "mcp:read": ("Read", "List directories, search code, and read workspace files"),
    "mcp:write": ("Write", "Edit and create UTF-8 files or restore tracked changes"),
    "mcp:exec": ("Execute", "Run shell commands and manage background jobs"),
}


def consent_page(query: dict[str, str], error: str = "") -> HTMLResponse:
    action = f"{public_origin()}/oauth/authorize"
    fields = "".join(
        f'<input type="hidden" name="{html.escape(key)}" value="{html.escape(value)}">'
        for key, value in query.items()
    )
    scopes = [s for s in query.get("scope", "").split() if s]
    scope_items = "".join(
        f'<li><span class="badge">{html.escape(s)}</span>'
        f'<span class="desc">{html.escape(_SCOPE_LABELS.get(s, ("Access", s))[1])}</span></li>'
        for s in scopes
    )
    error_html = (
        f'<div class="alert error" role="alert">{html.escape(error)}</div>' if error else ""
    )
    page = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize Gemini Remote Workspace</title>
<style>
  :root {{
    --bg: #f4f6f9;
    --card: #ffffff;
    --text: #111827;
    --muted: #4b5563;
    --border: #e5e7eb;
    --accent: #2563eb;
    --accent-hover: #1d4ed8;
    --warn-bg: #fffbeb;
    --warn-border: #fde68a;
    --warn-text: #92400e;
    --err-bg: #fef2f2;
    --err-border: #fecaca;
    --err-text: #b91c1c;
    --badge-bg: #eff6ff;
    --badge-text: #1d4ed8;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg: #0b0f17;
      --card: #111827;
      --text: #f3f4f6;
      --muted: #9ca3af;
      --border: #1f2937;
      --accent: #3b82f6;
      --accent-hover: #2563eb;
      --warn-bg: #271f0a;
      --warn-border: #78350f;
      --warn-text: #fcd34d;
      --err-bg: #2a1215;
      --err-border: #7f1d1d;
      --err-text: #fca5a5;
      --badge-bg: #1e293b;
      --badge-text: #93c5fd;
    }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: 24px;
    background: var(--bg);
    color: var(--text);
    font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }}
  .card {{
    width: 100%;
    max-width: 480px;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 28px;
    box-shadow: 0 12px 32px rgba(0, 0, 0, 0.08);
  }}
  .pill {{
    display: inline-block;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.02em;
    padding: 4px 10px;
    border-radius: 999px;
    background: var(--badge-bg);
    color: var(--badge-text);
    margin-bottom: 12px;
  }}
  h1 {{ margin: 0 0 8px; font-size: 22px; line-height: 1.25; }}
  .lead {{ margin: 0 0 18px; color: var(--muted); }}
  .scopes {{
    list-style: none;
    padding: 0;
    margin: 0 0 18px;
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
  }}
  .scopes li {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
    font-size: 13.5px;
  }}
  .scopes li:last-child {{ border-bottom: none; }}
  .badge {{
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 12px;
    font-weight: 600;
    padding: 2px 7px;
    border-radius: 6px;
    background: var(--badge-bg);
    color: var(--badge-text);
    white-space: nowrap;
  }}
  .desc {{ color: var(--muted); }}
  .alert {{
    padding: 12px 14px;
    border-radius: 10px;
    font-size: 13.5px;
    margin-bottom: 16px;
    border: 1px solid transparent;
  }}
  .warning {{
    background: var(--warn-bg);
    border-color: var(--warn-border);
    color: var(--warn-text);
  }}
  .error {{
    background: var(--err-bg);
    border-color: var(--err-border);
    color: var(--err-text);
  }}
  label {{ display: block; font-weight: 600; font-size: 13.5px; margin-bottom: 6px; }}
  input[type="password"] {{
    width: 100%;
    padding: 11px 12px;
    border: 1px solid var(--border);
    border-radius: 10px;
    background: transparent;
    color: var(--text);
    font-size: 15px;
    margin-bottom: 14px;
  }}
  input[type="password"]:focus {{
    outline: 2px solid var(--accent);
    outline-offset: 1px;
  }}
  button {{
    width: 100%;
    padding: 12px 16px;
    border: none;
    border-radius: 10px;
    background: var(--accent);
    color: #ffffff;
    font-size: 15px;
    font-weight: 600;
    cursor: pointer;
  }}
  button:hover {{ background: var(--accent-hover); }}
</style>
</head>
<body>
  <main class="card">
    <span class="pill">OAuth 2.1 · PKCE S256</span>
    <h1>Authorize remote workspace access</h1>
    <p class="lead">Gemini is requesting access to your configured remote workspace.</p>
    <ul class="scopes">{scope_items}</ul>
    <div class="alert warning">
      Only continue if you initiated this connection yourself.
      The issued token grants control over the configured workspace.
    </div>
    {error_html}
    <form method="post" action="{html.escape(action)}">
      {fields}
      <label for="passcode">Local setup passcode</label>
      <input id="passcode" name="passcode" type="password" autocomplete="off" required autofocus>
      <button type="submit">Authorize Gemini</button>
    </form>
  </main>
</body>
</html>"""
    return HTMLResponse(
        page,
        headers={
            "cache-control": "no-store",
            "x-frame-options": "DENY",
            "content-security-policy": (
                "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'"
            ),
        },
    )


def authorization_query(request: Request) -> dict[str, str]:
    query = request.query_params
    return {
        "client_id": query.get("client_id", ""),
        "redirect_uri": query.get("redirect_uri", ""),
        "state": query.get("state", ""),
        "code_challenge": query.get("code_challenge", ""),
        "code_challenge_method": query.get("code_challenge_method", ""),
        "scope": query.get("scope", ""),
    }


def validate_authorization(query: dict[str, str]) -> Response | None:
    credentials = load_or_create_credentials()
    requested_scopes = set(query["scope"].split())
    if not secrets.compare_digest(query["client_id"], credentials["client_id"]):
        return oauth_error("Unknown OAuth client", 401)
    if not valid_redirect(query["redirect_uri"]):
        return oauth_error("The redirect URI is not an allowed Gemini callback")
    if not query["state"] or len(query["state"]) > 2048:
        return oauth_error("A bounded OAuth state is required")
    if query["code_challenge_method"] != "S256" or not valid_code_verifier(query["code_challenge"]):
        return oauth_error("PKCE with S256 is required")
    if not requested_scopes or not requested_scopes.issubset(SCOPES):
        return oauth_error("Only mcp:read, mcp:write, and mcp:exec scopes are supported")
    return None


async def authorize(request: Request) -> Response:
    query = authorization_query(request)
    if request.method == "POST":
        form = await request.form()
        for key in query:
            query[key] = str(form.get(key, query[key]))
    error = validate_authorization(query)
    if error:
        return error
    if request.method == "GET":
        return consent_page(query)
    form = await request.form()
    passcode = str(form.get("passcode", ""))
    oauth_state.prune()
    attempt_key = request.client.host if request.client else "unknown"
    if len(oauth_state.failed_attempts_by_key[attempt_key]) >= 5:
        return consent_page(query, "Too many attempts. Try again in 15 minutes.")
    if not secrets.compare_digest(passcode, load_or_create_credentials()["passcode"]):
        oauth_state.failed_attempts_by_key[attempt_key].append(time.time())
        return consent_page(query, "Incorrect passcode")
    code = secrets.token_urlsafe(32)
    oauth_state.codes[hashlib.sha256(code.encode()).hexdigest()] = {
        **query,
        "expires": time.time() + 300,
    }
    separator = "&" if "?" in query["redirect_uri"] else "?"
    return RedirectResponse(
        query["redirect_uri"] + separator + urlencode({"code": code, "state": query["state"]}),
        status_code=302,
        headers={"cache-control": "no-store"},
    )


def client_credentials(request: Request, form: FormData) -> tuple[str, str]:
    authorization = request.headers.get("authorization", "")
    if authorization.startswith("Basic "):
        try:
            decoded = base64.b64decode(authorization[6:], validate=True).decode("utf-8")
            client_id, client_secret = decoded.split(":", 1)
            return client_id, client_secret
        except (ValueError, UnicodeDecodeError):
            return "", ""
    return str(form.get("client_id", "")), str(form.get("client_secret", ""))


def token_response(client_id: str, scope: str, refresh_token: str | None = None) -> JSONResponse:
    oauth_state.prune()
    if refresh_token is None:
        refresh_token = secrets.token_urlsafe(48)
        oauth_state.refresh_tokens[token_hash(refresh_token)] = {
            "client_id": client_id,
            "scope": scope,
            "expires": time.time() + 90 * 86400,
        }
        persist_refresh_tokens()
    return JSONResponse(
        {
            "access_token": issue_access_token(client_id, scope),
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": refresh_token,
            "scope": scope,
        },
        headers={"cache-control": "no-store", "pragma": "no-cache"},
    )


def _rate_limit_key(request: Request, suffix: str) -> str:
    host = request.client.host if request.client else "unknown"
    return f"{suffix}:{host}"


def _is_rate_limited(key: str, limit: int = 10) -> bool:
    oauth_state.prune()
    return len(oauth_state.failed_attempts_by_key[key]) >= limit


def _record_failure(key: str) -> None:
    oauth_state.failed_attempts_by_key[key].append(time.time())


async def token(request: Request) -> Response:
    rate_key = _rate_limit_key(request, "token")
    if _is_rate_limited(rate_key):
        return JSONResponse(
            {"error": "too_many_requests", "error_description": "Too many failed attempts"},
            status_code=429,
            headers={"cache-control": "no-store", "retry-after": "900"},
        )
    form = await request.form()
    load_refresh_tokens()
    client_id, client_secret = client_credentials(request, form)
    credentials = load_or_create_credentials()
    if not secrets.compare_digest(
        client_id, credentials["client_id"]
    ) or not secrets.compare_digest(client_secret, credentials["client_secret"]):
        _record_failure(rate_key)
        return JSONResponse({"error": "invalid_client"}, status_code=401)
    grant_type = str(form.get("grant_type", ""))
    if grant_type == "refresh_token":
        token_value = str(form.get("refresh_token", ""))
        grant_hash = token_hash(token_value)
        grant = oauth_state.refresh_tokens.get(grant_hash)
        if not grant or grant["expires"] <= time.time() or grant["client_id"] != client_id:
            _record_failure(rate_key)
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        if settings.rotate_refresh_tokens:
            oauth_state.refresh_tokens.pop(grant_hash, None)
            return token_response(client_id, grant["scope"], None)
        grant["expires"] = time.time() + 90 * 86400
        persist_refresh_tokens()
        return token_response(client_id, grant["scope"], token_value)
    if grant_type != "authorization_code":
        return oauth_error("Unsupported grant_type")
    code_hash = hashlib.sha256(str(form.get("code", "")).encode()).hexdigest()
    grant = oauth_state.codes.pop(code_hash, None)
    verifier = str(form.get("code_verifier", ""))
    if not grant or grant["expires"] <= time.time() or not valid_code_verifier(verifier):
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    expected_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    if (
        grant["client_id"] != client_id
        or grant["redirect_uri"] != str(form.get("redirect_uri", ""))
        or not secrets.compare_digest(grant["code_challenge"], expected_challenge)
    ):
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    return token_response(client_id, grant["scope"])


async def revoke(request: Request) -> Response:
    rate_key = _rate_limit_key(request, "revoke")
    if _is_rate_limited(rate_key):
        return JSONResponse(
            {"error": "too_many_requests", "error_description": "Too many failed attempts"},
            status_code=429,
            headers={"cache-control": "no-store", "retry-after": "900"},
        )
    form = await request.form()
    load_refresh_tokens()
    client_id, client_secret = client_credentials(request, form)
    credentials = load_or_create_credentials()
    if not secrets.compare_digest(
        client_id, credentials["client_id"]
    ) or not secrets.compare_digest(client_secret, credentials["client_secret"]):
        _record_failure(rate_key)
        return JSONResponse({"error": "invalid_client"}, status_code=401)
    token_value = str(form.get("token", ""))
    oauth_state.refresh_tokens.pop(token_hash(token_value), None)
    persist_refresh_tokens()
    return Response(status_code=200, headers={"cache-control": "no-store"})


async def authorization_metadata(_: Request) -> JSONResponse:
    origin = public_origin()
    return JSONResponse(
        {
            "issuer": origin,
            "authorization_endpoint": f"{origin}/oauth/authorize",
            "token_endpoint": f"{origin}/oauth/token",
            "revocation_endpoint": f"{origin}/oauth/revoke",
            "registration_endpoint": f"{origin}/oauth/register",
            "jwks_uri": f"{origin}/oauth/jwks",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "scopes_supported": list(SCOPES),
        },
        headers={"cache-control": "no-store"},
    )


async def register(_: Request) -> JSONResponse:
    return JSONResponse(
        {
            "error": "registration_not_supported",
            "error_description": "Use the pre-registered Client ID and secret in Gemini settings.",
        },
        status_code=400,
    )


async def jwks_endpoint(_: Request) -> JSONResponse:
    return JSONResponse(public_jwks(), headers={"cache-control": "public, max-age=300"})
