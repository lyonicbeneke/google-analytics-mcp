"""
Google Analytics 4 MCP Server — MCP Auth Spec 2025-03-26

OAuth 2.0 Authorization Server endpoints (spec-compliant paths, no /oauth/ prefix):
  GET  /.well-known/oauth-authorization-server  — RFC 8414 metadata
  POST /register                                — RFC 7591 Dynamic Client Registration
  GET  /authorize                               — authorization endpoint (proxies to Google)
  GET  /oauth/callback                          — Google OAuth callback (internal)
  POST /token                                   — token endpoint

MCP Streamable HTTP:
  POST /mcp   — JSON-RPC dispatcher (requires Bearer token)
  GET  /mcp   — SSE keepalive channel
"""

import base64
import hashlib
import json
import os
import secrets
import sys
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlencode

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse

from src.auth import (
    google_auth_url,
    google_exchange_code,
    credentials_from_token_data,
)
from src.storage import (
    save_client, load_client,
    save_oauth_session, load_oauth_session, delete_oauth_session,
    save_auth_code, load_auth_code, delete_auth_code,
    save_access_token, load_access_token,
    save_token, load_token,
)
import src.ga_tools as ga

BASE_URL = os.getenv("BASE_URL", "http://localhost:8000").rstrip("/")
MCP_PROTOCOL_VERSION = "2025-03-26"


# ─── MCP Tool definitions (JSON Schema) ──────────────────────────────────────

TOOLS = [
    {
        "name": "run_report",
        "description": (
            "Run a GA4 Data API report. "
            "Top pages: dimensions=['pagePath'], metrics=['screenPageViews','sessions']. "
            "Traffic sources: dimensions=['sessionSource','sessionMedium'], metrics=['sessions','conversions']. "
            "Countries: dimensions=['country'], metrics=['sessions','newUsers']."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "property_id": {"type": "string", "description": "GA4 property ID, e.g. '123456789'"},
                "dimensions": {"type": "array", "items": {"type": "string"}, "description": "e.g. ['pagePath','country','deviceCategory']"},
                "metrics": {"type": "array", "items": {"type": "string"}, "description": "e.g. ['sessions','conversions','totalRevenue','screenPageViews']"},
                "start_date": {"type": "string", "default": "7daysAgo", "description": "e.g. '7daysAgo', '30daysAgo', '2024-01-01'"},
                "end_date": {"type": "string", "default": "today", "description": "e.g. 'today', 'yesterday'"},
                "limit": {"type": "integer", "default": 10},
            },
            "required": ["property_id", "dimensions", "metrics"],
        },
    },
    {
        "name": "get_account_summaries",
        "description": "List all GA4 accounts and properties the user has access to. Call this first to discover property IDs.",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "add_referral_exclusion",
        "description": "Exclude a domain from referral traffic (e.g. 'paypal.com', 'checkout.stripe.com') to prevent session inflation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "property_id": {"type": "string"},
                "domain": {"type": "string", "description": "e.g. 'paypal.com'"},
            },
            "required": ["property_id", "domain"],
        },
    },
    {
        "name": "create_conversion_event",
        "description": "Mark an existing GA4 event as a conversion event.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "property_id": {"type": "string"},
                "event_name": {"type": "string", "description": "e.g. 'purchase', 'sign_up', 'form_submit'"},
            },
            "required": ["property_id", "event_name"],
        },
    },
    {
        "name": "create_audience",
        "description": "Create a GA4 audience for remarketing or analysis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "property_id": {"type": "string"},
                "display_name": {"type": "string"},
                "description": {"type": "string"},
                "membership_duration_days": {"type": "integer", "description": "1–540"},
                "filter_clauses": {"type": "array", "items": {"type": "object"}},
            },
            "required": ["property_id", "display_name", "description", "membership_duration_days", "filter_clauses"],
        },
    },
    {
        "name": "update_property_settings",
        "description": "Update GA4 property name, industry category, timezone, or currency.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "property_id": {"type": "string"},
                "display_name": {"type": "string"},
                "industry_category": {"type": "string", "description": "e.g. TECHNOLOGY, RETAIL, FINANCE, HEALTHCARE"},
                "time_zone": {"type": "string", "description": "e.g. 'Europe/Berlin'"},
                "currency_code": {"type": "string", "description": "e.g. 'EUR', 'USD'"},
            },
            "required": ["property_id"],
        },
    },
]


# ─── MCP tool dispatcher ──────────────────────────────────────────────────────

async def _dispatch_tool(name: str, args: dict, creds) -> Any:
    if name == "run_report":
        return ga.run_report(
            credentials=creds,
            property_id=args["property_id"],
            dimensions=args["dimensions"],
            metrics=args["metrics"],
            date_ranges=[{"start_date": args.get("start_date", "7daysAgo"), "end_date": args.get("end_date", "today")}],
            limit=args.get("limit", 10),
        )
    if name == "get_account_summaries":
        return ga.get_account_summaries(credentials=creds)
    if name == "add_referral_exclusion":
        return ga.add_referral_exclusion(credentials=creds, property_id=args["property_id"], domain=args["domain"])
    if name == "create_conversion_event":
        return ga.create_conversion_event(credentials=creds, property_id=args["property_id"], event_name=args["event_name"])
    if name == "create_audience":
        return ga.create_audience(
            credentials=creds,
            property_id=args["property_id"],
            display_name=args["display_name"],
            description=args["description"],
            membership_duration_days=args["membership_duration_days"],
            filter_clauses=args["filter_clauses"],
        )
    if name == "update_property_settings":
        return ga.update_property_settings(
            credentials=creds,
            property_id=args["property_id"],
            display_name=args.get("display_name"),
            industry_category=args.get("industry_category"),
            time_zone=args.get("time_zone"),
            currency_code=args.get("currency_code"),
        )
    raise ValueError(f"Unknown tool: {name}")


async def _handle_jsonrpc(msg: dict, creds, session_id: str) -> Optional[dict]:
    """Handle one JSON-RPC message. Returns None for notifications."""
    method = msg.get("method", "")
    params = msg.get("params", {})
    msg_id = msg.get("id")

    if msg_id is None:
        return None  # notification — no response

    try:
        if method == "initialize":
            result = {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "google-analytics", "version": "1.0.0"},
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            tool_result = await _dispatch_tool(params["name"], params.get("arguments", {}), creds)
            result = {"content": [{"type": "text", "text": json.dumps(tool_result, indent=2, ensure_ascii=False)}]}
        else:
            return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}
    except Exception as exc:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32603, "message": str(exc)}}


def _resolve_bearer(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def _unauthorized_response(session_id: str = "") -> Response:
    """Return 401 with WWW-Authenticate pointing to our auth server."""
    if not session_id:
        session_id = str(uuid.uuid4())
    return Response(
        content=json.dumps({"error": "unauthorized", "error_description": "Bearer token required"}),
        status_code=401,
        media_type="application/json",
        headers={
            "mcp-session-id": session_id,
            "WWW-Authenticate": (
                f'Bearer realm="google-analytics", '
                f'resource_metadata="{BASE_URL}/.well-known/oauth-protected-resource"'
            ),
        },
    )


# ─── FastAPI app ──────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    Path(os.getenv("TOKEN_STORAGE_DIR", "/tmp/ga_tokens")).mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(
    title="Google Analytics MCP Server",
    description="MCP Auth Spec 2025-03-26 — GA4 Data + Admin API",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Mcp-Session-Id", "MCP-Protocol-Version"],
    expose_headers=["Mcp-Session-Id"],
)


# ─── OAuth 2.0 Authorization Server Metadata (RFC 8414) ──────────────────────

@app.get("/.well-known/oauth-authorization-server")
async def oauth_authorization_server_metadata():
    # Paths MUST match the MCP spec default fallbacks: /authorize, /token, /register
    return JSONResponse({
        "issuer": BASE_URL,
        "authorization_endpoint": f"{BASE_URL}/authorize",
        "token_endpoint": f"{BASE_URL}/token",
        "registration_endpoint": f"{BASE_URL}/register",
        "scopes_supported": ["analytics"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        "service_documentation": f"{BASE_URL}/status",
    })


@app.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource_metadata():
    """RFC 9728 — tells clients where to find the auth server."""
    return JSONResponse({
        "resource": f"{BASE_URL}/mcp",
        "authorization_servers": [BASE_URL],
        "scopes_supported": ["analytics"],
        "bearer_methods_supported": ["header"],
        "resource_name": "Google Analytics MCP Server",
    })


# ─── Dynamic Client Registration (RFC 7591) ───────────────────────────────────

@app.post("/register")
async def oauth_register(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    redirect_uris = body.get("redirect_uris", [])
    if not redirect_uris:
        return JSONResponse({"error": "invalid_request", "error_description": "redirect_uris required"}, status_code=400)

    client_id = str(uuid.uuid4())
    client_secret = secrets.token_urlsafe(32)
    issued_at = int(time.time())

    auth_method = body.get("token_endpoint_auth_method", "client_secret_post")
    client_data = {
        "client_id": client_id,
        "client_id_issued_at": issued_at,
        "redirect_uris": redirect_uris,
        "client_name": body.get("client_name", "MCP Client"),
        "grant_types": body.get("grant_types", ["authorization_code"]),
        "response_types": body.get("response_types", ["code"]),
        "token_endpoint_auth_method": auth_method,
    }
    # Only include client_secret for confidential clients
    if auth_method != "none":
        client_data["client_secret"] = client_secret

    save_client(client_id, client_data)
    return JSONResponse(client_data, status_code=201)


# ─── Authorization endpoint ───────────────────────────────────────────────────

@app.get("/authorize")
async def oauth_authorize(
    request: Request,
    response_type: str = "code",
    client_id: Optional[str] = None,
    redirect_uri: Optional[str] = None,
    state: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: str = "S256",
    scope: Optional[str] = None,
):
    if response_type != "code":
        return JSONResponse({"error": "unsupported_response_type"}, status_code=400)

    # Validate redirect_uri against registered client if client is found in storage.
    if client_id and redirect_uri:
        client = load_client(client_id)
        if client and redirect_uri not in client["redirect_uris"]:
            return JSONResponse({"error": "invalid_request", "error_description": "redirect_uri mismatch"}, status_code=400)

    # Stable user_id ties this MCP session to GA4 credentials
    user_id = secrets.token_urlsafe(16)
    session_key = secrets.token_urlsafe(24)
    save_oauth_session(session_key, {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "client_state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "user_id": user_id,
    })

    # Show consent page — user must connect their GA4 account before proceeding
    ga_auth_url = f"{BASE_URL}/auth/google?user_id={user_id}&session_key={session_key}"
    return HTMLResponse(f"""<!DOCTYPE html>
<html><head><title>Connect Google Analytics</title>
<style>
  body{{font-family:system-ui,sans-serif;max-width:480px;margin:80px auto;padding:0 24px;text-align:center}}
  h1{{font-size:1.5em;margin-bottom:8px}}
  p{{color:#555;line-height:1.6}}
  .btn{{display:inline-block;background:#4285f4;color:#fff;padding:14px 36px;border-radius:8px;
        text-decoration:none;font-size:1em;font-weight:600;margin-top:28px}}
  .btn:hover{{background:#3367d6}}
  .note{{margin-top:24px;font-size:.85em;color:#888}}
</style></head>
<body>
  <div style="font-size:2.5em;margin-bottom:12px">📊</div>
  <h1>Google Analytics MCP</h1>
  <p>To use Google Analytics tools in Claude,<br>connect your Google Analytics account.</p>
  <a class="btn" href="{ga_auth_url}">Connect Google Analytics</a>
  <p class="note">You will be redirected to Google to grant read/write access<br>to your Analytics properties.</p>
</body></html>""")


# ─── GA4 OAuth (user-facing, separate from MCP auth) ─────────────────────────

@app.get("/auth/google")
async def auth_google(user_id: str, session_key: Optional[str] = None):
    """
    Start Google OAuth for a specific user_id.
    - Initial flow: called from the /authorize consent page with session_key
    - Reconnect flow: called from a tool error link with just user_id
    State passed to Google = "session_key:user_id" (initial) or "user_id" (reconnect).
    """
    if not user_id:
        return HTMLResponse("<h1>Bad Request</h1><p>user_id required.</p>", status_code=400)

    # Encode both pieces into the Google OAuth state so the callback can recover them
    google_state = f"{session_key}:{user_id}" if session_key else user_id
    return RedirectResponse(url=google_auth_url(google_state))


# ─── Google OAuth callback ────────────────────────────────────────────────────

@app.get("/oauth/callback")
async def oauth_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
):
    if error:
        return HTMLResponse(f"<h1>Google OAuth Error</h1><p>{error}</p>", status_code=400)
    if not code or not state:
        return HTMLResponse("<h1>Bad Request</h1><p>Missing code or state.</p>", status_code=400)

    # Exchange Google auth code for GA4 tokens
    try:
        google_tokens = google_exchange_code(code, state)
    except Exception as e:
        return HTMLResponse(f"<h1>Token Exchange Failed</h1><p>{e}</p>", status_code=400)

    if ":" in state:
        # ── Initial flow: state = "session_key:user_id" ──
        session_key, user_id = state.split(":", 1)
        session = load_oauth_session(session_key)
        if not session:
            return HTMLResponse(
                "<h1>Session Expired</h1>"
                "<p>The session was lost (server may have restarted). "
                "Please start the connection again from claude.ai.</p>",
                status_code=400,
            )
        delete_oauth_session(session_key)

        # Persist GA4 token for this user
        save_token(user_id, google_tokens)

        # Issue MCP auth code carrying user_id (not google_tokens)
        auth_code = secrets.token_urlsafe(32)
        save_auth_code(auth_code, {
            "client_id": session.get("client_id"),
            "redirect_uri": session.get("redirect_uri"),
            "code_challenge": session.get("code_challenge"),
            "code_challenge_method": session.get("code_challenge_method", "S256"),
            "user_id": user_id,
        })

        redirect_uri = session.get("redirect_uri")
        client_state = session.get("client_state")
        if redirect_uri:
            params: dict = {"code": auth_code}
            if client_state:
                params["state"] = client_state
            return RedirectResponse(url=f"{redirect_uri}?{urlencode(params)}")
        return HTMLResponse(f"<h1>Authorized</h1><p>Code: <code>{auth_code}</code></p>")

    else:
        # ── Reconnect flow: state = "user_id" ──
        user_id = state
        save_token(user_id, google_tokens)
        return HTMLResponse("""<!DOCTYPE html>
<html><head><title>GA4 Connected</title>
<style>body{font-family:system-ui,sans-serif;max-width:480px;margin:80px auto;padding:0 24px;text-align:center}
.ok{color:#16a34a;font-size:2em}</style></head>
<body>
  <div class="ok">✓</div>
  <h1>Google Analytics Connected</h1>
  <p>Your GA4 account has been linked. You can now use Google Analytics tools in Claude.</p>
  <p style="color:#888;font-size:.9em">You may close this tab.</p>
</body></html>""")


# ─── Token endpoint ───────────────────────────────────────────────────────────

@app.post("/token")
async def oauth_token(request: Request):
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid_request"}, status_code=400)
    else:
        form = await request.form()
        body = dict(form)

    grant_type = body.get("grant_type")
    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    code = body.get("code")
    client_id = body.get("client_id")
    redirect_uri = body.get("redirect_uri")
    code_verifier = body.get("code_verifier")

    if not code:
        return JSONResponse({"error": "invalid_request", "error_description": "code required"}, status_code=400)

    code_data = load_auth_code(code)
    if not code_data:
        return JSONResponse({"error": "invalid_grant", "error_description": "code not found or expired"}, status_code=400)

    # Verify client_id matches
    if client_id and code_data.get("client_id") and client_id != code_data["client_id"]:
        return JSONResponse({"error": "invalid_client"}, status_code=400)

    # Verify redirect_uri matches
    if redirect_uri and code_data.get("redirect_uri") and redirect_uri != code_data["redirect_uri"]:
        return JSONResponse({"error": "invalid_grant", "error_description": "redirect_uri mismatch"}, status_code=400)

    # Verify PKCE
    stored_challenge = code_data.get("code_challenge")
    if stored_challenge:
        if not code_verifier:
            return JSONResponse({"error": "invalid_request", "error_description": "code_verifier required"}, status_code=400)
        computed = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b"=").decode()
        if computed != stored_challenge:
            return JSONResponse({"error": "invalid_grant", "error_description": "code_verifier mismatch"}, status_code=400)

    # Issue our access token (stores user_id, not google_tokens — GA4 token lives separately)
    access_token = secrets.token_urlsafe(40)
    expires_in = 86400 * 30  # 30 days

    save_access_token(access_token, {
        "client_id": code_data.get("client_id"),
        "user_id": code_data["user_id"],
        "issued_at": time.time(),
        "expires_at": time.time() + expires_in,
    })
    delete_auth_code(code)

    return JSONResponse({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
        "scope": "analytics",
    })


# ─── MCP Streamable HTTP endpoints ───────────────────────────────────────────

@app.post("/mcp")
async def mcp_post(request: Request):
    session_id = request.headers.get("mcp-session-id", str(uuid.uuid4()))
    bearer = _resolve_bearer(request)

    # Two-layer auth:
    #   mcp_authed  = bearer token is known to our server (MCP-level auth)
    #   creds       = Google Analytics credentials (GA4-level auth)
    mcp_authed = False
    user_id = None
    creds = None

    if bearer:
        token_data = load_access_token(bearer)
        if token_data:
            mcp_authed = True
            user_id = token_data.get("user_id")
            if user_id:
                ga4_token_data = load_token(user_id)
                if ga4_token_data:
                    creds = credentials_from_token_data(
                        ga4_token_data,
                        bearer,
                        lambda updates: save_token(user_id, updates),
                    )

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
            status_code=400,
        )

    headers = {"mcp-session-id": session_id}

    # Methods that don't need any auth
    NO_AUTH = ("initialize", "ping", "notifications/initialized", "tools/list", None)

    def _needs_mcp_auth(msg: dict) -> bool:
        return msg.get("method") not in NO_AUTH

    def _is_tool_call(msg: dict) -> bool:
        return msg.get("method") == "tools/call"

    def _ga4_missing_error(msg: dict) -> dict:
        """Return a tools/call result telling the user to connect GA4."""
        auth_link = f"{BASE_URL}/auth/google?user_id={user_id}" if user_id else f"{BASE_URL}/status"
        return {
            "jsonrpc": "2.0",
            "id": msg.get("id"),
            "result": {
                "content": [{
                    "type": "text",
                    "text": (
                        "⚠️ Google Analytics is not connected yet.\n\n"
                        "Please authorize your GA4 account by opening this link:\n\n"
                        f"{auth_link}\n\n"
                        "After connecting, try again."
                    ),
                }],
                "isError": True,
            },
        }

    if isinstance(body, list):
        # 401 only if MCP token is missing for methods that need it
        if any(_needs_mcp_auth(m) for m in body) and not mcp_authed:
            return _unauthorized_response(session_id)
        responses = []
        for m in body:
            if _is_tool_call(m) and not creds:
                responses.append(_ga4_missing_error(m))
            else:
                r = await _handle_jsonrpc(m, creds, session_id)
                if r is not None:
                    responses.append(r)
        if not responses:
            return Response(status_code=202, headers=headers)
        return JSONResponse(content=responses, headers=headers)

    # Single message
    if _needs_mcp_auth(body) and not mcp_authed:
        return _unauthorized_response(session_id)

    if _is_tool_call(body) and not creds:
        return JSONResponse(content=_ga4_missing_error(body), headers=headers)

    response = await _handle_jsonrpc(body, creds, session_id)
    if response is None:
        return Response(status_code=202, headers=headers)
    return JSONResponse(content=response, headers=headers)


@app.get("/mcp")
async def mcp_get(request: Request):
    """SSE channel for server-initiated messages (required by MCP spec)."""
    bearer = _resolve_bearer(request)
    session_id = request.headers.get("mcp-session-id", str(uuid.uuid4()))

    if not bearer or not load_access_token(bearer):
        return _unauthorized_response(session_id)

    async def keepalive():
        yield ": keepalive\n\n"

    return StreamingResponse(
        keepalive(),
        media_type="text/event-stream",
        headers={"mcp-session-id": session_id, "cache-control": "no-cache"},
    )


# ─── Status & Health ──────────────────────────────────────────────────────────


@app.get("/status", response_class=HTMLResponse)
async def status():
    return HTMLResponse(f"""<!DOCTYPE html>
<html><head><title>GA MCP — Status</title>
<style>body{{font-family:system-ui,sans-serif;max-width:700px;margin:60px auto;padding:0 20px}}
code{{background:#f0f0f0;padding:2px 6px;border-radius:4px}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:8px 12px}}th{{background:#f5f5f5}}</style>
</head><body>
  <h1>Google Analytics MCP Server</h1>
  <p><strong style="color:#16a34a">Running</strong> &nbsp;|&nbsp; MCP Auth Spec <code>{MCP_PROTOCOL_VERSION}</code></p>
  <p>Auth metadata: <code><a href="/.well-known/oauth-authorization-server">/.well-known/oauth-authorization-server</a></code></p>
  <p>MCP endpoint: <code>{BASE_URL}/mcp</code></p>

  <h2>OAuth Flow (claude.ai)</h2>
  <ol>
    <li>claude.ai fetches <code>/.well-known/oauth-authorization-server</code></li>
    <li>Registers via <code>POST /register</code></li>
    <li>Redirects user to <code>/authorize</code> → Google OAuth</li>
    <li>Exchanges code at <code>POST /token</code> for Bearer token</li>
    <li>Uses Bearer token on <code>POST /mcp</code></li>
  </ol>

  <h2>Active MCP Sessions</h2>
  <p>Sessions are stored in <code>/tmp/ga_tokens/</code> (ephemeral on Render free tier).</p>
</body></html>""")


@app.get("/health")
async def health():
    return {"status": "ok", "protocol": MCP_PROTOCOL_VERSION}


@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(f"""<!DOCTYPE html>
<html><head><title>GA MCP Server</title>
<style>body{{font-family:system-ui,sans-serif;max-width:600px;margin:60px auto;padding:0 20px}}</style>
</head><body>
  <h1>Google Analytics MCP Server</h1>
  <p>MCP Auth Spec <code>{MCP_PROTOCOL_VERSION}</code></p>
  <ul>
    <li><a href="/.well-known/oauth-authorization-server">OAuth Metadata</a></li>
    <li><a href="/status">Server Status</a></li>
    <li>MCP endpoint: <code>{BASE_URL}/mcp</code></li>
  </ul>
</body></html>""")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=False)
