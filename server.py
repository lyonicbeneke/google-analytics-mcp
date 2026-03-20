"""
Google Analytics MCP Server — rebuilt on official google-analytics-mcp tooling.

OAuth 2.0 Authorization Server (MCP Auth Spec 2025-03-26):
  GET  /.well-known/oauth-authorization-server  — RFC 8414 metadata
  GET  /.well-known/oauth-protected-resource
  POST /register                                — RFC 7591 Dynamic Client Registration
  GET  /authorize                               — shows connect page, creates session
  GET  /auth/google                             — initiates Google OAuth
  GET  /oauth/callback                          — Google redirects here
  POST /token                                   — issues MCP access token

  PKCE design: code_verifier is Fernet-encrypted into the Google OAuth state
  parameter — no /tmp storage needed, survives server restarts.

MCP Streamable HTTP:
  POST /mcp   — JSON-RPC dispatcher
  GET  /mcp   — SSE keepalive
"""

import base64
import hashlib
import json
import os
import secrets
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
    _creds_to_dict,
    decrypt_state,
)
from src.storage import (
    save_client, load_client,
    save_auth_code, load_auth_code, delete_auth_code,
    save_access_token, load_access_token,
    save_token, load_token,
)
import src.ga_tools as ga

BASE_URL = os.getenv("BASE_URL", "http://localhost:8000").rstrip("/")
MCP_PROTOCOL_VERSION = "2025-03-26"

# ─── MCP Tool definitions ─────────────────────────────────────────────────────

_PROPERTY_ID = {
    "type": ["integer", "string"],
    "description": "GA4 property ID — a number (123456789) or 'properties/123456789'",
}

TOOLS = [
    {
        "name": "get_account_summaries",
        "description": "List all GA4 accounts and properties the user has access to. Call this first to discover property IDs.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_property_details",
        "description": "Returns full details for a specific GA4 property (time zone, currency, industry, etc.).",
        "inputSchema": {
            "type": "object",
            "properties": {"property_id": _PROPERTY_ID},
            "required": ["property_id"],
        },
    },
    {
        "name": "list_google_ads_links",
        "description": "Lists Google Ads account links for a GA4 property.",
        "inputSchema": {
            "type": "object",
            "properties": {"property_id": _PROPERTY_ID},
            "required": ["property_id"],
        },
    },
    {
        "name": "list_property_annotations",
        "description": "Returns date annotations for a GA4 property (release notes, campaign launches, traffic anomalies, etc.).",
        "inputSchema": {
            "type": "object",
            "properties": {"property_id": _PROPERTY_ID},
            "required": ["property_id"],
        },
    },
    {
        "name": "run_report",
        "description": (
            "Run a GA4 Data API report. "
            "Examples — top pages: dimensions=['pagePath'], metrics=['screenPageViews','sessions']. "
            "Traffic sources: dimensions=['sessionSource','sessionMedium'], metrics=['sessions','conversions']. "
            "Countries: dimensions=['country'], metrics=['sessions','newUsers']. "
            "Relative dates: '7daysAgo', '30daysAgo', 'yesterday', 'today'. "
            "Absolute dates: 'YYYY-MM-DD'."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "property_id": _PROPERTY_ID,
                "date_ranges": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "start_date": {"type": "string"},
                            "end_date": {"type": "string"},
                            "name": {"type": "string"},
                        },
                        "required": ["start_date", "end_date"],
                    },
                    "description": "e.g. [{'start_date':'7daysAgo','end_date':'today'}]",
                },
                "dimensions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "e.g. ['pagePath', 'country', 'deviceCategory', 'sessionSource']",
                },
                "metrics": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "e.g. ['sessions', 'screenPageViews', 'conversions', 'totalRevenue', 'newUsers']",
                },
                "dimension_filter": {
                    "type": "object",
                    "description": "FilterExpression for dimensions (see GA4 Data API docs)",
                },
                "metric_filter": {
                    "type": "object",
                    "description": "FilterExpression for metrics (see GA4 Data API docs)",
                },
                "order_bys": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": "List of OrderBy objects",
                },
                "limit": {"type": "integer", "description": "Max rows (default: all)"},
                "offset": {"type": "integer", "description": "Row offset for pagination"},
                "currency_code": {"type": "string", "description": "ISO4217 currency code, e.g. 'EUR'"},
                "return_property_quota": {"type": "boolean"},
            },
            "required": ["property_id", "date_ranges", "dimensions", "metrics"],
        },
    },
    {
        "name": "run_realtime_report",
        "description": "Run a GA4 realtime report showing live active users. Use realtime dimensions/metrics.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "property_id": _PROPERTY_ID,
                "dimensions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Realtime dimensions, e.g. ['country', 'deviceCategory', 'unifiedScreenName']",
                },
                "metrics": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Realtime metrics, e.g. ['activeUsers']",
                },
                "dimension_filter": {"type": "object"},
                "metric_filter": {"type": "object"},
                "order_bys": {"type": "array", "items": {"type": "object"}},
                "limit": {"type": "integer"},
                "offset": {"type": "integer"},
                "return_property_quota": {"type": "boolean"},
            },
            "required": ["property_id", "dimensions", "metrics"],
        },
    },
    {
        "name": "get_custom_dimensions_and_metrics",
        "description": "Returns the property's custom dimensions and metrics. Use before run_report to find custom field names.",
        "inputSchema": {
            "type": "object",
            "properties": {"property_id": _PROPERTY_ID},
            "required": ["property_id"],
        },
    },
]

# ─── Tool dispatcher ──────────────────────────────────────────────────────────

async def _dispatch(name: str, args: dict, creds) -> Any:
    if name == "get_account_summaries":
        return await ga.get_account_summaries(creds)
    if name == "get_property_details":
        return await ga.get_property_details(creds, args["property_id"])
    if name == "list_google_ads_links":
        return await ga.list_google_ads_links(creds, args["property_id"])
    if name == "list_property_annotations":
        return await ga.list_property_annotations(creds, args["property_id"])
    if name == "run_report":
        return await ga.run_report(
            creds,
            args["property_id"],
            args["date_ranges"],
            args["dimensions"],
            args["metrics"],
            dimension_filter=args.get("dimension_filter"),
            metric_filter=args.get("metric_filter"),
            order_bys=args.get("order_bys"),
            limit=args.get("limit"),
            offset=args.get("offset"),
            currency_code=args.get("currency_code"),
            return_property_quota=args.get("return_property_quota", False),
        )
    if name == "run_realtime_report":
        return await ga.run_realtime_report(
            creds,
            args["property_id"],
            args["dimensions"],
            args["metrics"],
            dimension_filter=args.get("dimension_filter"),
            metric_filter=args.get("metric_filter"),
            order_bys=args.get("order_bys"),
            limit=args.get("limit"),
            offset=args.get("offset"),
            return_property_quota=args.get("return_property_quota", False),
        )
    if name == "get_custom_dimensions_and_metrics":
        return await ga.get_custom_dimensions_and_metrics(creds, args["property_id"])
    raise ValueError(f"Unknown tool: {name}")


# ─── JSON-RPC handler ─────────────────────────────────────────────────────────

async def _handle(msg: dict, creds, session_id: str) -> Optional[dict]:
    method = msg.get("method", "")
    params = msg.get("params", {})
    msg_id = msg.get("id")
    if msg_id is None:
        return None  # notification

    try:
        if method == "initialize":
            result = {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "google-analytics", "version": "2.0.0"},
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            output = await _dispatch(params["name"], params.get("arguments", {}), creds)
            result = {"content": [{"type": "text", "text": json.dumps(output, indent=2, ensure_ascii=False)}]}
        else:
            return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}
    except Exception as exc:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32603, "message": str(exc)}}


# ─── Auth helpers ─────────────────────────────────────────────────────────────

def _bearer(request: Request) -> Optional[str]:
    auth = request.headers.get("authorization", "")
    return auth[7:].strip() if auth.lower().startswith("bearer ") else None


def _unauthorized(session_id: str = "") -> Response:
    return Response(
        content=json.dumps({"error": "unauthorized"}),
        status_code=401,
        media_type="application/json",
        headers={
            "mcp-session-id": session_id or str(uuid.uuid4()),
            "WWW-Authenticate": (
                f'Bearer realm="google-analytics", '
                f'resource_metadata="{BASE_URL}/.well-known/oauth-protected-resource"'
            ),
        },
    )


def _ga4_missing(msg: dict, user_id: str) -> dict:
    link = f"{BASE_URL}/auth/google?user_id={user_id}" if user_id else f"{BASE_URL}/status"
    return {
        "jsonrpc": "2.0",
        "id": msg.get("id"),
        "result": {
            "content": [{
                "type": "text",
                "text": (
                    "⚠️ Google Analytics is not connected yet.\n\n"
                    f"Please authorize your GA4 account:\n{link}\n\n"
                    "After connecting, try again."
                ),
            }],
            "isError": True,
        },
    }


# ─── FastAPI app ──────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    Path(os.getenv("TOKEN_STORAGE_DIR", "/tmp/ga_tokens")).mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(title="Google Analytics MCP Server", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Mcp-Session-Id", "MCP-Protocol-Version"],
    expose_headers=["Mcp-Session-Id"],
)


# ─── OAuth 2.0 Authorization Server Metadata (RFC 8414) ──────────────────────

@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata():
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
    })


@app.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource():
    return JSONResponse({
        "resource": f"{BASE_URL}/mcp",
        "authorization_servers": [BASE_URL],
        "scopes_supported": ["analytics"],
        "bearer_methods_supported": ["header"],
    })


# ─── Dynamic Client Registration (RFC 7591) ───────────────────────────────────

@app.post("/register")
async def register(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)

    redirect_uris = body.get("redirect_uris", [])
    if not redirect_uris:
        return JSONResponse({"error": "invalid_request", "error_description": "redirect_uris required"}, status_code=400)

    client_id = str(uuid.uuid4())
    auth_method = body.get("token_endpoint_auth_method", "client_secret_post")
    client_data = {
        "client_id": client_id,
        "client_id_issued_at": int(time.time()),
        "redirect_uris": redirect_uris,
        "client_name": body.get("client_name", "MCP Client"),
        "grant_types": body.get("grant_types", ["authorization_code"]),
        "response_types": body.get("response_types", ["code"]),
        "token_endpoint_auth_method": auth_method,
    }
    if auth_method != "none":
        client_data["client_secret"] = secrets.token_urlsafe(32)

    save_client(client_id, client_data)
    return JSONResponse(client_data, status_code=201)


# ─── Authorization endpoint ───────────────────────────────────────────────────

@app.get("/authorize")
async def authorize(
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

    if client_id and redirect_uri:
        client = load_client(client_id)
        if client and redirect_uri not in client["redirect_uris"]:
            return JSONResponse({"error": "invalid_request", "error_description": "redirect_uri mismatch"}, status_code=400)

    user_id = secrets.token_urlsafe(16)

    # All session data is passed to /auth/google via query params — no /tmp needed
    ga_auth_params = urlencode({
        "user_id": user_id,
        "client_id": client_id or "",
        "redirect_uri": redirect_uri or "",
        "client_state": state or "",
        "code_challenge": code_challenge or "",
    })
    ga_auth_link = f"{BASE_URL}/auth/google?{ga_auth_params}"

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
  <p>Connect your Google Analytics account to use GA4 tools in Claude.</p>
  <a class="btn" href="{ga_auth_link}">Connect Google Analytics</a>
  <p class="note">Read-only access to your Analytics properties.</p>
</body></html>""")


# ─── GA4 OAuth (encrypted PKCE state, no /tmp) ───────────────────────────────

@app.get("/auth/google")
async def auth_google(
    user_id: str,
    client_id: str = "",
    redirect_uri: str = "",
    client_state: str = "",
    code_challenge: str = "",
):
    """
    Initiate Google OAuth.
    All session data + PKCE verifier are encrypted into the state parameter —
    no /tmp storage needed.
    """
    session_payload = {
        "user_id": user_id,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "client_state": client_state,
        "code_challenge": code_challenge,  # client's PKCE challenge (for /token verification)
    }
    return RedirectResponse(url=google_auth_url(session_payload))


@app.get("/auth/google/reconnect")
async def auth_google_reconnect(user_id: str):
    """
    Re-authorize GA4 for an existing MCP session (e.g. after server restart).
    No MCP session data needed — just refreshes the GA4 token for user_id.
    """
    session_payload = {
        "user_id": user_id,
        "client_id": "",
        "redirect_uri": "",
        "client_state": "",
        "code_challenge": "",
        "reconnect": True,
    }
    return RedirectResponse(url=google_auth_url(session_payload))


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

    # Decrypt the Fernet-encrypted state (contains session + PKCE verifier)
    try:
        session = decrypt_state(state)
    except Exception:
        return HTMLResponse(
            "<h1>Invalid State</h1><p>Could not decrypt OAuth state. Please try connecting again.</p>",
            status_code=400,
        )

    user_id = session.get("user_id", "")
    pkce_verifier = session.get("pkce_verifier", "")

    # Exchange Google authorization code (with PKCE verifier from encrypted state)
    try:
        ga4_tokens = google_exchange_code(code, pkce_verifier)
    except Exception as e:
        return HTMLResponse(f"<h1>Token Exchange Failed</h1><p>{e}</p>", status_code=400)

    # Persist GA4 token for this user
    save_token(user_id, ga4_tokens)

    # Reconnect flow: just show success
    if session.get("reconnect"):
        return HTMLResponse("""<!DOCTYPE html>
<html><head><title>GA4 Reconnected</title>
<style>body{font-family:system-ui,sans-serif;max-width:480px;margin:80px auto;padding:0 24px;text-align:center}
.ok{color:#16a34a;font-size:2.5em}</style></head>
<body>
  <div class="ok">✓</div>
  <h1>Google Analytics Reconnected</h1>
  <p>Your GA4 account has been re-linked. You can now use Google Analytics tools in Claude.</p>
  <p style="color:#888;font-size:.9em">You may close this tab.</p>
</body></html>""")

    # Initial flow: issue MCP auth code and redirect back to claude.ai
    redirect_uri = session.get("redirect_uri", "")
    client_state = session.get("client_state", "")

    auth_code = secrets.token_urlsafe(32)
    save_auth_code(auth_code, {
        "client_id": session.get("client_id"),
        "redirect_uri": redirect_uri,
        "code_challenge": session.get("code_challenge"),
        "user_id": user_id,
    })

    if redirect_uri:
        params: dict = {"code": auth_code}
        if client_state:
            params["state"] = client_state
        return RedirectResponse(url=f"{redirect_uri}?{urlencode(params)}")

    return HTMLResponse(f"<h1>Authorized</h1><p>Code: <code>{auth_code}</code></p>")


# ─── Token endpoint ───────────────────────────────────────────────────────────

@app.post("/token")
async def token(request: Request):
    ct = request.headers.get("content-type", "")
    if "application/json" in ct:
        try:
            body = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid_request"}, status_code=400)
    else:
        form = await request.form()
        body = dict(form)

    if body.get("grant_type") != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    code = body.get("code")
    if not code:
        return JSONResponse({"error": "invalid_request", "error_description": "code required"}, status_code=400)

    code_data = load_auth_code(code)
    if not code_data:
        return JSONResponse({"error": "invalid_grant", "error_description": "code not found or expired"}, status_code=400)

    client_id = body.get("client_id")
    if client_id and code_data.get("client_id") and client_id != code_data["client_id"]:
        return JSONResponse({"error": "invalid_client"}, status_code=400)

    redirect_uri = body.get("redirect_uri")
    if redirect_uri and code_data.get("redirect_uri") and redirect_uri != code_data["redirect_uri"]:
        return JSONResponse({"error": "invalid_grant", "error_description": "redirect_uri mismatch"}, status_code=400)

    # Verify PKCE (client's code_verifier against code_challenge stored in auth code)
    stored_challenge = code_data.get("code_challenge")
    if stored_challenge:
        code_verifier = body.get("code_verifier")
        if not code_verifier:
            return JSONResponse({"error": "invalid_request", "error_description": "code_verifier required"}, status_code=400)
        computed = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode()).digest()
        ).rstrip(b"=").decode()
        if computed != stored_challenge:
            return JSONResponse({"error": "invalid_grant", "error_description": "code_verifier mismatch"}, status_code=400)

    access_token = secrets.token_urlsafe(40)
    expires_in = 86400 * 30

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


# ─── MCP Streamable HTTP ──────────────────────────────────────────────────────

@app.post("/mcp")
async def mcp_post(request: Request):
    session_id = request.headers.get("mcp-session-id", str(uuid.uuid4()))
    token_str = _bearer(request)

    mcp_authed = False
    user_id = None
    creds = None

    if token_str:
        token_data = load_access_token(token_str)
        if token_data:
            mcp_authed = True
            user_id = token_data.get("user_id")
            if user_id:
                ga4 = load_token(user_id)
                if ga4:
                    creds = credentials_from_token_data(
                        ga4, user_id,
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
    NO_AUTH = ("initialize", "ping", "notifications/initialized", "tools/list", None)

    def needs_mcp(msg):
        return msg.get("method") not in NO_AUTH

    def is_tool_call(msg):
        return msg.get("method") == "tools/call"

    if isinstance(body, list):
        if any(needs_mcp(m) for m in body) and not mcp_authed:
            return _unauthorized(session_id)
        responses = []
        for m in body:
            if is_tool_call(m) and not creds:
                responses.append(_ga4_missing(m, user_id or ""))
            else:
                r = await _handle(m, creds, session_id)
                if r is not None:
                    responses.append(r)
        return (Response(status_code=202, headers=headers) if not responses
                else JSONResponse(content=responses, headers=headers))

    if needs_mcp(body) and not mcp_authed:
        return _unauthorized(session_id)
    if is_tool_call(body) and not creds:
        return JSONResponse(content=_ga4_missing(body, user_id or ""), headers=headers)

    response = await _handle(body, creds, session_id)
    if response is None:
        return Response(status_code=202, headers=headers)
    return JSONResponse(content=response, headers=headers)


@app.get("/mcp")
async def mcp_get(request: Request):
    token_str = _bearer(request)
    session_id = request.headers.get("mcp-session-id", str(uuid.uuid4()))

    if not token_str or not load_access_token(token_str):
        return _unauthorized(session_id)

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
a{{color:#4285f4}}</style>
</head><body>
  <h1>Google Analytics MCP Server</h1>
  <p><strong style="color:#16a34a">Running</strong> &nbsp;|&nbsp;
     MCP Auth Spec <code>{MCP_PROTOCOL_VERSION}</code> &nbsp;|&nbsp;
     <a href="/.well-known/oauth-authorization-server">OAuth Metadata</a></p>
  <p>MCP endpoint: <code>{BASE_URL}/mcp</code></p>

  <h2>Tools (7)</h2>
  <ul>{''.join(f"<li><code>{t['name']}</code></li>" for t in TOOLS)}</ul>

  <h2>OAuth Flow (claude.ai)</h2>
  <ol>
    <li>claude.ai discovers <code>/.well-known/oauth-authorization-server</code></li>
    <li>Registers via <code>POST /register</code></li>
    <li>User visits <code>/authorize</code> → clicks "Connect Google Analytics"</li>
    <li><code>/auth/google</code> → Google OAuth (PKCE verifier encrypted in state)</li>
    <li>Callback → GA4 token saved, MCP auth code issued → redirected to claude.ai</li>
    <li>claude.ai exchanges code at <code>POST /token</code></li>
    <li>Uses Bearer token on <code>POST /mcp</code></li>
  </ol>
  <p>Re-authorize GA4: <code>{BASE_URL}/auth/google/reconnect?user_id=&lt;id&gt;</code></p>
</body></html>""")


@app.get("/health")
async def health():
    return {"status": "ok", "protocol": MCP_PROTOCOL_VERSION, "tools": len(TOOLS)}


@app.get("/", response_class=HTMLResponse)
async def root():
    return HTMLResponse(f"""<!DOCTYPE html>
<html><head><title>GA MCP Server</title>
<style>body{{font-family:system-ui,sans-serif;max-width:600px;margin:60px auto;padding:0 20px}}</style>
</head><body>
  <h1>Google Analytics MCP Server</h1>
  <p>MCP Auth Spec <code>{MCP_PROTOCOL_VERSION}</code> &mdash; 7 read-only tools</p>
  <ul>
    <li><a href="/.well-known/oauth-authorization-server">OAuth Metadata</a></li>
    <li><a href="/status">Server Status</a></li>
    <li>MCP endpoint: <code>{BASE_URL}/mcp</code></li>
  </ul>
</body></html>""")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=False)
