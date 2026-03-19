"""
Google Analytics 4 MCP Server
FastAPI app combining:
  - MCP Streamable HTTP transport (2025-03-26) at POST/GET /mcp
  - OAuth 2.0 web flow at /oauth/*
"""

import json
import os
import sys
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv

load_dotenv()

_REQUIRED = ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "SECRET_KEY"]
_missing = [v for v in _REQUIRED if not os.getenv(v)]
if _missing:
    print(f"ERROR: Missing required env vars: {', '.join(_missing)}", file=sys.stderr)

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse

from src.auth import get_authorization_url, exchange_code, get_credentials
from src.storage import (
    get_or_create_api_key,
    get_user_by_api_key,
    list_users,
    delete_token,
)
import src.ga_tools as ga


# ─── MCP Protocol ─────────────────────────────────────────────────────────────

MCP_PROTOCOL_VERSION = "2025-03-26"

TOOLS = [
    {
        "name": "run_report",
        "description": (
            "Run a GA4 Data API report to fetch traffic, conversions, top pages, or any metric combination. "
            "Common combos: top pages → dimensions=['pagePath'], metrics=['screenPageViews','sessions']; "
            "traffic sources → dimensions=['sessionSource','sessionMedium'], metrics=['sessions','conversions']; "
            "countries → dimensions=['country'], metrics=['sessions','newUsers']."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "description": "User ID from OAuth login (or 'auto' to resolve from API key)"},
                "property_id": {"type": "string", "description": "GA4 property ID, e.g. '123456789'"},
                "dimensions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Dimension names, e.g. ['pagePath', 'sessionSource', 'country', 'deviceCategory']",
                },
                "metrics": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Metric names, e.g. ['sessions', 'conversions', 'totalRevenue', 'screenPageViews', 'newUsers']",
                },
                "start_date": {"type": "string", "description": "Start date, e.g. '7daysAgo', '30daysAgo', '2024-01-01'", "default": "7daysAgo"},
                "end_date": {"type": "string", "description": "End date, e.g. 'today', 'yesterday', '2024-01-31'", "default": "today"},
                "limit": {"type": "integer", "description": "Max rows (default 10)", "default": 10},
            },
            "required": ["user_id", "property_id", "dimensions", "metrics"],
        },
    },
    {
        "name": "get_account_summaries",
        "description": "List all GA4 accounts and properties the authenticated user has access to. Use this first to discover property IDs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "description": "User ID from OAuth login (or 'auto')"},
            },
            "required": ["user_id"],
        },
    },
    {
        "name": "add_referral_exclusion",
        "description": "Add a referral exclusion to a GA4 property to prevent self-referral traffic inflation from payment processors like PayPal or Stripe.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "description": "User ID from OAuth login (or 'auto')"},
                "property_id": {"type": "string", "description": "GA4 property ID"},
                "domain": {"type": "string", "description": "Domain to exclude, e.g. 'paypal.com', 'checkout.stripe.com'"},
            },
            "required": ["user_id", "property_id", "domain"],
        },
    },
    {
        "name": "create_conversion_event",
        "description": "Mark an existing GA4 event as a conversion event. The event must already be tracked by GA4.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "description": "User ID from OAuth login (or 'auto')"},
                "property_id": {"type": "string", "description": "GA4 property ID"},
                "event_name": {"type": "string", "description": "Exact GA4 event name, e.g. 'purchase', 'sign_up', 'form_submit'"},
            },
            "required": ["user_id", "property_id", "event_name"],
        },
    },
    {
        "name": "create_audience",
        "description": "Create a GA4 audience for remarketing or analysis segments.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "description": "User ID from OAuth login (or 'auto')"},
                "property_id": {"type": "string", "description": "GA4 property ID"},
                "display_name": {"type": "string", "description": "Audience name, e.g. 'Purchasers last 30 days'"},
                "description": {"type": "string", "description": "Audience description"},
                "membership_duration_days": {"type": "integer", "description": "Days users stay in audience (1–540)"},
                "filter_clauses": {
                    "type": "array",
                    "items": {"type": "object"},
                    "description": (
                        "Audience filter clauses. Example: "
                        '[{"clauseType":"INCLUDE","simpleFilter":{"scope":"AUDIENCE_FILTER_SCOPE_ACROSS_ALL_SESSIONS",'
                        '"filterExpression":{"andGroup":{"filterExpressions":[{"dimensionOrMetricFilter":'
                        '{"fieldName":"eventName","stringFilter":{"matchType":"EXACT","value":"purchase"}}}]}}}}]'
                    ),
                },
            },
            "required": ["user_id", "property_id", "display_name", "description", "membership_duration_days", "filter_clauses"],
        },
    },
    {
        "name": "update_property_settings",
        "description": "Update GA4 property settings: display name, industry category, timezone, or currency.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "description": "User ID from OAuth login (or 'auto')"},
                "property_id": {"type": "string", "description": "GA4 property ID"},
                "display_name": {"type": "string", "description": "New property display name (optional)"},
                "industry_category": {
                    "type": "string",
                    "description": "Industry, e.g. TECHNOLOGY, RETAIL, FINANCE, HEALTHCARE, TRAVEL (optional)",
                },
                "time_zone": {"type": "string", "description": "IANA timezone, e.g. 'Europe/Berlin', 'America/New_York' (optional)"},
                "currency_code": {"type": "string", "description": "ISO 4217 currency, e.g. 'EUR', 'USD', 'GBP' (optional)"},
            },
            "required": ["user_id", "property_id"],
        },
    },
]


def _resolve_user(user_id: str, bearer_token: Optional[str]) -> str:
    """Resolve 'auto' user_id to the user matching the Bearer token."""
    if user_id == "auto" and bearer_token:
        token = bearer_token.removeprefix("Bearer ").strip()
        resolved = get_user_by_api_key(token)
        if resolved:
            return resolved
    return user_id


def _get_creds_or_raise(user_id: str):
    creds = get_credentials(user_id)
    if not creds:
        raise RuntimeError(
            f"No valid credentials for user '{user_id}'. "
            f"Visit /oauth/login?user_id={user_id} to authenticate."
        )
    return creds


async def _dispatch_tool(name: str, args: dict, bearer_token: Optional[str]) -> Any:
    """Call the appropriate GA tool function."""
    raw_user_id = args.get("user_id", "auto")
    user_id = _resolve_user(raw_user_id, bearer_token)
    creds = _get_creds_or_raise(user_id)

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


async def _handle_message(msg: dict, session_id: str, bearer_token: Optional[str]) -> Optional[dict]:
    """Handle one JSON-RPC message. Returns None for notifications (no response)."""
    method = msg.get("method", "")
    params = msg.get("params", {})
    msg_id = msg.get("id")

    # Notifications carry no id and expect no response
    if msg_id is None:
        return None

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
            tool_result = await _dispatch_tool(
                params["name"], params.get("arguments", {}), bearer_token
            )
            result = {
                "content": [
                    {"type": "text", "text": json.dumps(tool_result, indent=2, ensure_ascii=False)}
                ]
            }
        else:
            return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}

        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    except Exception as exc:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32603, "message": str(exc)}}


# ─── FastAPI App ──────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    Path(os.getenv("TOKEN_STORAGE_DIR", "/tmp/ga_tokens")).mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(
    title="Google Analytics MCP Server",
    description="MCP Streamable HTTP server for GA4 Data API and Admin API with OAuth 2.0",
    lifespan=lifespan,
)


# ─── MCP Endpoints ────────────────────────────────────────────────────────────

@app.post("/mcp")
async def mcp_post(request: Request):
    """MCP Streamable HTTP — client-to-server messages."""
    session_id = request.headers.get("mcp-session-id", str(uuid.uuid4()))
    bearer = request.headers.get("authorization")

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
            status_code=400,
        )

    headers = {"mcp-session-id": session_id}

    if isinstance(body, list):
        responses = [r for r in [await _handle_message(m, session_id, bearer) for m in body] if r is not None]
        if not responses:
            return Response(status_code=202, headers=headers)
        return JSONResponse(content=responses, headers=headers)

    response = await _handle_message(body, session_id, bearer)
    if response is None:
        return Response(status_code=202, headers=headers)
    return JSONResponse(content=response, headers=headers)


@app.get("/mcp")
async def mcp_get(request: Request):
    """MCP Streamable HTTP — SSE channel for server-initiated messages."""
    session_id = request.headers.get("mcp-session-id", str(uuid.uuid4()))

    async def keepalive():
        yield ": keepalive\n\n"

    return StreamingResponse(
        keepalive(),
        media_type="text/event-stream",
        headers={"mcp-session-id": session_id, "cache-control": "no-cache"},
    )


# ─── OAuth Endpoints ──────────────────────────────────────────────────────────

@app.get("/oauth/login", response_class=HTMLResponse)
async def oauth_login(user_id: str = "default"):
    if not os.getenv("GOOGLE_CLIENT_ID") or not os.getenv("GOOGLE_CLIENT_SECRET"):
        return HTMLResponse("<h1>Config Error</h1><p>GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be set.</p>", status_code=500)
    auth_url, _ = get_authorization_url(user_id)
    return RedirectResponse(url=auth_url)


@app.get("/oauth/callback")
async def oauth_callback(code: str, state: str, request: Request):
    try:
        creds, user_id = exchange_code(code=code, state=state)
        api_key = get_or_create_api_key(user_id)
        base_url = os.getenv("BASE_URL", str(request.base_url).rstrip("/"))

        return HTMLResponse(f"""<!DOCTYPE html>
<html>
<head>
  <title>GA MCP — Authenticated</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 700px; margin: 60px auto; padding: 0 20px; }}
    code {{ background: #f0f0f0; padding: 4px 8px; border-radius: 4px; font-size: 0.9em; }}
    pre {{ background: #1e1e1e; color: #d4d4d4; padding: 20px; border-radius: 8px; overflow-x: auto; }}
    .ok {{ color: #16a34a; font-weight: bold; font-size: 1.2em; }}
    .warn {{ background: #fef3c7; border: 1px solid #f59e0b; padding: 12px; border-radius: 6px; margin: 8px 0; }}
  </style>
</head>
<body>
  <p class="ok">✓ Authenticated successfully!</p>
  <p>User ID: <code>{user_id}</code></p>

  <h2>API Key</h2>
  <div class="warn"><strong>Keep this secret!</strong></div>
  <pre>{api_key}</pre>

  <h2>claude.ai / Claude Desktop Config</h2>
  <pre>{{
  "mcpServers": {{
    "google-analytics": {{
      "type": "http",
      "url": "{base_url}/mcp",
      "headers": {{
        "Authorization": "Bearer {api_key}"
      }}
    }}
  }}
}}</pre>

  <p>Tools accept <code>user_id: "{user_id}"</code> or <code>user_id: "auto"</code> (resolves from API key).</p>
  <p><a href="/status">Server status</a></p>
</body>
</html>""")
    except Exception as e:
        return HTMLResponse(
            f"<h1>Authentication Failed</h1><p>{e}</p><p><a href='/oauth/login'>Try again</a></p>",
            status_code=400,
        )


@app.get("/oauth/logout")
async def oauth_logout(user_id: str = "default"):
    delete_token(user_id)
    return JSONResponse({"success": True, "message": f"Token for '{user_id}' deleted"})


# ─── Status & Health ──────────────────────────────────────────────────────────

@app.get("/status", response_class=HTMLResponse)
async def status(request: Request):
    users = list_users()
    base_url = os.getenv("BASE_URL", str(request.base_url).rstrip("/"))
    rows = "".join(
        f"<tr><td><code>{uid}</code></td><td>{'✓' if get_credentials(uid) else '✗ expired'}</td></tr>"
        for uid in users
    )
    return HTMLResponse(f"""<!DOCTYPE html>
<html>
<head><title>GA MCP — Status</title>
<style>body{{font-family:system-ui,sans-serif;max-width:700px;margin:60px auto;padding:0 20px}}
code{{background:#f0f0f0;padding:2px 6px;border-radius:4px}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:8px 12px}}th{{background:#f5f5f5}}</style>
</head>
<body>
  <h1>Google Analytics MCP Server</h1>
  <p>Status: <strong style="color:#16a34a">Running</strong> &nbsp;|&nbsp; Protocol: <code>{MCP_PROTOCOL_VERSION}</code></p>
  <p>MCP endpoint: <code>{base_url}/mcp</code></p>
  <h2>Authenticated Users ({len(users)})</h2>
  <table><tr><th>User ID</th><th>Token</th></tr>
  {rows or "<tr><td colspan='2'>None yet</td></tr>"}
  </table>
  <h2>Add a User</h2>
  <p><code>{base_url}/oauth/login?user_id=&lt;name&gt;</code></p>
  <h2>Tools</h2>
  <ul>
    <li><code>run_report</code> — traffic, conversions, top pages</li>
    <li><code>get_account_summaries</code> — list all GA4 properties</li>
    <li><code>add_referral_exclusion</code> — block PayPal/Stripe self-referrals</li>
    <li><code>create_conversion_event</code> — mark events as conversions</li>
    <li><code>create_audience</code> — create remarketing audiences</li>
    <li><code>update_property_settings</code> — name, timezone, currency</li>
  </ul>
</body>
</html>""")


@app.get("/health")
async def health():
    return {"status": "ok", "protocol": MCP_PROTOCOL_VERSION}


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    base_url = os.getenv("BASE_URL", str(request.base_url).rstrip("/"))
    return HTMLResponse(f"""<!DOCTYPE html>
<html><head><title>GA MCP Server</title>
<style>body{{font-family:system-ui,sans-serif;max-width:600px;margin:60px auto;padding:0 20px}}</style>
</head><body>
  <h1>Google Analytics MCP Server</h1>
  <ul>
    <li><a href="/oauth/login?user_id=default">Authenticate with Google</a></li>
    <li><a href="/status">Server Status</a></li>
    <li>MCP endpoint: <code>{base_url}/mcp</code></li>
  </ul>
</body></html>""")


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=int(os.getenv("PORT", "8000")), reload=False)
