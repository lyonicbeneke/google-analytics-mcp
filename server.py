"""
Google Analytics 4 MCP Server
Combines FastAPI (OAuth web flow) + MCP (Streamable HTTP transport)
"""

import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv

load_dotenv()

# Validate required env vars early
_REQUIRED = ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "SECRET_KEY"]
_missing = [v for v in _REQUIRED if not os.getenv(v)]
if _missing:
    print(f"ERROR: Missing required environment variables: {', '.join(_missing)}", file=sys.stderr)
    print("Copy .env.example to .env and fill in the values.", file=sys.stderr)
    # Don't exit — Render might set vars differently; let it fail at runtime

import httpx
from fastapi import FastAPI, HTTPException, Request, Header
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from mcp.server.fastmcp import FastMCP

from src.auth import get_authorization_url, exchange_code, get_credentials
from src.storage import (
    get_or_create_api_key,
    get_user_by_api_key,
    list_users,
    delete_token,
)
import src.ga_tools as ga

# ─── MCP Server ───────────────────────────────────────────────────────────────

mcp = FastMCP(
    name="google-analytics",
    instructions=(
        "Google Analytics 4 MCP Server. "
        "Authenticate at /oauth/login?user_id=<your-id> then use your API key "
        "as the Authorization: Bearer <key> header on /mcp requests."
    ),
)


def _get_creds_or_raise(user_id: str):
    """Load credentials for user_id or raise RuntimeError."""
    creds = get_credentials(user_id)
    if not creds:
        raise RuntimeError(
            f"No valid credentials for user '{user_id}'. "
            f"Visit /oauth/login?user_id={user_id} to authenticate."
        )
    return creds


# ─── MCP Tools ────────────────────────────────────────────────────────────────

@mcp.tool()
def run_report(
    user_id: str,
    property_id: str,
    dimensions: list[str],
    metrics: list[str],
    start_date: str = "7daysAgo",
    end_date: str = "today",
    limit: int = 10,
) -> dict[str, Any]:
    """
    Run a GA4 report to fetch traffic, conversions, top pages, or any custom metric.

    Args:
        user_id: your user ID (set during OAuth login)
        property_id: GA4 property ID (numeric, e.g. "123456789")
        dimensions: dimensions to break down by, e.g. ["pagePath", "sessionSource", "country"]
        metrics: metrics to retrieve, e.g. ["sessions", "conversions", "totalRevenue", "screenPageViews"]
        start_date: start date e.g. "7daysAgo", "30daysAgo", "2024-01-01"
        end_date: end date e.g. "today", "yesterday", "2024-01-31"
        limit: max rows to return (default 10, max 100000)

    Common dimension/metric combos:
        - Top pages: dimensions=["pagePath"], metrics=["screenPageViews","sessions"]
        - Traffic sources: dimensions=["sessionSource","sessionMedium"], metrics=["sessions","conversions"]
        - Conversions: dimensions=["eventName"], metrics=["conversions","totalRevenue"]
        - Countries: dimensions=["country"], metrics=["sessions","newUsers"]
    """
    creds = _get_creds_or_raise(user_id)
    return ga.run_report(
        credentials=creds,
        property_id=property_id,
        dimensions=dimensions,
        metrics=metrics,
        date_ranges=[{"start_date": start_date, "end_date": end_date}],
        limit=limit,
    )


@mcp.tool()
def get_account_summaries(user_id: str) -> dict[str, Any]:
    """
    List all GA4 accounts and properties the authenticated user has access to.
    Use this to discover property IDs needed for other tools.

    Args:
        user_id: your user ID (set during OAuth login)
    """
    creds = _get_creds_or_raise(user_id)
    return ga.get_account_summaries(credentials=creds)


@mcp.tool()
def add_referral_exclusion(
    user_id: str,
    property_id: str,
    domain: str,
) -> dict[str, Any]:
    """
    Add a referral exclusion to a GA4 property to prevent self-referral inflation.
    Common uses: exclude PayPal, Stripe, or payment processors that redirect back to your site.

    Args:
        user_id: your user ID (set during OAuth login)
        property_id: GA4 property ID (numeric, e.g. "123456789")
        domain: domain to exclude, e.g. "paypal.com", "stripe.com", "checkout.stripe.com"
    """
    creds = _get_creds_or_raise(user_id)
    return ga.add_referral_exclusion(
        credentials=creds,
        property_id=property_id,
        domain=domain,
    )


@mcp.tool()
def create_conversion_event(
    user_id: str,
    property_id: str,
    event_name: str,
) -> dict[str, Any]:
    """
    Mark a GA4 event as a conversion event. The event must already be tracked in GA4.

    Args:
        user_id: your user ID (set during OAuth login)
        property_id: GA4 property ID (numeric, e.g. "123456789")
        event_name: exact name of the GA4 event to mark as conversion,
                    e.g. "purchase", "form_submit", "sign_up", "lead_generated"
    """
    creds = _get_creds_or_raise(user_id)
    return ga.create_conversion_event(
        credentials=creds,
        property_id=property_id,
        event_name=event_name,
    )


@mcp.tool()
def create_audience(
    user_id: str,
    property_id: str,
    display_name: str,
    description: str,
    membership_duration_days: int,
    filter_clauses: list[dict],
) -> dict[str, Any]:
    """
    Create a GA4 audience for remarketing or analysis.

    Args:
        user_id: your user ID (set during OAuth login)
        property_id: GA4 property ID (numeric, e.g. "123456789")
        display_name: audience name shown in GA4, e.g. "Purchasers last 30 days"
        description: audience description
        membership_duration_days: how long users stay in audience (1-540)
        filter_clauses: audience filter clauses. Example for users who purchased:
            [
              {
                "clauseType": "INCLUDE",
                "simpleFilter": {
                  "scope": "AUDIENCE_FILTER_SCOPE_ACROSS_ALL_SESSIONS",
                  "filterExpression": {
                    "andGroup": {
                      "filterExpressions": [
                        {
                          "dimensionOrMetricFilter": {
                            "fieldName": "eventName",
                            "stringFilter": {
                              "matchType": "EXACT",
                              "value": "purchase"
                            }
                          }
                        }
                      ]
                    }
                  }
                }
              }
            ]
    """
    creds = _get_creds_or_raise(user_id)
    return ga.create_audience(
        credentials=creds,
        property_id=property_id,
        display_name=display_name,
        description=description,
        membership_duration_days=membership_duration_days,
        filter_clauses=filter_clauses,
    )


@mcp.tool()
def update_property_settings(
    user_id: str,
    property_id: str,
    display_name: Optional[str] = None,
    industry_category: Optional[str] = None,
    time_zone: Optional[str] = None,
    currency_code: Optional[str] = None,
) -> dict[str, Any]:
    """
    Update GA4 property settings.

    Args:
        user_id: your user ID (set during OAuth login)
        property_id: GA4 property ID (numeric, e.g. "123456789")
        display_name: new display name for the property (optional)
        industry_category: industry category (optional). Valid values:
            AUTOMOTIVE, BUSINESS_AND_INDUSTRIAL_MARKETS, FINANCE, HEALTHCARE,
            TECHNOLOGY, TRAVEL, OTHER, ARTS_AND_ENTERTAINMENT, BEAUTY_AND_FITNESS,
            BOOKS_AND_LITERATURE, FOOD_AND_DRINK, GAMES, HOBBIES_AND_LEISURE,
            HOME_AND_GARDEN, INTERNET_AND_TELECOM, JOBS_AND_EDUCATION,
            LAW_AND_GOVERNMENT, NEWS, ONLINE_COMMUNITIES, PEOPLE_AND_SOCIETY,
            PETS_AND_ANIMALS, REAL_ESTATE, REFERENCE, SCIENCE, SHOPPING,
            SPORTS, UNSPECIFIED
        time_zone: IANA timezone e.g. "Europe/Berlin", "America/New_York" (optional)
        currency_code: ISO 4217 currency e.g. "EUR", "USD", "GBP" (optional)
    """
    creds = _get_creds_or_raise(user_id)
    return ga.update_property_settings(
        credentials=creds,
        property_id=property_id,
        display_name=display_name,
        industry_category=industry_category,
        time_zone=time_zone,
        currency_code=currency_code,
    )


# ─── FastAPI App ──────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure token storage dir exists
    storage_dir = Path(os.getenv("TOKEN_STORAGE_DIR", "/tmp/ga_tokens"))
    storage_dir.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(
    title="Google Analytics MCP Server",
    description="MCP server for GA4 Data API and Admin API with OAuth 2.0",
    lifespan=lifespan,
)

# Mount the MCP server at /mcp
app.mount("/mcp", mcp.streamable_http_app())


# ─── OAuth Endpoints ──────────────────────────────────────────────────────────

@app.get("/oauth/login", response_class=HTMLResponse)
async def oauth_login(user_id: str = "default"):
    """Start the OAuth flow. user_id identifies which user is authenticating."""
    if not os.getenv("GOOGLE_CLIENT_ID") or not os.getenv("GOOGLE_CLIENT_SECRET"):
        return HTMLResponse(
            "<h1>Configuration Error</h1>"
            "<p>GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be set.</p>",
            status_code=500,
        )
    auth_url, _ = get_authorization_url(user_id)
    return RedirectResponse(url=auth_url)


@app.get("/oauth/callback")
async def oauth_callback(code: str, state: str, request: Request):
    """Handle Google OAuth callback."""
    try:
        creds, user_id = exchange_code(code=code, state=state)
        api_key = get_or_create_api_key(user_id)

        base_url = os.getenv("BASE_URL", str(request.base_url).rstrip("/"))

        return HTMLResponse(f"""
<!DOCTYPE html>
<html>
<head>
  <title>GA MCP Server — Authenticated</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 700px; margin: 60px auto; padding: 0 20px; }}
    code {{ background: #f0f0f0; padding: 4px 8px; border-radius: 4px; font-size: 0.9em; }}
    pre {{ background: #1e1e1e; color: #d4d4d4; padding: 20px; border-radius: 8px; overflow-x: auto; }}
    .success {{ color: #16a34a; font-size: 1.2em; font-weight: bold; }}
    .warning {{ background: #fef3c7; border: 1px solid #f59e0b; padding: 12px; border-radius: 6px; }}
  </style>
</head>
<body>
  <p class="success">✓ Authentication successful!</p>
  <p>User ID: <code>{user_id}</code></p>

  <h2>Your MCP API Key</h2>
  <div class="warning">
    <strong>Keep this secret!</strong> Anyone with this key can access your GA4 data.
  </div>
  <pre>{api_key}</pre>

  <h2>Claude Desktop Configuration</h2>
  <p>Add to your <code>claude_desktop_config.json</code>:</p>
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

  <h2>Using the Tools</h2>
  <p>All tools require <code>user_id: "{user_id}"</code> as the first argument.</p>
  <p>Example: <em>"Show me the top 10 pages for property 123456789 in the last 30 days"</em></p>

  <p><a href="/status">View server status</a></p>
</body>
</html>
""")
    except Exception as e:
        return HTMLResponse(
            f"<h1>Authentication Failed</h1><p>{e}</p>"
            "<p><a href='/oauth/login'>Try again</a></p>",
            status_code=400,
        )


@app.get("/oauth/logout")
async def oauth_logout(user_id: str = "default"):
    """Revoke and delete stored token for a user."""
    delete_token(user_id)
    return JSONResponse({"success": True, "message": f"Token for '{user_id}' deleted"})


# ─── Status & Health ──────────────────────────────────────────────────────────

@app.get("/status", response_class=HTMLResponse)
async def status(request: Request):
    """Show server status and authenticated users."""
    users = list_users()
    base_url = os.getenv("BASE_URL", str(request.base_url).rstrip("/"))

    user_rows = ""
    for uid in users:
        creds = get_credentials(uid)
        status_icon = "✓" if creds else "✗ (token expired)"
        user_rows += f"<tr><td><code>{uid}</code></td><td>{status_icon}</td></tr>"

    return HTMLResponse(f"""
<!DOCTYPE html>
<html>
<head>
  <title>GA MCP Server — Status</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 700px; margin: 60px auto; padding: 0 20px; }}
    code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 4px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    td, th {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
    th {{ background: #f5f5f5; }}
  </style>
</head>
<body>
  <h1>Google Analytics MCP Server</h1>
  <p>Status: <strong style="color:#16a34a">Running</strong></p>
  <p>MCP endpoint: <code>{base_url}/mcp</code></p>

  <h2>Authenticated Users ({len(users)})</h2>
  <table>
    <tr><th>User ID</th><th>Token Status</th></tr>
    {user_rows if user_rows else "<tr><td colspan='2'>No users authenticated yet</td></tr>"}
  </table>

  <h2>Add a User</h2>
  <p>Visit: <code>{base_url}/oauth/login?user_id=&lt;desired-user-id&gt;</code></p>

  <h2>Available Tools</h2>
  <ul>
    <li><code>run_report</code> — fetch traffic, conversions, top pages</li>
    <li><code>get_account_summaries</code> — list all GA4 properties</li>
    <li><code>add_referral_exclusion</code> — block self-referral domains (e.g. PayPal)</li>
    <li><code>create_conversion_event</code> — mark events as conversions</li>
    <li><code>create_audience</code> — create remarketing audiences</li>
    <li><code>update_property_settings</code> — change property name, timezone, currency</li>
  </ul>
</body>
</html>
""")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    base_url = os.getenv("BASE_URL", str(request.base_url).rstrip("/"))
    return HTMLResponse(f"""
<!DOCTYPE html>
<html>
<head><title>GA MCP Server</title>
<style>body{{font-family:system-ui,sans-serif;max-width:600px;margin:60px auto;padding:0 20px}}</style>
</head>
<body>
  <h1>Google Analytics MCP Server</h1>
  <p>A Model Context Protocol server for GA4 Data API and Admin API.</p>
  <ul>
    <li><a href="/oauth/login?user_id=default">Authenticate with Google</a></li>
    <li><a href="/status">Server Status</a></li>
    <li>MCP endpoint: <code>{base_url}/mcp</code></li>
  </ul>
</body>
</html>
""")


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=False)
