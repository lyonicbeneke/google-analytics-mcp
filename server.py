"""
Google Analytics MCP Server — Official Python MCP SDK with OAuth 2.1.

Architecture:
  - Single Render service that is both AS (OAuth Authorization Server) and
    RS (MCP Resource Server) using the official Python MCP SDK.
  - All state is stateless: PKCE in encrypted Google state, GA4 refresh_token
    embedded in Fernet-encrypted MCP bearer token.  Zero /tmp dependency.
  - Tools cover GA4 Data API (read+write) and Admin API.

OAuth flow:
  1.  claude.ai → GET /authorize
  2.  → redirect to Google OAuth (PKCE + all state in encrypted URL param)
  3.  Google → GET /oauth/callback
  4.  → decrypt state, exchange code, issue MCP auth code, redirect to claude.ai
  5.  claude.ai → POST /token → self-contained Fernet-encrypted bearer token
  6.  claude.ai → POST /mcp (Bearer token) → GA4 calls via embedded refresh_token

Render env vars required:
  GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, BASE_URL, SECRET_KEY (auto-generated)
"""

import json
import logging
import os

from dotenv import load_dotenv
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.mcpserver import MCPServer
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

from src.ga_tools import (
    get_account_summaries,
    get_custom_dimensions_and_metrics,
    get_property_details,
    list_google_ads_links,
    list_property_annotations,
    run_realtime_report,
    run_report,
)
from src.provider import GoogleOAuthProvider, current_ga_creds

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_URL = os.getenv("BASE_URL", "http://localhost:8000").rstrip("/")

# ─── Auth provider ────────────────────────────────────────────────────────────

provider = GoogleOAuthProvider()

# ─── MCP Server ──────────────────────────────────────────────────────────────

mcp = MCPServer(
    name="Google Analytics MCP",
    auth_server_provider=provider,
    auth=AuthSettings(
        issuer_url=AnyHttpUrl(BASE_URL),
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=["analytics"],
            default_scopes=["analytics"],
        ),
        revocation_options=RevocationOptions(enabled=False),
        required_scopes=["analytics"],
        resource_server_url=AnyHttpUrl(f"{BASE_URL}/mcp"),
    ),
)


# ─── Tools ───────────────────────────────────────────────────────────────────

def _creds():
    """Get the current request's GA4 credentials (set by load_access_token)."""
    creds = current_ga_creds.get()
    if not creds:
        raise RuntimeError(
            "Google Analytics credentials not available. "
            "Please re-authorize: disconnect and reconnect the Google Analytics "
            "connector in claude.ai to trigger a new OAuth flow."
        )
    return creds


@mcp.tool(description="Retrieve all GA4 accounts and properties the authenticated user can access.")
async def ga_get_account_summaries() -> str:
    result = await get_account_summaries(_creds())
    return json.dumps(result, indent=2)


@mcp.tool(description="Get full details for a specific GA4 property.")
async def ga_get_property_details(property_id: str) -> str:
    """Args: property_id — numeric ID or 'properties/NNN'."""
    result = await get_property_details(_creds(), property_id)
    return json.dumps(result, indent=2)


@mcp.tool(description="List Google Ads account links for a GA4 property.")
async def ga_list_google_ads_links(property_id: str) -> str:
    result = await list_google_ads_links(_creds(), property_id)
    return json.dumps(result, indent=2)


@mcp.tool(description="Return date annotations for a GA4 property (release notes, campaign launches, etc.).")
async def ga_list_property_annotations(property_id: str) -> str:
    result = await list_property_annotations(_creds(), property_id)
    return json.dumps(result, indent=2)


@mcp.tool(
    description=(
        "Run a GA4 standard report. "
        "date_ranges: list of {start_date, end_date} (e.g. '7daysAgo', 'yesterday', 'YYYY-MM-DD'). "
        "dimensions: list of dimension names (e.g. ['pagePath', 'country']). "
        "metrics: list of metric names (e.g. ['sessions', 'screenPageViews'])."
    )
)
async def ga_run_report(
    property_id: str,
    date_ranges: list[dict],
    dimensions: list[str],
    metrics: list[str],
    dimension_filter: dict | None = None,
    metric_filter: dict | None = None,
    order_bys: list[dict] | None = None,
    limit: int | None = None,
    offset: int | None = None,
    currency_code: str | None = None,
    return_property_quota: bool = False,
) -> str:
    result = await run_report(
        _creds(),
        property_id,
        date_ranges=date_ranges,
        dimensions=dimensions,
        metrics=metrics,
        dimension_filter=dimension_filter,
        metric_filter=metric_filter,
        order_bys=order_bys,
        limit=limit,
        offset=offset,
        currency_code=currency_code,
        return_property_quota=return_property_quota,
    )
    return json.dumps(result, indent=2)


@mcp.tool(description="Run a GA4 realtime report showing live active users and events.")
async def ga_run_realtime_report(
    property_id: str,
    dimensions: list[str],
    metrics: list[str],
    dimension_filter: dict | None = None,
    metric_filter: dict | None = None,
    order_bys: list[dict] | None = None,
    limit: int | None = None,
    offset: int | None = None,
    return_property_quota: bool = False,
) -> str:
    result = await run_realtime_report(
        _creds(),
        property_id,
        dimensions=dimensions,
        metrics=metrics,
        dimension_filter=dimension_filter,
        metric_filter=metric_filter,
        order_bys=order_bys,
        limit=limit,
        offset=offset,
        return_property_quota=return_property_quota,
    )
    return json.dumps(result, indent=2)


@mcp.tool(description="Return custom dimensions and metrics defined for a GA4 property.")
async def ga_get_custom_dimensions_and_metrics(property_id: str) -> str:
    result = await get_custom_dimensions_and_metrics(_creds(), property_id)
    return json.dumps(result, indent=2)


# ─── Google OAuth callback route ─────────────────────────────────────────────

async def oauth_callback(request: Request):
    """Handle Google's redirect after user grants (or denies) consent."""
    error = request.query_params.get("error")
    if error:
        desc = request.query_params.get("error_description", error)
        return HTMLResponse(
            f"<h2>Authorization failed</h2><p>{desc}</p>",
            status_code=400,
        )

    code = request.query_params.get("code")
    state = request.query_params.get("state")
    if not code or not state:
        return HTMLResponse("<h2>Missing code or state</h2>", status_code=400)

    try:
        redirect_url = await provider.handle_google_callback(code, state)
    except Exception as exc:
        logger.exception("Google callback error")
        return HTMLResponse(
            f"<h2>OAuth error</h2><pre>{exc}</pre>",
            status_code=500,
        )

    return RedirectResponse(url=redirect_url, status_code=302)


async def health(request: Request):
    return JSONResponse({"status": "ok", "server": "google-analytics-mcp"})


# ─── Build the combined Starlette app ────────────────────────────────────────
# MCPServer.streamable_http_app() builds routes for /mcp, /authorize, /token,
# /register, /.well-known/*, etc.  We extract those routes and merge with our
# custom routes in a single flat Starlette app — no path-stripping Mount needed.

_mcp_app = mcp.streamable_http_app(stateless_http=True)

app = Starlette(
    routes=[
        Route("/oauth/callback", endpoint=oauth_callback, methods=["GET"]),
        Route("/health", endpoint=health, methods=["GET"]),
        *_mcp_app.router.routes,
    ],
)
