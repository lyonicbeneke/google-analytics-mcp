"""Google OAuth 2.0 helpers for the MCP auth flow."""

import os
from datetime import datetime
from typing import Optional

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow

from .storage import load_token, save_token

SCOPES = [
    "https://www.googleapis.com/auth/analytics.readonly",
    "https://www.googleapis.com/auth/analytics.edit",
    "https://www.googleapis.com/auth/analytics",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
]


def _client_config() -> dict:
    return {
        "web": {
            "client_id": os.getenv("GOOGLE_CLIENT_ID", ""),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET", ""),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [_google_callback_uri()],
        }
    }


def _google_callback_uri() -> str:
    base = os.getenv("BASE_URL", "http://localhost:8000").rstrip("/")
    return f"{base}/oauth/callback"



def _create_flow() -> Flow:
    config = _client_config()
    return Flow.from_client_config(
        config,
        scopes=SCOPES,
        redirect_uri=_google_callback_uri(),
    )


def creds_to_dict(creds: Credentials) -> dict:
    return {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "scopes": list(creds.scopes) if creds.scopes else SCOPES,
        "expiry": creds.expiry.isoformat() if creds.expiry else None,
    }


# ─── MCP Auth server flow ─────────────────────────────────────────────────────

def google_auth_url(session_key: str) -> str:
    """
    Build a Google OAuth URL. session_key is passed as the OAuth state
    so the callback can look up the original client request.
    No PKCE: our server is a confidential client (uses client_secret),
    so PKCE adds no security and would require persisting state across requests.
    """
    flow = _create_flow()
    auth_url, _ = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        state=session_key,
    )
    return auth_url


def google_exchange_code(code: str, session_key: str) -> dict:
    """
    Exchange a Google authorization code for tokens.
    Returns a raw token dict (not a Credentials object).
    """
    flow = _create_flow()
    flow.fetch_token(code=code)
    return creds_to_dict(flow.credentials)



def credentials_from_token_data(token_data: dict, mcp_token: str, update_fn) -> Optional[Credentials]:
    """
    Build a Credentials object from a stored token dict.
    Auto-refreshes and calls update_fn(updates) if the token was refreshed.
    """
    raw_expiry = token_data.get("expiry")
    expiry = None
    if raw_expiry:
        try:
            expiry = datetime.fromisoformat(raw_expiry)
        except (ValueError, TypeError):
            pass

    creds = Credentials(
        token=token_data.get("token"),
        refresh_token=token_data.get("refresh_token"),
        token_uri=token_data.get("token_uri", "https://oauth2.googleapis.com/token"),
        client_id=os.getenv("GOOGLE_CLIENT_ID", ""),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET", ""),
        scopes=token_data.get("scopes", SCOPES),
        expiry=expiry,
    )

    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            update_fn(creds_to_dict(creds))
        except Exception:
            return None

    return creds if creds.valid else None
