"""
OAuth 2.0 flow for Google Analytics.
Handles authorization, token refresh, and credential building.
"""

import os
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

CLIENT_CONFIG = {
    "web": {
        "client_id": os.getenv("GOOGLE_CLIENT_ID", ""),
        "client_secret": os.getenv("GOOGLE_CLIENT_SECRET", ""),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [],  # set dynamically
    }
}


def get_redirect_uri() -> str:
    base = os.getenv("BASE_URL", "http://localhost:8000").rstrip("/")
    return f"{base}/oauth/callback"


def create_flow(state: Optional[str] = None) -> Flow:
    config = CLIENT_CONFIG.copy()
    config["web"]["redirect_uris"] = [get_redirect_uri()]
    flow = Flow.from_client_config(
        config,
        scopes=SCOPES,
        state=state,
        redirect_uri=get_redirect_uri(),
    )
    return flow


def get_authorization_url(user_id: str) -> tuple[str, str]:
    """Returns (authorization_url, state)."""
    flow = create_flow()
    flow.redirect_uri = get_redirect_uri()
    auth_url, state = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
        # Encode user_id into state so callback knows who authenticated
        state=f"{state}:{user_id}",
    )
    return auth_url, state


def exchange_code(code: str, state: str) -> tuple[Credentials, str]:
    """Exchange auth code for credentials. Returns (credentials, user_id)."""
    # Extract user_id from state
    parts = state.rsplit(":", 1)
    user_id = parts[1] if len(parts) == 2 else "default"

    flow = create_flow(state=parts[0] if len(parts) == 2 else state)
    flow.redirect_uri = get_redirect_uri()
    flow.fetch_token(code=code)

    creds = flow.credentials
    save_token(user_id, _creds_to_dict(creds))
    return creds, user_id


def get_credentials(user_id: str) -> Optional[Credentials]:
    """Load and refresh credentials for a user."""
    data = load_token(user_id)
    if not data:
        return None

    creds = Credentials(
        token=data.get("token"),
        refresh_token=data.get("refresh_token"),
        token_uri=data.get("token_uri", "https://oauth2.googleapis.com/token"),
        client_id=os.getenv("GOOGLE_CLIENT_ID", ""),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET", ""),
        scopes=data.get("scopes", SCOPES),
    )

    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            save_token(user_id, _creds_to_dict(creds))
        except Exception:
            return None

    return creds if creds.valid else None


def _creds_to_dict(creds: Credentials) -> dict:
    return {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "scopes": list(creds.scopes) if creds.scopes else SCOPES,
        "expiry": creds.expiry.isoformat() if creds.expiry else None,
    }
