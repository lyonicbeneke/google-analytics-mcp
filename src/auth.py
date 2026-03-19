"""
Google OAuth 2.0 helpers.
Two flows coexist:
  - Legacy manual flow  (get_authorization_url / exchange_code) — used by /oauth/login
  - MCP Auth server flow (google_auth_url / google_exchange_code) — used by /oauth/authorize
"""

import base64
import hashlib
import os
import secrets
from typing import Optional

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow

from .storage import load_token, save_token, save_pkce, load_pkce, delete_pkce

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


def _make_pkce() -> tuple[str, str]:
    """Return (code_verifier, code_challenge_S256)."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


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
    """
    code_verifier, code_challenge = _make_pkce()
    save_pkce(session_key, code_verifier)

    flow = _create_flow()
    auth_url, _ = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        state=session_key,
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )
    return auth_url


def google_exchange_code(code: str, session_key: str) -> dict:
    """
    Exchange a Google authorization code for tokens.
    Returns a raw token dict (not a Credentials object).
    """
    code_verifier = load_pkce(session_key)
    delete_pkce(session_key)

    flow = _create_flow()
    fetch_kwargs: dict = {"code": code}
    if code_verifier:
        fetch_kwargs["code_verifier"] = code_verifier
    flow.fetch_token(**fetch_kwargs)

    return creds_to_dict(flow.credentials)


# ─── Legacy manual flow ───────────────────────────────────────────────────────

def get_authorization_url(user_id: str) -> tuple[str, str]:
    """Returns (authorization_url, combined_state). Used by /oauth/login."""
    state = secrets.token_urlsafe(16)
    combined_state = f"{state}:{user_id}"

    code_verifier, code_challenge = _make_pkce()
    save_pkce(combined_state, code_verifier)

    flow = _create_flow()
    auth_url, _ = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        state=combined_state,
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )
    return auth_url, combined_state


def exchange_code(code: str, state: str) -> tuple[Credentials, str]:
    """Exchange auth code. Returns (credentials, user_id). Used by /oauth/login callback."""
    parts = state.rsplit(":", 1)
    user_id = parts[1] if len(parts) == 2 else "default"

    code_verifier = load_pkce(state)
    delete_pkce(state)

    flow = _create_flow()
    fetch_kwargs: dict = {"code": code}
    if code_verifier:
        fetch_kwargs["code_verifier"] = code_verifier
    flow.fetch_token(**fetch_kwargs)

    creds = flow.credentials
    save_token(user_id, creds_to_dict(creds))
    return creds, user_id


def get_credentials(user_id: str) -> Optional[Credentials]:
    """Load and auto-refresh stored credentials for a user."""
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
            save_token(user_id, creds_to_dict(creds))
        except Exception:
            return None

    return creds if creds.valid else None


def credentials_from_token_data(token_data: dict, mcp_token: str, update_fn) -> Optional[Credentials]:
    """
    Build a Credentials object from a stored token dict.
    Auto-refreshes and calls update_fn(updates) if the token was refreshed.
    """
    creds = Credentials(
        token=token_data.get("token"),
        refresh_token=token_data.get("refresh_token"),
        token_uri=token_data.get("token_uri", "https://oauth2.googleapis.com/token"),
        client_id=os.getenv("GOOGLE_CLIENT_ID", ""),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET", ""),
        scopes=token_data.get("scopes", SCOPES),
    )

    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            update_fn(creds_to_dict(creds))
        except Exception:
            return None

    return creds if creds.valid else None
