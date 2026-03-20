"""
Google OAuth 2.0 helpers.

Key design: PKCE code_verifier is encrypted and embedded inside the Google
OAuth state parameter — no /tmp storage needed. This survives server restarts
between /authorize and /oauth/callback.

The auth URL is built manually (not via google_auth_oauthlib) so we have full
control over the PKCE parameters and avoid library version quirks.
"""

import asyncio
import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlencode

import httpx
from cryptography.fernet import Fernet
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

from .storage import save_token, load_token

SCOPES = ["https://www.googleapis.com/auth/analytics.readonly"]

_GOOGLE_AUTH_URI = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"


def _google_callback_uri() -> str:
    base = os.getenv("BASE_URL", "http://localhost:8000").rstrip("/")
    return f"{base}/oauth/callback"


# ─── Fernet encryption (key derived from SECRET_KEY or GOOGLE_CLIENT_SECRET) ─

def _get_fernet() -> Fernet:
    secret = os.getenv("SECRET_KEY") or os.getenv("GOOGLE_CLIENT_SECRET", "changeme")
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
    return Fernet(key)


def encrypt_state(data: dict) -> str:
    """Encrypt a dict into a URL-safe Fernet token (used for OAuth state)."""
    return _get_fernet().encrypt(json.dumps(data).encode()).decode()


def decrypt_state(token: str) -> dict:
    """Decrypt a Fernet token back into a dict (used for OAuth state)."""
    return json.loads(_get_fernet().decrypt(token.encode()))


def encrypt_mcp_token(data: dict) -> str:
    """
    Create a self-contained MCP Bearer token.
    Embeds user_id + refresh_token encrypted with Fernet.
    Survives server restarts — no /tmp lookup needed to validate.
    """
    return _get_fernet().encrypt(json.dumps(data).encode()).decode()


def decrypt_mcp_token(token: str) -> dict:
    """
    Verify and decrypt an MCP Bearer token.
    Raises cryptography.fernet.InvalidToken if tampered or wrong key.
    """
    return json.loads(_get_fernet().decrypt(token.encode()))


# ─── PKCE ─────────────────────────────────────────────────────────────────────

def _make_pkce() -> tuple[str, str]:
    """Return (code_verifier, code_challenge_S256)."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


# ─── Google OAuth URL builder ─────────────────────────────────────────────────

def google_auth_url(session_payload: dict) -> str:
    """
    Build a Google OAuth URL with PKCE.

    session_payload is encrypted into the state parameter so all data needed
    by the callback survives server restarts. The PKCE verifier is embedded
    inside session_payload before encryption.

    Returns the full Google authorization URL.
    """
    verifier, challenge = _make_pkce()
    session_payload["pkce_verifier"] = verifier  # embed — no /tmp needed

    encrypted_state = encrypt_state(session_payload)

    params = {
        "client_id": os.getenv("GOOGLE_CLIENT_ID", ""),
        "redirect_uri": _google_callback_uri(),
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": encrypted_state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return f"{_GOOGLE_AUTH_URI}?{urlencode(params)}"


# ─── Google token exchange ────────────────────────────────────────────────────

def google_exchange_code(code: str, code_verifier: str) -> dict:
    """
    Exchange a Google authorization code for tokens.
    Uses httpx directly to avoid google_auth_oauthlib PKCE interference.
    Returns a token dict compatible with credentials_from_token_data.
    """
    resp = httpx.post(_GOOGLE_TOKEN_URI, data={
        "code": code,
        "client_id": os.getenv("GOOGLE_CLIENT_ID", ""),
        "client_secret": os.getenv("GOOGLE_CLIENT_SECRET", ""),
        "redirect_uri": _google_callback_uri(),
        "grant_type": "authorization_code",
        "code_verifier": code_verifier,
    })
    resp.raise_for_status()
    data = resp.json()

    # Compute expiry from expires_in
    expiry = None
    if "expires_in" in data:
        import time
        expiry = datetime.fromtimestamp(time.time() + data["expires_in"], tz=timezone.utc).isoformat()

    return {
        "token": data["access_token"],
        "refresh_token": data.get("refresh_token"),
        "token_uri": _GOOGLE_TOKEN_URI,
        "scopes": SCOPES,
        "expiry": expiry,
    }


# ─── Credentials helpers ─────────────────────────────────────────────────────

async def credentials_from_refresh_token(refresh_token: str, user_id: str) -> Optional[Credentials]:
    """
    Return valid GA4 credentials from a refresh_token.
    Checks /tmp cache first (fast path). Falls back to a live token refresh
    (one extra round-trip) when /tmp is empty (e.g. after server restart).
    The refresh runs in a thread executor so it doesn't block the event loop.
    """
    if not refresh_token:
        return None

    # ── Fast path: valid cached access_token ──
    cached = load_token(user_id)
    if cached:
        raw_expiry = cached.get("expiry")
        expiry = None
        if raw_expiry:
            try:
                expiry = datetime.fromisoformat(raw_expiry)
            except (ValueError, TypeError):
                pass
        creds = Credentials(
            token=cached.get("token"),
            refresh_token=refresh_token,
            token_uri=cached.get("token_uri", _GOOGLE_TOKEN_URI),
            client_id=os.getenv("GOOGLE_CLIENT_ID", ""),
            client_secret=os.getenv("GOOGLE_CLIENT_SECRET", ""),
            scopes=cached.get("scopes", SCOPES),
            expiry=expiry,
        )
        if creds.valid:
            return creds
        # Cache exists but token expired — fall through to refresh below
        if creds.refresh_token:
            try:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, lambda: creds.refresh(Request()))
                save_token(user_id, _creds_to_dict(creds))
                return creds
            except Exception:
                return None

    # ── /tmp empty (server restart): refresh from scratch ──
    creds = Credentials(
        token=None,
        refresh_token=refresh_token,
        token_uri=_GOOGLE_TOKEN_URI,
        client_id=os.getenv("GOOGLE_CLIENT_ID", ""),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET", ""),
        scopes=SCOPES,
    )
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: creds.refresh(Request()))
        save_token(user_id, _creds_to_dict(creds))  # cache for subsequent calls
        return creds
    except Exception:
        return None


def credentials_from_token_data(token_data: dict, user_id: str, update_fn) -> Optional[Credentials]:
    """
    Build a google.oauth2.credentials.Credentials from a stored token dict.
    Auto-refreshes and calls update_fn(new_data) if the token was refreshed.
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
        token_uri=token_data.get("token_uri", _GOOGLE_TOKEN_URI),
        client_id=os.getenv("GOOGLE_CLIENT_ID", ""),
        client_secret=os.getenv("GOOGLE_CLIENT_SECRET", ""),
        scopes=token_data.get("scopes", SCOPES),
        expiry=expiry,
    )

    if creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            update_fn(_creds_to_dict(creds))
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
