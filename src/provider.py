"""
Google OAuth Provider implementing OAuthAuthorizationServerProvider.

Design:
- authorize() redirects to Google OAuth with all session state (PKCE verifier,
  MCP redirect_uri, client_id, etc.) Fernet-encrypted into the Google state param.
  No /tmp storage needed — survives Render restarts.
- Google callback decrypts state, exchanges code, gets refresh_token, issues a
  short-lived MCP auth code stored in memory.
- exchange_authorization_code() creates a self-contained Fernet-encrypted MCP
  access token that embeds the Google refresh_token — also survives restarts.
- load_access_token() decrypts the Fernet blob and returns GA4 credentials via
  a ContextVar so tool handlers can use them without extra lookup.
"""

import secrets
import time
from contextvars import ContextVar
from typing import Any, Optional

from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    AccessToken,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    RegistrationError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyHttpUrl

from .auth import (
    decrypt_mcp_token,
    decrypt_state,
    encrypt_mcp_token,
    encrypt_state,
    google_auth_url,
    google_exchange_code,
    credentials_from_refresh_token,
)
from .storage import (
    save_client,
    load_client,
    save_auth_code,
    load_auth_code,
    delete_auth_code,
)

# Context variable: set by load_access_token() before every tool invocation.
# Tool handlers read this to get GA4 credentials.
current_ga_creds: ContextVar[Any] = ContextVar("current_ga_creds", default=None)


class GoogleOAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    """
    MCP OAuth provider that delegates user authentication to Google OAuth 2.0.

    Token storage strategy (stateless / Render-restart-safe):
    - MCP clients: persisted to /tmp JSON (can be re-registered on restart)
    - MCP auth codes: in-memory dict (10-min TTL; user re-authenticates on restart)
    - MCP access tokens: self-contained Fernet blobs (no storage needed)
    - GA4 refresh token: embedded inside the Fernet access token blob
    """

    # In-memory auth code store.  Short-lived, so restart loss is acceptable.
    _auth_codes: dict[str, AuthorizationCode] = {}

    # ---------- client registration ----------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        data = load_client(client_id)
        if data is None:
            return None
        return OAuthClientInformationFull(**data)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        save_client(client_info.client_id, client_info.model_dump())

    # ---------- authorization ----------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """
        Build a Google OAuth URL.  All MCP session state is Fernet-encrypted into
        the Google state parameter so no /tmp lookup is needed in the callback.
        """
        session = {
            "mcp_state": params.state,
            "mcp_redirect_uri": str(params.redirect_uri),
            "mcp_code_challenge": params.code_challenge,
            "mcp_redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "client_id": client.client_id,
            "scopes": params.scopes or [],
            "resource": params.resource,
        }
        return google_auth_url(session)  # embeds PKCE verifier + encrypts all

    async def handle_google_callback(self, code: str, encrypted_state: str) -> str:
        """
        Called from the /oauth/callback route.
        Returns the MCP redirect URI (back to claude.ai) with code + state.
        """
        try:
            session = decrypt_state(encrypted_state)
        except Exception:
            raise ValueError("Invalid or expired OAuth state parameter")

        mcp_state = session.get("mcp_state")
        mcp_redirect_uri = session["mcp_redirect_uri"]
        mcp_code_challenge = session["mcp_code_challenge"]
        mcp_redirect_uri_provided_explicitly = session.get(
            "mcp_redirect_uri_provided_explicitly", True
        )
        client_id = session["client_id"]
        scopes = session.get("scopes", [])
        resource = session.get("resource")
        pkce_verifier = session["pkce_verifier"]  # embedded by google_auth_url()

        # Exchange Google auth code for tokens
        token_data = google_exchange_code(code, pkce_verifier)
        refresh_token = token_data.get("refresh_token")
        if not refresh_token:
            raise ValueError("Google did not return a refresh_token. Ensure offline access is requested.")

        # Issue short-lived MCP authorization code (stored in memory)
        mcp_code = f"mcp_{secrets.token_hex(24)}"
        auth_code_obj = AuthorizationCode(
            code=mcp_code,
            client_id=client_id,
            redirect_uri=AnyHttpUrl(mcp_redirect_uri),
            redirect_uri_provided_explicitly=mcp_redirect_uri_provided_explicitly,
            expires_at=time.time() + 300,  # 5 minutes
            scopes=scopes,
            code_challenge=mcp_code_challenge,
            resource=resource,
        )
        # Store both the auth code object AND the refresh_token (linked by code)
        self._auth_codes[mcp_code] = auth_code_obj
        save_auth_code(mcp_code, {"refresh_token": refresh_token})

        return construct_redirect_uri(mcp_redirect_uri, code=mcp_code, state=mcp_state)

    # ---------- token exchange ----------

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        obj = self._auth_codes.get(authorization_code)
        if obj is None:
            return None
        if time.time() > obj.expires_at:
            del self._auth_codes[authorization_code]
            return None
        return obj

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        code = authorization_code.code
        stored = load_auth_code(code)
        if not stored:
            raise ValueError("Authorization code not found or expired")

        refresh_token = stored["refresh_token"]

        # Clean up
        if code in self._auth_codes:
            del self._auth_codes[code]
        delete_auth_code(code)

        # Create a self-contained, Fernet-encrypted MCP access token.
        # Embed the Google refresh_token so the server can always get GA4 credentials.
        user_id = f"user_{client.client_id[:8]}"
        token_payload = {
            "user_id": user_id,
            "client_id": client.client_id,
            "refresh_token": refresh_token,
            "scopes": authorization_code.scopes,
            "resource": authorization_code.resource,
            "issued_at": time.time(),
        }
        access_token_str = encrypt_mcp_token(token_payload)

        # Fernet tokens don't expire by themselves, but we can set a long TTL
        return OAuthToken(
            access_token=access_token_str,
            token_type="Bearer",
            expires_in=365 * 24 * 3600,  # 1 year; real expiry via refresh
            scope=" ".join(authorization_code.scopes),
        )

    # ---------- access token verification ----------

    async def load_access_token(self, token: str) -> AccessToken | None:
        try:
            data = decrypt_mcp_token(token)
        except Exception:
            return None

        refresh_token = data.get("refresh_token")
        user_id = data.get("user_id", "default")

        # Fetch (and cache) GA4 credentials; set in ContextVar for tool handlers
        if refresh_token:
            creds = await credentials_from_refresh_token(refresh_token, user_id)
        else:
            creds = None

        current_ga_creds.set(creds)

        return AccessToken(
            token=token,
            client_id=data.get("client_id", ""),
            scopes=data.get("scopes", ["analytics"]),
            expires_at=None,
            resource=data.get("resource"),
        )

    # ---------- refresh tokens (not used — GA4 refresh embedded in access token) ----------

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        raise NotImplementedError("Refresh tokens not used; re-authenticate to get a new access token")

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        pass  # Fernet tokens are self-contained; nothing to revoke server-side
