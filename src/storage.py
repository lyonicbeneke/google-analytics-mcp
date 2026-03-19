"""
Storage for multi-user OAuth sessions and MCP Auth server state.
All data lives in JSON files under TOKEN_STORAGE_DIR.
"""

import json
import os
import secrets
import time
from pathlib import Path
from typing import Optional

STORAGE_DIR = Path(os.getenv("TOKEN_STORAGE_DIR", "/tmp/ga_tokens"))


def _ensure_dir() -> None:
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)


# ─── Generic key/value store helpers ─────────────────────────────────────────

def _store_path(name: str) -> Path:
    return STORAGE_DIR / f"_{name}.json"


def _load_store(name: str) -> dict:
    f = _store_path(name)
    if not f.exists():
        return {}
    try:
        return json.loads(f.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save_store(name: str, data: dict) -> None:
    _ensure_dir()
    _store_path(name).write_text(json.dumps(data))


# ─── Google token storage (legacy / manual login) ────────────────────────────

def _user_file(user_id: str) -> Path:
    safe_id = "".join(c for c in user_id if c.isalnum() or c in "-_")
    return STORAGE_DIR / f"{safe_id}.json"


def save_token(user_id: str, token_data: dict) -> None:
    _ensure_dir()
    token_data["saved_at"] = time.time()
    _user_file(user_id).write_text(json.dumps(token_data))


def load_token(user_id: str) -> Optional[dict]:
    path = _user_file(user_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def delete_token(user_id: str) -> None:
    path = _user_file(user_id)
    if path.exists():
        path.unlink()


def list_users() -> list[str]:
    _ensure_dir()
    # Exclude internal store files (prefixed with _)
    return [p.stem for p in STORAGE_DIR.glob("*.json") if not p.stem.startswith("_")]


# ─── PKCE storage (Google OAuth, keyed by state) ─────────────────────────────

def save_pkce(state: str, code_verifier: str) -> None:
    store = _load_store("pkce")
    store[state] = {"verifier": code_verifier, "saved_at": time.time()}
    _save_store("pkce", store)


def load_pkce(state: str) -> Optional[str]:
    return _load_store("pkce").get(state, {}).get("verifier")


def delete_pkce(state: str) -> None:
    store = _load_store("pkce")
    store.pop(state, None)
    _save_store("pkce", store)


# ─── OAuth server: registered clients ────────────────────────────────────────

def save_client(client_id: str, data: dict) -> None:
    store = _load_store("clients")
    store[client_id] = data
    _save_store("clients", store)


def load_client(client_id: str) -> Optional[dict]:
    return _load_store("clients").get(client_id)


# ─── OAuth server: in-flight authorization sessions ──────────────────────────
# Keyed by our internal session_key (used as Google OAuth state).
# Stores the original client request so we can redirect back after Google auth.

def save_oauth_session(key: str, data: dict) -> None:
    store = _load_store("oauth_sessions")
    store[key] = {"data": data, "saved_at": time.time()}
    _save_store("oauth_sessions", store)


def load_oauth_session(key: str) -> Optional[dict]:
    record = _load_store("oauth_sessions").get(key)
    return record["data"] if record else None


def delete_oauth_session(key: str) -> None:
    store = _load_store("oauth_sessions")
    store.pop(key, None)
    _save_store("oauth_sessions", store)


# ─── OAuth server: authorization codes (short-lived, single-use) ─────────────

def save_auth_code(code: str, data: dict) -> None:
    store = _load_store("auth_codes")
    store[code] = {"data": data, "saved_at": time.time()}
    _save_store("auth_codes", store)


def load_auth_code(code: str) -> Optional[dict]:
    record = _load_store("auth_codes").get(code)
    if not record:
        return None
    # Auth codes expire after 10 minutes
    if time.time() - record["saved_at"] > 600:
        delete_auth_code(code)
        return None
    return record["data"]


def delete_auth_code(code: str) -> None:
    store = _load_store("auth_codes")
    store.pop(code, None)
    _save_store("auth_codes", store)


# ─── OAuth server: access tokens ─────────────────────────────────────────────

def save_access_token(token: str, data: dict) -> None:
    store = _load_store("access_tokens")
    store[token] = data
    _save_store("access_tokens", store)


def load_access_token(token: str) -> Optional[dict]:
    return _load_store("access_tokens").get(token)


def update_access_token(token: str, updates: dict) -> None:
    """Patch fields in an existing access token record (e.g. after Google token refresh)."""
    store = _load_store("access_tokens")
    if token in store:
        store[token].update(updates)
        _save_store("access_tokens", store)


# ─── Legacy API keys (manual login) ──────────────────────────────────────────

def get_or_create_api_key(user_id: str) -> str:
    keys = _load_store("api_keys")
    if user_id not in keys:
        keys[user_id] = secrets.token_urlsafe(32)
        _save_store("api_keys", keys)
    return keys[user_id]
