"""
Minimal persistent storage under TOKEN_STORAGE_DIR (defaults to /tmp/ga_tokens).

Stores:
  - Registered MCP clients (Dynamic Client Registration) — keyed by client_id
  - MCP authorization codes (short-lived, 10-min TTL) — keyed by code
  - GA4 user access tokens cache (keyed by user_id, for fast credential refresh)

PKCE and MCP access tokens are NOT stored here — they live in encrypted URL
state / Fernet-encrypted bearer tokens and survive Render restarts.
"""

import json
import os
import time
from pathlib import Path
from typing import Optional

STORAGE_DIR = Path(os.getenv("TOKEN_STORAGE_DIR", "/tmp/ga_tokens"))


def _ensure_dir() -> None:
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)


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


# ─── Registered MCP clients ──────────────────────────────────────────────────

def save_client(client_id: str, data: dict) -> None:
    store = _load_store("clients")
    store[client_id] = data
    _save_store("clients", store)


def load_client(client_id: str) -> Optional[dict]:
    return _load_store("clients").get(client_id)


# ─── MCP authorization codes (short-lived, single-use) ───────────────────────

def save_auth_code(code: str, data: dict) -> None:
    store = _load_store("auth_codes")
    store[code] = {"data": data, "saved_at": time.time()}
    _save_store("auth_codes", store)


def load_auth_code(code: str) -> Optional[dict]:
    record = _load_store("auth_codes").get(code)
    if not record:
        return None
    if time.time() - record["saved_at"] > 600:  # 10-minute expiry
        delete_auth_code(code)
        return None
    return record["data"]


def delete_auth_code(code: str) -> None:
    store = _load_store("auth_codes")
    store.pop(code, None)
    _save_store("auth_codes", store)


# ─── GA4 user token cache (keyed by user_id) ─────────────────────────────────

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
