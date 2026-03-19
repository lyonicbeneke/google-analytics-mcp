"""
Token storage for multi-user OAuth sessions.
Stores Google OAuth tokens per user in JSON files.
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


def _user_file(user_id: str) -> Path:
    # Sanitize user_id to prevent path traversal
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
    return [p.stem for p in STORAGE_DIR.glob("*.json")]


# API key management — each user gets a stable API key after OAuth
def _keys_file() -> Path:
    return STORAGE_DIR / "_api_keys.json"


def _load_keys() -> dict:
    f = _keys_file()
    if not f.exists():
        return {}
    try:
        return json.loads(f.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save_keys(keys: dict) -> None:
    _ensure_dir()
    _keys_file().write_text(json.dumps(keys))


def get_or_create_api_key(user_id: str) -> str:
    keys = _load_keys()
    if user_id not in keys:
        api_key = secrets.token_urlsafe(32)
        keys[user_id] = api_key
        _save_keys(keys)
    return keys[user_id]


def get_user_by_api_key(api_key: str) -> Optional[str]:
    keys = _load_keys()
    for user_id, key in keys.items():
        if key == api_key:
            return user_id
    return None
