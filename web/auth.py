"""
auth.py - dashboard user accounts.

Passwords are never stored in plain text. We keep a salted hash (via werkzeug)
in data/users.json. On first run we create a default admin/admin account and
flag it, so the dashboard can nudge you to change it.
"""

from __future__ import annotations

import json
import os
import threading

from werkzeug.security import generate_password_hash, check_password_hash

from fwcore.config import DATA_DIR

USERS_PATH = os.path.join(DATA_DIR, "users.json")
_lock = threading.Lock()


def _load() -> dict:
    try:
        with open(USERS_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _save(users: dict) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = USERS_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(users, f, indent=2)
    os.replace(tmp, USERS_PATH)


def ensure_default_admin() -> None:
    """Create admin/admin on first run (marked as a default to be changed)."""
    with _lock:
        users = _load()
        if not users:
            users["admin"] = {
                "hash": generate_password_hash("admin"),
                "is_default": True,
            }
            _save(users)


def validate(username: str, password: str) -> bool:
    users = _load()
    rec = users.get(username)
    if not rec:
        return False
    return check_password_hash(rec["hash"], password)


def is_default_password(username: str) -> bool:
    users = _load()
    rec = users.get(username, {})
    return bool(rec.get("is_default"))


def set_password(username: str, new_password: str) -> None:
    with _lock:
        users = _load()
        users[username] = {
            "hash": generate_password_hash(new_password),
            "is_default": False,
        }
        _save(users)
