import json
import os
from pathlib import Path
from typing import Optional

import bcrypt

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
_USERS_FILE = DATA_DIR / "users.json"

_BOOTSTRAP_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
_BOOTSTRAP_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

VALID_ROLES = ("admin", "viewer")


def _load() -> list[dict]:
    try:
        return json.loads(_USERS_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save(users: list[dict]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    _USERS_FILE.write_text(json.dumps(users, indent=2))


def _bootstrap() -> None:
    """Seed a default admin from env vars the first time (no file yet)."""
    if _load():
        return
    _save([{
        "username": _BOOTSTRAP_USERNAME,
        "password_hash": bcrypt.hashpw(_BOOTSTRAP_PASSWORD.encode(), bcrypt.gensalt()).decode(),
        "role": "admin",
    }])


def get_all() -> list[dict]:
    _bootstrap()
    return [{"username": u["username"], "role": u["role"]} for u in _load()]


def _get_record(username: str) -> Optional[dict]:
    _bootstrap()
    return next((u for u in _load() if u["username"] == username), None)


def authenticate(username: str, password: str) -> Optional[str]:
    """Returns the user's role on success, None on failure."""
    rec = _get_record(username)
    if rec and bcrypt.checkpw(password.encode(), rec["password_hash"].encode()):
        return rec["role"]
    return None


def create_user(username: str, password: str, role: str) -> tuple[bool, str]:
    username = username.strip()
    if not username or "/" in username or username.startswith("."):
        return False, "Invalid username"
    if role not in VALID_ROLES:
        return False, "Invalid role"
    if not password:
        return False, "Password is required"
    users = _load()
    if any(u["username"] == username for u in users):
        return False, f"User '{username}' already exists"
    users.append({
        "username": username,
        "password_hash": bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
        "role": role,
    })
    _save(users)
    return True, f"User '{username}' created"


def update_user(username: str, password: Optional[str], role: str) -> tuple[bool, str]:
    if role not in VALID_ROLES:
        return False, "Invalid role"
    users = _load()
    target = next((u for u in users if u["username"] == username), None)
    if not target:
        return False, "User not found"
    if target["role"] == "admin" and role != "admin":
        if len([u for u in users if u["role"] == "admin"]) <= 1:
            return False, "Cannot demote the last admin"
    target["role"] = role
    if password:
        target["password_hash"] = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    _save(users)
    return True, f"User '{username}' updated"


def delete_user(username: str, requesting_user: str) -> tuple[bool, str]:
    if username == requesting_user:
        return False, "You cannot delete your own account"
    users = _load()
    target = next((u for u in users if u["username"] == username), None)
    if not target:
        return False, "User not found"
    if target["role"] == "admin" and len([u for u in users if u["role"] == "admin"]) <= 1:
        return False, "Cannot delete the last admin"
    _save([u for u in users if u["username"] != username])
    return True, f"User '{username}' deleted"
