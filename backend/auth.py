import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from jose import JWTError, jwt

# Values that have shipped in this repo's examples/defaults. A JWT secret that
# is public lets anyone mint an admin session, so these are never used.
WEAK_SECRETS = {
    "", "nginx-ui-dev-secret-change-in-production", "change-this-to-a-random-secret",
    "change-this-to-a-random-secret-in-production", "secret", "changeme",
}
_SECRET_FILE = Path(os.getenv("DATA_DIR", "/data")) / ".jwt_secret"


def _load_secret() -> tuple[str, str]:
    """Return (secret, source). Prefer a strong SECRET_KEY from the
    environment; otherwise use (or create once) a random key persisted in
    DATA_DIR so sessions survive restarts without ever falling back to a
    publicly known default."""
    env = os.getenv("SECRET_KEY", "")
    if env not in WEAK_SECRETS and len(env) >= 32:
        return env, "env"
    try:
        stored = _SECRET_FILE.read_text().strip()
        if len(stored) >= 32:
            return stored, "generated"
    except OSError:
        pass
    key = secrets.token_hex(32)
    try:
        _SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        _SECRET_FILE.write_text(key)
        os.chmod(_SECRET_FILE, 0o600)
        source = "generated"
    except OSError:
        source = "ephemeral"  # not persisted: sessions reset on restart, still unforgeable
    logging.getLogger("nginx_ui").warning(
        "SECRET_KEY missing or weak — using a random key (%s). Set a strong SECRET_KEY in .env.", source)
    return key, source


SECRET_KEY, SECRET_SOURCE = _load_secret()
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = int(os.getenv("TOKEN_EXPIRE_HOURS", "8"))


def authenticate(username: str, password: str) -> Optional[str]:
    """Returns the user's role on success, None on failure."""
    from backend import users
    return users.authenticate(username, password)


def create_token(username: str, role: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS)
    return jwt.encode({"sub": username, "role": role, "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: Optional[str]) -> Optional[dict]:
    """Returns {"username": str, "role": str} or None if invalid/expired."""
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            return None
        return {"username": username, "role": payload.get("role", "viewer")}
    except JWTError:
        return None
