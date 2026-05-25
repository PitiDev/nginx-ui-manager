import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt

SECRET_KEY = os.getenv("SECRET_KEY", "nginx-ui-dev-secret-change-in-production")
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
