import json
import os
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
_ACTIVITY_FILE = DATA_DIR / "activity.json"
_MAX_ENTRIES = 2000

CATEGORIES = ["auth", "nginx", "config", "ssl", "backup", "node", "user", "proxy", "audit"]


def _load() -> list[dict]:
    try:
        return json.loads(_ACTIVITY_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _save(entries: list[dict]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    _ACTIVITY_FILE.write_text(json.dumps(entries))


def log(
    user: str,
    role: str,
    action: str,
    target: str = "",
    detail: str = "",
    ip: str = "",
    result: str = "success",
    node: str = "local",
) -> None:
    entries = _load()
    entries.append({
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "user": user,
        "role": role,
        "action": action,
        "target": target,
        "detail": detail,
        "ip": ip,
        "result": result,
        "node": node,
    })
    if len(entries) > _MAX_ENTRIES:
        entries = entries[-_MAX_ENTRIES:]
    _save(entries)


def get_logs(
    limit: int = 500,
    user: str = "",
    category: str = "",
    result: str = "",
    search: str = "",
) -> list[dict]:
    entries = list(reversed(_load()))
    if user:
        entries = [e for e in entries if e.get("user") == user]
    if category:
        entries = [e for e in entries if e.get("action", "").startswith(category + ".")]
    if result:
        entries = [e for e in entries if e.get("result") == result]
    if search:
        s = search.lower()
        entries = [e for e in entries if s in json.dumps(e).lower()]
    return entries[:limit]


def get_unique_users() -> list[str]:
    seen: list[str] = []
    for e in _load():
        u = e.get("user", "")
        if u and u not in seen:
            seen.append(u)
    return seen


def get_stats() -> dict:
    entries = _load()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return {
        "total": len(entries),
        "today": sum(1 for e in entries if e.get("ts", "").startswith(today)),
        "errors": sum(1 for e in entries if e.get("result") == "error"),
        "unique_users": len({e.get("user") for e in entries if e.get("user")}),
    }


def clear_logs() -> None:
    _save([])
