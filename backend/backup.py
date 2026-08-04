import json
import os
import re
import tarfile
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

DATA_DIR        = Path(os.getenv("DATA_DIR", "/data"))
BACKUP_DIR      = DATA_DIR / "backups"
SETTINGS_FILE   = DATA_DIR / "backup_settings.json"
SITES_AVAILABLE = Path(os.getenv("NGINX_SITES_AVAILABLE", "/etc/nginx/sites-available"))
SITES_ENABLED   = Path(os.getenv("NGINX_SITES_ENABLED",   "/etc/nginx/sites-enabled"))

# Strict filename pattern — prevents path traversal on delete
_NAME_RE = re.compile(r'^backup_\d{8}_\d{6}(_note_[\w]{1,50})?\.tar\.gz$')


def _human_size(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def list_backups() -> list[dict]:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    for f in sorted(BACKUP_DIR.glob("backup_*.tar.gz"), reverse=True):
        try:
            stat   = f.stat()
            stem   = f.name[:-7]          # strip .tar.gz
            parts  = stem.split("_note_", 1)
            ts_str = parts[0].replace("backup_", "")
            note   = parts[1].replace("_", " ") if len(parts) > 1 else ""
            try:
                ts_display = datetime.strptime(ts_str, "%Y%m%d_%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                ts_display = "unknown"
            results.append({
                "name":       f.name,
                "timestamp":  ts_display,
                "note":       note,
                "kind":       "auto" if "auto backup" in note.lower() else "manual",
                "size":       stat.st_size,
                "size_human": _human_size(stat.st_size),
            })
        except Exception:
            continue
    return results


def create_backup(note: str = "") -> tuple[bool, str]:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_note = re.sub(r"[^\w]", "_", note.strip())[:40] if note.strip() else ""
    filename  = f"backup_{ts}" + (f"_note_{safe_note}" if safe_note else "") + ".tar.gz"
    path      = BACKUP_DIR / filename
    try:
        file_count = 0
        with tarfile.open(path, "w:gz") as tar:
            for label, directory in (("sites-available", SITES_AVAILABLE), ("sites-enabled", SITES_ENABLED)):
                if not directory.is_dir():
                    continue
                for f in directory.iterdir():
                    if f.is_file():
                        tar.add(f, arcname=f"{label}/{f.name}")
                        file_count += 1
        s = get_auto_backup_settings()
        s["last_backup_time"] = time.time()
        _write_settings(s)
        return True, f"Backup created: {filename} ({file_count} config file(s))"
    except Exception as e:
        path.unlink(missing_ok=True)
        return False, str(e)


def delete_backup(name: str) -> tuple[bool, str]:
    if not _NAME_RE.match(name):
        return False, "Invalid backup name"
    path = BACKUP_DIR / name
    if not path.exists():
        return False, "Backup not found"
    try:
        path.unlink()
        return True, "Backup deleted"
    except PermissionError:
        return False, "Permission denied"


def get_auto_backup_settings() -> dict:
    try:
        return json.loads(SETTINGS_FILE.read_text())
    except Exception:
        return {"enabled": False, "interval_hours": 24, "last_backup_time": None}


def _write_settings(settings: dict) -> None:
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(settings, indent=2))


def save_auto_backup_settings(enabled: bool, interval_hours: int) -> None:
    s = get_auto_backup_settings()
    s["enabled"]        = enabled
    s["interval_hours"] = interval_hours
    _write_settings(s)


# ── Background scheduler ──────────────────────────────────────────────────────

def _auto_backup_loop() -> None:
    while True:
        time.sleep(60)
        try:
            s = get_auto_backup_settings()
            if not s.get("enabled"):
                continue
            interval_secs = int(s.get("interval_hours", 24)) * 3600
            last = s.get("last_backup_time")
            if last is None or (time.time() - float(last)) >= interval_secs:
                create_backup("Auto backup")
        except Exception:
            pass


def start_scheduler() -> None:
    threading.Thread(
        target=_auto_backup_loop,
        daemon=True,
        name="backup-scheduler",
    ).start()
