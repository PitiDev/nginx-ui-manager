import os
import re
from datetime import datetime
from pathlib import Path

ACCESS_LOG = Path(os.getenv("NGINX_ACCESS_LOG", "/var/log/nginx/access.log"))
ERROR_LOG   = Path(os.getenv("NGINX_ERROR_LOG",  "/var/log/nginx/error.log"))

# Nginx combined access log: ip - user [dt] "req" status bytes "referer" "ua"
_ACCESS_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<dt>[^\]]+)\] '
    r'"(?P<req>[^"]*)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)
# Nginx error log: YYYY/MM/DD HH:MM:SS [level] pid#tid: msg
_ERROR_RE = re.compile(
    r'(?P<dt>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] '
    r'\d+#\d+: (?P<msg>.*)'
)


def _dt_access(s: str) -> str:
    try:
        return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z").isoformat()
    except Exception:
        return ""


def _dt_error(s: str) -> str:
    try:
        return datetime.strptime(s, "%Y/%m/%d %H:%M:%S").isoformat()
    except Exception:
        return ""


def _tail(path: Path, lines: int) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            block = min(size, lines * 300)
            f.seek(max(0, size - block))
            content = f.read().decode("utf-8", errors="replace")
            all_lines = content.splitlines()
            return "\n".join(all_lines[-lines:])
    except FileNotFoundError:
        return f"Log file not found: {path}"
    except PermissionError:
        return f"Permission denied: {path}"
    except Exception as e:
        return f"Error reading log: {e}"


def _parse_access(line: str) -> dict:
    m = _ACCESS_RE.match(line)
    if not m:
        return {"raw": line, "type": "access", "unparsed": True}
    d = m.groupdict()
    parts = (d["req"] or "").split(None, 2)
    try:
        bytes_v = int(d["bytes"])
    except (TypeError, ValueError):
        bytes_v = 0
    return {
        "raw":    line,
        "type":   "access",
        "ip":     d["ip"],
        "dt_raw": d["dt"],
        "dt_iso": _dt_access(d["dt"]),
        "method": parts[0] if parts else "-",
        "path":   parts[1] if len(parts) > 1 else "-",
        "status": int(d["status"]),
        "bytes":  bytes_v,
        "ua":      d.get("ua") or "-",
        "referer": d.get("referer") or "-",
    }


def _parse_error(line: str) -> dict:
    m = _ERROR_RE.match(line)
    if not m:
        return {"raw": line, "type": "error", "unparsed": True}
    d = m.groupdict()
    return {
        "raw":     line,
        "type":    "error",
        "dt_raw":  d["dt"],
        "dt_iso":  _dt_error(d["dt"]),
        "level":   d["level"].lower(),
        "message": d["msg"],
    }


def get_access_log(lines: int = 100) -> str:
    return _tail(ACCESS_LOG, lines)


def get_error_log(lines: int = 100) -> str:
    return _tail(ERROR_LOG, lines)


def get_access_log_json(lines: int = 100) -> list:
    return [_parse_access(l) for l in get_access_log(lines).splitlines() if l.strip()]


def get_error_log_json(lines: int = 100) -> list:
    return [_parse_error(l) for l in get_error_log(lines).splitlines() if l.strip()]
