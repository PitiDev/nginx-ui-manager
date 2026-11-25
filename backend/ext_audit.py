"""External Security Audit: web wrapper around tools/security_audit.

Scope (the authorized host list) and reports live in DATA_DIR so they survive
container rebuilds. Only one scan runs at a time, process-wide, so the polite
rate limits (2 concurrent, 500 ms spacing) hold no matter how many people click
"Run". Scans run in a background thread; the page polls `status()`.
"""

import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from backend import activity, nginx
from tools.security_audit import runner
from tools.security_audit.net import ScanCancelled, build_user_agent
from tools.security_audit.report import write_reports
from tools.security_audit.scope import ScopeError, parse_host, parse_targets

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
SCOPE_FILE = DATA_DIR / "audit_domains.txt"
SETTINGS_FILE = DATA_DIR / "audit_settings.json"
REPORT_DIR = DATA_DIR / "audit_reports"
KEEP_REPORTS = 50
MAX_SCOPE_BYTES = 50_000

_REPORT_ID = re.compile(r"^security-report-\d{4}-\d{2}-\d{2}_\d{6}$")
_CONTACT_RE = re.compile(r"^[\w.@+:/#\- ]{0,100}$")
_SERVER_NAME = re.compile(r"^\s*server_name\s+([^;]+);", re.MULTILINE)

DEFAULT_SCOPE = """\
# Authorized scan targets: one host per line.
# List ONLY hosts your organization owns or has written permission to test.
# Allowed:  example.com   www.example.com   203.0.113.10   staging.example.com:8443
"""


# ── Scope & settings ──────────────────────────────────────────────────────────

def get_settings() -> dict:
    try:
        s = json.loads(SETTINGS_FILE.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        s = {}
    return {"contact": s.get("contact", ""), "expiry_days": int(s.get("expiry_days", 30))}


def get_scope_text() -> str:
    try:
        return SCOPE_FILE.read_text(encoding="utf-8")
    except FileNotFoundError:
        return DEFAULT_SCOPE


def get_scope() -> dict:
    text = get_scope_text()
    try:
        hosts = [t.label for t in parse_targets(text, allow_empty=True)]
        error = None
    except ScopeError as e:
        hosts, error = [], str(e)
    return {"text": text, "hosts": hosts, "error": error, **runner.estimate(len(hosts))}


def save_scope(text: str, contact: str, expiry_days: int) -> tuple[bool, str]:
    text = text.replace("\r\n", "\n")
    if len(text.encode()) > MAX_SCOPE_BYTES:
        return False, "Scope list is too large."
    try:
        targets = parse_targets(text, allow_empty=True)
    except ScopeError as e:
        return False, f"Scope not saved: {e}"
    contact = contact.strip()
    if not _CONTACT_RE.match(contact):
        return False, "Contact may only contain letters, digits, spaces and . @ + : / # -"
    expiry_days = max(1, min(int(expiry_days), 365))

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SCOPE_FILE.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    SETTINGS_FILE.write_text(json.dumps({"contact": contact, "expiry_days": expiry_days}))
    return True, f"Scope saved: {len(targets)} authorized host(s)."


def suggest_hosts() -> list[str]:
    """Hostnames from `server_name` in the local node's enabled sites (read-only)."""
    found: set[str] = set()
    try:
        files = [p for p in nginx.SITES_ENABLED.iterdir() if p.is_file()]
    except (FileNotFoundError, PermissionError):
        return []
    for path in files:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        text = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
        for m in _SERVER_NAME.finditer(text):
            for name in m.group(1).split():
                if name in ("_", "localhost") or name.startswith("~") or "*" in name or "$" in name:
                    continue
                try:
                    found.add(parse_host(name).label)
                except ScopeError:
                    continue
    return sorted(found)


# ── Scan job ──────────────────────────────────────────────────────────────────

_lock = threading.Lock()
_cancel = threading.Event()
_job: dict = {"state": "idle"}


def status() -> dict:
    with _lock:
        job = json.loads(json.dumps(_job))  # deep copy
    if job.get("state") == "running":
        job["elapsed"] = round(time.time() - job["started_ts"], 1)
    return job


def start_scan(user: str, role: str, ip: str) -> tuple[bool, str]:
    try:
        targets = parse_targets(get_scope_text())
    except ScopeError as e:
        return False, str(e).replace("\n", " ")
    settings = get_settings()

    with _lock:
        if _job.get("state") == "running":
            return False, "A scan is already running."
        _cancel.clear()
        _job.clear()
        _job.update({
            "state": "running",
            "started_by": user,
            "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "started_ts": time.time(),
            "total": len(targets),
            "done": 0,
            "current": [],
            "hosts": [],
            **runner.estimate(len(targets)),
        })

    threading.Thread(target=_run, args=(targets, settings, user, role, ip),
                     name="ext-audit", daemon=True).start()
    return True, f"Scan started for {len(targets)} host(s)."


def cancel_scan() -> bool:
    with _lock:
        if _job.get("state") != "running":
            return False
    _cancel.set()
    return True


def _progress(event: str, target, payload) -> None:
    with _lock:
        if event == "start":
            _job["current"].append(target.label)
            return
        if target.label in _job["current"]:
            _job["current"].remove(target.label)
        _job["done"] += 1
        if event == "done":
            _job["hosts"].append({"domain": target.label, "worst": payload["worst"], "counts": payload["counts"]})
        else:
            _job["hosts"].append({"domain": target.label, "worst": "ERROR", "error": str(payload)[:200]})


def _run(targets, settings, user, role, ip) -> None:
    try:
        report = runner.run_scan(
            targets, expiry_days=settings["expiry_days"], contact=settings["contact"] or None,
            source="Nginx UI scope list", on_progress=_progress, cancel_event=_cancel,
        )
        report["started_by"] = user
        json_path, _ = write_reports(report, REPORT_DIR, datetime.now())
        _prune()
        s = report["summary"]
        with _lock:
            _job.update(state="done", report=json_path.stem, summary=s, current=[],
                        duration=report["duration_seconds"])
        activity.log(user, role, "audit.complete", target=json_path.stem, ip=ip,
                     detail=f"{s['total_domains']} hosts: {s['critical']} critical, "
                            f"{s['medium']} medium, {s['low']} low, {s['passed']} passed",
                     result="error" if s["critical"] else "success")
    except ScanCancelled:
        with _lock:
            _job.update(state="cancelled", current=[])
        activity.log(user, role, "audit.cancel", detail="Scan cancelled; no report written", ip=ip)
    except Exception as e:  # surface, never crash the app
        with _lock:
            _job.update(state="error", error=f"{type(e).__name__}: {e}", current=[])
        activity.log(user, role, "audit.complete", detail=f"Scan failed: {type(e).__name__}", ip=ip, result="error")


# ── Reports ───────────────────────────────────────────────────────────────────

def _valid(report_id: str) -> bool:
    return bool(_REPORT_ID.match(report_id or ""))


def report_path(report_id: str, ext: str) -> Path | None:
    if not _valid(report_id) or ext not in ("json", "html"):
        return None
    p = REPORT_DIR / f"{report_id}.{ext}"
    return p if p.is_file() else None


def list_reports() -> list[dict]:
    out = []
    if not REPORT_DIR.is_dir():
        return out
    for p in sorted(REPORT_DIR.glob("security-report-*.json"), reverse=True):
        if not _valid(p.stem):
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        out.append({"id": p.stem, "generated_at": data.get("generated_at"),
                    "started_by": data.get("started_by"), "summary": data.get("summary", {})})
    return out


def get_report(report_id: str) -> dict | None:
    p = report_path(report_id, "json")
    if not p:
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def delete_report(report_id: str) -> tuple[bool, str]:
    if not _valid(report_id):
        return False, "Invalid report id."
    removed = False
    for ext in ("json", "html"):
        p = REPORT_DIR / f"{report_id}.{ext}"
        if p.is_file():
            p.unlink()
            removed = True
    return (True, "Report deleted.") if removed else (False, "Report not found.")


def _prune() -> None:
    reports = sorted(REPORT_DIR.glob("security-report-*.json"), reverse=True)
    for p in reports[KEEP_REPORTS:]:
        for ext in ("json", "html"):
            (REPORT_DIR / f"{p.stem}.{ext}").unlink(missing_ok=True)


def user_agent_preview() -> str:
    return build_user_agent(get_settings()["contact"] or None)
