"""Cyber Security Monitor.

Three independent analyses, all read-only:

1. Threat detection: signature + behavioural analysis of nginx access/error
   logs (local, one remote node, or the whole fleet). Flags SQLi, XSS, path
   traversal, RCE, Log4Shell, Shellshock, scanners, sensitive-file probes,
   brute force, enumeration and floods, and scores each source IP.
2. Hardening audit: static checks over nginx.conf, conf.d, snippets and every
   enabled site (TLS versions/ciphers, security headers, autoindex, rate
   limiting, hidden-file blocking, default server, cert expiry).
3. App self-audit: this Nginx UI's own posture (JWT secret, default admin
   password, failed logins against the UI).

Nothing here writes to nginx, runs user-controlled shell input, or blocks
traffic. Blocking is left to the operator (the UI generates `deny` snippets).
"""

import fnmatch
import glob
import ipaddress
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote_plus

from backend import activity, geoip, laos, logs, proxy_mgr
from backend.traffic import _split_server_blocks

NGINX_CONF_DIR = Path(os.getenv("NGINX_CONF_DIR", "/etc/nginx"))

# Behavioural thresholds (per source IP, over the analysed log window).
BRUTE_FORCE_THRESHOLD = int(os.getenv("SECURITY_BRUTE_FORCE_THRESHOLD", "10"))
ENUM_404_THRESHOLD    = int(os.getenv("SECURITY_ENUM_404_THRESHOLD", "40"))
FLOOD_RPM_THRESHOLD   = int(os.getenv("SECURITY_FLOOD_RPM_THRESHOLD", "300"))


def _parse_nets(raw: str) -> list:
    nets = []
    for part in (raw or "").replace(";", ",").split(","):
        part = part.strip()
        if part:
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                pass
    return nets


# Load balancers, upstream proxies, health checkers, monitoring: excluded from
# the volume-based (behavioural) detections. Signature detections still apply
# to them, because attacks relayed through a proxy arrive with the proxy's IP.
TRUSTED_NETS = _parse_nets(os.getenv("SECURITY_TRUSTED_IPS", ""))

TIMELINE_BUCKET_SECONDS = 300   # 5 min
TIMELINE_BUCKETS        = 24    # 2 h window

SEVERITY_RANK   = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_POINTS = {"info": 0, "low": 3, "medium": 8, "high": 20, "critical": 40}

BLOCKED_STATUSES = {403, 429, 444}


# ── Signatures ────────────────────────────────────────────────────────────────
# (id, label, severity, fields, pattern). `fields` picks what is matched:
#   "path" → URL-decoded request target, "ua" → User-Agent,
#   "any"  → path + UA + referer (header-borne payloads like Log4Shell).
_SIGNATURES = [
    ("log4shell", "Log4Shell / JNDI injection", "critical", "any",
     r"\$\{\s*(jndi|\$\{|lower:|upper:|env:|::-j)"),
    ("shellshock", "Shellshock (CVE-2014-6271)", "critical", "any",
     r"\(\)\s*\{\s*:?\s*;\s*\}\s*;"),
    ("rce", "Command injection / RCE", "critical", "path",
     r"(;|\||&&|`|\$\()\s*(cat|wget|curl|bash|sh|nc|ncat|id|uname|whoami|python|perl|chmod|rm)\b"
     r"|/bin/(ba)?sh\b|cmd\.exe|powershell|\b(shell_exec|passthru|proc_open|base64_decode|assert)\s*\("
     r"|\beval\s*\(|\bsystem\s*\(|allow_url_include|auto_prepend_file"),
    ("sqli", "SQL injection", "high", "path",
     r"union(\s|\+|/\*.*?\*/)+(all(\s|\+)+)?select|\bselect\b.{1,80}\bfrom\b.{1,80}\b(where|information_schema|dual)\b.*(--|#|'|\))"
     r"|'\s*(or|and)\s*'?\d+'?\s*=\s*'?\d+|\b(or|and)\s+\d+\s*=\s*\d+\s*(--|#|/\*)"
     r"|\b(sleep|benchmark|pg_sleep)\s*\(\s*\d+|waitfor\s+delay|information_schema"
     r"|extractvalue\s*\(|updatexml\s*\(|load_file\s*\(|into\s+(out|dump)file"
     r"|;\s*(drop|truncate|delete|insert|update)\s+|'\s*--|xp_cmdshell"),
    ("traversal", "Path traversal / LFI", "high", "path",
     r"\.\./|\.\.\\|%2e%2e|/etc/(passwd|shadow|hosts|group)|/proc/self/"
     r"|c:\\windows|boot\.ini|win\.ini|(php|file|expect|data|zip|phar|gopher)://"),
    ("xss", "Cross-site scripting (XSS)", "medium", "path",
     r"<\s*script|<\s*/\s*script|javascript\s*:|\bon(error|load|mouseover|focus|click)\s*="
     r"|<\s*(svg|img|iframe|body|details)[^>]*\bon\w+|document\.(cookie|domain)|\balert\s*\(|\bprompt\s*\("),
    ("ssrf", "SSRF / cloud metadata probe", "high", "path",
     r"169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data|127\.0\.0\.1:\d+|localhost:\d+"),
    ("sensitive", "Sensitive file probe", "medium", "path",
     r"/\.(env|git|svn|hg|htaccess|htpasswd|aws|ssh|docker|npmrc|DS_Store|vscode|idea)(/|$|\b)"
     r"|wp-config\.php|/config\.(php|json|ya?ml)$|\.(sql|bak|old|swp|backup|sqlite3?)(\?|$)"
     r"|/(phpinfo|info)\.php|/server-status|/server-info|id_rsa|/actuator(/|$)|/\.well-known/security\.txt\.bak"
     r"|/web\.config|/composer\.(json|lock)|/package\.json|/docker-compose\.ya?ml|/credentials"),
    ("cms_probe", "CMS / admin panel probe", "low", "path",
     r"/wp-(login|admin|content|includes)|/xmlrpc\.php|/phpmyadmin|/pma/|/myadmin|/administrator/"
     r"|/admin\.php|/cgi-bin/|/boaform|/hnap1|/vendor/phpunit|/solr/|/manager/html|/jenkins"
     r"|/owa/|/autodiscover|/telescope|/_ignition|/console/|/druid/|/geoserver|/\+cscoe\+"),
    ("scanner", "Vulnerability scanner", "medium", "ua",
     r"sqlmap|nikto|nmap|masscan|zgrab|nuclei|wpscan|gobuster|dirbuster|dirb\b|ffuf|feroxbuster"
     r"|acunetix|nessus|openvas|w3af|burp|zmeu|hydra|jaeles|whatweb|wfuzz|arachni|netsparker"
     r"|qualys|censysinspect|internet-measurement|l9explore|xfa1|fuzz"),
]
_COMPILED = [(sid, label, sev, fields, re.compile(pat, re.IGNORECASE))
             for sid, label, sev, fields, pat in _SIGNATURES]

_BAD_METHODS = {"TRACE", "TRACK", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL",
                "DEBUG", "SEARCH", "COPY", "MOVE", "LOCK", "UNLOCK"}
_KNOWN_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} | _BAD_METHODS

CATEGORY_META = {sid: {"label": label, "severity": sev} for sid, label, sev, _, _ in _SIGNATURES}
CATEGORY_META.update({
    "bad_method":  {"label": "Dangerous HTTP method",        "severity": "medium"},
    "protocol":    {"label": "Malformed / non-HTTP request", "severity": "low"},
    "brute_force": {"label": "Brute force (auth failures)",  "severity": "high"},
    "enumeration": {"label": "Directory / file enumeration", "severity": "medium"},
    "flood":       {"label": "Request flood / DoS",          "severity": "high"},
})

_AUTH_PATH_RE = re.compile(
    r"login|signin|sign-in|logon|auth|wp-login|/admin|token|session|oauth|password|/user", re.IGNORECASE)


def _decode(s: str) -> str:
    """Double URL-decode so `%252e%252e%252f` style evasion is still caught."""
    try:
        return unquote_plus(unquote_plus(s or ""))
    except Exception:
        return s or ""


def _is_internal(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local
    except ValueError:
        return False


def _is_trusted(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in TRUSTED_NETS)


_INTERNAL_HINT = ("internal address — usually a load balancer, upstream proxy or health check. "
                  "Not counted toward the threat level. Add it to SECURITY_TRUSTED_IPS to hide.")


def _parse_dt(iso: str):
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def classify(entry: dict) -> list[str]:
    """Return the attack categories one parsed access-log entry matches."""
    raw_path = entry.get("path") or ""
    path = _decode(raw_path)
    ua = entry.get("ua") or ""
    any_text = f"{raw_path} {path} {ua} {entry.get('referer') or ''}"
    cats = []
    for sid, _label, _sev, fields, rx in _COMPILED:
        target = path if fields == "path" else ua if fields == "ua" else any_text
        if rx.search(target):
            cats.append(sid)
    method = (entry.get("method") or "").upper()
    if method in _BAD_METHODS:
        cats.append("bad_method")
    elif method and method not in _KNOWN_METHODS:
        # Binary junk, TLS ClientHello sent to a plain-HTTP port, etc.
        cats.append("protocol")
    return cats


def _max_severity(cats) -> str:
    best = "info"
    for c in cats:
        s = CATEGORY_META.get(c, {}).get("severity", "info")
        if SEVERITY_RANK[s] > SEVERITY_RANK[best]:
            best = s
    return best


def _risk_level(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 15:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def _outcome(status: int) -> str:
    if status in BLOCKED_STATUSES:
        return "blocked"
    if status >= 400:
        return "failed"
    return "served"


# ── Error-log signals ─────────────────────────────────────────────────────────
_ERROR_SIGNALS = [
    ("rate_limited",   "Rate limited (limit_req)",        re.compile(r"limiting requests", re.I)),
    ("conn_limited",   "Connection limited (limit_conn)", re.compile(r"limiting connections", re.I)),
    ("denied_rule",    "Denied by allow/deny rule",       re.compile(r"access forbidden by rule", re.I)),
    ("dir_listing",    "Directory listing forbidden",     re.compile(r"directory index of .* is forbidden", re.I)),
    ("oversized_body", "Oversized request body",          re.compile(r"client intended to send too large", re.I)),
    ("malformed",      "Malformed request / bad host",    re.compile(r"client sent invalid|invalid host|client sent plain HTTP|request header.*too large", re.I)),
    ("tls_error",      "TLS handshake failure",           re.compile(r"SSL_do_handshake\(\) failed|ssl.*(handshake|alert|no shared cipher|unsupported protocol)", re.I)),
    ("upstream_down",  "Upstream unavailable",            re.compile(r"no live upstreams|upstream timed out|connect\(\) failed .* while connecting to upstream", re.I)),
]
_CLIENT_RE = re.compile(r"client:\s*([0-9a-fA-F.:]+)")


def analyze_error_log(entries: list) -> dict:
    counts = Counter()
    ip_counts = Counter()
    recent = []
    for e in entries:
        if e.get("unparsed"):
            continue
        msg = e.get("message") or ""
        for sid, _label, rx in _ERROR_SIGNALS:
            if rx.search(msg):
                counts[sid] += 1
                m = _CLIENT_RE.search(msg)
                ip = m.group(1) if m else ""
                if ip and sid != "upstream_down":
                    ip_counts[ip] += 1
                recent.append({
                    "dt_iso": e.get("dt_iso", ""), "level": e.get("level", ""),
                    "signal": sid, "ip": ip, "message": msg[:300], "node": e.get("node"),
                })
                break
    labels = {sid: label for sid, label, _ in _ERROR_SIGNALS}
    recent.sort(key=lambda r: r["dt_iso"] or "", reverse=True)
    return {
        "signals": [{"id": sid, "label": labels[sid], "count": counts.get(sid, 0)} for sid, _, _ in _ERROR_SIGNALS],
        "top_ips": [{"ip": ip, "count": c} for ip, c in ip_counts.most_common(8)],
        "recent": recent[:30],
    }


# ── Threat analysis ───────────────────────────────────────────────────────────

def _peak_per_minute(timestamps: list) -> int:
    """Max requests in any sliding 60s window (calendar-minute buckets would
    split a burst that straddles a minute boundary and under-count it)."""
    ts = sorted(timestamps)
    best = lo = 0
    for hi, t in enumerate(ts):
        while t - ts[lo] >= 60:
            lo += 1
        best = max(best, hi - lo + 1)
    return best


def analyze(access_entries: list, error_entries: list | None = None) -> dict:
    """Core threat analysis over parsed access-log entries (logs._parse_access
    shape, optionally tagged with "node")."""
    now = datetime.now(timezone.utc)
    parsed = [e for e in access_entries if not e.get("unparsed")]

    events = []
    cat_counts = Counter()
    sev_counts = Counter()
    outcome_counts = Counter()
    ips: dict[str, dict] = {}
    per_ip_times = defaultdict(list)
    node_stats: dict[str, dict] = {}

    def _ns(name):
        n = node_stats.get(name)
        if n is None:
            n = node_stats[name] = {"name": name, "requests": 0, "threats": 0, "blocked": 0, "served": 0,
                                    "critical": 0, "high": 0, "medium": 0, "low": 0,
                                    "attackers": set(), "last_threat": ""}
        return n

    buckets = [{"total": 0, "low": 0, "medium": 0, "high": 0, "critical": 0,
                "blocked": 0, "served": 0, "attackers": 0} for _ in range(TIMELINE_BUCKETS)]
    bucket_ips = [set() for _ in range(TIMELINE_BUCKETS)]
    window = TIMELINE_BUCKET_SECONDS * TIMELINE_BUCKETS
    first_dt = last_dt = None

    for e in parsed:
        ip = e.get("ip") or "-"
        status = int(e.get("status") or 0)
        dt = _parse_dt(e.get("dt_iso"))
        if dt:
            first_dt = dt if not first_dt or dt < first_dt else first_dt
            last_dt = dt if not last_dt or dt > last_dt else last_dt
            per_ip_times[ip].append(dt.timestamp())

        p = ips.get(ip)
        if p is None:
            p = ips[ip] = {
                "ip": ip, "hits": 0, "threat_hits": 0, "cats": Counter(),
                "status": Counter(), "auth_fail": 0, "not_found": 0, "blocked": 0,
                "served_threats": 0, "first_seen": "", "last_seen": "",
                "ua": "", "samples": [], "nodes": set(),
            }
        p["hits"] += 1
        p["status"][status // 100] += 1
        if e.get("node"):
            p["nodes"].add(e["node"])
        if status in BLOCKED_STATUSES:
            p["blocked"] += 1
        if status == 404:
            p["not_found"] += 1
        if status in (401, 403) and _AUTH_PATH_RE.search(e.get("path") or ""):
            p["auth_fail"] += 1
        iso = e.get("dt_iso") or ""
        if iso and (not p["first_seen"] or iso < p["first_seen"]):
            p["first_seen"] = iso
        if iso and iso >= p["last_seen"]:
            p["last_seen"] = iso
            p["ua"] = (e.get("ua") or "")[:200]

        idx = None
        if dt:
            age = (now - dt).total_seconds()
            if 0 <= age < window:
                idx = TIMELINE_BUCKETS - 1 - int(age // TIMELINE_BUCKET_SECONDS)
                buckets[idx]["total"] += 1
                if status in BLOCKED_STATUSES:
                    buckets[idx]["blocked"] += 1

        ns = _ns(e["node"]) if e.get("node") else None
        if ns:
            ns["requests"] += 1
            if status in BLOCKED_STATUSES:
                ns["blocked"] += 1

        cats = classify(e)
        if not cats:
            continue

        sev = _max_severity(cats)
        outcome = _outcome(status)
        p["threat_hits"] += 1
        for c in cats:
            p["cats"][c] += 1
            cat_counts[c] += 1
        sev_counts[sev] += 1
        outcome_counts[outcome] += 1
        if outcome == "served":
            p["served_threats"] += 1
        if ns:
            ns["threats"] += 1
            ns[sev] += 1
            ns["attackers"].add(ip)
            ns["served"] += outcome == "served"
            ns["last_threat"] = max(ns["last_threat"], iso)
        if len(p["samples"]) < 4:
            p["samples"].append((e.get("path") or "")[:160])
        if idx is not None:
            buckets[idx][sev] += 1
            bucket_ips[idx].add(ip)
            if outcome == "served":
                buckets[idx]["served"] += 1

        events.append({
            "dt_iso": iso, "ip": ip, "method": e.get("method", "-"),
            "path": (e.get("path") or "")[:300], "status": status,
            "ua": (e.get("ua") or "")[:200], "cats": cats, "severity": sev,
            "outcome": outcome, "node": e.get("node"),
            "internal": _is_internal(ip),
        })

    for b, seen in zip(buckets, bucket_ips):
        b["attackers"] = len(seen)

    # Behavioural detections ------------------------------------------------
    # Volume patterns from internal/private addresses are almost always the
    # infrastructure in front of nginx (LB, proxy, health checks) — they are
    # listed for visibility but never escalate the threat level or make the
    # IP an "attacker". Trusted networks are skipped entirely.
    behaviors = []
    for ip, p in ips.items():
        peak = _peak_per_minute(per_ip_times.get(ip, []))
        p["peak_rpm"] = peak
        if _is_trusted(ip):
            continue
        internal = _is_internal(ip)
        found = []
        if p["auth_fail"] >= BRUTE_FORCE_THRESHOLD:
            found.append(("brute_force", "high", f"{p['auth_fail']} failed auth responses (401/403) on login-like paths"))
        if p["not_found"] >= ENUM_404_THRESHOLD and p["not_found"] / max(p["hits"], 1) >= 0.5:
            found.append(("enumeration", "medium", f"{p['not_found']} × 404 out of {p['hits']} requests"))
        if peak >= FLOOD_RPM_THRESHOLD:
            found.append(("flood", "high", f"peak {peak} req/min (threshold {FLOOD_RPM_THRESHOLD})"))
        for kind, sev, detail in found:
            if internal:
                behaviors.append({"ip": ip, "type": kind, "severity": "info", "internal": True,
                                  "detail": f"{detail} · {_INTERNAL_HINT}", "peak_rpm": peak})
            else:
                p["cats"][kind] += 1
                cat_counts[kind] += 1
                behaviors.append({"ip": ip, "type": kind, "severity": sev, "internal": False,
                                  "detail": detail, "peak_rpm": peak})
    behaviors.sort(key=lambda b: -SEVERITY_RANK[b["severity"]])

    # Per-IP scoring ---------------------------------------------------------
    attackers = []
    for ip, p in ips.items():
        if not p["cats"]:
            continue
        score = 0
        for c, n in p["cats"].items():
            # Diminishing returns per category: repeats of the same probe add
            # half-weight (capped), while variety (recon → exploit) adds full.
            pts = SEVERITY_POINTS[CATEGORY_META[c]["severity"]]
            score += pts + pts * (min(n, 5) - 1) // 2
        if p["served_threats"]:
            score += 10
        score = min(100, score)
        attackers.append({
            "ip": ip, "score": score, "risk": _risk_level(score),
            "hits": p["hits"], "threat_hits": p["threat_hits"],
            "categories": [c for c, _ in p["cats"].most_common()],
            "blocked": p["blocked"], "served_threats": p["served_threats"],
            "peak_rpm": p["peak_rpm"], "first_seen": p["first_seen"], "last_seen": p["last_seen"],
            "ua": p["ua"], "samples": p["samples"], "internal": _is_internal(ip),
            "nodes": sorted(p["nodes"]),
        })
    attackers.sort(key=lambda a: (-a["score"], -a["threat_hits"]))

    # Overall threat level (recency-weighted) -------------------------------
    recent_cutoff = (now - timedelta(minutes=15)).isoformat()
    hour_cutoff = (now - timedelta(hours=1)).isoformat()
    recent_sev = Counter(ev["severity"] for ev in events if ev["dt_iso"] and ev["dt_iso"] >= recent_cutoff)
    hour_events = sum(1 for ev in events if ev["dt_iso"] and ev["dt_iso"] >= hour_cutoff)
    active = {a["ip"] for a in attackers if a["last_seen"] >= recent_cutoff}
    floods = [b for b in behaviors if b["type"] == "flood" and not b["internal"] and b["ip"] in active]
    recent_cats = Counter(c for ev in events if ev["dt_iso"] and ev["dt_iso"] >= recent_cutoff
                          and ev["severity"] in ("critical", "high") for c in ev["cats"])
    top_recent = ", ".join(CATEGORY_META[c]["label"] for c, _ in recent_cats.most_common(2))
    hot = next((a for a in attackers if a["risk"] == "critical" and a["last_seen"] >= recent_cutoff), None)
    n_recent = sum(recent_sev.values())
    if recent_sev["critical"] or floods:
        level = "critical"
        reason = (f"{recent_sev['critical']} critical attack(s) in the last 15 min: {top_recent}" if recent_sev["critical"]
                  else f"Request flood from {floods[0]['ip']} ({floods[0]['peak_rpm']} req/min)")
    elif recent_sev["high"] or hot:
        level = "high"
        reason = (f"{recent_sev['high']} high-severity attack(s) in the last 15 min: {top_recent}" if recent_sev["high"]
                  else f"Critical-risk attacker {hot['ip']} active in the last 15 min")
    elif n_recent or hour_events >= 20:
        level = "elevated"
        reason = (f"{n_recent} suspicious request(s) in the last 15 min" if n_recent
                  else f"{hour_events} suspicious requests in the last hour")
    elif events:
        level = "guarded"
        reason = f"{len(events)} older suspicious request(s) in the window, none in the last 15 min"
    else:
        level = "low"
        reason = "No suspicious traffic in the analysed window"

    # Is nginx logging a proxy/LB instead of real clients? Then every client
    # shares one IP: attackers can't be told apart or blocked individually.
    proxy_hint = None
    if len(parsed) >= 200:
        top_ip, top_n = Counter(e.get("ip") for e in parsed).most_common(1)[0]
        if top_n / len(parsed) >= 0.8 and _is_internal(top_ip or ""):
            proxy_hint = {"ip": top_ip, "share": round(top_n / len(parsed) * 100)}

    events.sort(key=lambda ev: ev["dt_iso"] or "", reverse=True)
    geo = geo_summary(attackers)

    # Laos map: every client (not only attackers) geolocated to Lao PDR
    att_by_ip = {a["ip"]: a for a in attackers}
    lao_clients, external_requests = [], 0
    for ip, p in ips.items():
        if _is_internal(ip):
            continue
        external_requests += p["hits"]
        g = geoip.lookup(ip)
        if g and g.get("cc") == "LA":
            a = att_by_ip.get(ip)
            lao_clients.append({"ip": ip, "hits": p["hits"], "threat_hits": p["threat_hits"],
                                "score": a["score"] if a else 0, "is_attacker": bool(a), "geo": g})
    lao = laos.summarize(lao_clients)
    lao["share"] = round(lao["requests"] / external_requests * 100, 1) if external_requests else 0.0
    lao["external_requests"] = external_requests
    for ev in events[:200]:
        g = geoip.lookup(ev["ip"])
        ev["cc"] = g["cc"] if g else None
        ev["country"] = g["country"] if g else None
        ev["lat"] = g["lat"] if g else None
        ev["lon"] = g["lon"] if g else None
    total = len(parsed)

    return {
        "generated_at": now.isoformat(),
        "threat_level": level,
        "level_reason": reason,
        "proxy_hint": proxy_hint,
        "analyzed_requests": total,
        "window": {
            "from": first_dt.isoformat() if first_dt else None,
            "to": last_dt.isoformat() if last_dt else None,
        },
        "threat_requests": len(events),
        "threat_ratio": round(len(events) / total * 100, 2) if total else 0.0,
        "unique_attackers": len(attackers),
        "severity": {s: sev_counts.get(s, 0) for s in ("critical", "high", "medium", "low")},
        "outcomes": {o: outcome_counts.get(o, 0) for o in ("blocked", "failed", "served")},
        "categories": [
            {"id": c, "label": CATEGORY_META[c]["label"], "severity": CATEGORY_META[c]["severity"], "count": n}
            for c, n in cat_counts.most_common()
        ],
        "attackers": attackers[:50],
        "behaviors": behaviors[:30],
        "events": events[:200],
        "geo": geo,
        "laos": lao,
        "timeline": buckets,
        "timeline_bucket_seconds": TIMELINE_BUCKET_SECONDS,
        "errors": analyze_error_log(error_entries or []),
        "nodes": [{**n, "attackers": len(n["attackers"])} for n in node_stats.values()],
        "thresholds": {
            "brute_force": BRUTE_FORCE_THRESHOLD, "enumeration_404": ENUM_404_THRESHOLD,
            "flood_rpm": FLOOD_RPM_THRESHOLD,
        },
    }


_KNOWN_LOG_LINE = re.compile(r"^\S+ \S+ \S+ \[|^\d{4}/\d{2}/\d{2} ")


def geo_summary(attackers: list) -> dict:
    """Locate every attacker IP (offline DB) and aggregate for the world map:
    per-location points (≈11 km grid) and per-country totals. Also tags each
    attacker dict with a small `geo` field for the attacker table."""
    st = geoip.status()
    points, countries, unlocated = {}, {}, 0
    for a in attackers:
        g = geoip.lookup(a["ip"])
        a["geo"] = {"cc": g["cc"], "country": g["country"], "city": g["city"]} if g else None
        if not g or not g.get("cc"):
            unlocated += 1
            continue
        c = countries.setdefault(g["cc"], {"cc": g["cc"], "country": g["country"],
                                           "attackers": 0, "hits": 0, "score": 0})
        c["attackers"] += 1
        c["hits"] += a["threat_hits"]
        c["score"] = max(c["score"], a["score"])
        if g.get("lat") is None:
            continue
        key = (round(g["lat"], 1), round(g["lon"], 1))
        p = points.get(key)
        if p is None:
            p = points[key] = {"lat": g["lat"], "lon": g["lon"], "cc": g["cc"], "country": g["country"],
                               "city": g["city"], "ips": 0, "hits": 0, "score": -1, "top_ip": "",
                               "last_seen": "", "cats": Counter()}
        p["ips"] += 1
        p["hits"] += a["threat_hits"]
        p["cats"].update(a["categories"])
        if a["score"] > p["score"]:
            p["score"], p["top_ip"] = a["score"], a["ip"]
        p["last_seen"] = max(p["last_seen"], a["last_seen"] or "")
    for x in list(countries.values()) + list(points.values()):
        x["risk"] = _risk_level(x["score"])
    for p in points.values():
        p["cats"] = [c for c, _ in p["cats"].most_common(3)]
    return {
        "available": st["available"],
        "error": st.get("error"),
        "source": st.get("source"),
        "attribution": st.get("attribution"),
        "home": geoip.home(),
        "points": sorted(points.values(), key=lambda p: (-p["score"], -p["hits"]))[:250],
        "countries": sorted(countries.values(), key=lambda c: (-c["hits"], -c["score"]))[:30],
        "country_count": len(countries),
        "located": len(attackers) - unlocated,
        "unlocated": unlocated,
    }


def _unreachable(entries: list) -> str | None:
    """get_remote_logs() folds SSH failures into a single unparsed entry whose
    `raw` is the exception text (not a log line)."""
    if len(entries) == 1 and entries[0].get("unparsed"):
        raw = entries[0].get("raw", "")
        if raw and not _KNOWN_LOG_LINE.match(raw):
            return raw
    return None


# node id → (retry_after_monotonic, last_error). An unreachable node is not
# re-dialled on every refresh — each attempt can block up to the SSH timeout.
_node_backoff: dict = {}
NODE_RETRY_SECONDS = 60


def _collect(node_id: str, lines: int) -> tuple[list, list, list]:
    """Gather access + error entries for local / one node / all nodes.

    Remote nodes are read in parallel (one thread per node, access and error
    log fetched concurrently), so one offline node costs a single SSH timeout
    instead of delaying the whole fleet sequentially.
    Returns (access, errors, node_meta) where node_meta lists every node that
    was in scope with its reachability.
    """
    from backend import node_ssh, nodes as node_store

    def tag(entries, name):
        for x in entries:
            x["node"] = name
        return entries

    access, errors, meta = [], [], []
    if node_id in ("local", "all"):
        access += tag(logs.get_access_log_json(lines), "Local")
        errors += tag(logs.get_error_log_json(min(lines, 2000)), "Local")
        meta.append({"id": "local", "name": "Local", "host": "", "reachable": True, "error": None})

    if node_id == "all":
        targets = node_store.list_nodes()
    elif node_id == "local":
        targets = []
    else:
        n = node_store.get_node(node_id)
        if not n:
            raise ValueError("Node not found")
        targets = [n]

    def fetch(n):
        until, err = _node_backoff.get(n["id"], (0, None))
        if time.monotonic() < until:
            left = int(until - time.monotonic())
            return n, [{"raw": f"{err} (retrying in {left}s)", "unparsed": True}], []
        with ThreadPoolExecutor(max_workers=2) as ex:
            fa = ex.submit(node_ssh.get_remote_logs, n, "access", lines)
            fe = ex.submit(node_ssh.get_remote_logs, n, "error", min(lines, 2000))
            return n, fa.result(), fe.result()

    if targets:
        with ThreadPoolExecutor(max_workers=min(8, len(targets))) as ex:
            for n, a, e in ex.map(fetch, targets):
                reason = _unreachable(a)
                meta.append({"id": n["id"], "name": n["name"], "host": n.get("host", ""),
                             "reachable": not reason, "error": reason[:200] if reason else None})
                if reason:
                    if n["id"] not in _node_backoff or time.monotonic() >= _node_backoff[n["id"]][0]:
                        _node_backoff[n["id"]] = (time.monotonic() + NODE_RETRY_SECONDS, reason[:160])
                    continue
                _node_backoff.pop(n["id"], None)
                access += tag(a, n["name"])
                if not _unreachable(e):
                    errors += tag(e, n["name"])
    return access, errors, meta


_cache: dict = {}
_cache_lock = threading.Lock()
_CACHE_TTL = 4.0


_inflight: dict = {}


def get_overview(node_id: str = "local", lines: int = 5000) -> dict:
    """Cached, and de-duplicated while in flight: several open dashboards (or
    a wall monitor + a laptop) share one log read / SSH round instead of each
    starting their own."""
    lines = max(200, min(int(lines), 20000))
    key = (node_id, lines)
    with _cache_lock:
        hit = _cache.get(key)
        if hit and time.monotonic() - hit[0] < _CACHE_TTL:
            return hit[1]
        lock = _inflight.setdefault(key, threading.Lock())
    with lock:
        with _cache_lock:  # another caller may have just filled it
            hit = _cache.get(key)
            if hit and time.monotonic() - hit[0] < _CACHE_TTL:
                return hit[1]
        access, errors, meta = _collect(node_id, lines)
        result = analyze(access, errors)
        stats = {n["name"]: n for n in result["nodes"]}
        empty = {"requests": 0, "threats": 0, "blocked": 0, "served": 0, "critical": 0, "high": 0,
                 "medium": 0, "low": 0, "attackers": 0, "last_threat": ""}
        result["nodes"] = [{**empty, **stats.get(m["name"], {}), **m} for m in meta]
        result["node"] = node_id
        result["unreachable"] = [{"name": m["name"], "error": m["error"]} for m in meta if not m["reachable"]]
        with _cache_lock:
            _cache[key] = (time.monotonic(), result)
            for k in [k for k, v in _cache.items() if time.monotonic() - v[0] > 60]:
                _cache.pop(k, None)
        return result


# ── Hardening audit ───────────────────────────────────────────────────────────

_COMMENT_RE = re.compile(r"(?m)#.*$")
_INCLUDE_RE = re.compile(r"\binclude\s+([^;]+);")


def _strip_comments(text: str) -> str:
    return _COMMENT_RE.sub("", text or "")


def _resolve_includes(text: str, files: dict, depth: int = 0) -> str:
    """Inline `include` targets we have content for (snippets, conf.d,
    letsencrypt options) so headers/TLS settings defined there count."""
    if depth > 2:
        return text

    def repl(m):
        pattern = m.group(1).strip().strip("'\"")
        if not pattern.startswith("/"):
            pattern = str(NGINX_CONF_DIR / pattern)
        parts = [_strip_comments(files[p]) for p in sorted(files) if fnmatch.fnmatch(p, pattern)]
        if not parts:
            return m.group(0)
        return "\n".join(_resolve_includes(p, files, depth + 1) for p in parts)

    return _INCLUDE_RE.sub(repl, text)


def _http_context(nginx_conf: str) -> str:
    """Directives at http{} level in nginx.conf (server blocks removed so a
    default site inside nginx.conf isn't mistaken for global config)."""
    text = nginx_conf
    for block in _split_server_blocks(text):
        text = text.replace(block, "{}")
    return text


def _directive_values(text: str, name: str) -> list[str]:
    return [m.group(1).strip() for m in re.finditer(rf"(?<![\w$]){name}\s+([^;]+);", text)]


def _has_header(block: str, global_headers: str, header: str) -> bool:
    """nginx gotcha: add_header is inherited from the parent level ONLY if
    the current level defines no add_header of its own."""
    rx = re.compile(rf"add_header\s+['\"]?{header}\b", re.IGNORECASE)
    if rx.search(block):
        return True
    if re.search(r"\badd_header\s", block):
        return False
    return bool(rx.search(global_headers))


def _local_global_files() -> dict:
    files = {}
    pats = [NGINX_CONF_DIR / "nginx.conf", NGINX_CONF_DIR / "conf.d" / "*.conf",
            NGINX_CONF_DIR / "snippets" / "*.conf", Path("/etc/letsencrypt/options-ssl-nginx.conf")]
    for pat in pats:
        for p in glob.glob(str(pat)):
            try:
                files[p] = Path(p).read_text(errors="replace")
            except (OSError, PermissionError):
                continue
    return files


def audit_config(global_files: dict, sites: list) -> dict:
    """Static hardening checks. `global_files` maps absolute path → content
    for nginx.conf / conf.d / snippets; `sites` is list_proxies()-shaped."""
    main_conf = _strip_comments(global_files.get(str(NGINX_CONF_DIR / "nginx.conf"), ""))
    confd = "\n".join(_strip_comments(c) for p, c in global_files.items() if "/conf.d/" in p)
    http_ctx = _resolve_includes(_http_context(main_conf), global_files) + "\n" + confd

    # Per-server-block facts ---------------------------------------------------
    blocks = []
    for site in sites:
        if not site.get("enabled"):
            continue
        content = _resolve_includes(_strip_comments(site.get("content", "")), global_files)
        for raw in _split_server_blocks(content):
            names = []
            for v in _directive_values(raw, "server_name"):
                names += [n for n in v.split() if n != "_"]
            listens = _directive_values(raw, "listen")
            tls_listen = [bool(re.search(r"\b443\b|\bssl\b|\bquic\b", l)) for l in listens]
            is_ssl = any(tls_listen) or "ssl_certificate" in raw
            has_plain = not listens or not all(tls_listen)
            redirect = bool(re.search(r"return\s+30[1278]\s+https://|rewrite\s+\S+\s+https://", raw))
            only_redirect = redirect and "proxy_pass" not in raw and "root " not in raw
            blocks.append({
                "label": f"{site['name']}: {names[0] if names else '_'}",
                "site": site["name"], "names": names, "listens": listens, "raw": raw,
                "ssl": is_ssl, "plain": has_plain, "redirect": redirect, "only_redirect": only_redirect,
                "default": any("default_server" in l for l in listens),
            })
    # nginx.conf may itself carry server blocks
    for raw in _split_server_blocks(main_conf):
        listens = _directive_values(raw, "listen")
        blocks.append({
            "label": "nginx.conf: server", "site": "nginx.conf", "names": [], "listens": listens,
            "raw": raw, "ssl": "ssl_certificate" in raw, "plain": True, "redirect": False, "only_redirect": False,
            "default": any("default_server" in l for l in listens),
        })

    all_text = http_ctx + "\n" + "\n".join(b["raw"] for b in blocks)
    ssl_blocks = [b for b in blocks if b["ssl"]]
    content_blocks = [b for b in blocks if not b["only_redirect"]]
    checks = []

    def add(cid, title, severity, status, detail, recommendation="", affected=None):
        checks.append({"id": cid, "title": title, "severity": severity, "status": status,
                       "detail": detail, "recommendation": recommendation,
                       "affected": sorted(set(affected or []))[:40]})

    # 1. server_tokens
    tokens = [v.lower() for v in _directive_values(all_text, "server_tokens")]
    add("server_tokens", "Hide nginx version (server_tokens)", "medium",
        "pass" if tokens and all(v == "off" for v in tokens) else "fail",
        "Version banner disabled." if tokens and all(v == "off" for v in tokens)
        else "nginx version is exposed in the Server header and error pages, helping attackers pick exploits.",
        "http {\n    server_tokens off;\n}")

    # 2. TLS protocol versions
    if ssl_blocks:
        legacy, unset = [], []
        global_protocols = _directive_values(http_ctx, "ssl_protocols")
        for b in ssl_blocks:
            protos = _directive_values(b["raw"], "ssl_protocols") or global_protocols
            if not protos:
                unset.append(b["label"])
            elif re.search(r"SSLv[23]|TLSv1(\.1)?(\s|$)", " ".join(protos)):
                legacy.append(b["label"])
        status = "fail" if legacy else "warn" if unset else "pass"
        add("tls_protocols", "Only modern TLS (1.2 / 1.3)", "high", status,
            f"{len(legacy)} server block(s) allow SSLv3/TLS 1.0/1.1." if legacy
            else f"{len(unset)} SSL block(s) rely on nginx's built-in default (old nginx builds enable TLS 1.0/1.1)." if unset
            else "All SSL server blocks restrict protocols to modern TLS.",
            "ssl_protocols TLSv1.2 TLSv1.3;", legacy or unset)

        # 3. Weak ciphers
        weak = []
        global_ciphers = _directive_values(http_ctx, "ssl_ciphers")
        for b in ssl_blocks:
            for c in (_directive_values(b["raw"], "ssl_ciphers") or global_ciphers):
                toks = re.split(r"[:\s'\"]+", c)
                if any(re.search(r"RC4|(^|[-_])3?DES|MD5|NULL|EXPORT|aNULL|eNULL", t) and not t.startswith("!") for t in toks):
                    weak.append(b["label"])
        add("tls_ciphers", "No weak cipher suites", "high", "fail" if weak else "pass",
            "RC4/DES/3DES/MD5/NULL/EXPORT ciphers are enabled." if weak else "No known-weak cipher suites enabled.",
            "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-CHACHA20-POLY1305;\nssl_prefer_server_ciphers off;", weak)

        # 4. HSTS
        no_hsts = [b["label"] for b in ssl_blocks if not _has_header(b["raw"], http_ctx, "Strict-Transport-Security")]
        add("hsts", "HSTS on HTTPS sites", "medium", "fail" if no_hsts else "pass",
            f"{len(no_hsts)} HTTPS server block(s) send no Strict-Transport-Security header (SSL-strip / downgrade risk)."
            if no_hsts else "All HTTPS server blocks send HSTS.",
            'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;', no_hsts)

        # 5. HTTP → HTTPS redirect
        ssl_names = {n for b in ssl_blocks for n in b["names"]}
        # Plain-HTTP listeners for a host that also has HTTPS — either a
        # separate :80 block or `listen 80; listen 443 ssl;` in one block.
        plain_dupes = [b["label"] for b in blocks
                       if b["plain"] and not b["redirect"] and b["site"] != "nginx.conf"
                       and (b["ssl"] or set(b["names"]) & ssl_names)]
        add("https_redirect", "HTTP redirects to HTTPS", "medium", "warn" if plain_dupes else "pass",
            "These hosts are also served over plain HTTP without redirecting to HTTPS." if plain_dupes
            else "Every host that has HTTPS also redirects plain HTTP.",
            "server {\n    listen 80;\n    server_name example.com;\n    return 301 https://$host$request_uri;\n}", plain_dupes)
    else:
        add("tls_protocols", "HTTPS enabled", "high", "warn",
            "No enabled server block listens with TLS — all traffic (incl. credentials) is plaintext.",
            "listen 443 ssl;\nssl_certificate /path/fullchain.pem;\nssl_certificate_key /path/privkey.pem;")

    # 6-8. Security headers on content-serving blocks
    for cid, header, title, sev, rec in [
        ("xfo", "X-Frame-Options", "Clickjacking protection (X-Frame-Options)", "low",
         'add_header X-Frame-Options "SAMEORIGIN" always;'),
        ("nosniff", "X-Content-Type-Options", "MIME sniffing protection (X-Content-Type-Options)", "low",
         'add_header X-Content-Type-Options "nosniff" always;'),
        ("csp", "Content-Security-Policy", "Content-Security-Policy", "low",
         "add_header Content-Security-Policy \"default-src 'self'; frame-ancestors 'self'\" always;"),
        ("referrer", "Referrer-Policy", "Referrer-Policy", "low",
         'add_header Referrer-Policy "strict-origin-when-cross-origin" always;'),
    ]:
        missing = [b["label"] for b in content_blocks if not _has_header(b["raw"], http_ctx, header)]
        if cid == "xfo":
            missing = [m for m in missing
                       if not any(b["label"] == m and re.search(r"frame-ancestors", b["raw"], re.I) for b in content_blocks)]
        add(cid, title, sev, "warn" if missing else "pass",
            f"{len(missing)} server block(s) don't send {header}." if missing else f"{header} is set everywhere.",
            rec, missing)

    # 9. autoindex
    autoindex = [b["label"] for b in blocks if re.search(r"\bautoindex\s+on\s*;", b["raw"])]
    if re.search(r"\bautoindex\s+on\s*;", http_ctx):
        autoindex.append("http (global)")
    add("autoindex", "Directory listing disabled", "high", "fail" if autoindex else "pass",
        "autoindex on exposes full directory listings." if autoindex else "No directory listings enabled.",
        "autoindex off;", autoindex)

    # 10. Rate limiting
    zones = _directive_values(all_text, "limit_req_zone")
    applied = re.search(r"(?<!_)\blimit_req\s+zone=", all_text)
    add("rate_limit", "Request rate limiting (limit_req)", "medium",
        "pass" if zones and applied else "warn",
        f"{len(zones)} limit_req zone(s) defined and applied." if zones and applied
        else "limit_req_zone defined but never applied." if zones
        else "No rate limiting — login endpoints are open to brute force and floods.",
        "http {\n    limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n}\n"
        "server {\n    location /login { limit_req zone=perip burst=5 nodelay; }\n}")

    # 11. Hidden files
    hidden_rx = re.compile(r"location\s+~\*?\s+[\"']?(\^?)?/\\\.")
    no_hidden = [b["label"] for b in content_blocks if not hidden_rx.search(b["raw"])]
    add("hidden_files", "Block dotfiles (.git, .env)", "medium", "warn" if no_hidden else "pass",
        "Requests for /.git/, /.env etc. reach the backend/filesystem unfiltered." if no_hidden
        else "Dotfile access is denied.",
        "location ~ /\\.(?!well-known) {\n    deny all;\n}", no_hidden)

    # 12. Default catch-all server
    default_ok = any(b["default"] and re.search(r"return\s+(444|403|404)\b", b["raw"]) for b in blocks)
    add("default_server", "Catch-all default_server drops unknown hosts", "low",
        "pass" if default_ok else "warn",
        "Requests with unknown/IP Host headers are dropped." if default_ok
        else "Scanners hitting the server by IP are served by whichever site loads first.",
        "server {\n    listen 80 default_server;\n    listen 443 ssl default_server;\n"
        "    ssl_reject_handshake on;\n    server_name _;\n    return 444;\n}")

    # 13. Request body cap
    add("body_size", "Request body size capped", "low",
        "pass" if _directive_values(all_text, "client_max_body_size") else "info",
        "client_max_body_size is set explicitly." if _directive_values(all_text, "client_max_body_size")
        else "Using nginx default (1m). Set it explicitly per upload endpoint.",
        "client_max_body_size 10m;")

    return _score(checks, len(blocks))


def _score(checks: list, blocks: int) -> dict:
    penalty = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
    score = 100
    for c in checks:
        if c["status"] == "fail":
            score -= penalty[c["severity"]]
        elif c["status"] == "warn":
            score -= penalty[c["severity"]] // 2
    score = max(0, score)
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"
    order = {"fail": 0, "warn": 1, "info": 2, "pass": 3}
    checks.sort(key=lambda c: (order[c["status"]], -SEVERITY_RANK[c["severity"]]))
    return {
        "score": score, "grade": grade, "server_blocks": blocks, "checks": checks,
        "summary": Counter(c["status"] for c in checks),
    }


def audit_certificates() -> list[dict]:
    from backend import ssl_mgr
    out = []
    for f in ssl_mgr.list_ssl_files():
        info = f.get("cert_info")
        if not info:
            continue
        d = info["days_left"]
        status = "fail" if d < 0 else "fail" if d < 14 else "warn" if d < 30 else "pass"
        out.append({"name": f["name"], "cn": info.get("cn", ""), "expiry": info["expiry"],
                    "days_left": d, "status": status})
    out.sort(key=lambda c: c["days_left"])
    return out


def get_audit(node_id: str = "local") -> dict:
    from backend import node_ssh, nodes as node_store
    if node_id == "local":
        result = audit_config(_local_global_files(), proxy_mgr.list_proxies())
        result["certificates"] = audit_certificates()
    else:
        node = node_store.get_node(node_id)
        if not node:
            return {"error": "Node not found"}
        files = node_ssh.get_remote_nginx_globals(node)
        sites = node_ssh.list_remote_proxies(node)
        if not files and not sites:
            return {"error": f"Could not read nginx configuration from {node['name']} over SSH"}
        result = audit_config(files, sites)
        result["certificates"] = None
    result["node"] = node_id
    return result


def get_fleet_audit() -> dict:
    """Local audit in full, plus a grade for every node (audited in parallel)."""
    from backend import nodes as node_store
    nodes = node_store.list_nodes()
    targets = [("local", "Local")] + [(n["id"], n["name"]) for n in nodes]

    def one(t):
        try:
            return t, get_audit(t[0])
        except Exception as e:  # one broken node must not sink the fleet view
            return t, {"error": str(e)}

    with ThreadPoolExecutor(max_workers=min(8, len(targets))) as ex:
        results = list(ex.map(one, targets))
    result = dict(results[0][1])
    result["fleet"] = [{
        "id": nid, "name": name, "score": r.get("score"), "grade": r.get("grade"),
        "fail": (r.get("summary") or {}).get("fail", 0), "warn": (r.get("summary") or {}).get("warn", 0),
        "error": r.get("error"),
    } for (nid, name), r in results]
    result["node"] = "all"
    return result


# ── App self-audit (this Nginx UI) ───────────────────────────────────────────

def app_audit() -> dict:
    from backend import auth, users

    checks = []

    def add(title, severity, ok, detail, rec=""):
        checks.append({"title": title, "severity": severity, "status": "pass" if ok else "fail",
                       "detail": detail, "recommendation": rec})

    weak_secret = auth.SECRET_KEY in auth.WEAK_SECRETS or len(auth.SECRET_KEY) < 32
    src = getattr(auth, "SECRET_SOURCE", "env")
    if weak_secret:
        add("JWT signing secret", "critical", False,
            "Signing key is a known default or too short — anyone can forge an admin session token.",
            "SECRET_KEY=$(openssl rand -hex 32)")
    elif src == "env":
        add("JWT signing secret", "critical", True, "Strong SECRET_KEY supplied via environment (.env).")
    elif src == "generated":
        add("JWT signing secret", "critical", True,
            "SECRET_KEY in .env is missing or a known default, so the app generated a random key and "
            "stored it in DATA_DIR/.jwt_secret. Safe — but fix .env so the setting is explicit.")
    else:
        add("Persistent JWT signing secret", "low", False,
            "SECRET_KEY is missing/weak and DATA_DIR isn't writable: using a random in-memory key. "
            "Tokens are unforgeable but every restart logs everyone out.",
            "SECRET_KEY=$(openssl rand -hex 32)")

    default_pw = False
    try:
        default_pw = users.authenticate(users._BOOTSTRAP_USERNAME, "admin123") is not None
    except Exception:
        pass
    add("Default admin password", "critical", not default_pw,
        f"User '{users._BOOTSTRAP_USERNAME}' still accepts the default password 'admin123'."
        if default_pw else "Default bootstrap password is not accepted.",
        "Change it on the Users page.")

    add("Session lifetime", "low", auth.TOKEN_EXPIRE_HOURS <= 12,
        f"Tokens are valid for {auth.TOKEN_EXPIRE_HOURS}h.", "TOKEN_EXPIRE_HOURS=8")

    admins = [u for u in users.get_all() if u["role"] == "admin"]
    add("Admin accounts", "low", len(admins) <= 3,
        f"{len(admins)} admin account(s): {', '.join(u['username'] for u in admins)}.",
        "Keep admin accounts to the minimum; use the viewer role for read-only access.")

    # Failed logins against this UI ------------------------------------------
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    fails = [e for e in activity.get_logs(limit=2000, category="auth", result="error")
             if e.get("action") == "auth.login" and e.get("ts", "") >= since]
    ok_logins = [e for e in activity.get_logs(limit=2000, category="auth", result="success")
                 if e.get("action") == "auth.login" and e.get("ts", "") >= since]
    by_ip = Counter(e.get("ip") or "?" for e in fails)
    by_user = Counter(e.get("user") or "?" for e in fails)
    brute = [ip for ip, n in by_ip.items() if n >= BRUTE_FORCE_THRESHOLD]
    add("UI login brute force (24h)", "high", not brute,
        f"{len(brute)} IP(s) with ≥{BRUTE_FORCE_THRESHOLD} failed logins: {', '.join(brute[:5])}" if brute
        else f"{len(fails)} failed login(s) in the last 24h, no brute-force pattern.",
        "Put the UI behind VPN/SSH tunnel, or add limit_req on /login in the fronting nginx.")

    order = {"fail": 0, "pass": 1}
    checks.sort(key=lambda c: (order[c["status"]], -SEVERITY_RANK[c["severity"]]))
    return {
        "checks": checks,
        "failed_logins_24h": len(fails),
        "successful_logins_24h": len(ok_logins),
        "failed_by_ip": [{"ip": ip, "count": n} for ip, n in by_ip.most_common(10)],
        "failed_by_user": [{"user": u, "count": n} for u, n in by_user.most_common(10)],
        "recent_failed": fails[:20],
    }
