"""Read-only security checks.

Classification is split from I/O: the `classify_*` / `evaluate_*` functions are
pure and unit-tested; `scan_target` performs the requests and assembles results.

DATA SAFETY: response bodies are inspected in memory only to decide whether a
file is genuinely exposed. Findings record the URL, status code, severity and
*counts* (e.g. "9 KEY=VALUE lines"); never key names, values or file content.
"""

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from .net import AuditClient, HttpResult, TlsResult, resolves
from .remediation import remediation_for
from .scope import Target

CRITICAL, MEDIUM, LOW, PASS = "CRITICAL", "MEDIUM", "LOW", "PASS"
SEVERITY_ORDER = {CRITICAL: 0, MEDIUM: 1, LOW: 2, PASS: 3}

HSTS_MIN_AGE = 15552000  # 180 days

# (path, kind, severity-if-exposed)
SENSITIVE_PATHS = [
    ("/.env", "env", CRITICAL),
    ("/.env.production", "env", CRITICAL),
    ("/.env.backup", "env", CRITICAL),
    ("/.git/config", "git", CRITICAL),
    ("/phpinfo.php", "phpinfo", MEDIUM),
]


@dataclass
class Finding:
    check_id: str
    category: str
    check: str
    severity: str
    title: str
    detail: str = ""
    url: str | None = None
    http_status: int | None = None
    evidence: dict = field(default_factory=dict)
    remediation_id: str | None = None

    def to_dict(self, domain: str) -> dict:
        d = asdict(self)
        d.pop("remediation_id")
        d["remediation"] = remediation_for(self.remediation_id, domain) if self.severity != PASS else None
        return d


# ---------------------------------------------------------------------------
# Sensitive file exposure
# ---------------------------------------------------------------------------

_ENV_LINE = re.compile(r"^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=")
_GIT_CORE = re.compile(r"^\s*\[core\]\s*$", re.MULTILINE)
_HTML_START = re.compile(r"^\s*(<!doctype|<html|<head|<body|<\?xml)", re.IGNORECASE)


def env_line_count(text: str) -> tuple[int, int]:
    """Return (KEY=VALUE lines, meaningful lines). Comments/blank lines excluded."""
    matches = total = 0
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        total += 1
        if _ENV_LINE.match(s):
            matches += 1
    return matches, total


def looks_like_env(text: str) -> tuple[bool, int]:
    if _HTML_START.match(text):
        return False, 0
    matches, total = env_line_count(text)
    # Require structure, not a single stray '='. Either several assignments, or
    # a short file that is *entirely* assignments.
    ok = (matches >= 2 and matches / max(total, 1) >= 0.5) or (matches == 1 and total == 1)
    return ok, matches


def looks_like_git_config(text: str) -> bool:
    return bool(_GIT_CORE.search(text)) and not _HTML_START.match(text)


def looks_like_phpinfo(text: str) -> bool:
    if "<title>phpinfo()</title>" in text or "phpinfo()" in text[:4096]:
        return True
    return "PHP Version" in text and any(m in text for m in ("PHP License", "Zend Engine", "PHP Credits", "php.ini"))


def classify_probe(path: str, kind: str, exposed_severity: str, res: HttpResult) -> Finding:
    check = f"Exposed file {path}"
    rid = {"env": "exposed-env", "git": "exposed-git", "phpinfo": "exposed-phpinfo"}[kind]
    base = dict(check_id=f"files{path}", category="Sensitive Files", check=check,
                url=res.url, http_status=res.status)

    if res.status is None:
        return Finding(**base, severity=LOW, title="Probe inconclusive",
                       detail=res.error or "No response", remediation_id="probe-inconclusive")

    status = res.status
    if status == 200:
        text = res.body.decode("utf-8", errors="replace")

        # Soft-404 filter: dotfiles/config are never legitimately served as HTML.
        # phpinfo() *is* HTML, so it is validated by content signature instead.
        if kind in ("env", "git") and res.content_type == "text/html":
            return Finding(**base, severity=PASS, title="Not exposed (HTML response)",
                           detail="200 OK with Content-Type text/html: treated as a custom error / catch-all page.")

        if kind == "env":
            ok, n = looks_like_env(text)
            if ok:
                return Finding(**base, severity=exposed_severity, title="Environment file publicly readable",
                               detail=f"Response contains {n} KEY=VALUE assignment line(s). Content not recorded.",
                               evidence={"key_value_lines": n, "content_type": res.content_type or None},
                               remediation_id=rid)
        elif kind == "git":
            if looks_like_git_config(text):
                return Finding(**base, severity=exposed_severity, title="Git repository metadata exposed",
                               detail="Response contains a [core] section: /.git/ is being served. Content not recorded.",
                               evidence={"git_core_section": True, "content_type": res.content_type or None},
                               remediation_id=rid)
        elif kind == "phpinfo":
            if looks_like_phpinfo(text):
                return Finding(**base, severity=exposed_severity, title="phpinfo() page publicly accessible",
                               detail="Response matches phpinfo() output signature. Content not recorded.",
                               evidence={"phpinfo_signature": True}, remediation_id=rid)

        return Finding(**base, severity=PASS, title="Not exposed (content mismatch)",
                       detail=f"200 OK ({res.content_type or 'no content-type'}) but content does not match the "
                              f"expected file structure; likely a catch-all route.")

    if status in (401, 403):
        return Finding(**base, severity=PASS, title="Blocked", detail=f"Access denied ({status}).")
    if status in (404, 410):
        return Finding(**base, severity=PASS, title="Not found", detail=f"Path not served ({status}).")
    if 300 <= status < 400:
        return Finding(**base, severity=PASS, title="Redirected, not served",
                       detail=f"{status} redirect; file content not returned.")
    if status >= 500:
        return Finding(**base, severity=LOW, title="Probe inconclusive (server error)",
                       detail=f"Server returned {status}; exposure could not be ruled out.",
                       remediation_id="probe-inconclusive")
    return Finding(**base, severity=PASS, title="Not served", detail=f"Server returned {status}.")


# ---------------------------------------------------------------------------
# HTTP security headers
# ---------------------------------------------------------------------------

def parse_csp(value: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            out.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return out


def _csp_script_weakness(directives: dict[str, list[str]]) -> str | None:
    src = directives.get("script-src", directives.get("default-src"))
    if src is None:
        return "no script-src or default-src directive, so scripts are unrestricted"
    has_nonce_or_hash = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in src)
    problems = []
    if "'unsafe-inline'" in src and not has_nonce_or_hash:
        problems.append("'unsafe-inline'")
    if "'unsafe-eval'" in src:
        problems.append("'unsafe-eval'")
    if any(t in ("*", "http:", "https:", "data:") for t in src):
        problems.append("wildcard/scheme-only source")
    if problems:
        which = "script-src" if "script-src" in directives else "default-src"
        return f"{which} allows " + ", ".join(problems)
    return None


def evaluate_headers(res: HttpResult) -> list[Finding]:
    h = res.headers
    base = dict(category="Security Headers", url=res.url, http_status=res.status)
    findings: list[Finding] = []

    # --- HSTS
    hsts = h.get("strict-transport-security")
    if not hsts:
        findings.append(Finding(check_id="headers.hsts", check="Strict-Transport-Security", severity=MEDIUM,
                                title="HSTS header missing", remediation_id="hsts-missing", **base))
    else:
        m = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.IGNORECASE)
        age = int(m.group(1)) if m else None
        ev = {"value": hsts}
        if age is None or age == 0:
            findings.append(Finding(check_id="headers.hsts", check="Strict-Transport-Security", severity=MEDIUM,
                                    title="HSTS ineffective", detail="max-age missing or 0 (disables HSTS).",
                                    evidence=ev, remediation_id="hsts-missing", **base))
        elif age < HSTS_MIN_AGE:
            findings.append(Finding(check_id="headers.hsts", check="Strict-Transport-Security", severity=LOW,
                                    title="HSTS max-age too short",
                                    detail=f"max-age={age} ({age // 86400} days); recommend ≥ 180 days.",
                                    evidence=ev, remediation_id="hsts-weak", **base))
        else:
            findings.append(Finding(check_id="headers.hsts", check="Strict-Transport-Security", severity=PASS,
                                    title="HSTS configured", detail=f"max-age={age} ({age // 86400} days).",
                                    evidence=ev, **base))

    # --- CSP
    csp = h.get("content-security-policy")
    csp_ro = h.get("content-security-policy-report-only")
    directives = parse_csp(csp) if csp else {}
    if not csp and not csp_ro:
        findings.append(Finding(check_id="headers.csp", check="Content-Security-Policy", severity=MEDIUM,
                                title="CSP header missing", remediation_id="csp-missing", **base))
    elif not csp:
        findings.append(Finding(check_id="headers.csp", check="Content-Security-Policy", severity=LOW,
                                title="CSP is report-only", detail="Policy is monitored but not enforced.",
                                evidence={"report_only": csp_ro}, remediation_id="csp-weak", **base))
    else:
        weak = _csp_script_weakness(directives)
        if weak:
            findings.append(Finding(check_id="headers.csp", check="Content-Security-Policy", severity=LOW,
                                    title="CSP present but weak", detail=weak[0].upper() + weak[1:] + ".",
                                    evidence={"value": csp}, remediation_id="csp-weak", **base))
        else:
            findings.append(Finding(check_id="headers.csp", check="Content-Security-Policy", severity=PASS,
                                    title="CSP configured", evidence={"value": csp}, **base))

    # --- X-Frame-Options (CSP frame-ancestors is the modern equivalent)
    xfo = (h.get("x-frame-options") or "").strip()
    frame_ancestors = "frame-ancestors" in directives
    if xfo.upper() in ("DENY", "SAMEORIGIN"):
        findings.append(Finding(check_id="headers.xfo", check="X-Frame-Options", severity=PASS,
                                title="Clickjacking protection set", detail=f"X-Frame-Options: {xfo}", **base))
    elif frame_ancestors:
        findings.append(Finding(check_id="headers.xfo", check="X-Frame-Options", severity=PASS,
                                title="Clickjacking protection via CSP",
                                detail="CSP frame-ancestors is set" + (f"; X-Frame-Options value '{xfo}' is ignored." if xfo else "."),
                                **base))
    elif xfo:
        findings.append(Finding(check_id="headers.xfo", check="X-Frame-Options", severity=LOW,
                                title="X-Frame-Options value invalid",
                                detail=f"'{xfo}' is not honoured by modern browsers.",
                                remediation_id="xfo-invalid", **base))
    else:
        findings.append(Finding(check_id="headers.xfo", check="X-Frame-Options", severity=LOW,
                                title="X-Frame-Options missing", remediation_id="xfo-missing", **base))

    # --- X-Content-Type-Options
    xcto = (h.get("x-content-type-options") or "").strip()
    if xcto.lower() == "nosniff":
        findings.append(Finding(check_id="headers.xcto", check="X-Content-Type-Options", severity=PASS,
                                title="MIME sniffing disabled", detail="nosniff", **base))
    else:
        findings.append(Finding(check_id="headers.xcto", check="X-Content-Type-Options", severity=LOW,
                                title="X-Content-Type-Options missing" if not xcto else "X-Content-Type-Options invalid",
                                detail=f"Value: '{xcto}'" if xcto else "", remediation_id="xcto-missing", **base))
    return findings


# ---------------------------------------------------------------------------
# TLS / transport
# ---------------------------------------------------------------------------

def evaluate_tls(target: Target, tls: TlsResult, expiry_days: int, now: datetime | None = None) -> Finding:
    now = now or datetime.now(timezone.utc)
    base = dict(check_id="tls.certificate", category="TLS/SSL", check="TLS certificate", url=target.https_base)
    ev = {}
    days_left = None
    if tls.not_after:
        days_left = (tls.not_after - now).total_seconds() / 86400
        ev = {"not_after": tls.not_after.isoformat(), "days_left": int(days_left // 1),
              "issuer": tls.issuer, "subject_cn": tls.subject_cn, "protocol": tls.protocol}

    if not tls.available:
        return Finding(**base, severity=CRITICAL, title="HTTPS not available",
                       detail=tls.error or "TLS connection failed.", remediation_id="https-unavailable")
    if not tls.verified:
        extra = ""
        if days_left is not None:
            extra = f" Certificate {'expired' if days_left < 0 else 'expires'} {tls.not_after:%Y-%m-%d}."
        return Finding(**base, severity=CRITICAL, title="Certificate validation failed",
                       detail=f"{tls.verify_error}.{extra}", evidence=ev, remediation_id="tls-invalid")
    if days_left is not None and days_left <= 7:
        return Finding(**base, severity=CRITICAL, title="Certificate expires within 7 days",
                       detail=f"Expires {tls.not_after:%Y-%m-%d %H:%M} UTC ({days_left:.1f} days).",
                       evidence=ev, remediation_id="tls-expiring")
    if days_left is not None and days_left <= expiry_days:
        return Finding(**base, severity=MEDIUM, title=f"Certificate expires within {expiry_days} days",
                       detail=f"Expires {tls.not_after:%Y-%m-%d} ({int(days_left)} days).",
                       evidence=ev, remediation_id="tls-expiring")
    return Finding(**base, severity=PASS, title="Certificate valid",
                   detail=f"Valid until {tls.not_after:%Y-%m-%d} ({int(days_left)} days), "
                          f"issuer {tls.issuer or 'unknown'}, {tls.protocol or 'TLS'}.",
                   evidence=ev)


def evaluate_http_redirect(res: HttpResult) -> Finding:
    base = dict(check_id="transport.http_redirect", category="TLS/SSL", check="HTTP → HTTPS redirect",
                url=res.url, http_status=res.status)
    if res.status is None:
        return Finding(**base, severity=PASS, title="Plain HTTP not served",
                       detail=f"Port 80 not reachable ({res.error}).")
    loc = res.headers.get("location", "")
    if 300 <= res.status < 400 and loc.lower().startswith("https://"):
        kind = "permanent" if res.status in (301, 308) else "temporary"
        return Finding(**base, severity=PASS, title="Redirects to HTTPS",
                       detail=f"{res.status} ({kind}) redirect to HTTPS.")
    if 300 <= res.status < 400:
        return Finding(**base, severity=MEDIUM, title="HTTP redirect does not go to HTTPS",
                       detail=f"{res.status} redirect stays on plain HTTP.", remediation_id="http-no-redirect")
    return Finding(**base, severity=MEDIUM, title="HTTP serves content without redirect",
                   detail=f"http:// responded {res.status} instead of redirecting to HTTPS.",
                   remediation_id="http-no-redirect")


# ---------------------------------------------------------------------------
# Orchestration for one target
# ---------------------------------------------------------------------------

def scan_target(target: Target, client: AuditClient, expiry_days: int) -> dict:
    started = datetime.now(timezone.utc)
    findings: list[Finding] = []
    notes: list[str] = []

    dns_err = resolves(target.host)
    if dns_err:
        findings.append(Finding(check_id="dns.resolve", category="Availability", check="DNS resolution",
                                severity=MEDIUM, title="Host does not resolve", detail=dns_err,
                                remediation_id="dns-failed"))
        notes.append("All other checks skipped: host does not resolve.")
        return _domain_record(target, started, findings, notes)

    # 1. TLS
    tls = client.tls_probe(target.host, target.port)
    findings.append(evaluate_tls(target, tls, expiry_days))
    https_ok = tls.available
    verify = tls.verified
    if https_ok and not verify:
        notes.append("Certificate is invalid; HTTP checks below were run with certificate verification disabled.")

    # 2. HTTP -> HTTPS redirect (standard ports only)
    if https_ok and not target.custom_port:
        findings.append(evaluate_http_redirect(client.get(target.http_base + "/", read_body=False)))

    # 3. Security headers on the landing page
    if https_ok:
        res = client.get(target.https_base + "/", verify=verify, follow_redirects=True, read_body=False)
        if res.status is None:
            notes.append(f"Header checks skipped: {res.error}")
        else:
            if res.redirect_chain:
                notes.append("Landing page redirected: " + " · ".join(res.redirect_chain))
            if res.stopped_off_scope:
                notes.append(f"Stopped at a redirect to an out-of-scope host ({res.stopped_off_scope}); "
                             f"headers evaluated on the redirect response.")
            findings.extend(evaluate_headers(res))
    else:
        notes.append("Header checks skipped: HTTPS not available (HSTS/CSP are only meaningful over HTTPS).")

    # 4. Sensitive files
    if https_ok:
        probe_base = target.https_base
    elif not target.custom_port:
        probe_base = target.http_base
        notes.append("Sensitive-file probes ran over plain HTTP because HTTPS is unavailable.")
    else:
        probe_base = None
        notes.append("Sensitive-file probes skipped: HTTPS unavailable on the custom port.")

    if probe_base:
        for path, kind, sev in SENSITIVE_PATHS:
            res = client.get(probe_base + path, verify=verify)
            findings.append(classify_probe(path, kind, sev, res))
            res.body = b""  # drop content as soon as it is classified

    return _domain_record(target, started, findings, notes)


def _domain_record(target: Target, started: datetime, findings: list[Finding], notes: list[str]) -> dict:
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1
    return {
        "domain": target.label,
        "scanned_at": started.isoformat(timespec="seconds"),
        "duration_seconds": round((datetime.now(timezone.utc) - started).total_seconds(), 1),
        "counts": counts,
        "worst": next((s for s in SEVERITY_ORDER if counts[s]), PASS),
        "notes": notes,
        "findings": [f.to_dict(target.host) for f in findings],
    }
