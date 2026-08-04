import concurrent.futures
import http.client
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


def _clean_domain(raw: str) -> str:
    raw = raw.strip()
    for prefix in ("https://", "http://"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
    return raw.split("/")[0].split(":")[0]


def _ensure_url(raw: str) -> str:
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        return "https://" + raw
    return raw


# ── SSL Test ──────────────────────────────────────────────────────────────────

def test_ssl(domain: str) -> dict:
    domain = _clean_domain(domain)
    out: dict = {"domain": domain, "cert": None, "checks": [], "score": 0, "max_score": 0}

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert   = ssock.getpeercert()
                cipher = ssock.cipher()   # (name, protocol, bits)
                proto  = ssock.version()  # e.g. "TLSv1.3"
    except ssl.SSLCertVerificationError as e:
        out["error"] = f"Certificate verification failed: {e.reason}"
        return out
    except ssl.SSLError as e:
        out["error"] = f"SSL error: {e}"
        return out
    except (socket.gaierror, socket.timeout, OSError) as e:
        out["error"] = f"Connection error: {e}"
        return out

    try:
        not_after  = datetime.strptime(cert["notAfter"],  "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except (KeyError, ValueError) as e:
        out["error"] = f"Could not parse certificate dates: {e}"
        return out

    now       = datetime.now(timezone.utc)
    days_left = (not_after - now).days

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer  = dict(x[0] for x in cert.get("issuer",  []))
    san     = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

    out["cert"] = {
        "cn":          subject.get("commonName", ""),
        "issuer_org":  issuer.get("organizationName", ""),
        "issuer_cn":   issuer.get("commonName", ""),
        "not_before":  not_before.strftime("%Y-%m-%d"),
        "not_after":   not_after.strftime("%Y-%m-%d"),
        "days_left":   days_left,
        "san":         san,
        "protocol":    proto or "",
        "cipher":      cipher[0] if cipher else "",
        "cipher_bits": cipher[2] if cipher else 0,
    }

    checks: list[dict] = []

    def chk(name: str, passed: bool, detail: str, warn: bool = False) -> None:
        checks.append({"name": name, "pass": passed, "warn": warn, "detail": detail})

    # 1. Not expired
    chk("Certificate not expired",
        days_left > 0,
        f"Expires {not_after.strftime('%Y-%m-%d')} ({days_left}d left)"
        if days_left > 0 else f"EXPIRED {abs(days_left)} days ago")

    # 2. Expiry warning
    if days_left > 0:
        chk("Expiry > 30 days",
            days_left > 30,
            f"{days_left} days remaining" if days_left > 30 else f"Only {days_left}d left — renew soon!",
            warn=(0 < days_left <= 30))

    # 3. Protocol
    safe_protos = {"TLSv1.2", "TLSv1.3"}
    chk("TLS 1.2 or higher", proto in safe_protos, proto or "unknown")

    # 4. Cipher strength
    weak_kw    = ("RC4", "DES", "NULL", "EXPORT", "MD5", "ANON")
    cipher_str = cipher[0] if cipher else ""
    is_strong  = not any(k in cipher_str.upper() for k in weak_kw)
    chk("Strong cipher suite", is_strong,
        f"{cipher_str} ({cipher[2]}-bit)" if cipher else "unknown")

    # 5. Domain in SAN
    def in_san(d: str, names: list[str]) -> bool:
        d = d.lower()
        for name in names:
            n = name.lower()
            if n == d:
                return True
            if n.startswith("*."):
                parts = d.split(".", 1)
                if len(parts) == 2 and parts[1] == n[2:]:
                    return True
        return False

    matched = in_san(domain, san)
    san_str  = ", ".join(san[:4]) + ("…" if len(san) > 4 else "")
    chk("Domain matches certificate", matched,
        f"SANs: {san_str}" if san else "No SAN entries")

    # 6. Key bits
    bits = cipher[2] if cipher else 0
    chk("Key strength >= 128-bit", bits >= 128, f"{bits}-bit" if bits else "unknown")

    passed = sum(1 for c in checks if c["pass"] and not c.get("warn"))
    out["checks"]    = checks
    out["score"]     = passed
    out["max_score"] = len(checks)
    return out


# ── Security Headers Test ─────────────────────────────────────────────────────

def test_security(url: str) -> dict:
    url = _ensure_url(url)
    out: dict = {"url": url, "checks": [], "response_headers": {}, "score": 0, "max_score": 0}

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NginxUI-SecurityTest/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw_h     = dict(resp.headers)
            final_url = resp.url
            status    = resp.status
            resp.read()
    except urllib.error.URLError as e:
        out["error"] = f"Request failed: {e.reason}"
        return out
    except Exception as e:
        out["error"] = str(e)[:200]
        return out

    h = {k.lower(): v for k, v in raw_h.items()}

    interesting = {
        "strict-transport-security", "x-frame-options", "x-content-type-options",
        "x-xss-protection", "content-security-policy", "referrer-policy",
        "permissions-policy", "feature-policy", "server", "x-powered-by",
    }
    out["response_headers"] = {k: v for k, v in h.items() if k in interesting}
    out["final_url"]        = final_url
    out["status"]           = status

    checks: list[dict] = []

    def chk(name: str, passed: bool, detail: str, warn: bool = False) -> None:
        checks.append({"name": name, "pass": passed, "warn": warn, "detail": detail})

    chk("HTTPS enforced",
        final_url.startswith("https://"),
        "Served over HTTPS" if final_url.startswith("https://") else "Not on HTTPS")

    hsts = h.get("strict-transport-security", "")
    if hsts:
        max_age = 0
        for part in hsts.split(";"):
            p = part.strip()
            if p.lower().startswith("max-age="):
                try:
                    max_age = int(p.split("=", 1)[1])
                except ValueError:
                    pass
        good = max_age >= 31_536_000
        chk("HSTS (max-age >= 1 year)", good,
            hsts if good else f"max-age={max_age} — needs >= 31536000")
    else:
        chk("HSTS (max-age >= 1 year)", False, "Missing Strict-Transport-Security")

    xfo = h.get("x-frame-options", "")
    chk("X-Frame-Options", bool(xfo), xfo or "Missing")

    xcto = h.get("x-content-type-options", "")
    chk("X-Content-Type-Options: nosniff",
        xcto.lower() == "nosniff", xcto or "Missing")

    csp = h.get("content-security-policy", "")
    chk("Content-Security-Policy", bool(csp),
        (csp[:100] + "…") if len(csp) > 100 else (csp or "Missing"))

    rp = h.get("referrer-policy", "")
    chk("Referrer-Policy", bool(rp), rp or "Missing")

    pp = h.get("permissions-policy", "") or h.get("feature-policy", "")
    chk("Permissions-Policy", bool(pp),
        (pp[:80] + "…") if len(pp) > 80 else (pp or "Missing"))

    server = h.get("server", "")
    version_leaked = bool(re.search(r"\d+\.\d+", server))
    chk("Server version hidden",
        not version_leaked,
        server if server else "Not disclosed",
        warn=version_leaked and bool(server))

    xpb = h.get("x-powered-by", "")
    chk("X-Powered-By absent", not bool(xpb), xpb or "Not present")

    passed = sum(1 for c in checks if c["pass"] and not c.get("warn"))
    out["checks"]    = checks
    out["score"]     = passed
    out["max_score"] = len(checks)
    return out


# ── Load Test ────────────────────────────────────────────────────────────────

def test_load(url: str, total: int = 20, concurrency: int = 5) -> dict:
    url         = _ensure_url(url)
    total       = max(1, min(total, 1000))
    concurrency = max(1, min(concurrency, 500))
    out: dict   = {
        "url": url, "total": total, "concurrency": concurrency,
        "requests": [], "summary": {},
    }

    def fetch_one(n: int) -> dict:
        t0 = time.monotonic()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "NginxUI-LoadTest/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
                ms = round((time.monotonic() - t0) * 1000)
                return {"n": n + 1, "status": resp.status, "ms": ms, "ok": True}
        except urllib.error.HTTPError as e:
            ms = round((time.monotonic() - t0) * 1000)
            return {"n": n + 1, "status": e.code, "ms": ms, "ok": False, "error": str(e)}
        except Exception as e:
            ms = round((time.monotonic() - t0) * 1000)
            return {"n": n + 1, "status": 0, "ms": ms, "ok": False, "error": str(e)[:80]}

    t_wall = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        reqs = list(ex.map(fetch_one, range(total)))
    wall_ms = (time.monotonic() - t_wall) * 1000

    ok_times = sorted(r["ms"] for r in reqs if r["ok"])

    def pct(lst: list[int], p: float) -> int:
        if not lst:
            return 0
        return lst[max(0, int(len(lst) * p) - 1)]

    out["requests"] = reqs
    out["summary"] = {
        "total":    total,
        "success":  len(ok_times),
        "failed":   total - len(ok_times),
        "wall_ms":  round(wall_ms),
        "rps":      round(total / (wall_ms / 1000), 2) if wall_ms > 0 else 0,
        "avg_ms":   round(sum(ok_times) / len(ok_times)) if ok_times else 0,
        "min_ms":   ok_times[0]  if ok_times else 0,
        "max_ms":   ok_times[-1] if ok_times else 0,
        "p50_ms":   pct(ok_times, 0.50),
        "p90_ms":   pct(ok_times, 0.90),
        "p99_ms":   pct(ok_times, 0.99),
    }
    return out


# ── API Security Test ─────────────────────────────────────────────────────────

_SENSITIVE_RE = re.compile(
    r'\b(password|passwd|secret|api[_\-]?key|access[_\-]?token|auth[_\-]?token|'
    r'private[_\-]?key|client[_\-]?secret|bearer\s+[a-zA-Z0-9._\-]{10,})\b',
    re.IGNORECASE,
)


def _send_method(url: str, method: str, timeout: int = 10) -> tuple[int, dict, str]:
    """Send an arbitrary HTTP method and return (status, headers_dict, body_snippet)."""
    parsed  = urllib.parse.urlparse(url)
    host    = parsed.hostname or ""
    port    = parsed.port or (443 if parsed.scheme == "https" else 80)
    path    = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    use_ssl = parsed.scheme == "https"

    try:
        if use_ssl:
            ctx  = ssl.create_default_context()
            conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request(method, path, headers={
            "Host":       host,
            "User-Agent": "NginxUI-APISecTest/1.0",
            "Accept":     "*/*",
        })
        resp    = conn.getresponse()
        status  = resp.status
        hdrs    = {k.lower(): v for k, v in resp.getheaders()}
        body    = resp.read(4096).decode("utf-8", errors="replace")
        conn.close()
        return status, hdrs, body
    except Exception as e:
        return 0, {}, str(e)[:200]


def test_api_security(url: str, method: str = "GET") -> dict:
    url    = _ensure_url(url)
    method = method.upper() if method.upper() in ("GET","POST","PUT","DELETE","PATCH","HEAD") else "GET"
    out: dict = {
        "url": url, "method": method,
        "checks": [], "response_headers": {},
        "score": 0, "max_score": 0,
        "status": 0, "final_url": url,
    }

    checks: list[dict] = []
    def chk(name: str, passed: bool, detail: str, warn: bool = False) -> None:
        checks.append({"name": name, "pass": passed, "warn": warn, "detail": detail})

    # ── 1. Primary request ────────────────────────────────────────────────────
    status, hdrs, body = _send_method(url, method)
    if status == 0:
        out["error"] = f"Connection failed: {body}"
        return out

    out["status"]    = status
    out["final_url"] = url

    interesting = {
        "content-type","x-content-type-options","x-frame-options",
        "strict-transport-security","content-security-policy","referrer-policy",
        "x-ratelimit-limit","x-ratelimit-remaining","x-rate-limit-limit",
        "retry-after","ratelimit-limit","ratelimit-remaining",
        "access-control-allow-origin","access-control-allow-credentials",
        "access-control-allow-methods","server","x-powered-by","www-authenticate",
        "cache-control","pragma",
    }
    out["response_headers"] = {k: v for k, v in hdrs.items() if k in interesting}

    # ── 2. HTTPS enforcement ──────────────────────────────────────────────────
    chk("HTTPS enforced",
        url.startswith("https://"),
        "Served over HTTPS" if url.startswith("https://") else "Endpoint is HTTP only")

    # ── 3. Auth check (2xx without creds → open, 4xx → protected) ────────────
    is_protected = status in (401, 403)
    is_open      = status < 400
    chk("Authentication required",
        is_protected,
        "Returns 401/403 — auth enforced" if is_protected else f"Returns {status} — may be publicly accessible",
        warn=(is_open and method in ("GET",)))

    # ── 4. CORS – Allow-Origin ────────────────────────────────────────────────
    origin = hdrs.get("access-control-allow-origin", "")
    creds  = hdrs.get("access-control-allow-credentials", "").lower() == "true"
    if origin == "*" and creds:
        chk("CORS Allow-Credentials with wildcard", False,
            "CRITICAL: Allow-Credentials=true with Allow-Origin=* is insecure")
    elif origin == "*":
        chk("CORS Allow-Origin not wildcard", False,
            "Access-Control-Allow-Origin: * allows any domain",
            warn=True)
    elif origin:
        chk("CORS Allow-Origin restricted", True,
            f"Access-Control-Allow-Origin: {origin}")
    else:
        chk("CORS Allow-Origin not wildcard", True, "No CORS header (default deny)")

    # ── 5. TRACE method ───────────────────────────────────────────────────────
    trace_status, _, _ = _send_method(url, "TRACE")
    trace_ok = trace_status not in (200, 201, 204)
    chk("TRACE method disabled",
        trace_ok,
        f"TRACE returns {trace_status} — disabled" if trace_ok else
        f"TRACE returns {trace_status} — should be disabled (XST risk)")

    # ── 6. Rate limiting headers ──────────────────────────────────────────────
    rate_keys = {"x-ratelimit-limit","x-rate-limit-limit","ratelimit-limit","retry-after"}
    has_rate  = any(k in hdrs for k in rate_keys)
    chk("Rate limiting headers present",
        has_rate,
        next((f"{k}: {hdrs[k]}" for k in rate_keys if k in hdrs), "No rate-limit headers found"),
        warn=not has_rate)

    # ── 7. Security headers ───────────────────────────────────────────────────
    xcto = hdrs.get("x-content-type-options", "")
    chk("X-Content-Type-Options: nosniff",
        xcto.lower() == "nosniff",
        xcto or "Missing")

    csp = hdrs.get("content-security-policy", "")
    chk("Content-Security-Policy present",
        bool(csp),
        (csp[:80] + "…") if len(csp) > 80 else (csp or "Missing"),
        warn=not csp)

    # ── 8. Server/technology disclosure ──────────────────────────────────────
    server = hdrs.get("server", "")
    version_leaked = bool(re.search(r"\d+\.\d+", server))
    chk("Server version hidden",
        not version_leaked,
        server if server else "Not disclosed",
        warn=version_leaked and bool(server))

    xpb = hdrs.get("x-powered-by", "")
    chk("X-Powered-By absent", not bool(xpb), xpb or "Not present")

    # ── 9. Content-Type for API response ─────────────────────────────────────
    ct = hdrs.get("content-type", "")
    looks_json = "json" in ct.lower()
    if body.strip().startswith(("{", "[")):
        chk("Content-Type: application/json", looks_json,
            ct or "Missing — response body looks like JSON but Content-Type is not set")
    else:
        chk("Content-Type present", bool(ct), ct or "Missing")

    # ── 10. Sensitive data in response ────────────────────────────────────────
    sensitive_found = _SENSITIVE_RE.search(body)
    chk("No sensitive data in response",
        not bool(sensitive_found),
        f"Found pattern: '{sensitive_found.group(0)[:40]}'" if sensitive_found else "No sensitive keywords detected",
        warn=bool(sensitive_found))

    # ── 11. Cache-Control for API ─────────────────────────────────────────────
    cc = hdrs.get("cache-control", "")
    no_store = "no-store" in cc.lower() or "no-cache" in cc.lower() or "private" in cc.lower()
    chk("Cache-Control prevents caching",
        no_store,
        cc if cc else "Missing — API responses may be cached by proxies",
        warn=not no_store)

    passed = sum(1 for c in checks if c["pass"] and not c.get("warn"))
    out["checks"]    = checks
    out["score"]     = passed
    out["max_score"] = len(checks)
    return out
