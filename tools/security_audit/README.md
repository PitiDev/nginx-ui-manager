# Security Audit CLI

A command-line tool that runs **read-only** security checks against a fixed list of hosts your organization owns, then writes a JSON report and a standalone dark-mode HTML dashboard.

You can use it two ways:

- **From the Nginx UI dashboard:** the **External Audit** page in the sidebar (see [Web UI](#web-ui) below).
- **As a standalone CLI:** it has its own dependencies and runs from any machine that can reach your sites.

> **Authorization:** Only list hosts that your organization owns or has written permission to test. The tool cannot verify ownership. That is your responsibility.

---

## What it checks

| Category | Check | Severity when failing |
|---|---|---|
| **Sensitive Files** | `/.env`, `/.env.production`, `/.env.backup` served as a real `KEY=VALUE` file | CRITICAL |
| | `/.git/config` served (contains a `[core]` section) | CRITICAL |
| | `/phpinfo.php` returns real phpinfo() output | MEDIUM |
| **Security Headers** | `Strict-Transport-Security`: missing or `max-age=0` / under 180 days | MEDIUM / LOW |
| | `Content-Security-Policy`: missing / report-only or weak (`'unsafe-inline'`, `'unsafe-eval'`, `*`) | MEDIUM / LOW |
| | `X-Frame-Options`: missing or invalid (CSP `frame-ancestors` counts as a pass) | LOW |
| | `X-Content-Type-Options`: not `nosniff` | LOW |
| **TLS/SSL** | HTTPS not reachable on 443 | CRITICAL |
| | Certificate fails validation (expired, self-signed, wrong host, broken chain) | CRITICAL |
| | Certificate expires in ≤ 7 days / ≤ 30 days | CRITICAL / MEDIUM |
| | `http://` does not redirect to `https://` | MEDIUM |
| **Availability** | Host does not resolve in DNS | MEDIUM |

Every failed check in the HTML report has a **How to fix** panel with steps and copy-paste **Nginx** and **Apache** snippets, already filled in with the affected hostname.

### False-positive handling

Many sites return `200 OK` for every path (SPAs, catch-all routes, custom 404 pages). To avoid false alarms:

- A `.env` or `.git/config` probe that returns `200` with `Content-Type: text/html` is treated as a soft 404 and **not** flagged.
- The body must also match the file's real structure: at least two `KEY=VALUE` lines making up most of the file for `.env`, or a `[core]` section for `.git/config`.
- `phpinfo()` output is legitimately HTML, so it is matched by its content signature (`<title>phpinfo()</title>`, "PHP Version" + "Zend Engine", and so on) instead of by content type.
- `401`, `403`, `404`, `410` and redirects count as **PASS**. `5xx` responses and timeouts are **LOW (inconclusive)**, because exposure could not be ruled out.

### Data safety

Response bodies are read with a 64 KB cap, examined in memory, and then discarded. Reports contain **only** the URL, HTTP status, severity, and counts (for example "3 KEY=VALUE lines"). They never contain secret values, key names, or file contents. The unit tests check this with a planted secret.

---

## Safety controls

| Control | Value |
|---|---|
| Scope | Only hosts in `authorized_domains.txt`. The tool refuses to run if the file is missing, empty, or has a malformed line. URLs, paths, wildcards and CIDR ranges are rejected. |
| Redirects | Followed only to hosts that are also on the list. Off-list redirects are recorded but never requested. |
| Concurrency | At most **2** connections in flight, across all hosts. |
| Rate | At least **500 ms** between the start of any two requests. |
| Timeout | **10 s** per request. |
| Methods | `GET` and TLS handshakes only. No `POST`/`PUT`/`DELETE`, no payloads, no fuzzing, no brute force. |
| User-Agent | `NginxUI-SecurityAudit/1.0.0 (internal security audit; authorized scan of organization-owned assets[; contact: …])` |

Each host takes about 8 requests (TLS, HTTP redirect, landing page, 5 file probes), so roughly 4 seconds per host at the rate limit.

---

## Install

Requires Python 3.10+.

```bash
cd tools/security_audit
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Dependencies: `requests` (HTTP) and `cryptography` (reads expiry dates from certificates that *fail* validation; optional).

## Configure scope

Edit `authorized_domains.txt` with one host per line:

```text
# Production
example.com
www.example.com
api.example.com

# Staging on a non-standard HTTPS port (the HTTP→HTTPS check is skipped)
staging.example.com:8443
```

## Run

```bash
# 1. Check scope and request budget without sending any traffic
python3 audit.py --dry-run

# 2. Run the scan
python3 audit.py

# Options
python3 audit.py -d /etc/audit/domains.txt \
                 -o /var/lib/audit/reports \
                 --contact "secops@yourcompany.example" \
                 --expiry-days 21 \
                 --fail-on-critical
```

| Flag | Default | Meaning |
|---|---|---|
| `-d, --domains` | `./authorized_domains.txt` | Target list |
| `-o, --output` | `./reports` | Where reports are written |
| `--expiry-days` | `30` | Certificate-expiry warning window |
| `--contact` | none | Added to the User-Agent so server owners and WAF teams can identify the scan |
| `--dry-run` | off | Validate scope and print the plan; no network traffic |
| `--fail-on-critical` | off | Exit `2` if any CRITICAL finding exists (for cron or CI alerting) |
| `--no-color` | off | Plain terminal output |

**Exit codes:** `0` scan completed · `1` scope file missing, empty or invalid · `2` CRITICAL findings (only with `--fail-on-critical`).

## Output

```
reports/
├── security-report-2026-11-25_101053.json   # structured findings for automation/archiving
└── security-report-2026-11-25_101053.html   # standalone dashboard; no internet needed to view
```

**HTML dashboard:** summary cards (Domains Scanned, Critical Issues, Warnings, Passed Checks), a severity breakdown bar, and findings grouped by domain. You can filter by severity, domain and category, or search the text. Each failed row has a **How to fix** panel with Nginx and Apache tabs and a copy button.

**JSON shape:**

```jsonc
{
  "tool": {...}, "generated_at": "...", "duration_seconds": 3.9, "request_count": 8,
  "scope":  { "source": "authorized_domains.txt", "hosts": ["example.com"] },
  "limits": { "max_concurrent": 2, "min_interval_ms": 500, "timeout_seconds": 10, ... },
  "summary": { "total_domains": 1, "critical": 1, "medium": 2, "low": 1, "warnings": 3, "passed": 6, ... },
  "domains": [{
    "domain": "example.com", "worst": "CRITICAL", "counts": {...}, "notes": [...],
    "findings": [{
      "check_id": "files/.env", "category": "Sensitive Files", "check": "Exposed file /.env",
      "severity": "CRITICAL", "title": "Environment file publicly readable",
      "detail": "Response contains 3 KEY=VALUE assignment line(s). Content not recorded.",
      "url": "https://example.com/.env", "http_status": 200,
      "evidence": { "key_value_lines": 3 },
      "remediation": { "summary": "...", "steps": [...], "snippets": { "nginx": "...", "apache": "..." } }
    }]
  }]
}
```

> Reports describe weaknesses in your infrastructure, so treat them as confidential. `reports/` and `security-report-*` files are git-ignored.

## Scheduling (optional)

A weekly run with alerting on criticals:

```cron
0 6 * * 1  cd /opt/nginx_ui/tools/security_audit && .venv/bin/python audit.py --fail-on-critical --no-color >> audit.log 2>&1 || echo "Critical findings" | mail -s "Security audit" secops@yourcompany.example
```

## Web UI

The Nginx UI's **External Audit** page (`/audit`) wraps the same engine:

- **Authorized scope:** an editable host list, stored in `$DATA_DIR/audit_domains.txt` and validated with the same strict rules as the CLI. **Suggest from Nginx configs** offers the `server_name` hosts from the local node's enabled sites. You review them before saving.
- **Run scan:** starts a background scan with live per-host progress and a Cancel button. Only one scan runs at a time across the whole app, so the rate limits always hold.
- **Report:** summary cards, severity filters, findings grouped by domain, and **How to fix** panels. **Full report** opens the standalone HTML. **JSON** downloads the raw data. The last 50 reports are kept in `$DATA_DIR/audit_reports/`.
- **Roles:** admins edit the scope, run scans and delete reports. Viewers can read reports.
- **Activity log:** scope changes, runs, completions, cancellations and deletions are recorded under the **Audit** category.

## Tests

Offline unit tests cover scope parsing, false-positive filtering, header and TLS grading, and secret non-leakage:

```bash
python3 -m unittest test_audit -v
```

## Files

| File | Purpose |
|---|---|
| `audit.py` | CLI entry script (thin wrapper around `cli.py`) |
| `cli.py` | Argument parsing and terminal output |
| `runner.py` | Shared scan loop (CLI + web UI): concurrency, progress callbacks, cancellation |
| `scope.py` | Loads and validates `authorized_domains.txt` |
| `net.py` | Rate-limited, scope-locked HTTP client and TLS probe |
| `checks.py` | Check logic and severity classification |
| `remediation.py` | Fix-it text and Nginx/Apache snippets |
| `report.py`, `report_template.html` | JSON and HTML report generation |
| `test_audit.py` | Unit tests |
