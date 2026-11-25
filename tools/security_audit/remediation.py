"""Actionable remediation text, keyed by finding id.

Each entry has a short `summary`, ordered `steps`, and copy-paste `snippets`
for Nginx and Apache. `{domain}` is substituted with the affected host.
"""

NGINX_HEADER_NOTE = (
    "Nginx gotcha: `add_header` directives are NOT inherited into a `location` block that "
    "declares its own `add_header`. Put security headers in a shared snippet "
    "(e.g. /etc/nginx/snippets/security-headers.conf) and `include` it in every server "
    "AND every location that sets other headers. Always use the `always` flag so headers "
    "are also sent on 4xx/5xx responses."
)

REMEDIATIONS = {
    "exposed-env": {
        "summary": "An environment file is publicly downloadable. Treat every secret in it as compromised.",
        "steps": [
            "Block the path immediately with the server rule below, then reload the web server.",
            "Rotate EVERY credential the file contained (DB passwords, API keys, JWT/app secrets, SMTP, cloud keys).",
            "Move the file outside the web root; the document root should contain only public assets.",
            "Review access logs for prior downloads: `grep -E '/\\.env' /var/log/nginx/access.log*`",
        ],
        "snippets": {
            "nginx": (
                "# /etc/nginx/sites-available/{domain}  (inside the server { } block)\n"
                "# Deny all dotfiles except ACME challenges (Let's Encrypt)\n"
                "location ~ /\\.(?!well-known/) {\n"
                "    deny all;\n"
                "    return 404;\n"
                "}\n"
                "# Belt-and-braces: common backup/env variants\n"
                "location ~* \\.(env|env\\..*|bak|backup|old|swp|sql)$ {\n"
                "    deny all;\n"
                "    return 404;\n"
                "}\n\n"
                "# then: sudo nginx -t && sudo systemctl reload nginx"
            ),
            "apache": (
                "# VirtualHost for {domain}, or .htaccess\n"
                "<FilesMatch \"^\\.\">\n"
                "    Require all denied\n"
                "</FilesMatch>\n"
                "<FilesMatch \"\\.(env|bak|backup|old|swp|sql)$\">\n"
                "    Require all denied\n"
                "</FilesMatch>\n\n"
                "# then: sudo apachectl configtest && sudo systemctl reload apache2"
            ),
        },
    },
    "exposed-git": {
        "summary": "The .git directory is served. Attackers can reconstruct the full source tree and history, including any committed secrets.",
        "steps": [
            "Block dotfiles with the rule below and reload.",
            "Remove .git from the deployed web root. Deploy build artifacts (`rsync --exclude=.git`, CI artifacts, container images) instead of `git pull` in the docroot.",
            "Scan the repository history for secrets (e.g. gitleaks, trufflehog) and rotate anything found.",
            "Check the remote URL in .git/config for embedded tokens and revoke them.",
        ],
        "snippets": {
            "nginx": (
                "# /etc/nginx/sites-available/{domain}  (inside the server { } block)\n"
                "location ~ /\\.(?!well-known/) {\n"
                "    deny all;\n"
                "    return 404;\n"
                "}\n\n"
                "# then: sudo nginx -t && sudo systemctl reload nginx"
            ),
            "apache": (
                "# VirtualHost for {domain}\n"
                "RedirectMatch 404 /\\.git\n"
                "<DirectoryMatch \"/\\.git\">\n"
                "    Require all denied\n"
                "</DirectoryMatch>"
            ),
        },
    },
    "exposed-phpinfo": {
        "summary": "phpinfo() output is public. It discloses PHP/extension versions, file paths, and often environment variables and secrets.",
        "steps": [
            "Delete the file from the server; it should never exist in production.",
            "Until it is deleted, block the path with the rule below.",
            "If the page printed environment variables, rotate any secrets it showed.",
        ],
        "snippets": {
            "nginx": (
                "# /etc/nginx/sites-available/{domain}\n"
                "location ~* ^/(phpinfo|info|test)\\.php$ {\n"
                "    return 404;\n"
                "}"
            ),
            "apache": (
                "<FilesMatch \"^(phpinfo|info|test)\\.php$\">\n"
                "    Require all denied\n"
                "</FilesMatch>"
            ),
        },
    },
    "probe-inconclusive": {
        "summary": "The probe could not be completed, so exposure is unknown.",
        "steps": [
            "Re-run the scan. If the error persists, test manually from an authorized host: `curl -sI https://{domain}<path>`",
            "A 5xx on a dotfile path can mean the request reached an application handler; confirm the dotfile deny rule is evaluated first.",
        ],
        "snippets": {},
    },
    "hsts-missing": {
        "summary": "No Strict-Transport-Security header. Browsers may be downgraded to HTTP by an on-path attacker.",
        "steps": [
            "Add the header in the HTTPS server block (never on plain HTTP).",
            "Start with a shorter max-age (e.g. 300) if unsure every subdomain supports HTTPS, then raise to 1 year.",
            "Only add `includeSubDomains` once all subdomains serve valid HTTPS. Only add `preload` if you intend to submit to hstspreload.org.",
        ],
        "snippets": {
            "nginx": (
                "# server { listen 443 ssl; server_name {domain}; ... }\n"
                "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
            ),
            "apache": (
                "# <VirtualHost *:443> for {domain}  (requires: a2enmod headers)\n"
                "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\""
            ),
        },
        "note": NGINX_HEADER_NOTE,
    },
    "hsts-weak": {
        "summary": "HSTS is present but max-age is shorter than 180 days, which limits protection.",
        "steps": ["Raise max-age to at least 15552000 (180 days); 31536000 (1 year) is recommended."],
        "snippets": {
            "nginx": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;",
            "apache": "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"",
        },
        "note": NGINX_HEADER_NOTE,
    },
    "csp-missing": {
        "summary": "No Content-Security-Policy. XSS bugs have no browser-side containment.",
        "steps": [
            "Deploy the policy below as Content-Security-Policy-Report-Only first and watch the browser console / reports for a week.",
            "Add the third-party origins your site really uses (CDNs, analytics, fonts) to the matching directives.",
            "Switch the header name to Content-Security-Policy once no legitimate violations remain.",
        ],
        "snippets": {
            "nginx": (
                "# Step 1: report-only\n"
                "add_header Content-Security-Policy-Report-Only \"default-src 'self'; img-src 'self' data:; "
                "object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'\" always;\n\n"
                "# Step 2: enforce\n"
                "add_header Content-Security-Policy \"default-src 'self'; img-src 'self' data:; "
                "object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'\" always;"
            ),
            "apache": (
                "Header always set Content-Security-Policy \"default-src 'self'; img-src 'self' data:; "
                "object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'\""
            ),
        },
        "note": NGINX_HEADER_NOTE,
    },
    "csp-weak": {
        "summary": "A CSP is present but allows patterns that largely defeat XSS protection.",
        "steps": [
            "Remove 'unsafe-inline' / 'unsafe-eval' from script-src; move inline scripts to files or use nonces/hashes.",
            "Replace wildcard (*) sources with explicit origins.",
            "If only Content-Security-Policy-Report-Only is set, promote it to the enforcing header once violations are resolved.",
        ],
        "snippets": {
            "nginx": (
                "# Example nonce-free hardened script policy\n"
                "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; "
                "base-uri 'self'; frame-ancestors 'self'\" always;"
            ),
            "apache": (
                "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; "
                "object-src 'none'; base-uri 'self'; frame-ancestors 'self'\""
            ),
        },
        "note": NGINX_HEADER_NOTE,
    },
    "xfo-missing": {
        "summary": "No X-Frame-Options (and no CSP frame-ancestors). Pages can be framed for clickjacking.",
        "steps": [
            "Add X-Frame-Options: SAMEORIGIN (or DENY if the site is never framed).",
            "Modern equivalent: CSP `frame-ancestors 'self'`. Sending both is fine.",
        ],
        "snippets": {
            "nginx": "add_header X-Frame-Options \"SAMEORIGIN\" always;",
            "apache": "Header always set X-Frame-Options \"SAMEORIGIN\"",
        },
        "note": NGINX_HEADER_NOTE,
    },
    "xfo-invalid": {
        "summary": "X-Frame-Options has a value browsers ignore (ALLOW-FROM is obsolete; only DENY and SAMEORIGIN work).",
        "steps": ["Use DENY or SAMEORIGIN. To allow specific framing origins use CSP `frame-ancestors 'self' https://partner.example`."],
        "snippets": {
            "nginx": "add_header X-Frame-Options \"SAMEORIGIN\" always;",
            "apache": "Header always set X-Frame-Options \"SAMEORIGIN\"",
        },
        "note": NGINX_HEADER_NOTE,
    },
    "xcto-missing": {
        "summary": "X-Content-Type-Options: nosniff is missing. Browsers may MIME-sniff uploads into executable content.",
        "steps": ["Add the header globally."],
        "snippets": {
            "nginx": "add_header X-Content-Type-Options \"nosniff\" always;",
            "apache": "Header always set X-Content-Type-Options \"nosniff\"",
        },
        "note": NGINX_HEADER_NOTE,
    },
    "https-unavailable": {
        "summary": "HTTPS is not reachable on this host. All traffic, including credentials, is exposed in transit.",
        "steps": [
            "Confirm port 443 is open in the firewall / security group: `sudo ufw status`",
            "Issue a certificate: `sudo certbot --nginx -d {domain}`",
            "Ensure a server block listens on 443 with the certificate (snippet below).",
        ],
        "snippets": {
            "nginx": (
                "server {\n"
                "    listen 443 ssl;\n"
                "    http2 on;\n"
                "    server_name {domain};\n"
                "    ssl_certificate     /etc/letsencrypt/live/{domain}/fullchain.pem;\n"
                "    ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;\n"
                "    ssl_protocols TLSv1.2 TLSv1.3;\n"
                "    # ... locations ...\n"
                "}"
            ),
            "apache": (
                "<VirtualHost *:443>\n"
                "    ServerName {domain}\n"
                "    SSLEngine on\n"
                "    SSLCertificateFile    /etc/letsencrypt/live/{domain}/fullchain.pem\n"
                "    SSLCertificateKeyFile /etc/letsencrypt/live/{domain}/privkey.pem\n"
                "    SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
                "</VirtualHost>"
            ),
        },
    },
    "tls-invalid": {
        "summary": "The certificate fails validation. Browsers show a full-page warning and users are trained to click through.",
        "steps": [
            "Read the validation error in the finding: expired, hostname mismatch, self-signed, or incomplete chain.",
            "Incomplete chain is the most common cause on Nginx: use `fullchain.pem`, not `cert.pem`.",
            "Hostname mismatch: re-issue covering every name this server block serves: `sudo certbot --nginx -d {domain} -d <other-name>`",
            "Expired: `sudo certbot renew && sudo systemctl reload nginx`, then fix auto-renewal (see tls-expiring).",
        ],
        "snippets": {
            "nginx": (
                "ssl_certificate     /etc/letsencrypt/live/{domain}/fullchain.pem;  # NOT cert.pem\n"
                "ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;"
            ),
            "apache": (
                "SSLCertificateFile    /etc/letsencrypt/live/{domain}/fullchain.pem\n"
                "SSLCertificateKeyFile /etc/letsencrypt/live/{domain}/privkey.pem"
            ),
        },
    },
    "tls-expiring": {
        "summary": "The certificate expires soon. Auto-renewal is probably not working.",
        "steps": [
            "Renew now: `sudo certbot renew && sudo systemctl reload nginx`",
            "Check the renewal timer exists and is active: `systemctl list-timers | grep certbot`",
            "Dry-run renewal to surface errors (DNS, port 80 blocked, webroot moved): `sudo certbot renew --dry-run`",
            "Ensure a deploy hook reloads the web server after renewal (snippet below).",
        ],
        "snippets": {
            "nginx": (
                "# /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh  (chmod +x)\n"
                "#!/bin/sh\n"
                "systemctl reload nginx"
            ),
            "apache": (
                "# /etc/letsencrypt/renewal-hooks/deploy/reload-apache.sh  (chmod +x)\n"
                "#!/bin/sh\n"
                "systemctl reload apache2"
            ),
        },
    },
    "http-no-redirect": {
        "summary": "Plain HTTP serves content instead of redirecting to HTTPS.",
        "steps": ["Redirect every HTTP request to HTTPS with a 301, keeping the path and query string."],
        "snippets": {
            "nginx": (
                "server {\n"
                "    listen 80;\n"
                "    listen [::]:80;\n"
                "    server_name {domain};\n"
                "    # keep ACME HTTP-01 challenges working\n"
                "    location /.well-known/acme-challenge/ { root /var/www/letsencrypt; }\n"
                "    location / { return 301 https://$host$request_uri; }\n"
                "}"
            ),
            "apache": (
                "<VirtualHost *:80>\n"
                "    ServerName {domain}\n"
                "    Redirect permanent / https://{domain}/\n"
                "</VirtualHost>"
            ),
        },
    },
    "dns-failed": {
        "summary": "The host did not resolve, so no checks ran.",
        "steps": [
            "Confirm the name is spelled correctly in authorized_domains.txt.",
            "If the host was decommissioned, remove it from the list. Check for dangling CNAMEs pointing at deleted cloud resources (subdomain-takeover risk).",
        ],
        "snippets": {},
    },
}


def remediation_for(rid: str | None, domain: str) -> dict | None:
    if not rid or rid not in REMEDIATIONS:
        return None
    src = REMEDIATIONS[rid]
    return {
        "id": rid,
        "summary": src["summary"].replace("{domain}", domain),
        "steps": [s.replace("{domain}", domain) for s in src["steps"]],
        "snippets": {k: v.replace("{domain}", domain) for k, v in src["snippets"].items()},
        "note": src.get("note"),
    }
