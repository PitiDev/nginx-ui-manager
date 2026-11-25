"""Offline unit tests: scope parsing and finding classification (no network).

    python3 -m unittest test_audit -v
"""

import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security_audit.checks import (CRITICAL, LOW, MEDIUM, PASS, classify_probe, evaluate_headers,  # noqa: E402
                    evaluate_http_redirect, evaluate_tls, looks_like_env)
from security_audit.net import HttpResult, TlsResult  # noqa: E402
from security_audit.scope import ScopeError, Target, load_targets, parse_targets  # noqa: E402

SECRET = "s3cr3t-DO-NOT-LEAK"


def _write(text: str) -> Path:
    f = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    f.write(text)
    f.close()
    return Path(f.name)


class ScopeTests(unittest.TestCase):
    def test_missing_file_refused(self):
        with self.assertRaises(ScopeError):
            load_targets(Path("/nonexistent/authorized_domains.txt"))

    def test_empty_and_comment_only_refused(self):
        for text in ("", "\n\n", "# only.comments.example\n   # another\n"):
            with self.assertRaises(ScopeError):
                load_targets(_write(text))

    def test_valid_entries_dedup_and_ports(self):
        t = load_targets(_write("Example.COM\nexample.com.\nwww.example.com # inline comment\napi.example.com:8443\n203.0.113.5\n"))
        self.assertEqual([x.label for x in t], ["example.com", "www.example.com", "api.example.com:8443", "203.0.113.5"])
        self.assertTrue(t[2].custom_port)

    def test_parse_text_allow_empty(self):
        self.assertEqual(parse_targets("# nothing\n", allow_empty=True), [])
        with self.assertRaises(ScopeError):
            parse_targets("\n".join(f"h{i}.example.com" for i in range(501)))

    def test_rejects_out_of_scope_forms(self):
        for bad in ("https://example.com", "example.com/admin", "*.example.com", "10.0.0.0/24",
                    "-bad.example.com", "exa mple.com", "example.com:99999", "::1"):
            with self.subTest(bad=bad), self.assertRaises(ScopeError):
                load_targets(_write(bad + "\n"))


def _res(status, ctype="text/plain", body=b"", headers=None, url="https://example.com/x"):
    h = {"content-type": ctype, **(headers or {})}
    return HttpResult(url=url, status=status, headers=h, content_type=ctype, body=body)


class ProbeTests(unittest.TestCase):
    def test_env_exposed_is_critical_and_never_leaks_values(self):
        body = f"APP_KEY={SECRET}\nDB_PASSWORD={SECRET}\n# comment\nexport MAIL_HOST=smtp\n".encode()
        f = classify_probe("/.env", "env", CRITICAL, _res(200, body=body))
        self.assertEqual(f.severity, CRITICAL)
        self.assertEqual(f.evidence["key_value_lines"], 3)
        dumped = str(f.to_dict("example.com"))
        self.assertNotIn(SECRET, dumped)
        self.assertNotIn("APP_KEY", dumped)
        self.assertNotIn("DB_PASSWORD", dumped)

    def test_html_200_is_soft_404(self):
        f = classify_probe("/.env", "env", CRITICAL, _res(200, "text/html", b"A=1\nB=2\n"))
        self.assertEqual(f.severity, PASS)

    def test_non_env_text_not_flagged(self):
        f = classify_probe("/.env", "env", CRITICAL, _res(200, "text/plain", b"Not found. Try ?page=2 or go home.\nThanks"))
        self.assertEqual(f.severity, PASS)
        self.assertFalse(looks_like_env("<!DOCTYPE html>\nA=1\nB=2")[0])

    def test_git_config(self):
        body = b"[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = https://tok@github.com/x/y\n"
        f = classify_probe("/.git/config", "git", CRITICAL, _res(200, "application/octet-stream", body))
        self.assertEqual(f.severity, CRITICAL)
        self.assertNotIn("tok@", str(f.to_dict("example.com")))
        self.assertEqual(classify_probe("/.git/config", "git", CRITICAL, _res(200, body=b"hello")).severity, PASS)

    def test_phpinfo_validated_by_signature_even_as_html(self):
        html = b"<html><head><title>phpinfo()</title></head><body>PHP Version 8.2</body></html>"
        self.assertEqual(classify_probe("/phpinfo.php", "phpinfo", MEDIUM, _res(200, "text/html", html)).severity, MEDIUM)
        self.assertEqual(classify_probe("/phpinfo.php", "phpinfo", MEDIUM, _res(200, "text/html", b"<html>404</html>")).severity, PASS)

    def test_status_codes(self):
        self.assertEqual(classify_probe("/.env", "env", CRITICAL, _res(403)).severity, PASS)
        self.assertEqual(classify_probe("/.env", "env", CRITICAL, _res(404)).severity, PASS)
        self.assertEqual(classify_probe("/.env", "env", CRITICAL, _res(301)).severity, PASS)
        self.assertEqual(classify_probe("/.env", "env", CRITICAL, _res(502)).severity, LOW)
        err = HttpResult(url="https://example.com/.env", error="Timed out")
        self.assertEqual(classify_probe("/.env", "env", CRITICAL, err).severity, LOW)


class HeaderTests(unittest.TestCase):
    def sev(self, headers):
        return {f.check_id: f.severity for f in evaluate_headers(_res(200, "text/html", headers=headers))}

    def test_all_missing(self):
        s = self.sev({})
        self.assertEqual(s, {"headers.hsts": MEDIUM, "headers.csp": MEDIUM, "headers.xfo": LOW, "headers.xcto": LOW})

    def test_all_good(self):
        s = self.sev({
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'; object-src 'none'",
            "x-frame-options": "SAMEORIGIN",
            "x-content-type-options": "nosniff",
        })
        self.assertTrue(all(v == PASS for v in s.values()), s)

    def test_weak_values(self):
        s = self.sev({
            "strict-transport-security": "max-age=3600",
            "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
            "x-content-type-options": "sniff",
        })
        self.assertEqual(s["headers.hsts"], LOW)
        self.assertEqual(s["headers.csp"], LOW)
        self.assertEqual(s["headers.xfo"], PASS)  # covered by frame-ancestors
        self.assertEqual(s["headers.xcto"], LOW)

    def test_unsafe_inline_with_nonce_ok_and_report_only(self):
        s = self.sev({"content-security-policy": "script-src 'nonce-abc' 'unsafe-inline' 'strict-dynamic'"})
        self.assertEqual(s["headers.csp"], PASS)
        s = self.sev({"content-security-policy-report-only": "default-src 'self'"})
        self.assertEqual(s["headers.csp"], LOW)
        s = self.sev({"strict-transport-security": "max-age=0"})
        self.assertEqual(s["headers.hsts"], MEDIUM)


class TlsTests(unittest.TestCase):
    T = Target("example.com")
    NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def tls(self, days, **kw):
        return TlsResult(available=True, verified=True, not_after=self.NOW + timedelta(days=days), **kw)

    def test_expiry_bands(self):
        self.assertEqual(evaluate_tls(self.T, self.tls(90), 30, self.NOW).severity, PASS)
        self.assertEqual(evaluate_tls(self.T, self.tls(20), 30, self.NOW).severity, MEDIUM)
        self.assertEqual(evaluate_tls(self.T, self.tls(3), 30, self.NOW).severity, CRITICAL)

    def test_invalid_and_unavailable(self):
        bad = TlsResult(available=True, verified=False, verify_error="certificate has expired",
                        not_after=self.NOW - timedelta(days=2))
        f = evaluate_tls(self.T, bad, 30, self.NOW)
        self.assertEqual(f.severity, CRITICAL)
        self.assertIn("expired", f.detail)
        self.assertEqual(evaluate_tls(self.T, TlsResult(error="refused"), 30, self.NOW).severity, CRITICAL)

    def test_http_redirect(self):
        ok = _res(301, headers={"location": "https://example.com/"}, url="http://example.com/")
        self.assertEqual(evaluate_http_redirect(ok).severity, PASS)
        self.assertEqual(evaluate_http_redirect(_res(200, url="http://example.com/")).severity, MEDIUM)
        self.assertEqual(evaluate_http_redirect(HttpResult(url="http://example.com/", error="refused")).severity, PASS)


if __name__ == "__main__":
    unittest.main()
