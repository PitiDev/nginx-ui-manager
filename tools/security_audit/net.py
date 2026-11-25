"""Polite, scope-locked network access.

Every outbound connection (HTTP request or raw TLS handshake) goes through a
single `PoliteGate`, which enforces:

* at most `max_concurrent` connections in flight across the whole run, and
* at least `min_interval` seconds between the start of any two connections.

Response bodies are read with a hard size cap and are never written anywhere;
callers receive the bytes only long enough to classify them.
"""

import socket
import ssl
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

import requests
import urllib3

TOOL_NAME = "NginxUI-SecurityAudit"
TOOL_VERSION = "1.0.0"
MAX_BODY_BYTES = 64 * 1024
MAX_REDIRECTS = 5


def build_user_agent(contact: str | None = None) -> str:
    ua = f"{TOOL_NAME}/{TOOL_VERSION} (internal security audit; authorized scan of organization-owned assets"
    if contact:
        ua += f"; contact: {contact}"
    return ua + ")"


class ScanCancelled(Exception):
    """Raised inside a worker when the run has been cancelled."""


class PoliteGate:
    """Global concurrency cap + minimum spacing between connection starts."""

    def __init__(self, max_concurrent: int = 2, min_interval: float = 0.5,
                 cancel_event: threading.Event | None = None):
        self._slots = threading.BoundedSemaphore(max_concurrent)
        self._spacing_lock = threading.Lock()
        self._min_interval = min_interval
        self._next_start = 0.0
        self._cancel = cancel_event
        self.request_count = 0

    def _check_cancel(self):
        if self._cancel is not None and self._cancel.is_set():
            raise ScanCancelled()

    @contextmanager
    def slot(self):
        self._check_cancel()
        self._slots.acquire()
        try:
            with self._spacing_lock:
                self._check_cancel()
                delay = self._next_start - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                self._next_start = time.monotonic() + self._min_interval
                self.request_count += 1
            yield
        finally:
            self._slots.release()


@dataclass
class HttpResult:
    url: str
    status: int | None = None
    headers: dict = field(default_factory=dict)
    content_type: str = ""
    body: bytes = b""             # capped; never persisted
    error: str | None = None
    redirect_chain: list = field(default_factory=list)
    stopped_off_scope: str | None = None


@dataclass
class TlsResult:
    available: bool = False
    verified: bool = False
    error: str | None = None
    verify_error: str | None = None
    protocol: str | None = None
    subject_cn: str | None = None
    issuer: str | None = None
    not_after: datetime | None = None


class AuditClient:
    def __init__(self, gate: PoliteGate, user_agent: str, timeout: float, allowed_hosts: set[str]):
        self.gate = gate
        self.user_agent = user_agent
        self.timeout = timeout
        self.allowed_hosts = allowed_hosts
        self._local = threading.local()
        # We deliberately probe with verify=False when a cert is already known to
        # be broken (it is reported separately); silence the per-request warning.
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # -- HTTP ---------------------------------------------------------------

    def _session(self) -> requests.Session:
        s = getattr(self._local, "session", None)
        if s is None:
            s = requests.Session()
            s.headers.update({
                "User-Agent": self.user_agent,
                "Accept": "*/*",
            })
            s.max_redirects = 0
            self._local.session = s
        return s

    def get(self, url: str, *, verify: bool = True, follow_redirects: bool = False,
            read_body: bool = True) -> HttpResult:
        """GET `url`. Redirects are followed manually and only to in-scope hosts."""
        result = HttpResult(url=url)
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            try:
                with self.gate.slot():
                    resp = self._session().get(
                        current, timeout=self.timeout, verify=verify,
                        allow_redirects=False, stream=True,
                    )
                    try:
                        body = resp.raw.read(MAX_BODY_BYTES, decode_content=True) if read_body else b""
                    finally:
                        resp.close()
            except requests.exceptions.SSLError as e:
                result.error = f"TLS error: {_short(e)}"
                return result
            except requests.exceptions.Timeout:
                result.error = f"Timed out after {self.timeout:g}s"
                return result
            except requests.exceptions.ConnectionError as e:
                result.error = f"Connection failed: {_short(e)}"
                return result
            except requests.exceptions.RequestException as e:
                result.error = f"Request failed: {_short(e)}"
                return result

            result.url = current
            result.status = resp.status_code
            result.headers = {k.lower(): v for k, v in resp.headers.items()}
            result.content_type = result.headers.get("content-type", "").split(";")[0].strip().lower()
            result.body = body or b""

            location = resp.headers.get("location")
            if not follow_redirects or not resp.is_redirect or not location:
                return result

            nxt = urljoin(current, location)
            host = (urlsplit(nxt).hostname or "").lower()
            if host not in self.allowed_hosts:
                result.stopped_off_scope = nxt
                return result
            result.redirect_chain.append(f"{resp.status_code} -> {nxt}")
            current = nxt
        return result

    # -- TLS ----------------------------------------------------------------

    def tls_probe(self, host: str, port: int) -> TlsResult:
        out = TlsResult()
        ctx = ssl.create_default_context()
        try:
            with self.gate.slot():
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as tls:
                        cert = tls.getpeercert()
                        out.protocol = tls.version()
            out.available = out.verified = True
            out.not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
            out.subject_cn = _name_field(cert.get("subject"), "commonName")
            out.issuer = _name_field(cert.get("issuer"), "organizationName") or _name_field(cert.get("issuer"), "commonName")
            return out
        except ssl.SSLCertVerificationError as e:
            out.available = True
            out.verify_error = e.verify_message or _short(e)
        except ssl.SSLError as e:
            out.error = f"TLS handshake failed: {_short(e)}"
            return out
        except (socket.timeout, TimeoutError):
            out.error = f"Connection to port {port} timed out after {self.timeout:g}s"
            return out
        except OSError as e:
            out.error = f"Cannot connect to port {port}: {e.strerror or _short(e)}"
            return out

        # Verification failed: grab the cert unverified so we can still report expiry.
        self._fill_unverified(host, port, out)
        return out

    def _fill_unverified(self, host: str, port: int, out: TlsResult) -> None:
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
        except ImportError:
            return
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with self.gate.slot():
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as tls:
                        der = tls.getpeercert(binary_form=True)
                        out.protocol = tls.version()
        except (OSError, ssl.SSLError):
            return
        if not der:
            return
        cert = x509.load_der_x509_certificate(der)
        out.not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        out.subject_cn = cn[0].value if cn else None
        org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) or \
            cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        out.issuer = org[0].value if org else None


def resolves(host: str) -> str | None:
    """Return None if the host resolves, otherwise an error string. DNS only."""
    try:
        socket.getaddrinfo(host, None)
        return None
    except socket.gaierror as e:
        return f"DNS lookup failed: {e.strerror or e}"


def _name_field(name, key):
    for rdn in name or ():
        for k, v in rdn:
            if k == key:
                return v
    return None


def _short(exc: Exception, limit: int = 160) -> str:
    text = str(exc).replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"
