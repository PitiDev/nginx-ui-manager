import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

SSL_DIR = Path(os.getenv("SSL_DIR", "/ssl"))


def _safe_path(name: str) -> Optional[Path]:
    try:
        p = (SSL_DIR / name).resolve()
        p.relative_to(SSL_DIR.resolve())
        return p
    except (ValueError, OSError):
        return None


def _cert_info(path: Path) -> Optional[dict]:
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import NameOID, ExtensionOID

        cert = x509.load_pem_x509_certificate(path.read_bytes(), default_backend())

        # Support both cryptography <42 (naive datetime) and >=42 (timezone-aware)
        try:
            expiry = cert.not_valid_after_utc
            now = datetime.now(timezone.utc)
        except AttributeError:
            expiry = cert.not_valid_after  # type: ignore[attr-defined]
            now = datetime.utcnow()

        days_left = (expiry - now).days

        cn = ""
        try:
            attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            cn = attrs[0].value if attrs else ""
        except Exception:
            pass

        sans: list[str] = []
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = [str(n.value) for n in ext.value][:6]
        except Exception:
            pass

        return {
            "cn": cn,
            "sans": sans,
            "expiry": expiry.strftime("%Y-%m-%d"),
            "days_left": days_left,
        }
    except Exception:
        return None


def _file_type(name: str) -> str:
    low = name.lower()
    if low.endswith(".key"):
        return "Private Key"
    if low.endswith((".crt", ".cer")):
        return "Certificate"
    if low.endswith(".pem"):
        return "PEM"
    if low.endswith(".ca-bundle"):
        return "CA Bundle"
    if low.endswith(".p7b"):
        return "PKCS#7"
    if low.endswith((".pfx", ".p12")):
        return "PKCS#12"
    return "File"


def list_ssl_files() -> list[dict]:
    files = []
    try:
        for entry in sorted(SSL_DIR.iterdir()):
            if not entry.is_file():
                continue
            ftype = _file_type(entry.name)
            item: dict = {
                "name": entry.name,
                "size": entry.stat().st_size,
                "type": ftype,
                "cert_info": None,
            }
            if ftype in ("Certificate", "PEM"):
                item["cert_info"] = _cert_info(entry)
            files.append(item)
    except (PermissionError, FileNotFoundError):
        pass
    return files


def save_ssl_file(name: str, content: bytes) -> tuple[bool, str]:
    path = _safe_path(name)
    if path is None:
        return False, "Invalid filename"
    try:
        SSL_DIR.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        # Private keys should not be world-readable
        if name.lower().endswith(".key"):
            os.chmod(path, 0o600)
        return True, f"Saved {name}"
    except PermissionError:
        return False, "Permission denied writing to SSL directory"
    except Exception as e:
        return False, str(e)


def read_ssl_file(name: str) -> Optional[str]:
    path = _safe_path(name)
    if path is None or not path.is_file():
        return None
    try:
        return path.read_text(errors="replace")
    except (PermissionError, OSError):
        return None


def delete_ssl_file(name: str) -> tuple[bool, str]:
    path = _safe_path(name)
    if path is None or not path.exists():
        return False, "File not found"
    try:
        path.unlink()
        return True, f"Deleted {name}"
    except PermissionError:
        return False, "Permission denied"
    except Exception as e:
        return False, str(e)
