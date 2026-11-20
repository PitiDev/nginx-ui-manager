import json
import os
import re
from pathlib import Path
from typing import Optional

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
_FILE    = DATA_DIR / "system_diagram.json"

_SRC_RE = re.compile(r'src\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


def _read() -> dict:
    try:
        return json.loads(_FILE.read_text())
    except Exception:
        return {}


def _write(data: dict) -> None:
    _FILE.parent.mkdir(parents=True, exist_ok=True)
    _FILE.write_text(json.dumps(data, indent=2))


def get_embed_url() -> Optional[str]:
    return _read().get("embed_url") or None


def extract_url(raw: str) -> Optional[str]:
    """Accept either a full <iframe> embed snippet or a bare URL and return
    just the src URL, or None if nothing usable/safe was found."""
    raw = (raw or "").strip()
    if not raw:
        return None

    m = _SRC_RE.search(raw)
    url = m.group(1) if m else raw

    if not re.match(r"^https://", url, re.IGNORECASE):
        return None

    return url


def set_embed_url(raw: str) -> tuple[bool, str]:
    url = extract_url(raw)
    if not url:
        return False, "Paste a valid embed <iframe> snippet or an https:// URL"
    _write({"embed_url": url})
    return True, "Diagram embed saved"


def clear_embed() -> None:
    _write({})
