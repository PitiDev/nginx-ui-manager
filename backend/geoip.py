"""Offline IP geolocation for the Security Monitor threat map.

Reads a MaxMind-format (.mmdb) database — by default DB-IP "IP to City Lite"
(CC BY 4.0, https://db-ip.com), fetched at image build time by
scripts/fetch_geoip.py. Lookups never leave the server, so attacker IPs are
not sent to any third-party API and the map works on isolated networks.

If the database or the `maxminddb` package is missing, every lookup returns
None and the UI shows the map without origins.
"""

import ipaddress
import os
import threading
import time
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

try:
    import maxminddb
except ImportError:  # pragma: no cover - optional dependency
    maxminddb = None

_CANDIDATES = [
    os.getenv("GEOIP_DB", ""),
    "/app/geoip/dbip-city-lite.mmdb",
    str(Path(__file__).resolve().parent.parent / "geoip" / "dbip-city-lite.mmdb"),
]
_RETRY_SECONDS = 300

_reader = None
_path = None
_error = None
_last_try = 0.0
_lock = threading.Lock()


def _open():
    """Open the first database found. A missing file is re-checked every few
    minutes so dropping the DB in place doesn't require a restart."""
    global _reader, _path, _error, _last_try
    if _reader is not None:
        return _reader
    if time.monotonic() - _last_try < _RETRY_SECONDS and _last_try:
        return None
    with _lock:
        if _reader is not None:
            return _reader
        _last_try = time.monotonic()
        if maxminddb is None:
            _error = "Python package 'maxminddb' is not installed"
            return None
        for p in _CANDIDATES:
            if p and Path(p).is_file():
                try:
                    _reader = maxminddb.open_database(p)
                    _path, _error = p, None
                    lookup.cache_clear()
                    return _reader
                except Exception as e:  # corrupt / wrong format
                    _error = f"Cannot open {p}: {e}"
        _error = _error or "GeoIP database not found (run scripts/fetch_geoip.py)"
        return None


@lru_cache(maxsize=65536)
def lookup(ip: str):
    """→ {cc, country, city, lat, lon} for a public IP, else None."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if not addr.is_global:
        return None
    reader = _open()
    if reader is None:
        return None
    try:
        rec = reader.get(ip)
    except Exception:
        return None
    if not rec:
        return None
    country = rec.get("country") or {}
    loc = rec.get("location") or {}
    city = ((rec.get("city") or {}).get("names") or {}).get("en")
    subs = rec.get("subdivisions") or []
    region = ((subs[0] if subs else {}).get("names") or {}).get("en")
    return {
        "region": region,
        "cc": country.get("iso_code"),
        "country": (country.get("names") or {}).get("en") or country.get("iso_code"),
        "city": city,
        "lat": loc.get("latitude"),
        "lon": loc.get("longitude"),
    }


def status() -> dict:
    reader = _open()
    if reader is None:
        return {"available": False, "error": _error, "source": None}
    meta = reader.metadata()
    built = datetime.fromtimestamp(meta.build_epoch, tz=timezone.utc).strftime("%Y-%m")
    is_dbip = "dbip" in f"{meta.database_type} {_path}".lower().replace("-", "")
    return {
        "available": True,
        "error": None,
        "source": f"{meta.database_type} ({built})",
        # CC BY 4.0 requires this attribution wherever DB-IP data is shown.
        "attribution": "IP geolocation by DB-IP" if is_dbip else None,
    }


def home() -> dict:
    """Where attack arcs land on the map — this deployment's location.
    SECURITY_MAP_HOME="lat,lon,Label" (default: Vientiane, Laos)."""
    raw = os.getenv("SECURITY_MAP_HOME", "17.9757,102.6331,Vientiane")
    try:
        lat, lon, *label = [x.strip() for x in raw.split(",")]
        return {"lat": float(lat), "lon": float(lon), "label": ",".join(label) or "Home"}
    except ValueError:
        return {"lat": 17.9757, "lon": 102.6331, "label": "Vientiane"}
