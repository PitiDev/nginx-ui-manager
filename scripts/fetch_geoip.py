#!/usr/bin/env python3
"""Download the free DB-IP "IP to City Lite" database for the threat map.

    python scripts/fetch_geoip.py [DEST_DIR]      # default: ./geoip

DB-IP publishes a new build monthly; this tries the current month, then
falls back to previous ones (a new month's file appears a day or two late).
License: CC BY 4.0 — the UI shows "IP geolocation by DB-IP".
"""

import gzip
import shutil
import sys
import urllib.request
from datetime import date
from pathlib import Path

URL = "https://download.db-ip.com/free/dbip-city-lite-{ym}.mmdb.gz"
NAME = "dbip-city-lite.mmdb"


def months_back(n: int):
    y, m = date.today().year, date.today().month
    for _ in range(n):
        yield f"{y:04d}-{m:02d}"
        y, m = (y, m - 1) if m > 1 else (y - 1, 12)


def main() -> int:
    dest = Path(sys.argv[1] if len(sys.argv) > 1 else "geoip")
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / NAME
    tmp = dest / (NAME + ".part")
    for ym in months_back(3):
        url = URL.format(ym=ym)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "nginx-ui-geoip-fetch"})
            with urllib.request.urlopen(req, timeout=120) as resp, gzip.GzipFile(fileobj=resp) as gz, open(tmp, "wb") as f:
                shutil.copyfileobj(gz, f, 1 << 20)
        except Exception as e:
            print(f"  {ym}: {e}")
            tmp.unlink(missing_ok=True)
            continue
        tmp.replace(out)
        print(f"GeoIP database {ym} → {out} ({out.stat().st_size / 1e6:.0f} MB)")
        return 0
    print("Could not download a GeoIP database", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
