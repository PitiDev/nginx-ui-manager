FROM python:3.12-slim

# nginx: for nginx -t validation
# procps: provides ps, uptime (fallback)
RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx procps util-linux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Offline GeoIP database for the Security Monitor threat map (DB-IP City Lite,
# CC BY 4.0). Its own layer, before the app code, so normal code changes reuse
# the cached ~130 MB layer. Bump GEOIP_REFRESH (e.g. --build-arg
# GEOIP_REFRESH=2027-01) to pull a newer monthly build. Non-fatal: without it
# the map renders but can't place attackers.
ARG GEOIP_REFRESH=2026-11
COPY scripts/fetch_geoip.py /tmp/fetch_geoip.py
RUN echo "geoip refresh ${GEOIP_REFRESH}" && python /tmp/fetch_geoip.py /app/geoip \
    || echo "WARNING: GeoIP download failed — threat map will have no locations"

COPY backend/ ./backend/
COPY frontend/ ./frontend/

EXPOSE 8080

# Run as root — container is already privileged so this doesn't change the
# security posture, and it avoids sudo complexity for systemctl/nginx commands.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080"]
