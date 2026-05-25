FROM python:3.12-slim

# nginx: for nginx -t validation
# procps: provides ps, uptime (fallback)
RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

EXPOSE 8080

# Run as root — container is already privileged so this doesn't change the
# security posture, and it avoids sudo complexity for systemctl/nginx commands.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080"]
