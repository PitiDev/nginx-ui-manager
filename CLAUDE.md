# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **web-based GUI for managing Nginx configurations** on an Ubuntu server. The app is called `nginx_ui`. No code exists yet — this CLAUDE.md documents the intended design based on `requiment.txt`.

### Target Features
- **Dashboard**: Nginx service status (active/inactive) and system uptime
- **Config Manager (CRUD)**: Create, read, update, delete server blocks in `/etc/nginx/sites-available`
- **Toggle Sites**: Enable/disable sites via symlinks in `/etc/nginx/sites-enabled`
- **Validation & Reload**: Run `sudo nginx -t` before saving; `sudo systemctl reload nginx` to apply
- **Log Viewer**: Last 100 lines of `/var/log/nginx/access.log` and `error.log`
- **Authentication**: Login screen (username/password) securing all routes

## Planned Stack

- **Backend**: Python FastAPI (preferred) or Node.js Express
- **Frontend**: HTML + JS + Tailwind CSS (no heavy SPA framework)
- **Target OS**: Ubuntu Server

## Architecture Intent

```
nginx_ui/
├── backend/          # FastAPI app
│   ├── main.py       # App entry, route registration
│   ├── auth.py       # Session/JWT auth middleware
│   ├── nginx.py      # Nginx file I/O, symlink management, shell commands
│   └── logs.py       # Log file reading
├── frontend/
│   ├── templates/    # Jinja2 HTML templates (or static HTML)
│   └── static/       # Tailwind CSS, JS
└── requirements.txt
```

Shell commands executed by the backend must be whitelisted via `visudo` — the app user should only be permitted to run specific `nginx` and `systemctl` commands as root, not run the entire process as root.

## Security Constraints

- All nginx/systemctl shell calls must use a hardcoded command list (no user-controlled shell input)
- The `visudo` sudoers entry should look like:
  ```
  nginx_ui_user ALL=(ALL) NOPASSWD: /usr/sbin/nginx -t, /bin/systemctl reload nginx, /bin/systemctl status nginx
  ```
- Authenticate every API endpoint; JWT tokens stored in `httpOnly` cookies are preferred over `localStorage`

## Reference Files

- [`../my_config/default`](../my_config/default) — Production Nginx server block for `laobullionbank.com` (multi-server, SSL, reverse proxy pattern to use as a template)
- [`../my_config/nginx-v2.conf`](../my_config/nginx-v2.conf) — Alternate config version
- [`../my_config/step-deploy.txt`](../my_config/step-deploy.txt) — Manual deployment workflow (backup → copy → `nginx -t` → reload)
- [`requiment.txt`](requiment.txt) — Full original requirements prompt

## Development Commands (once built)

```bash
# Install dependencies
pip install -r requirements.txt

# Run dev server
uvicorn backend.main:app --reload --port 8080

# Run with production settings
uvicorn backend.main:app --host 0.0.0.0 --port 8080
```

## Deployment Notes

The app is deployed on the same Ubuntu server that runs Nginx. The web UI itself does **not** need to be exposed publicly — it is typically accessed over an internal network or SSH tunnel.
