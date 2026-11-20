import asyncio
import re
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

from backend import activity, auth, backup, logs, nginx, node_ssh, nodes as node_store, proxy_mgr, security, ssl_mgr, system, system_diagram, tester, traffic
from backend import users as user_store

app = FastAPI(title="Nginx UI")


@app.on_event("startup")
async def startup_event():
    backup.start_scheduler()

BASE_DIR = Path(__file__).parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "frontend" / "templates"))

static_dir = BASE_DIR / "frontend" / "static"
static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

DEFAULT_CONFIG_TEMPLATE = """\
server {
    listen 80;
    server_name example.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
"""


class AuthMiddleware(BaseHTTPMiddleware):
    PUBLIC = {"/login"}

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path in self.PUBLIC or path.startswith("/static"):
            return await call_next(request)

        user = auth.verify_token(request.cookies.get("access_token"))
        if not user:
            return RedirectResponse(url="/login", status_code=302)

        request.state.user = user
        role = user.get("role", "viewer")

        # Admin-only sections
        if (path.startswith("/users") or path.startswith("/activity")) and role != "admin":
            resp = RedirectResponse(url="/dashboard", status_code=302)
            resp.set_cookie("flash_msg", "Access denied: admin only", max_age=5, samesite="lax")
            resp.set_cookie("flash_cat", "error", max_age=5, samesite="lax")
            return resp

        # Viewers cannot perform any write operations
        if role != "admin" and request.method == "POST" and path != "/logout":
            resp = RedirectResponse(url="/dashboard", status_code=302)
            resp.set_cookie("flash_msg", "Access denied: viewer role cannot make changes", max_age=5, samesite="lax")
            resp.set_cookie("flash_cat", "error", max_age=5, samesite="lax")
            return resp

        return await call_next(request)


app.add_middleware(AuthMiddleware)


def _flash_ctx(request: Request) -> dict:
    return {
        "flash_msg": request.cookies.get("flash_msg", ""),
        "flash_cat": request.cookies.get("flash_cat", "info"),
    }


def _clear_flash(response: Response) -> None:
    response.delete_cookie("flash_msg")
    response.delete_cookie("flash_cat")


def _get_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def _actor(request: Request) -> tuple[str, str]:
    user = getattr(request.state, "user", None) or {}
    return user.get("username", "?"), user.get("role", "viewer")


def _set_flash(response: Response, msg: str, cat: str = "info") -> None:
    # Cookies cannot contain newlines, semicolons, or other control characters.
    # Collapse them to spaces and cap length so the cookie header stays valid.
    safe = re.sub(r"[\x00-\x1f\x7f;]", " ", msg).strip()[:300]
    response.set_cookie("flash_msg", safe, max_age=5, samesite="lax")
    response.set_cookie("flash_cat", cat, max_age=5, samesite="lax")


def tmpl(request: Request, name: str, ctx: dict | None = None, status_code: int = 200):
    """Shorthand for templates.TemplateResponse with Starlette 1.x API."""
    active_node_id = request.cookies.get("active_node", "local")
    all_nodes      = node_store.list_nodes()
    active_node    = next((n for n in all_nodes if n["id"] == active_node_id), None)
    if active_node_id != "local" and not active_node:
        active_node_id = "local"
    base = {
        "current_user":  getattr(request.state, "user", None),
        "all_nodes":     all_nodes,
        "active_node_id": active_node_id,
        "active_node":   active_node,
    }
    if ctx:
        base.update(ctx)
    return templates.TemplateResponse(request, name, base, status_code=status_code)


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return tmpl(request, "login.html")


@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    role = auth.authenticate(username, password)
    if role:
        activity.log(username, role, "auth.login", ip=_get_ip(request))
        response = RedirectResponse(url="/dashboard", status_code=302)
        response.set_cookie(
            "access_token",
            auth.create_token(username, role),
            httponly=True,
            samesite="lax",
        )
        return response
    activity.log(username, "?", "auth.login", detail="Invalid credentials", ip=_get_ip(request), result="error")
    return tmpl(request, "login.html", {"error": "Invalid username or password"}, status_code=401)


@app.post("/logout")
async def logout(request: Request):
    user, role = _actor(request)
    activity.log(user, role, "auth.logout", ip=_get_ip(request))
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("access_token")
    return response


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return RedirectResponse(url="/dashboard", status_code=302)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    status = nginx.get_nginx_status()
    sites = nginx.list_sites()
    ctx = {
        "status": status,
        "total_sites": len(sites),
        "enabled_sites": sum(1 for s in sites if s["enabled"]),
        "nodes": node_store.list_nodes(),
        **_flash_ctx(request),
    }
    response = tmpl(request, "dashboard.html", ctx)
    _clear_flash(response)
    return response


# ── Config Manager ────────────────────────────────────────────────────────────

@app.get("/set-node")
async def set_node_cookie(request: Request, id: str = "local", next: str = "/dashboard"):
    """Set the active node cookie and redirect back."""
    if id != "local" and not node_store.get_node(id):
        id = "local"
    if not next.startswith("/"):
        next = "/dashboard"
    response = RedirectResponse(url=next, status_code=302)
    response.set_cookie("active_node", id, httponly=False, samesite="lax", max_age=86400 * 7)
    return response


@app.get("/configs", response_class=HTMLResponse)
async def list_configs(request: Request):
    active_node_id = request.cookies.get("active_node", "local")
    if active_node_id != "local":
        node = node_store.get_node(active_node_id)
        if node:
            return RedirectResponse(url=f"/nodes/{active_node_id}", status_code=302)
    ctx = {"sites": nginx.list_sites(), **_flash_ctx(request)}
    response = tmpl(request, "configs.html", ctx)
    _clear_flash(response)
    return response


@app.get("/configs/proxy-builder", response_class=HTMLResponse)
async def proxy_builder_page(request: Request, edit: str = ""):
    config_content = ""
    enabled = True
    if edit:
        content = nginx.get_config(edit)
        if content is not None:
            config_content = content
            enabled = nginx.is_enabled(edit)
        else:
            edit = ""
    return tmpl(request, "proxy_builder.html", {
        "edit_name": edit,
        "config_content": config_content,
        "enabled": enabled,
    })


@app.get("/configs/new", response_class=HTMLResponse)
async def new_config_page(request: Request):
    return tmpl(request, "editor.html", {
        "mode": "new",
        "name": "",
        "content": DEFAULT_CONFIG_TEMPLATE,
        "error": "",
        "output": "",
        "flash_msg": "",
        "flash_cat": "",
    })


@app.post("/configs/create")
async def create_config(
    request: Request,
    name: str = Form(...),
    content: str = Form(...),
):
    name = name.strip()
    if not name or "/" in name or name.startswith("."):
        return tmpl(request, "editor.html", {
            "mode": "new",
            "name": name,
            "content": content,
            "error": "Invalid config name. Must not contain '/' or start with '.'",
            "output": "",
            "flash_msg": "",
            "flash_cat": "",
        })

    ok, output = nginx.save_config(name, content)
    user, role = _actor(request)
    if not ok:
        activity.log(user, role, "config.create", target=name, detail=output, ip=_get_ip(request), result="error")
        return tmpl(request, "editor.html", {
            "mode": "new",
            "name": name,
            "content": content,
            "error": output,
            "output": "",
            "flash_msg": "",
            "flash_cat": "",
        })

    activity.log(user, role, "config.create", target=name, ip=_get_ip(request))
    response = RedirectResponse(url="/configs", status_code=302)
    _set_flash(response, f"Config '{name}' created successfully", "success")
    return response


@app.get("/configs/{name}/edit", response_class=HTMLResponse)
async def edit_config_page(request: Request, name: str):
    content = nginx.get_config(name)
    if content is None:
        response = RedirectResponse(url="/configs", status_code=302)
        _set_flash(response, f"Config '{name}' not found", "error")
        return response
    return tmpl(request, "editor.html", {
        "mode": "edit",
        "name": name,
        "content": content,
        "enabled": nginx.is_enabled(name),
        "error": "",
        "output": "",
        "flash_msg": "",
        "flash_cat": "",
    })


@app.post("/configs/{name}/save")
async def save_config_route(
    request: Request,
    name: str,
    content: str = Form(...),
):
    ok, output = nginx.save_config(name, content)
    user, role = _actor(request)
    activity.log(user, role, "config.save", target=name, detail=output, ip=_get_ip(request), result="success" if ok else "error")
    return tmpl(request, "editor.html", {
        "mode": "edit",
        "name": name,
        "content": content,
        "enabled": nginx.is_enabled(name),
        "error": "" if ok else output,
        "output": output if ok else "",
        "flash_msg": "",
        "flash_cat": "",
    })


@app.post("/configs/{name}/delete")
async def delete_config_route(request: Request, name: str):
    nginx.delete_config(name)
    user, role = _actor(request)
    activity.log(user, role, "config.delete", target=name, ip=_get_ip(request))
    response = RedirectResponse(url="/configs", status_code=302)
    _set_flash(response, f"Config '{name}' deleted", "info")
    return response


@app.post("/configs/{name}/enable")
async def enable_site_route(request: Request, name: str):
    ok, output = nginx.enable_site(name)
    user, role = _actor(request)
    activity.log(user, role, "config.enable", target=name, detail=output, ip=_get_ip(request), result="success" if ok else "error")
    response = RedirectResponse(url="/configs", status_code=302)
    _set_flash(response, f"Enabled '{name}'" if ok else output, "success" if ok else "error")
    return response


@app.post("/configs/{name}/disable")
async def disable_site_route(request: Request, name: str):
    ok, output = nginx.disable_site(name)
    user, role = _actor(request)
    activity.log(user, role, "config.disable", target=name, detail=output, ip=_get_ip(request), result="success" if ok else "error")
    response = RedirectResponse(url="/configs", status_code=302)
    _set_flash(response, f"Disabled '{name}'" if ok else output, "success" if ok else "error")
    return response


# ── Nginx Controls ────────────────────────────────────────────────────────────

@app.post("/nginx/reload")
async def reload_nginx_route(request: Request):
    ok, output = nginx.reload_nginx()
    user, role = _actor(request)
    activity.log(user, role, "nginx.reload", detail=output, ip=_get_ip(request), result="success" if ok else "error")
    response = RedirectResponse(url="/dashboard", status_code=302)
    _set_flash(
        response,
        "Nginx reloaded successfully" if ok else f"Reload failed: {output}",
        "success" if ok else "error",
    )
    return response


# ── API ───────────────────────────────────────────────────────────────────────

@app.get("/api/nginx/status")
async def api_nginx_status():
    return JSONResponse(nginx.get_nginx_status())


@app.get("/api/system/stats")
def api_system_stats():
    return JSONResponse(system.get_stats())


@app.get("/api/debug/stats")
def api_debug_stats():
    """Diagnostic endpoint — shows raw info for troubleshooting monitoring on deployed server."""
    return JSONResponse(system.get_debug_info())


@app.get("/api/logs/{log_type}")
async def api_get_logs(log_type: str, lines: int = 100):
    if log_type == "access":
        return JSONResponse(logs.get_access_log_json(lines))
    elif log_type == "error":
        return JSONResponse(logs.get_error_log_json(lines))
    else:
        return JSONResponse({"error": "Unknown log type"}, status_code=400)


@app.get("/api/traffic/stats")
def api_traffic_stats(lines: int = 4000):
    return JSONResponse(traffic.get_local_stats(min(lines, 8000)))


@app.get("/api/traffic/all")
def api_traffic_all(lines: int = 4000):
    return JSONResponse(traffic.get_fleet_stats(min(lines, 4000)))


def _traffic_stats_for(node_id: str, lines: int) -> dict:
    if node_id == "all":
        return traffic.get_fleet_stats(lines)
    if node_id != "local":
        node = node_store.get_node(node_id)
        if not node:
            return {"error": "Node not found"}
        return traffic.get_node_stats(node, lines)
    return traffic.get_local_stats(lines)


@app.websocket("/ws/traffic")
async def ws_traffic(websocket: WebSocket):
    """Pushes Traffic Monitor stats (incl. the Live Request Flow diagram's
    upstream breakdown) to the client on a server-driven interval, replacing
    client-side fetch polling with a persistent connection.

    BaseHTTPMiddleware (AuthMiddleware) only wraps the HTTP scope, not
    websocket connections, so the session cookie has to be checked here too.
    """
    user = auth.verify_token(websocket.cookies.get("access_token"))
    # Accept before closing on auth failure: a close() sent before accept()
    # gets flattened into a bare HTTP 403 at the handshake, and the custom
    # 4401 code never reaches the browser's onclose handler.
    await websocket.accept()
    if not user:
        await websocket.close(code=4401)
        return

    node_id = websocket.query_params.get("node", "local")
    raw_lines = websocket.query_params.get("lines")
    try:
        lines = min(max(int(raw_lines), 100), 8000) if raw_lines else 4000
    except ValueError:
        lines = 4000

    try:
        while True:
            try:
                stats = await asyncio.to_thread(_traffic_stats_for, node_id, lines)
            except Exception as e:
                stats = {"error": str(e)}
            await websocket.send_json(stats)
            await asyncio.sleep(6 if node_id == "all" else 2)
    except WebSocketDisconnect:
        pass


# ── Logs Page ─────────────────────────────────────────────────────────────────

@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    return tmpl(request, "logs.html", {"flash_msg": "", "flash_cat": ""})


# ── Traffic Monitor ───────────────────────────────────────────────────────────

@app.get("/traffic", response_class=HTMLResponse)
async def traffic_page(request: Request):
    return tmpl(request, "traffic.html", {"flash_msg": "", "flash_cat": ""})


# ── Cyber Security Monitor ────────────────────────────────────────────────────

@app.get("/security", response_class=HTMLResponse)
async def security_page(request: Request):
    return tmpl(request, "security.html", {"flash_msg": "", "flash_cat": ""})


def _security_lines(raw) -> int:
    try:
        return min(max(int(raw), 200), 20000)
    except (TypeError, ValueError):
        return 5000


@app.get("/api/security/overview")
def api_security_overview(node: str = "local", lines: int = 5000):
    try:
        return JSONResponse(security.get_overview(node, _security_lines(lines)))
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=404)


@app.get("/api/security/ip")
def api_security_ip(ip: str, node: str = "local", lines: int = 20000):
    """Everything one source IP did in the logs (IP investigation drawer)."""
    try:
        depth = min(max(int(lines), 200), 50000)
    except (TypeError, ValueError):
        depth = 20000
    try:
        return JSONResponse(security.investigate(ip, node, depth))
    except ValueError as e:
        msg = str(e)
        return JSONResponse({"error": msg if msg == "Node not found" else "Invalid IP address"},
                            status_code=404 if msg == "Node not found" else 400)


@app.get("/api/security/audit")
def api_security_audit(node: str = "local"):
    if node == "all":
        return JSONResponse(security.get_fleet_audit())
    return JSONResponse(security.get_audit(node))


@app.get("/api/security/app-audit")
def api_security_app_audit(request: Request):
    # Exposes login IPs/usernames from the activity log → admin only.
    if getattr(request.state, "user", {}).get("role") != "admin":
        return JSONResponse({"error": "admin only"}, status_code=403)
    return JSONResponse(security.app_audit())


@app.websocket("/ws/security")
async def ws_security(websocket: WebSocket):
    """Live threat feed. Same auth pattern as /ws/traffic (the HTTP auth
    middleware doesn't cover websocket scope)."""
    user = auth.verify_token(websocket.cookies.get("access_token"))
    await websocket.accept()
    if not user:
        await websocket.close(code=4401)
        return

    node_id = websocket.query_params.get("node", "local")
    lines = _security_lines(websocket.query_params.get("lines"))
    interval = 5 if node_id == "local" else 15 if node_id == "all" else 10

    try:
        while True:
            try:
                data = await asyncio.to_thread(security.get_overview, node_id, lines)
            except Exception as e:
                data = {"error": str(e)}
            await websocket.send_json(data)
            await asyncio.sleep(interval)
    except WebSocketDisconnect:
        pass


# ── About ─────────────────────────────────────────────────────────────────────

@app.get("/about", response_class=HTMLResponse)
async def about_page(request: Request):
    return tmpl(request, "about.html")


# ── System Diagram ────────────────────────────────────────────────────────────

@app.get("/system-diagram", response_class=HTMLResponse)
async def system_diagram_page(request: Request):
    ctx = {
        "embed_url": system_diagram.get_embed_url(),
        **_flash_ctx(request),
    }
    response = tmpl(request, "system_diagram.html", ctx)
    _clear_flash(response)
    return response


@app.post("/system-diagram/save")
async def system_diagram_save(request: Request, embed_code: str = Form(...)):
    ok, msg = system_diagram.set_embed_url(embed_code)
    user, role = _actor(request)
    activity.log(user, role, "system_diagram.save", detail=msg, ip=_get_ip(request), result="success" if ok else "error")
    response = RedirectResponse(url="/system-diagram", status_code=302)
    _set_flash(response, msg, "success" if ok else "error")
    return response


@app.post("/system-diagram/clear")
async def system_diagram_clear(request: Request):
    system_diagram.clear_embed()
    user, role = _actor(request)
    activity.log(user, role, "system_diagram.clear", ip=_get_ip(request))
    response = RedirectResponse(url="/system-diagram", status_code=302)
    _set_flash(response, "Diagram embed removed", "info")
    return response


# ── SSL Manager ───────────────────────────────────────────────────────────────

@app.get("/ssl", response_class=HTMLResponse)
async def ssl_page(request: Request):
    files = ssl_mgr.list_ssl_files()
    ctx = {
        "files": files,
        "ssl_dir": str(ssl_mgr.SSL_DIR),
        **_flash_ctx(request),
    }
    response = tmpl(request, "ssl.html", ctx)
    _clear_flash(response)
    return response


@app.post("/ssl/upload")
async def upload_ssl(
    request: Request,
    files: list[UploadFile] = File(...),
):
    if not files or (len(files) == 1 and not files[0].filename):
        response = RedirectResponse(url="/ssl", status_code=302)
        _set_flash(response, "No files selected", "error")
        return response

    results = []
    any_ok = False
    for f in files:
        name = (f.filename or "").strip()
        if not name or "/" in name or name.startswith("."):
            results.append(f"Skipped invalid name: {name!r}")
            continue
        content = await f.read()
        ok, msg = ssl_mgr.save_ssl_file(name, content)
        results.append(msg)
        if ok:
            any_ok = True

    summary = "; ".join(results) or "Nothing uploaded"
    user, role = _actor(request)
    names = ", ".join(f.filename for f in files if f.filename)
    activity.log(user, role, "ssl.upload", target=names, detail=summary, ip=_get_ip(request), result="success" if any_ok else "error")
    response = RedirectResponse(url="/ssl", status_code=302)
    _set_flash(response, summary, "success" if any_ok else "error")
    return response


@app.get("/ssl/{name}/edit", response_class=HTMLResponse)
async def edit_ssl_page(request: Request, name: str):
    content = ssl_mgr.read_ssl_file(name)
    if content is None:
        response = RedirectResponse(url="/ssl", status_code=302)
        _set_flash(response, f"File '{name}' not found", "error")
        return response
    ftype = ssl_mgr._file_type(name)
    cert_info = None
    path = ssl_mgr._safe_path(name)
    if path and ftype in ("Certificate", "PEM"):
        cert_info = ssl_mgr._cert_info(path)
    return tmpl(request, "ssl_editor.html", {
        "name": name,
        "content": content,
        "ftype": ftype,
        "cert_info": cert_info,
        "error": "",
        "output": "",
        "flash_msg": "",
        "flash_cat": "",
    })


@app.post("/ssl/{name}/update")
async def update_ssl_route(
    request: Request,
    name: str,
    content: str = Form(...),
):
    ok, msg = ssl_mgr.save_ssl_file(name, content.encode())
    user, role = _actor(request)
    activity.log(user, role, "ssl.update", target=name, detail=msg, ip=_get_ip(request), result="success" if ok else "error")
    ftype = ssl_mgr._file_type(name)
    cert_info = None
    if ok:
        path = ssl_mgr._safe_path(name)
        if path and ftype in ("Certificate", "PEM"):
            cert_info = ssl_mgr._cert_info(path)
    return tmpl(request, "ssl_editor.html", {
        "name": name,
        "content": content,
        "ftype": ftype,
        "cert_info": cert_info,
        "error": "" if ok else msg,
        "output": msg if ok else "",
        "flash_msg": "",
        "flash_cat": "",
    })


@app.post("/ssl/{name}/delete")
async def delete_ssl_route(request: Request, name: str):
    ok, msg = ssl_mgr.delete_ssl_file(name)
    user, role = _actor(request)
    activity.log(user, role, "ssl.delete", target=name, detail=msg, ip=_get_ip(request), result="success" if ok else "error")
    response = RedirectResponse(url="/ssl", status_code=302)
    _set_flash(response, msg, "success" if ok else "error")
    return response


# ── User Management (admin only) ──────────────────────────────────────────────

@app.get("/users", response_class=HTMLResponse)
async def users_page(request: Request):
    ctx = {"users": user_store.get_all(), **_flash_ctx(request)}
    response = tmpl(request, "users.html", ctx)
    _clear_flash(response)
    return response


@app.get("/users/new", response_class=HTMLResponse)
async def new_user_page(request: Request):
    return tmpl(request, "user_form.html", {"mode": "new", "edit_user": None, "error": ""})


@app.post("/users/create")
async def create_user_route(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
):
    ok, msg = user_store.create_user(username, password, role)
    actor, actor_role = _actor(request)
    activity.log(actor, actor_role, "user.create", target=username, detail=msg, ip=_get_ip(request), result="success" if ok else "error")
    if not ok:
        return tmpl(request, "user_form.html", {
            "mode": "new",
            "edit_user": {"username": username, "role": role},
            "error": msg,
        })
    response = RedirectResponse(url="/users", status_code=302)
    _set_flash(response, msg, "success")
    return response


@app.get("/users/{username}/edit", response_class=HTMLResponse)
async def edit_user_page(request: Request, username: str):
    found = next((u for u in user_store.get_all() if u["username"] == username), None)
    if not found:
        response = RedirectResponse(url="/users", status_code=302)
        _set_flash(response, "User not found", "error")
        return response
    return tmpl(request, "user_form.html", {"mode": "edit", "edit_user": found, "error": ""})


@app.post("/users/{username}/update")
async def update_user_route(
    request: Request,
    username: str,
    password: str = Form(""),
    role: str = Form(...),
):
    ok, msg = user_store.update_user(username, password or None, role)
    actor, actor_role = _actor(request)
    activity.log(actor, actor_role, "user.update", target=username, detail=msg, ip=_get_ip(request), result="success" if ok else "error")
    if not ok:
        return tmpl(request, "user_form.html", {
            "mode": "edit",
            "edit_user": {"username": username, "role": role},
            "error": msg,
        })
    response = RedirectResponse(url="/users", status_code=302)
    _set_flash(response, msg, "success")
    return response


@app.post("/users/{username}/delete")
async def delete_user_route(request: Request, username: str):
    current = request.state.user["username"]
    ok, msg = user_store.delete_user(username, current)
    actor, actor_role = _actor(request)
    activity.log(actor, actor_role, "user.delete", target=username, detail=msg, ip=_get_ip(request), result="success" if ok else "error")
    response = RedirectResponse(url="/users", status_code=302)
    _set_flash(response, msg, "success" if ok else "error")
    return response


# ── Backup ────────────────────────────────────────────────────────────────────

@app.get("/backup", response_class=HTMLResponse)
async def backup_page(request: Request):
    ctx = {
        "backups": backup.list_backups(),
        "settings": backup.get_auto_backup_settings(),
        **_flash_ctx(request),
    }
    response = tmpl(request, "backup.html", ctx)
    _clear_flash(response)
    return response


@app.post("/backup/create")
async def backup_create_route(
    request: Request,
    note: str = Form(""),
):
    ok, msg = backup.create_backup(note.strip())
    user, role = _actor(request)
    activity.log(user, role, "backup.create", target=note.strip(), detail=msg, ip=_get_ip(request), result="success" if ok else "error")
    response = RedirectResponse(url="/backup", status_code=302)
    _set_flash(response, msg, "success" if ok else "error")
    return response


@app.post("/backup/settings")
async def backup_settings_route(
    request: Request,
    enabled: str = Form("off"),
    interval_hours: int = Form(24),
):
    backup.save_auto_backup_settings(enabled == "on", max(1, interval_hours))
    user, role = _actor(request)
    activity.log(user, role, "backup.settings", detail=f"enabled={enabled} interval={interval_hours}h", ip=_get_ip(request))
    response = RedirectResponse(url="/backup", status_code=302)
    _set_flash(response, "Auto backup settings saved", "success")
    return response


@app.post("/backup/{name}/delete")
async def backup_delete_route(request: Request, name: str):
    ok, msg = backup.delete_backup(name)
    user, role = _actor(request)
    activity.log(user, role, "backup.delete", target=name, detail=msg, ip=_get_ip(request), result="success" if ok else "error")
    response = RedirectResponse(url="/backup", status_code=302)
    _set_flash(response, msg, "success" if ok else "error")
    return response


@app.post("/backup/node/{node_id}/create")
async def backup_node_create(
    request: Request,
    node_id: str,
    note: str = Form(""),
):
    node = node_store.get_node(node_id)
    if not node:
        response = RedirectResponse(url="/backup", status_code=302)
        _set_flash(response, "Node not found", "error")
        return response
    ok, msg = node_ssh.create_remote_backup(node, note.strip())
    user, role = _actor(request)
    activity.log(user, role, "backup.create", target=note.strip(), detail=msg, ip=_get_ip(request), result="success" if ok else "error", node=node.get("name", node_id))
    response = RedirectResponse(url="/backup", status_code=302)
    _set_flash(response, msg, "success" if ok else "error")
    return response


# ── Proxy Manager ────────────────────────────────────────────────────────────

@app.get("/proxy-manager", response_class=HTMLResponse)
async def proxy_manager_page(request: Request):
    ctx = {
        "proxies": proxy_mgr.list_proxies(),
        **_flash_ctx(request),
    }
    response = tmpl(request, "proxy_manager.html", ctx)
    _clear_flash(response)
    return response


# ── Testing ───────────────────────────────────────────────────────────────────

@app.get("/testing", response_class=HTMLResponse)
async def testing_page(request: Request):
    return tmpl(request, "testing.html", {})


# GET endpoints so both admin and viewer roles can run tests
@app.get("/api/testing/ssl")
def api_test_ssl(domain: str):
    return JSONResponse(tester.test_ssl(domain))


@app.get("/api/testing/security")
def api_test_security(url: str):
    return JSONResponse(tester.test_security(url))


@app.get("/api/testing/load")
def api_test_load(url: str, total: int = 20, concurrency: int = 5):
    return JSONResponse(tester.test_load(url, total, concurrency))


@app.get("/api/testing/api-security")
def api_test_api_security(url: str, method: str = "GET"):
    return JSONResponse(tester.test_api_security(url, method))


# ── Nodes (Multi-node management) ─────────────────────────────────────────────

@app.get("/nodes", response_class=HTMLResponse)
async def nodes_page(request: Request):
    ctx = {"nodes": node_store.list_nodes(), **_flash_ctx(request)}
    response = tmpl(request, "nodes.html", ctx)
    _clear_flash(response)
    return response


@app.get("/nodes/new", response_class=HTMLResponse)
async def new_node_page(request: Request):
    return tmpl(request, "node_form.html", {"mode": "new", "node": None, "error": ""})


@app.post("/nodes/create")
async def create_node_route(
    request: Request,
    name:            str = Form(...),
    host:            str = Form(...),
    port:            int = Form(22),
    username:        str = Form("root"),
    auth_type:       str = Form("password"),
    password:        str = Form(""),
    ssh_key:         str = Form(""),
    sudo_password:   str = Form(""),
    sites_available: str = Form("/etc/nginx/sites-available"),
    sites_enabled:   str = Form("/etc/nginx/sites-enabled"),
):
    ok, msg = node_store.create_node(locals())
    user, role = _actor(request)
    activity.log(user, role, "node.create", target=name, detail=msg, ip=_get_ip(request), result="success" if ok else "error")
    if not ok:
        return tmpl(request, "node_form.html", {
            "mode": "new", "node": locals(), "error": msg,
        })
    response = RedirectResponse(url="/nodes", status_code=302)
    _set_flash(response, msg, "success")
    return response


@app.get("/nodes/{node_id}/edit", response_class=HTMLResponse)
async def edit_node_page(request: Request, node_id: str):
    node = node_store.get_node(node_id)
    if not node:
        response = RedirectResponse(url="/nodes", status_code=302)
        _set_flash(response, "Node not found", "error")
        return response
    return tmpl(request, "node_form.html", {"mode": "edit", "node": node, "error": ""})


@app.post("/nodes/{node_id}/update")
async def update_node_route(
    request: Request,
    node_id:         str,
    name:            str = Form(...),
    host:            str = Form(...),
    port:            int = Form(22),
    username:        str = Form("root"),
    auth_type:       str = Form("password"),
    password:        str = Form(""),
    ssh_key:         str = Form(""),
    sudo_password:   str = Form(""),
    sites_available: str = Form("/etc/nginx/sites-available"),
    sites_enabled:   str = Form("/etc/nginx/sites-enabled"),
):
    ok, msg = node_store.update_node(node_id, locals())
    user, role = _actor(request)
    activity.log(user, role, "node.update", target=name, detail=msg, ip=_get_ip(request), result="success" if ok else "error", node=name)
    if not ok:
        node = node_store.get_node(node_id)
        return tmpl(request, "node_form.html", {
            "mode": "edit", "node": node, "error": msg,
        })
    response = RedirectResponse(url="/nodes", status_code=302)
    _set_flash(response, msg, "success")
    return response


@app.post("/nodes/{node_id}/delete")
async def delete_node_route(request: Request, node_id: str):
    node = node_store.get_node(node_id)
    node_name = node.get("name", node_id) if node else node_id
    ok, msg = node_store.delete_node(node_id)
    user, role = _actor(request)
    activity.log(user, role, "node.delete", target=node_name, detail=msg, ip=_get_ip(request), result="success" if ok else "error")
    response = RedirectResponse(url="/nodes", status_code=302)
    _set_flash(response, msg, "success" if ok else "error")
    return response


@app.get("/nodes/{node_id}", response_class=HTMLResponse)
async def node_detail_page(request: Request, node_id: str):
    node = node_store.get_node(node_id)
    if not node:
        response = RedirectResponse(url="/nodes", status_code=302)
        _set_flash(response, "Node not found", "error")
        return response
    ctx = {"node": node, **_flash_ctx(request)}
    response = tmpl(request, "node_detail.html", ctx)
    _clear_flash(response)
    return response


@app.post("/nodes/{node_id}/reload")
async def node_reload_route(request: Request, node_id: str):
    node = node_store.get_node(node_id)
    if not node:
        response = RedirectResponse(url="/nodes", status_code=302)
        _set_flash(response, "Node not found", "error")
        return response
    ok, msg = node_ssh.reload_nginx(node)
    user, role = _actor(request)
    activity.log(user, role, "nginx.reload", target=node["name"], detail=msg, ip=_get_ip(request), result="success" if ok else "error", node=node["name"])
    response = RedirectResponse(url=f"/nodes/{node_id}", status_code=302)
    _set_flash(response, msg, "success" if ok else "error")
    return response


@app.post("/nodes/{node_id}/sites/{name}/enable")
async def node_enable_site(request: Request, node_id: str, name: str):
    node = node_store.get_node(node_id)
    ok, msg = node_ssh.enable_site(node, name) if node else (False, "Node not found")
    user, role = _actor(request)
    node_name = node.get("name", node_id) if node else node_id
    activity.log(user, role, "config.enable", target=name, detail=msg, ip=_get_ip(request), result="success" if ok else "error", node=node_name)
    response = RedirectResponse(url=f"/nodes/{node_id}", status_code=302)
    _set_flash(response, msg, "success" if ok else "error")
    return response


@app.post("/nodes/{node_id}/sites/{name}/disable")
async def node_disable_site(request: Request, node_id: str, name: str):
    node = node_store.get_node(node_id)
    ok, msg = node_ssh.disable_site(node, name) if node else (False, "Node not found")
    user, role = _actor(request)
    node_name = node.get("name", node_id) if node else node_id
    activity.log(user, role, "config.disable", target=name, detail=msg, ip=_get_ip(request), result="success" if ok else "error", node=node_name)
    response = RedirectResponse(url=f"/nodes/{node_id}", status_code=302)
    _set_flash(response, msg, "success" if ok else "error")
    return response


@app.get("/nodes/{node_id}/configs/new", response_class=HTMLResponse)
async def node_new_config_page(request: Request, node_id: str):
    node = node_store.get_node(node_id)
    if not node:
        response = RedirectResponse(url="/nodes", status_code=302)
        _set_flash(response, "Node not found", "error")
        return response
    return tmpl(request, "node_config_editor.html", {
        "node": node,
        "mode": "new",
        "name": "",
        "content": DEFAULT_CONFIG_TEMPLATE,
        "enabled": True,
        "error": "",
        "output": "",
    })


@app.post("/nodes/{node_id}/configs/create")
async def node_config_create(
    request: Request,
    node_id: str,
    name:    str = Form(...),
    content: str = Form(...),
):
    node = node_store.get_node(node_id)
    if not node:
        response = RedirectResponse(url="/nodes", status_code=302)
        _set_flash(response, "Node not found", "error")
        return response
    name = name.strip()
    if not name or "/" in name or name.startswith("."):
        return tmpl(request, "node_config_editor.html", {
            "node": node,
            "mode": "new",
            "name": name,
            "content": content,
            "enabled": True,
            "error": "Invalid config name. Must not contain '/' or start with '.'",
            "output": "",
        })
    ok, msg = node_ssh.save_config(node, name, content)
    user, role = _actor(request)
    activity.log(user, role, "config.create", target=name, detail=msg, ip=_get_ip(request), result="success" if ok else "error", node=node["name"])
    if not ok:
        return tmpl(request, "node_config_editor.html", {
            "node": node,
            "mode": "new",
            "name": name,
            "content": content,
            "enabled": True,
            "error": msg,
            "output": "",
        })
    response = RedirectResponse(url=f"/nodes/{node_id}", status_code=302)
    _set_flash(response, f"Config '{name}' created on {node['name']}", "success")
    return response


@app.get("/nodes/{node_id}/configs/{name}", response_class=HTMLResponse)
async def node_config_editor(request: Request, node_id: str, name: str):
    node = node_store.get_node(node_id)
    if not node:
        response = RedirectResponse(url="/nodes", status_code=302)
        _set_flash(response, "Node not found", "error")
        return response
    ok, content = node_ssh.get_config(node, name)
    return tmpl(request, "node_config_editor.html", {
        "node": node,
        "mode": "edit",
        "name": name,
        "content": content if ok else "",
        "enabled": node_ssh.is_enabled(node, name) if ok else True,
        "error": "" if ok else content,
        "output": "",
    })


@app.post("/nodes/{node_id}/configs/{name}/save")
async def node_config_save(
    request: Request,
    node_id: str,
    name:    str,
    content: str = Form(...),
):
    node = node_store.get_node(node_id)
    if not node:
        response = RedirectResponse(url="/nodes", status_code=302)
        _set_flash(response, "Node not found", "error")
        return response
    ok, msg = node_ssh.save_config(node, name, content)
    user, role = _actor(request)
    activity.log(user, role, "config.save", target=name, detail=msg, ip=_get_ip(request), result="success" if ok else "error", node=node["name"])
    return tmpl(request, "node_config_editor.html", {
        "node": node,
        "mode": "edit",
        "name": name,
        "content": content,
        "enabled": node_ssh.is_enabled(node, name),
        "error": "" if ok else msg,
        "output": msg if ok else "",
    })


# ── Node Proxy Builder ────────────────────────────────────────────────────────

@app.get("/nodes/{node_id}/builder", response_class=HTMLResponse)
async def node_builder_page(request: Request, node_id: str, edit: str = ""):
    node = node_store.get_node(node_id)
    if not node:
        response = RedirectResponse(url="/nodes", status_code=302)
        _set_flash(response, "Node not found", "error")
        return response
    config_content = ""
    enabled = True
    if edit:
        ok, content = node_ssh.get_config(node, edit)
        if ok:
            config_content = content
            enabled = node_ssh.is_enabled(node, edit)
        else:
            edit = ""
    return tmpl(request, "node_proxy_builder.html", {
        "node": node,
        "edit_name": edit,
        "config_content": config_content,
        "enabled": enabled,
        "error": "",
    })


@app.post("/nodes/{node_id}/builder/save")
async def node_builder_save(
    request: Request,
    node_id: str,
    name:    str = Form(...),
    content: str = Form(...),
):
    node = node_store.get_node(node_id)
    if not node:
        response = RedirectResponse(url="/nodes", status_code=302)
        _set_flash(response, "Node not found", "error")
        return response
    name = name.strip()
    if not name or "/" in name or name.startswith("."):
        return tmpl(request, "node_proxy_builder.html", {
            "node": node, "edit_name": name, "config_content": content,
            "error": "Invalid config name — must not contain '/' or start with '.'",
        })
    ok, msg = node_ssh.save_config(node, name, content)
    user, role = _actor(request)
    activity.log(user, role, "proxy.save", target=name, detail=msg, ip=_get_ip(request), result="success" if ok else "error", node=node["name"])
    if not ok:
        return tmpl(request, "node_proxy_builder.html", {
            "node": node, "edit_name": name, "config_content": content,
            "error": msg,
        })
    response = RedirectResponse(url=f"/nodes/{node_id}", status_code=302)
    _set_flash(response, f"Config '{name}' saved to {node['name']}", "success")
    return response


# JSON APIs for node detail page (loaded asynchronously)
@app.get("/api/nodes/{node_id}/ping")
def api_node_ping(node_id: str):
    node = node_store.get_node(node_id)
    if not node:
        return JSONResponse({"ok": False, "msg": "Node not found"})
    ok, msg = node_ssh.test_connection(node)
    return JSONResponse({"ok": ok, "msg": msg})


@app.get("/api/nodes/{node_id}/status")
def api_node_status(node_id: str):
    node = node_store.get_node(node_id)
    if not node:
        return JSONResponse({"error": "Node not found"})
    return JSONResponse(node_ssh.get_status(node))


@app.get("/api/nodes/{node_id}/sites")
def api_node_sites(node_id: str):
    node = node_store.get_node(node_id)
    if not node:
        return JSONResponse({"error": "Node not found"})
    return JSONResponse(node_ssh.list_sites(node))


@app.get("/api/nodes/{node_id}/stats")
def api_node_stats(node_id: str):
    node = node_store.get_node(node_id)
    if not node:
        return JSONResponse({"error": "Node not found"})
    return JSONResponse(node_ssh.get_remote_stats(node))


@app.get("/api/nodes/{node_id}/stats/debug")
def api_node_stats_debug(node_id: str):
    """Diagnostic endpoint — returns raw SSH script output for troubleshooting remote node stats."""
    node = node_store.get_node(node_id)
    if not node:
        return JSONResponse({"error": "Node not found"})
    return JSONResponse(node_ssh.get_remote_stats_debug(node))


@app.get("/api/nodes/{node_id}/logs/{log_type}")
def api_node_logs(node_id: str, log_type: str, lines: int = 100):
    node = node_store.get_node(node_id)
    if not node:
        return JSONResponse([{"raw": "Node not found", "type": log_type, "unparsed": True}])
    if log_type not in ("access", "error"):
        return JSONResponse({"error": "Unknown log type"}, status_code=400)
    return JSONResponse(node_ssh.get_remote_logs(node, log_type, min(lines, 500)))


@app.get("/api/nodes/{node_id}/traffic")
def api_node_traffic(node_id: str, lines: int = 4000):
    node = node_store.get_node(node_id)
    if not node:
        return JSONResponse({"error": "Node not found"})
    return JSONResponse(traffic.get_node_stats(node, min(lines, 8000)))


@app.get("/api/nodes/{node_id}/ssl")
def api_node_ssl(node_id: str):
    node = node_store.get_node(node_id)
    if not node:
        return JSONResponse({"error": "Node not found"})
    return JSONResponse(node_ssh.list_remote_ssl(node))


@app.get("/api/nodes/{node_id}/proxies")
def api_node_proxies(node_id: str):
    node = node_store.get_node(node_id)
    if not node:
        return JSONResponse({"error": "Node not found"})
    return JSONResponse(node_ssh.list_remote_proxies(node))


@app.post("/api/nodes/test-connection")
async def api_test_node_connection(request: Request):
    data = await request.json()
    ok, msg = node_ssh.test_connection(data)
    return JSONResponse({"ok": ok, "msg": msg})


# ── Activity Log (admin only) ──────────────────────────────────────────────────

@app.get("/activity", response_class=HTMLResponse)
async def activity_page(request: Request):
    stats = activity.get_stats()
    users = activity.get_unique_users()
    ctx = {"stats": stats, "users": users, **_flash_ctx(request)}
    response = tmpl(request, "activity.html", ctx)
    _clear_flash(response)
    return response


@app.get("/api/activity")
def api_activity(
    user: str = "",
    category: str = "",
    result: str = "",
    search: str = "",
    limit: int = 500,
):
    logs = activity.get_logs(
        limit=min(limit, 1000),
        user=user,
        category=category,
        result=result,
        search=search,
    )
    return JSONResponse(logs)


@app.post("/api/activity/clear")
async def api_activity_clear(request: Request):
    user, role = _actor(request)
    activity.clear_logs()
    activity.log(user, role, "activity.clear", detail="Activity log cleared", ip=_get_ip(request))
    return JSONResponse({"ok": True})
