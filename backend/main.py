import re
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

from backend import auth, logs, nginx, ssl_mgr, system
from backend import users as user_store

app = FastAPI(title="Nginx UI")

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

        # Users section is admin-only
        if path.startswith("/users") and role != "admin":
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


def _set_flash(response: Response, msg: str, cat: str = "info") -> None:
    # Cookies cannot contain newlines, semicolons, or other control characters.
    # Collapse them to spaces and cap length so the cookie header stays valid.
    safe = re.sub(r"[\x00-\x1f\x7f;]", " ", msg).strip()[:300]
    response.set_cookie("flash_msg", safe, max_age=5, samesite="lax")
    response.set_cookie("flash_cat", cat, max_age=5, samesite="lax")


def tmpl(request: Request, name: str, ctx: dict | None = None, status_code: int = 200):
    """Shorthand for templates.TemplateResponse with Starlette 1.x API."""
    base = {"current_user": getattr(request.state, "user", None)}
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
        response = RedirectResponse(url="/dashboard", status_code=302)
        response.set_cookie(
            "access_token",
            auth.create_token(username, role),
            httponly=True,
            samesite="lax",
        )
        return response
    return tmpl(request, "login.html", {"error": "Invalid username or password"}, status_code=401)


@app.post("/logout")
async def logout():
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
        **_flash_ctx(request),
    }
    response = tmpl(request, "dashboard.html", ctx)
    _clear_flash(response)
    return response


# ── Config Manager ────────────────────────────────────────────────────────────

@app.get("/configs", response_class=HTMLResponse)
async def list_configs(request: Request):
    ctx = {"sites": nginx.list_sites(), **_flash_ctx(request)}
    response = tmpl(request, "configs.html", ctx)
    _clear_flash(response)
    return response


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
    if not ok:
        return tmpl(request, "editor.html", {
            "mode": "new",
            "name": name,
            "content": content,
            "error": output,
            "output": "",
            "flash_msg": "",
            "flash_cat": "",
        })

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
    return tmpl(request, "editor.html", {
        "mode": "edit",
        "name": name,
        "content": content,
        "error": "" if ok else output,
        "output": output if ok else "",
        "flash_msg": "",
        "flash_cat": "",
    })


@app.post("/configs/{name}/delete")
async def delete_config_route(name: str):
    nginx.delete_config(name)
    response = RedirectResponse(url="/configs", status_code=302)
    _set_flash(response, f"Config '{name}' deleted", "info")
    return response


@app.post("/configs/{name}/enable")
async def enable_site_route(name: str):
    ok, output = nginx.enable_site(name)
    response = RedirectResponse(url="/configs", status_code=302)
    _set_flash(response, f"Enabled '{name}'" if ok else output, "success" if ok else "error")
    return response


@app.post("/configs/{name}/disable")
async def disable_site_route(name: str):
    ok, output = nginx.disable_site(name)
    response = RedirectResponse(url="/configs", status_code=302)
    _set_flash(response, f"Disabled '{name}'" if ok else output, "success" if ok else "error")
    return response


# ── Nginx Controls ────────────────────────────────────────────────────────────

@app.post("/nginx/reload")
async def reload_nginx_route():
    ok, output = nginx.reload_nginx()
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


@app.get("/api/logs/{log_type}")
async def api_get_logs(log_type: str, lines: int = 100):
    if log_type == "access":
        return JSONResponse(logs.get_access_log_json(lines))
    elif log_type == "error":
        return JSONResponse(logs.get_error_log_json(lines))
    else:
        return JSONResponse({"error": "Unknown log type"}, status_code=400)


# ── Logs Page ─────────────────────────────────────────────────────────────────

@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    return tmpl(request, "logs.html", {"flash_msg": "", "flash_cat": ""})


# ── About ─────────────────────────────────────────────────────────────────────

@app.get("/about", response_class=HTMLResponse)
async def about_page(request: Request):
    return tmpl(request, "about.html")


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
async def delete_ssl_route(name: str):
    ok, msg = ssl_mgr.delete_ssl_file(name)
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
    response = RedirectResponse(url="/users", status_code=302)
    _set_flash(response, msg, "success" if ok else "error")
    return response
