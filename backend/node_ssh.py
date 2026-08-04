"""SSH-based remote nginx operations using paramiko."""
import io
import shlex

try:
    import paramiko
    _AVAILABLE = True
except ImportError:
    _AVAILABLE = False


def _no_paramiko() -> tuple[bool, str]:
    return False, "paramiko is not installed — run: pip install paramiko"


def _load_key(key_str: str):
    """Auto-detect and load a private key from a PEM string."""
    for cls in (
        paramiko.RSAKey,
        paramiko.Ed25519Key,
        paramiko.ECDSAKey,
        paramiko.DSSKey,
    ):
        try:
            return cls.from_private_key(io.StringIO(key_str))
        except Exception:
            continue
    raise ValueError("Unsupported SSH key format or key is passphrase-protected")


def _connect(node: dict):
    if not _AVAILABLE:
        raise RuntimeError("paramiko not installed")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    host     = node["host"]
    port     = int(node.get("port") or 22)
    username = node.get("username") or "root"
    if node.get("auth_type") == "key" and node.get("ssh_key"):
        pkey = _load_key(node["ssh_key"])
        client.connect(host, port=port, username=username, pkey=pkey, timeout=10)
    else:
        client.connect(host, port=port, username=username,
                       password=node.get("password", ""), timeout=10)
    return client


def _exec(ssh, cmd: str) -> tuple[bool, str]:
    try:
        stdin, stdout, stderr = ssh.exec_command(cmd, timeout=20)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        rc  = stdout.channel.recv_exit_status()
        return rc == 0, (out + err).strip()
    except Exception as e:
        return False, str(e)


def _sudo(ssh, cmd: str, sudo_pass: str) -> tuple[bool, str]:
    """Run `cmd` as root via `sudo -S bash -s`, streaming the script over
    stdin so bash parses it.

    `sudo -S <cmd>` (the naive form) only works when `cmd` is a single
    literal program name — sudo execs argv[0] directly, it does not invoke a
    shell. Anything containing shell syntax (for/if/&&/;/subshells/quoting —
    e.g. the migration snippets below) fails with something like
    "sudo: for: command not found", or worse, the shell running exec_command
    swallows the syntax error and the raw script text leaks back as output.
    Piping through `bash -s` makes both simple commands and full scripts work
    the same way.
    """
    try:
        stdin, stdout, stderr = ssh.exec_command("sudo -S bash -s", timeout=20)
        payload = (sudo_pass + "\n" if sudo_pass else "") + cmd
        stdin.write(payload)
        stdin.flush()
        stdin.channel.shutdown_write()
        out = stdout.read().decode(errors="replace")
        err = stdout.channel.recv_exit_status()
        raw_err = stderr.read().decode(errors="replace")
        clean_err = "\n".join(
            l for l in raw_err.splitlines() if "password" not in l.lower()
        )
        return err == 0, (out + clean_err).strip()
    except Exception as e:
        return False, str(e)


def _run_nginx(ssh, args: str, sudo_pass: str) -> tuple[bool, str]:
    return _sudo(ssh, f"nginx {args} -e /dev/null", sudo_pass)


# ── Public API ────────────────────────────────────────────────────────────────

def test_connection(node: dict) -> tuple[bool, str]:
    if not _AVAILABLE:
        return _no_paramiko()
    try:
        ssh = _connect(node)
        ok, out = _exec(ssh, "nginx -v 2>&1 || nginx -V 2>&1 | head -1")
        ssh.close()
        if ok or "nginx" in out.lower():
            return True, out or "Connected"
        return True, "SSH connected (nginx check returned non-zero but connection works)"
    except Exception as e:
        return False, str(e)


def get_status(node: dict) -> dict:
    if not _AVAILABLE:
        return {"error": _no_paramiko()[1]}
    try:
        ssh = _connect(node)
        sudo_pass = node.get("sudo_password", "")

        _, active_out = _sudo(ssh, "systemctl is-active nginx", sudo_pass)
        active = active_out.strip() == "active"

        _, version_out = _exec(ssh, "nginx -v 2>&1")

        _, uptime_out = _exec(ssh, "cat /proc/uptime 2>/dev/null")
        uptime = "unknown"
        try:
            seconds = float(uptime_out.split()[0])
            d, rem = divmod(int(seconds), 86400)
            h, rem = divmod(rem, 3600)
            m = rem // 60
            parts = []
            if d: parts.append(f"{d}d")
            if h: parts.append(f"{h}h")
            parts.append(f"{m}m")
            uptime = "up " + " ".join(parts)
        except Exception:
            pass

        _, status_out = _sudo(ssh, "systemctl status nginx --no-pager -l 2>&1 | head -20", sudo_pass)
        ssh.close()

        return {
            "active": active,
            "status_text": active_out.strip() or "unknown",
            "version": version_out.strip() or "unknown",
            "uptime": uptime,
            "status_detail": status_out,
        }
    except Exception as e:
        return {"error": str(e)}


def _safe_name(name: str) -> str:
    return name.replace("/", "").replace("..", "")


def _migrate_shell(available_path: str, enabled_path: str) -> str:
    """Bash snippet: materialize a legacy sites-enabled symlink (from the old
    available-symlinked-into-enabled model) into a real file, and drop the
    now-redundant sites-available duplicate. No-op if enabled_path isn't a
    symlink. Mirrors the local single-node self-healing behavior."""
    ep  = shlex.quote(enabled_path)
    ap  = shlex.quote(available_path)
    tmp = shlex.quote(enabled_path + ".nginxui_tmp")
    return (
        f"if [ -L {ep} ]; then "
        f"if [ -e {ep} ]; then cp {ep} {tmp} && rm -f {ep} && mv {tmp} {ep}; "
        f"else rm -f {ep}; fi; "
        f"rm -f {ap}; "
        f"fi"
    )


def list_sites(node: dict) -> dict:
    if not _AVAILABLE:
        return {"error": _no_paramiko()[1]}
    try:
        ssh       = _connect(node)
        sudo_pass = node.get("sudo_password", "")
        sa_raw    = node.get("sites_available") or "/etc/nginx/sites-available"
        se_raw    = node.get("sites_enabled")   or "/etc/nginx/sites-enabled"
        sa        = shlex.quote(sa_raw)
        se        = shlex.quote(se_raw)

        # Self-heal any legacy available->enabled symlinks first, same as the
        # local single-node model — then list every name found in either
        # directory, with sites-enabled (live) taking precedence.
        #
        # NOTE: this loop body embeds "$f" inside double quotes (not
        # shlex.quote/_migrate_shell) so the shell loop variable actually
        # expands — shlex.quote would wrap it in single quotes and silently
        # suppress expansion.
        cmd = (
            f"for f in $(ls -1 {se} 2>/dev/null); do "
            f"  ef=\"{se_raw}/$f\"; af=\"{sa_raw}/$f\"; "
            f"  if [ -L \"$ef\" ]; then "
            f"    if [ -e \"$ef\" ]; then "
            f"      cp \"$ef\" \"$ef.nginxui_tmp\" && rm -f \"$ef\" && mv \"$ef.nginxui_tmp\" \"$ef\"; "
            f"    else "
            f"      rm -f \"$ef\"; "
            f"    fi; "
            f"    rm -f \"$af\"; "
            f"  fi; "
            f"done; "
            f"for f in $(ls -1 {sa} 2>/dev/null); do "
            f"  af=\"{sa_raw}/$f\"; "
            f"  [ -f \"$af\" ] || continue; "
            f"  [ -f \"{se_raw}/$f\" ] && continue; "
            f"  sz=$(stat -c%s \"$af\" 2>/dev/null || echo 0); "
            f"  echo \"$f|0|$sz\"; "
            f"done; "
            f"for f in $(ls -1 {se} 2>/dev/null); do "
            f"  ef=\"{se_raw}/$f\"; "
            f"  [ -f \"$ef\" ] || continue; "
            f"  sz=$(stat -c%s \"$ef\" 2>/dev/null || echo 0); "
            f"  echo \"$f|1|$sz\"; "
            f"done"
        )
        ok, out = _sudo(ssh, cmd, sudo_pass)
        ssh.close()

        # Only accept lines that look exactly like "<name>|0-or-1|<digits>" —
        # anything else (e.g. a shell error if sudo/bash misbehaves) is
        # dropped instead of leaking into the UI as a bogus site row.
        sites = []
        for line in out.splitlines():
            parts = line.split("|")
            if len(parts) == 3 and parts[1] in ("0", "1") and parts[2].isdigit() and parts[0]:
                sites.append({
                    "name":    parts[0],
                    "enabled": parts[1] == "1",
                    "size":    int(parts[2]),
                })
        if not ok and not sites:
            return {"error": out or "Failed to list sites"}
        return {"sites": sites}
    except Exception as e:
        return {"error": str(e)}


def get_config(node: dict, name: str) -> tuple[bool, str]:
    if not _AVAILABLE:
        return _no_paramiko()
    try:
        ssh       = _connect(node)
        sudo_pass = node.get("sudo_password", "")
        sa        = node.get("sites_available") or "/etc/nginx/sites-available"
        se        = node.get("sites_enabled")   or "/etc/nginx/sites-enabled"
        safe      = _safe_name(name)
        se_f      = se + "/" + safe
        sa_f      = sa + "/" + safe

        _sudo(ssh, _migrate_shell(sa_f, se_f), sudo_pass)

        ok, out = _exec(ssh, f"cat {shlex.quote(se_f)} 2>/dev/null || cat {shlex.quote(sa_f)} 2>/dev/null")
        ssh.close()
        return ok, out
    except Exception as e:
        return False, str(e)


def save_config(node: dict, name: str, content: str) -> tuple[bool, str]:
    if not _AVAILABLE:
        return _no_paramiko()
    try:
        ssh       = _connect(node)
        sudo_pass = node.get("sudo_password", "")
        sa        = node.get("sites_available") or "/etc/nginx/sites-available"
        se        = node.get("sites_enabled")   or "/etc/nginx/sites-enabled"
        safe      = _safe_name(name)
        se_f      = se + "/" + safe
        sa_f      = sa + "/" + safe
        tmp       = f"/tmp/nginx_ui_{safe}"

        _sudo(ssh, _migrate_shell(sa_f, se_f), sudo_pass)

        # Edit wherever the config currently lives — sites-enabled (live) if
        # present, else sites-available (archived); brand-new configs are
        # created directly in sites-enabled (live immediately).
        _, loc_out = _exec(
            ssh,
            f"if [ -f {shlex.quote(se_f)} ]; then echo enabled; "
            f"elif [ -f {shlex.quote(sa_f)} ]; then echo available; "
            f"else echo new; fi",
        )
        dest = sa_f if loc_out.strip() == "available" else se_f

        # Write via SFTP to temp path
        sftp = ssh.open_sftp()
        with sftp.open(tmp, "w") as f:
            f.write(content)
        sftp.close()

        ok, out = _sudo(ssh, f"mv {shlex.quote(tmp)} {shlex.quote(dest)}", sudo_pass)
        if not ok:
            ssh.close()
            return False, f"Failed to write config: {out}"

        # Validate
        ok, test_out = _run_nginx(ssh, "-t", sudo_pass)
        if not ok:
            _sudo(ssh, f"rm -f {shlex.quote(dest)}", sudo_pass)
            ssh.close()
            return False, f"nginx -t failed (rolled back):\n{test_out}"

        ssh.close()
        return True, f"Config saved and validated.\n{test_out}"
    except Exception as e:
        return False, str(e)


def enable_site(node: dict, name: str) -> tuple[bool, str]:
    """Move <name> from sites-available (archived) into sites-enabled (live)."""
    if not _AVAILABLE:
        return _no_paramiko()
    try:
        ssh       = _connect(node)
        sudo_pass = node.get("sudo_password", "")
        sa        = node.get("sites_available") or "/etc/nginx/sites-available"
        se        = node.get("sites_enabled")   or "/etc/nginx/sites-enabled"
        safe      = _safe_name(name)
        src       = sa + "/" + safe   # archived
        dst       = se + "/" + safe   # live

        _sudo(ssh, _migrate_shell(src, dst), sudo_pass)

        _, check_out = _exec(ssh, f"[ -f {shlex.quote(dst)} ] && echo yes || echo no")
        if check_out.strip() == "yes":
            ssh.close()
            return False, "Site is already enabled"

        ok, out = _sudo(ssh, f"mv {shlex.quote(src)} {shlex.quote(dst)}", sudo_pass)
        if not ok:
            ssh.close()
            return False, f"Failed to enable site: {out}"

        ok, test_out = _run_nginx(ssh, "-t", sudo_pass)
        if not ok:
            _sudo(ssh, f"mv {shlex.quote(dst)} {shlex.quote(src)}", sudo_pass)
            ssh.close()
            return False, f"Enable failed — nginx -t error (reverted):\n{test_out}"

        ssh.close()
        return True, f"Site enabled.\n{test_out}"
    except Exception as e:
        return False, str(e)


def disable_site(node: dict, name: str) -> tuple[bool, str]:
    """Move <name> from sites-enabled (live) into sites-available (archived)."""
    if not _AVAILABLE:
        return _no_paramiko()
    try:
        ssh       = _connect(node)
        sudo_pass = node.get("sudo_password", "")
        sa        = node.get("sites_available") or "/etc/nginx/sites-available"
        se        = node.get("sites_enabled")   or "/etc/nginx/sites-enabled"
        safe      = _safe_name(name)
        src       = se + "/" + safe   # live
        dst       = sa + "/" + safe   # archived

        _sudo(ssh, _migrate_shell(dst, src), sudo_pass)

        _, check_out = _exec(ssh, f"[ -f {shlex.quote(src)} ] && echo yes || echo no")
        if check_out.strip() != "yes":
            ssh.close()
            return False, "Site is not enabled"

        ok, out = _sudo(ssh, f"mv {shlex.quote(src)} {shlex.quote(dst)}", sudo_pass)
        if not ok:
            ssh.close()
            return False, f"Failed to disable site: {out}"

        ok, test_out = _run_nginx(ssh, "-t", sudo_pass)
        if not ok:
            _sudo(ssh, f"mv {shlex.quote(dst)} {shlex.quote(src)}", sudo_pass)
            ssh.close()
            return False, f"Disable failed — nginx -t error (reverted):\n{test_out}"

        ssh.close()
        return True, f"Site disabled.\n{test_out}"
    except Exception as e:
        return False, str(e)


def is_enabled(node: dict, name: str) -> bool:
    """True if <name> currently lives in the node's sites-enabled (live)."""
    if not _AVAILABLE:
        return False
    try:
        ssh  = _connect(node)
        se_f = (node.get("sites_enabled") or "/etc/nginx/sites-enabled") + "/" + _safe_name(name)
        _, out = _exec(ssh, f"[ -f {shlex.quote(se_f)} ] && echo yes || echo no")
        ssh.close()
        return out.strip() == "yes"
    except Exception:
        return False


def reload_nginx(node: dict) -> tuple[bool, str]:
    if not _AVAILABLE:
        return _no_paramiko()
    try:
        ssh       = _connect(node)
        sudo_pass = node.get("sudo_password", "")

        ok, test_out = _run_nginx(ssh, "-t", sudo_pass)
        if not ok:
            ssh.close()
            return False, f"nginx -t failed — reload aborted:\n{test_out}"

        ok, out = _sudo(ssh, "systemctl reload nginx", sudo_pass)
        ssh.close()
        return ok, out or "Nginx reloaded"
    except Exception as e:
        return False, str(e)


# ── Remote log parsing ────────────────────────────────────────────────────────

import re as _re
from datetime import datetime as _dt

_ACCESS_RE = _re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<dt>[^\]]+)\] '
    r'"(?P<req>[^"]*)" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)
_ERROR_RE = _re.compile(
    r'(?P<dt>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] '
    r'\d+#\d+: (?P<msg>.*)'
)


def _parse_access_line(line: str) -> dict:
    m = _ACCESS_RE.match(line)
    if not m:
        return {"raw": line, "type": "access", "unparsed": True}
    d = m.groupdict()
    parts = (d["req"] or "").split(None, 2)
    try:
        bytes_v = int(d["bytes"])
    except (TypeError, ValueError):
        bytes_v = 0
    try:
        dt_iso = _dt.strptime(d["dt"], "%d/%b/%Y:%H:%M:%S %z").isoformat()
    except Exception:
        dt_iso = ""
    return {
        "raw": line, "type": "access",
        "ip": d["ip"], "dt_raw": d["dt"], "dt_iso": dt_iso,
        "method": parts[0] if parts else "-",
        "path": parts[1] if len(parts) > 1 else "-",
        "status": int(d["status"]), "bytes": bytes_v,
        "ua": d.get("ua") or "-", "referer": d.get("referer") or "-",
    }


def _parse_error_line(line: str) -> dict:
    m = _ERROR_RE.match(line)
    if not m:
        return {"raw": line, "type": "error", "unparsed": True}
    d = m.groupdict()
    try:
        dt_iso = _dt.strptime(d["dt"], "%Y/%m/%d %H:%M:%S").isoformat()
    except Exception:
        dt_iso = ""
    return {
        "raw": line, "type": "error",
        "dt_raw": d["dt"], "dt_iso": dt_iso,
        "level": d["level"].lower(),
        "message": d["msg"],
    }


def get_remote_logs(node: dict, log_type: str, lines: int = 100) -> list:
    """Fetch and parse nginx access/error log from a remote node via SSH."""
    if not _AVAILABLE:
        return [{"raw": _no_paramiko()[1], "type": log_type, "unparsed": True}]
    try:
        ssh = _connect(node)
        if log_type == "access":
            log_path = node.get("access_log") or "/var/log/nginx/access.log"
        else:
            log_path = node.get("error_log") or "/var/log/nginx/error.log"
        sudo_pass = node.get("sudo_password", "")
        _, out = _sudo(ssh, f"tail -n {int(lines)} {shlex.quote(log_path)}", sudo_pass)
        ssh.close()
        parser = _parse_access_line if log_type == "access" else _parse_error_line
        return [parser(ln) for ln in out.splitlines() if ln.strip()]
    except Exception as e:
        return [{"raw": str(e), "type": log_type, "unparsed": True}]


def list_remote_ssl(node: dict) -> list:
    """List SSL cert/key files from common paths on a remote node."""
    if not _AVAILABLE:
        return []
    try:
        ssh = _connect(node)
        cmd = (
            r"find /etc/ssl/private /etc/nginx/ssl /etc/nginx/certs "
            r"/etc/letsencrypt/live -maxdepth 3 -type f "
            r"\( -name '*.crt' -o -name '*.key' -o -name '*.pem' "
            r"-o -name '*.cer' -o -name '*.ca-bundle' \) 2>/dev/null | "
            r"while read f; do echo \"$f|$(stat -c%s \"$f\" 2>/dev/null || echo 0)\"; done"
        )
        _, out = _exec(ssh, cmd)
        ssh.close()
        files = []
        _ext_map = {
            "key": "Private Key", "crt": "Certificate", "cer": "Certificate",
            "pem": "PEM", "ca-bundle": "CA Bundle",
        }
        for line in out.splitlines():
            parts = line.split("|")
            if len(parts) < 2:
                continue
            path = parts[0].strip()
            try:
                size = int(parts[1].strip())
            except ValueError:
                size = 0
            ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
            files.append({
                "name": path.rsplit("/", 1)[-1],
                "path": path,
                "size": size,
                "type": _ext_map.get(ext, "Other"),
            })
        return files
    except Exception:
        return []


# ── Remote proxy config parsing ────────────────────────────────────────────────

_P_SN   = _re.compile(r"server_name\s+([^;]+);")
_P_LP   = _re.compile(r"listen\s+(?:\[::\]:)?(\d+)")
_P_SSL  = _re.compile(r"ssl_certificate\b|listen\s+\S*443\S*\s+ssl")
_P_LOC  = _re.compile(r"location\s+([^\s{]+)\s*\{([^}]*)\}", _re.DOTALL)
_P_PASS = _re.compile(r"proxy_pass\s+(https?://[^\s;]+)\s*;")
_P_IP   = _re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _pick_display_name(server_names: list[str], filename: str) -> str:
    """Prefer a domain-looking server_name over a bare IP (common on a
    catch-all/default block) — see proxy_mgr._pick_display_name."""
    for name in server_names:
        if not _P_IP.match(name):
            return name
    return filename


def _parse_proxy_text(name: str, content: str, enabled: bool) -> dict:
    server_names: list[str] = []
    seen: set[str] = set()
    for m in _P_SN.finditer(content):
        for part in m.group(1).split():
            if part != "_" and part not in seen:
                server_names.append(part); seen.add(part)
    listen_ports: list[str] = []
    seen_p: set[str] = set()
    for m in _P_LP.finditer(content):
        p = m.group(1)
        if p not in seen_p:
            listen_ports.append(p); seen_p.add(p)
    ssl = bool(_P_SSL.search(content))
    locations = []
    for m in _P_LOC.finditer(content):
        pp = _P_PASS.search(m.group(2))
        if pp:
            locations.append({"path": m.group(1).rstrip("/") or "/", "upstream": pp.group(1)})
    return {
        "name": name, "enabled": enabled,
        "size": len(content.encode()),
        "server_names": server_names, "listen_ports": listen_ports,
        "ssl": ssl, "locations": locations,
        "has_proxy": bool(locations),
        "display_name": _pick_display_name(server_names, name),
        "content": content,
    }


def list_remote_proxies(node: dict) -> list:
    """List and parse nginx proxy configs from a remote node's sites-enabled
    (live) and sites-available (archived) directories."""
    if not _AVAILABLE:
        return []
    try:
        ssh = _connect(node)
        sa_raw = node.get("sites_available") or "/etc/nginx/sites-available"
        se_raw = node.get("sites_enabled")   or "/etc/nginx/sites-enabled"
        sa = shlex.quote(sa_raw)
        se = shlex.quote(se_raw)
        cmd = (
            f"for f in $(ls -1 {sa} 2>/dev/null); do "
            f"  [ -f \"{sa_raw}/$f\" ] || continue; "
            f"  [ -f \"{se_raw}/$f\" ] && continue; "
            f"  echo \"$f|0\"; "
            f"done; "
            f"for f in $(ls -1 {se} 2>/dev/null); do "
            f"  [ -f \"{se_raw}/$f\" ] || continue; "
            f"  echo \"$f|1\"; "
            f"done"
        )
        _, out = _exec(ssh, cmd)
        result = []
        for line in out.splitlines():
            parts = line.split("|")
            if len(parts) != 2 or parts[1] not in ("0", "1") or not parts[0].strip():
                continue
            name = parts[0].strip()
            enabled = parts[1].strip() == "1"
            path = (se_raw if enabled else sa_raw) + "/" + name
            ok, content = _exec(ssh, f"cat {shlex.quote(path)}")
            if ok or content:
                result.append(_parse_proxy_text(name, content, enabled))
        ssh.close()
        return result
    except Exception:
        return []


def create_remote_backup(node: dict, note: str = "") -> tuple[bool, str]:
    """Backup a remote node's sites-enabled and sites-available directories
    via SFTP and store the archive locally."""
    if not _AVAILABLE:
        return _no_paramiko()
    import io
    import os
    import re as re2
    import tarfile
    from datetime import datetime
    from pathlib import Path

    try:
        ssh  = _connect(node)
        sa   = node.get("sites_available") or "/etc/nginx/sites-available"
        se   = node.get("sites_enabled")   or "/etc/nginx/sites-enabled"
        node_name = node.get("name", "remote")

        ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = re2.sub(r"[^\w]", "_", node_name)[:20]
        safe_note = re2.sub(r"[^\w]", "_", note.strip())[:20] if note.strip() else ""
        note_part = f"remote_{safe_name}" + (f"_{safe_note}" if safe_note else "")
        filename  = f"backup_{ts}_note_{note_part}.tar.gz"

        DATA_DIR   = Path(os.getenv("DATA_DIR", "/data"))
        BACKUP_DIR = DATA_DIR / "backups"
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        dest_path  = BACKUP_DIR / filename

        sftp    = ssh.open_sftp()
        count   = 0
        with tarfile.open(dest_path, "w:gz") as tar:
            for label, directory in (("sites-available", sa), ("sites-enabled", se)):
                _, out = _exec(ssh, f"ls -1 {shlex.quote(directory)} 2>/dev/null")
                filenames = [f.strip() for f in out.splitlines() if f.strip()]
                for fname in filenames:
                    fpath = directory + "/" + fname
                    try:
                        buf = io.BytesIO()
                        sftp.getfo(fpath, buf)
                        buf.seek(0)
                        ti      = tarfile.TarInfo(name=f"{label}/{fname}")
                        ti.size = len(buf.getvalue())
                        buf.seek(0)
                        tar.addfile(ti, buf)
                        count += 1
                    except Exception:
                        pass
        sftp.close()
        ssh.close()
        return True, f"Remote backup created: {filename} ({count} config file(s))"
    except Exception as e:
        return False, str(e)


def get_remote_stats_debug(node: dict) -> dict:
    """Return raw SSH output + parsed stats in a single SSH session (for debugging)."""
    if not _AVAILABLE:
        return {"error": _no_paramiko()[1]}
    try:
        ssh = _connect(node)
        script = (
            "echo '---CPU1---'; head -1 /proc/stat; "
            "sleep 1; "
            "echo '---CPU2---'; head -1 /proc/stat; "
            "echo '---LOAD---'; cat /proc/loadavg; "
            "echo '---MEM---'; cat /proc/meminfo; "
            "echo '---DISK---'; df -PB1 / 2>/dev/null | tail -1; "
            "echo '---NET---'; cat /proc/net/dev"
        )
        ok, out = _exec(ssh, script)

        # Parse sections
        sections: dict[str, list[str]] = {}
        current: str | None = None
        for line in out.splitlines():
            if line.startswith("---") and line.endswith("---"):
                current = line.strip("-")
                sections.setdefault(current, [])
            elif current is not None:
                sections[current].append(line)

        # Summarize sections for easy reading
        section_summary = {k: v[:3] for k, v in sections.items()}

        ssh.close()
        return {
            "ssh_ok": ok,
            "raw_length": len(out),
            "raw_output": out[:2000],
            "sections_found": list(sections.keys()),
            "section_preview": section_summary,
            "node_host": node.get("host"),
            "node_user": node.get("username"),
        }
    except Exception as e:
        return {
            "error": str(e),
            "node_host": node.get("host"),
            "node_user": node.get("username"),
        }


def get_remote_stats(node: dict) -> dict:
    """Gather CPU/RAM/Disk/Network metrics from a remote node via a single SSH session."""
    if not _AVAILABLE:
        return {"error": _no_paramiko()[1]}
    try:
        ssh = _connect(node)
        # Single round-trip: gather all /proc files + df, with a 1-second CPU sample window.
        # Use ';' (not '&&') so every section always runs even if one command fails.
        # Use 'df -PB1' — the -P (POSIX) flag guarantees no line-wrapping regardless of
        # how long the filesystem name is (fixes LVM/mapper devices on Ubuntu).
        script = (
            "echo '---CPU1---'; head -1 /proc/stat; "
            "sleep 1; "
            "echo '---CPU2---'; head -1 /proc/stat; "
            "echo '---LOAD---'; cat /proc/loadavg; "
            "echo '---MEM---'; cat /proc/meminfo; "
            "echo '---DISK---'; df -PB1 / 2>/dev/null | tail -1; "
            "echo '---NET---'; cat /proc/net/dev"
        )
        _, out = _exec(ssh, script)
        ssh.close()

        # Parse into named sections
        sections: dict[str, list[str]] = {}
        current: str | None = None
        for line in out.splitlines():
            if line.startswith("---") and line.endswith("---"):
                current = line.strip("-")
                sections.setdefault(current, [])
            elif current is not None:
                sections[current].append(line)

        def _lines(key: str) -> list[str]:
            return sections.get(key, [])

        # ── CPU ──────────────────────────────────────────────────────────────
        cpu_pct = 0.0
        load1   = 0.0
        try:
            v1 = list(map(int, " ".join(_lines("CPU1")).split()[1:]))
            v2 = list(map(int, " ".join(_lines("CPU2")).split()[1:]))
            i1 = v1[3] + (v1[4] if len(v1) > 4 else 0)
            i2 = v2[3] + (v2[4] if len(v2) > 4 else 0)
            dt = sum(v2) - sum(v1)
            cpu_pct = round((1 - (i2 - i1) / dt) * 100, 1) if dt > 0 else 0.0
        except Exception:
            pass
        try:
            load1 = float(" ".join(_lines("LOAD")).split()[0])
        except Exception:
            pass

        # ── Memory ───────────────────────────────────────────────────────────
        mem: dict[str, int] = {}
        for ln in _lines("MEM"):
            p = ln.split()
            if len(p) >= 2:
                try:
                    mem[p[0].rstrip(":")] = int(p[1])
                except ValueError:
                    pass
        total_mem = mem.get("MemTotal", 0)
        avail_mem = mem.get("MemAvailable", 0)
        used_mem  = total_mem - avail_mem

        # ── Disk ─────────────────────────────────────────────────────────────
        total_disk = used_disk = free_disk = 0
        try:
            dp = " ".join(_lines("DISK")).split()
            total_disk = int(dp[1])
            used_disk  = int(dp[2])
            free_disk  = int(dp[3])
        except Exception:
            pass

        # ── Network ──────────────────────────────────────────────────────────
        rx = tx = 0
        for ln in _lines("NET")[2:]:
            p = ln.split()
            if len(p) >= 10 and p[0].rstrip(":") not in ("lo", ""):
                try:
                    rx += int(p[1])
                    tx += int(p[9])
                except (ValueError, IndexError):
                    pass

        return {
            "cpu":    {"percent": cpu_pct, "load1": load1, "load5": 0.0, "load15": 0.0},
            "memory": {
                "total_mb": total_mem // 1024,
                "used_mb":  used_mem  // 1024,
                "free_mb":  avail_mem // 1024,
                "percent":  round(used_mem / total_mem * 100, 1) if total_mem else 0.0,
            },
            "disk": {
                "total_gb": round(total_disk / 1e9, 1),
                "used_gb":  round(used_disk  / 1e9, 1),
                "free_gb":  round(free_disk  / 1e9, 1),
                "percent":  round(used_disk / total_disk * 100, 1) if total_disk else 0.0,
            },
            "network": {"rx_bytes": rx, "tx_bytes": tx},
        }
    except Exception as e:
        return {"error": str(e)}
