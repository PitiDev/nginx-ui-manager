import os
import subprocess
from pathlib import Path
from typing import Optional

SITES_AVAILABLE = Path(os.getenv("NGINX_SITES_AVAILABLE", "/etc/nginx/sites-available"))
SITES_ENABLED = Path(os.getenv("NGINX_SITES_ENABLED", "/etc/nginx/sites-enabled"))

# Auto-detect: if we're root inside the container we don't need sudo.
_ROOT = os.getuid() == 0

# When the container runs as root with pid:host + privileged=true, nsenter
# enters the host's namespaces so systemctl actually reaches the host's systemd
# instead of failing over D-Bus.
_USE_NSENTER = _ROOT

_SUDO_PASSWORD = os.getenv("SUDO_PASSWORD", "")


def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.returncode == 0, (result.stdout + result.stderr).strip()
    except FileNotFoundError:
        return False, f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


def _sudo(cmd: list[str]) -> tuple[bool, str]:
    """Run with sudo, using -S to pipe password if configured."""
    if _SUDO_PASSWORD:
        try:
            result = subprocess.run(
                ["sudo", "-S"] + cmd,
                input=_SUDO_PASSWORD + "\n",
                capture_output=True,
                text=True,
                timeout=30,
            )
            stderr = "\n".join(
                l for l in result.stderr.splitlines()
                if "password" not in l.lower()
            )
            return result.returncode == 0, (result.stdout + "\n" + stderr).strip()
        except Exception as e:
            return False, str(e)
    return _run(["sudo"] + cmd)


def _systemctl(args: list[str]) -> tuple[bool, str]:
    """
    Run systemctl.
    - In container (root + pid:host): use nsenter to enter host namespaces
      so the command reaches the real systemd, not the container's D-Bus stub.
    - On bare metal with a limited user: use sudo.
    """
    if _USE_NSENTER:
        return _run(
            ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "systemctl"] + args
        )
    return _sudo(["systemctl"] + args)


def _nginx(args: list[str]) -> tuple[bool, str]:
    """Run nginx commands — no nsenter needed, container nginx tests mounted configs.

    Always redirect nginx's own error log to /dev/null during -t runs so the
    read-only (or absent) /var/log/nginx mount never blocks validation.
    Real config errors still appear on stderr and are captured normally.
    """
    effective = list(args)
    if "-t" in effective and "-e" not in effective:
        effective += ["-e", "/dev/null"]
    if _ROOT:
        return _run(["nginx"] + effective)
    return _sudo(["nginx"] + effective)


def _get_uptime() -> str:
    try:
        seconds = float(Path("/proc/uptime").read_text().split()[0])
        days, rem = divmod(int(seconds), 86400)
        hours, rem = divmod(rem, 3600)
        minutes = rem // 60
        parts = []
        if days:
            parts.append(f"{days}d")
        if hours:
            parts.append(f"{hours}h")
        parts.append(f"{minutes}m")
        return "up " + " ".join(parts)
    except Exception:
        return "unknown"


def _safe_path(base: Path, name: str) -> Optional[Path]:
    try:
        resolved = (base / name).resolve()
        resolved.relative_to(base.resolve())
        return resolved
    except (ValueError, OSError):
        return None


# ── Public API ────────────────────────────────────────────────────────────────

def list_sites() -> list[dict]:
    sites = []
    try:
        for entry in sorted(SITES_AVAILABLE.iterdir()):
            if not entry.is_file():
                continue
            enabled_path = SITES_ENABLED / entry.name
            sites.append({
                "name": entry.name,
                "enabled": enabled_path.exists() or enabled_path.is_symlink(),
                "size": entry.stat().st_size,
            })
    except (PermissionError, FileNotFoundError):
        pass
    return sites


def get_config(name: str) -> Optional[str]:
    path = _safe_path(SITES_AVAILABLE, name)
    if path is None or not path.is_file():
        return None
    try:
        return path.read_text()
    except (PermissionError, OSError):
        return None


def save_config(name: str, content: str) -> tuple[bool, str]:
    path = _safe_path(SITES_AVAILABLE, name)
    if path is None:
        return False, "Invalid config name"

    is_new = not path.exists()
    old_content: Optional[str] = None
    if not is_new:
        try:
            old_content = path.read_text()
        except Exception:
            pass

    try:
        path.write_text(content)
    except PermissionError:
        return False, "Permission denied writing to sites-available."

    ok, output = _nginx(["-t"])
    if not ok:
        try:
            if is_new:
                path.unlink(missing_ok=True)
            elif old_content is not None:
                path.write_text(old_content)
        except Exception:
            pass
        return False, f"nginx -t failed (changes rolled back):\n{output}"

    return True, f"Config saved and validated.\n{output}"


def delete_config(name: str) -> tuple[bool, str]:
    path = _safe_path(SITES_AVAILABLE, name)
    if path is None or not path.exists():
        return False, "Config not found"
    disable_site(name)
    try:
        path.unlink()
        return True, f"Deleted {name}"
    except PermissionError:
        return False, "Permission denied"


def enable_site(name: str) -> tuple[bool, str]:
    src = _safe_path(SITES_AVAILABLE, name)
    dst = _safe_path(SITES_ENABLED, name)
    if src is None or dst is None:
        return False, "Invalid config name"
    if not src.exists():
        return False, "Config not found in sites-available"
    if dst.exists() or dst.is_symlink():
        return False, "Site is already enabled"

    try:
        dst.symlink_to(src)
    except PermissionError:
        return False, "Permission denied creating symlink."

    ok, output = _nginx(["-t"])
    if not ok:
        try:
            dst.unlink(missing_ok=True)
        except Exception:
            pass
        return False, f"Enable failed — nginx -t error (reverted):\n{output}"

    return True, f"Site enabled.\n{output}"


def disable_site(name: str) -> tuple[bool, str]:
    dst = _safe_path(SITES_ENABLED, name)
    if dst is None:
        return False, "Invalid name"
    if not dst.exists() and not dst.is_symlink():
        return False, "Site is not enabled"
    try:
        dst.unlink()
        return True, "Site disabled"
    except PermissionError:
        return False, "Permission denied removing symlink"


def reload_nginx() -> tuple[bool, str]:
    return _systemctl(["reload", "nginx"])


def get_nginx_status() -> dict:
    active_ok, active_out = _systemctl(["is-active", "nginx"])
    _, status_out = _systemctl(["status", "nginx", "--no-pager", "-l"])
    _, version_out = _run(["nginx", "-v"])

    return {
        "active": active_ok and active_out.strip() == "active",
        "status_text": active_out.strip() or "unknown",
        "version": version_out.strip() or "unknown",
        "uptime": _get_uptime(),
        "status_detail": status_out or "",
    }
