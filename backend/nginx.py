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


def _materialize_if_symlink(name: str) -> None:
    """Self-heal a legacy sites-enabled/<name> symlink (from the old
    available-symlinked-into-enabled model) into a real file living directly
    in sites-enabled, and drop the now-redundant sites-available copy.

    Editing now always happens directly on whatever file nginx actually
    loads, so a symlink here (working or broken) is legacy state that would
    otherwise let content silently diverge between the two directories — the
    exact drift that used to require a manual `ln -sf` to fix.
    """
    enabled_path = _safe_path(SITES_ENABLED, name)
    if enabled_path is None or not enabled_path.is_symlink():
        return
    try:
        if enabled_path.exists():
            content = enabled_path.read_text()
            enabled_path.unlink()
            enabled_path.write_text(content)
        else:
            enabled_path.unlink(missing_ok=True)
    except Exception:
        return
    available_path = _safe_path(SITES_AVAILABLE, name)
    if available_path is not None and available_path.is_file():
        try:
            available_path.unlink()
        except Exception:
            pass


def _migrate_all_legacy_symlinks() -> None:
    try:
        for entry in list(SITES_ENABLED.iterdir()):
            if entry.is_symlink():
                _materialize_if_symlink(entry.name)
    except (PermissionError, FileNotFoundError):
        pass


def _locate(name: str) -> Optional[Path]:
    """Return the path where <name> currently lives.

    sites-enabled (live) takes precedence over sites-available (archived);
    returns None if the config doesn't exist in either.
    """
    _materialize_if_symlink(name)
    enabled_path = _safe_path(SITES_ENABLED, name)
    if enabled_path is not None and enabled_path.is_file():
        return enabled_path
    available_path = _safe_path(SITES_AVAILABLE, name)
    if available_path is not None and available_path.is_file():
        return available_path
    return None


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
    """Join `base / name`, rejecting anything that could escape `base`.

    Deliberately does NOT resolve() the joined path: entries under
    sites-enabled are meant to be symlinks pointing outside `base` (into
    sites-available), and resolving would follow the symlink and reject a
    perfectly valid, already-enabled site as "escaping" the directory.
    Traversal is instead blocked by rejecting any path separator in `name`.
    """
    if not name or name in (".", "..") or "/" in name or "\\" in name:
        return None
    try:
        base_resolved = base.resolve()
    except OSError:
        return None
    return base_resolved / name


# ── Public API ────────────────────────────────────────────────────────────────

def is_enabled(name: str) -> bool:
    """True if <name> currently lives in sites-enabled (live), False if it's
    archived in sites-available or doesn't exist at all."""
    path = _locate(name)
    if path is None:
        return False
    try:
        return path.parent == SITES_ENABLED.resolve()
    except OSError:
        return False


def list_sites() -> list[dict]:
    """List every config, merged from both directories.

    sites-enabled holds the live configs nginx actually loads — editing acts
    on these files directly. sites-available is just an archive of disabled
    configs, populated only when a site is disabled. A name present in both
    (e.g. a leftover archived duplicate of a live site) is reported once, as
    enabled — the live copy always wins.
    """
    _migrate_all_legacy_symlinks()
    sites: dict[str, dict] = {}
    try:
        for entry in sorted(SITES_AVAILABLE.iterdir()):
            if entry.is_file():
                sites[entry.name] = {"name": entry.name, "enabled": False, "size": entry.stat().st_size}
    except (PermissionError, FileNotFoundError):
        pass
    try:
        for entry in sorted(SITES_ENABLED.iterdir()):
            if entry.is_file():
                sites[entry.name] = {"name": entry.name, "enabled": True, "size": entry.stat().st_size}
    except (PermissionError, FileNotFoundError):
        pass
    return [sites[name] for name in sorted(sites)]


def get_config(name: str) -> Optional[str]:
    path = _locate(name)
    if path is None:
        return None
    try:
        return path.read_text()
    except (PermissionError, OSError):
        return None


def save_config(name: str, content: str) -> tuple[bool, str]:
    path = _locate(name)
    is_new = path is None
    if is_new:
        # Brand-new configs are created directly in sites-enabled — live immediately.
        path = _safe_path(SITES_ENABLED, name)
        if path is None:
            return False, "Invalid config name"

    old_content: Optional[str] = None
    if not is_new:
        try:
            old_content = path.read_text()
        except Exception:
            pass

    try:
        path.write_text(content)
    except PermissionError:
        return False, "Permission denied writing config."

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
    path = _locate(name)
    if path is None:
        return False, "Config not found"
    try:
        path.unlink()
        return True, f"Deleted {name}"
    except PermissionError:
        return False, "Permission denied"


def enable_site(name: str) -> tuple[bool, str]:
    """Move <name> from sites-available (archived) into sites-enabled (live)."""
    _materialize_if_symlink(name)
    enabled_path = _safe_path(SITES_ENABLED, name)
    available_path = _safe_path(SITES_AVAILABLE, name)
    if enabled_path is None or available_path is None:
        return False, "Invalid config name"
    if enabled_path.is_file():
        return False, "Site is already enabled"
    if not available_path.is_file():
        return False, "Config not found in sites-available"

    try:
        content = available_path.read_text()
    except Exception as e:
        return False, f"Could not read archived config: {e}"

    try:
        enabled_path.write_text(content)
        available_path.unlink()
    except PermissionError:
        return False, "Permission denied enabling site."

    ok, output = _nginx(["-t"])
    if not ok:
        try:
            enabled_path.unlink(missing_ok=True)
            available_path.write_text(content)
        except Exception:
            pass
        return False, f"Enable failed — nginx -t error (reverted):\n{output}"

    return True, f"Site enabled.\n{output}"


def disable_site(name: str) -> tuple[bool, str]:
    """Move <name> from sites-enabled (live) into sites-available (archived)."""
    _materialize_if_symlink(name)
    enabled_path = _safe_path(SITES_ENABLED, name)
    available_path = _safe_path(SITES_AVAILABLE, name)
    if enabled_path is None or available_path is None:
        return False, "Invalid name"
    if not enabled_path.is_file():
        return False, "Site is not enabled"

    try:
        content = enabled_path.read_text()
    except Exception as e:
        return False, f"Could not read config: {e}"

    try:
        available_path.write_text(content)
        enabled_path.unlink()
    except PermissionError:
        return False, "Permission denied disabling site."

    ok, output = _nginx(["-t"])
    if not ok:
        try:
            available_path.unlink(missing_ok=True)
            enabled_path.write_text(content)
        except Exception:
            pass
        return False, f"Disable failed — nginx -t error (reverted):\n{output}"

    return True, f"Site disabled.\n{output}"


def reload_nginx() -> tuple[bool, str]:
    _migrate_all_legacy_symlinks()

    ok, test_out = _nginx(["-t"])
    if not ok:
        return False, f"nginx config test failed — reload aborted:\n{test_out}"

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
