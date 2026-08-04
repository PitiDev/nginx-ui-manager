import os
import time
import subprocess
from pathlib import Path

_ROOT = os.getuid() == 0


def _read(path: str) -> str:
    try:
        return Path(path).read_text()
    except Exception:
        return ""


def _nsenter(args: list[str], ns_flags: list[str] | None = None) -> str:
    """Run a command inside the host's namespaces via nsenter.

    Default ns_flags: ['-n', '-m'] (network + mount namespace).
    Pass custom flags like ['-m'] for mount-only (disk stats).
    """
    if ns_flags is None:
        ns_flags = ["-n", "-m"]
    try:
        r = subprocess.run(
            ["nsenter", "-t", "1"] + ns_flags + ["--"] + args,
            capture_output=True, text=True, timeout=5,
        )
        return r.stdout if r.returncode == 0 else ""
    except Exception:
        return ""


def get_cpu() -> dict:
    def _stat():
        for line in _read("/proc/stat").splitlines():
            if line.startswith("cpu "):
                v = list(map(int, line.split()[1:]))
                idle = v[3] + (v[4] if len(v) > 4 else 0)
                return idle, sum(v)
        return 0, 0

    try:
        i1, t1 = _stat()
        time.sleep(0.25)
        i2, t2 = _stat()
        dt = t2 - t1
        pct = round((1 - (i2 - i1) / dt) * 100, 1) if dt > 0 else 0.0
    except Exception:
        pct = 0.0

    load = [0.0, 0.0, 0.0]
    try:
        parts = _read("/proc/loadavg").split()
        load = [float(parts[i]) for i in range(3)]
    except Exception:
        pass

    return {"percent": pct, "load1": load[0], "load5": load[1], "load15": load[2]}


def get_memory() -> dict:
    m: dict[str, int] = {}
    for line in _read("/proc/meminfo").splitlines():
        p = line.split()
        if len(p) >= 2:
            try:
                m[p[0].rstrip(":")] = int(p[1])
            except ValueError:
                pass
    total = m.get("MemTotal", 0)
    avail = m.get("MemAvailable", 0)
    used = total - avail
    return {
        "total_mb": total // 1024,
        "used_mb": used // 1024,
        "free_mb": avail // 1024,
        "percent": round(used / total * 100, 1) if total else 0.0,
    }


def get_network() -> dict:
    # Try nsenter (network namespace only) to get HOST network stats.
    # Falls back to container /proc/net/dev if nsenter is unavailable.
    raw = ""
    if _ROOT:
        raw = _nsenter(["cat", "/proc/net/dev"], ns_flags=["-n"])
    if not raw:
        raw = _read("/proc/net/dev")
    rx = tx = 0
    for line in raw.splitlines()[2:]:
        p = line.split()
        if len(p) >= 10 and p[0].rstrip(":") not in ("lo", ""):
            try:
                rx += int(p[1])
                tx += int(p[9])
            except (ValueError, IndexError):
                pass
    return {"rx_bytes": rx, "tx_bytes": tx}


def get_disk() -> dict:
    # Try nsenter (mount namespace) to get HOST disk stats.
    # Falls back to shutil.disk_usage for non-Docker / non-root scenarios.
    if _ROOT:
        raw = _nsenter(["df", "-PB1", "/"], ns_flags=["-m"])
        if raw:
            try:
                lines = raw.strip().splitlines()
                parts = lines[-1].split()
                total = int(parts[1])
                used = int(parts[2])
                free = int(parts[3])
                if total > 0:
                    return {
                        "total_gb": round(total / 1e9, 1),
                        "used_gb": round(used / 1e9, 1),
                        "free_gb": round(free / 1e9, 1),
                        "percent": round(used / total * 100, 1),
                    }
            except Exception:
                pass
    try:
        import shutil
        total, used, free = shutil.disk_usage("/")
        return {
            "total_gb": round(total / 1e9, 1),
            "used_gb": round(used / 1e9, 1),
            "free_gb": round(free / 1e9, 1),
            "percent": round(used / total * 100, 1) if total else 0.0,
        }
    except Exception:
        return {"total_gb": 0, "used_gb": 0, "free_gb": 0, "percent": 0.0}


def get_stats() -> dict:
    try:
        return {
            "cpu": get_cpu(),
            "memory": get_memory(),
            "network": get_network(),
            "disk": get_disk(),
        }
    except Exception as e:
        return {"error": str(e)}


def get_debug_info() -> dict:
    """Verbose diagnostic info — for /api/debug/stats only."""
    info: dict = {
        "running_as_root": _ROOT,
        "uid": os.getuid(),
        "nsenter_available": False,
        "proc_stat_readable": bool(_read("/proc/stat")),
        "proc_meminfo_readable": bool(_read("/proc/meminfo")),
        "proc_net_dev_readable": bool(_read("/proc/net/dev")),
        "proc_loadavg_readable": bool(_read("/proc/loadavg")),
    }

    # Check nsenter availability
    try:
        r = subprocess.run(["nsenter", "--version"], capture_output=True, timeout=3)
        info["nsenter_available"] = r.returncode == 0 or r.returncode == 1
        info["nsenter_version"] = (r.stdout or r.stderr).decode(errors="replace").strip()[:80]
    except FileNotFoundError:
        info["nsenter_error"] = "nsenter not found (install util-linux)"
    except Exception as e:
        info["nsenter_error"] = str(e)

    # Try nsenter network
    if _ROOT:
        net_raw = _nsenter(["cat", "/proc/net/dev"], ns_flags=["-n"])
        info["nsenter_net_ok"] = bool(net_raw)
        if net_raw:
            info["nsenter_net_lines"] = len(net_raw.splitlines())

        # Try nsenter disk
        disk_raw = _nsenter(["df", "-PB1", "/"], ns_flags=["-m"])
        info["nsenter_disk_ok"] = bool(disk_raw)
        if disk_raw:
            info["nsenter_disk_output"] = disk_raw.strip()[:200]

    # Try actual stats
    try:
        info["stats"] = get_stats()
    except Exception as e:
        info["stats_error"] = str(e)

    return info
