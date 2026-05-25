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


def _nsenter(args: list[str]) -> str:
    try:
        r = subprocess.run(
            ["nsenter", "-t", "1", "-n", "-m", "--"] + args,
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

    i1, t1 = _stat()
    time.sleep(0.25)
    i2, t2 = _stat()
    dt = t2 - t1
    pct = round((1 - (i2 - i1) / dt) * 100, 1) if dt > 0 else 0.0

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
            m[p[0].rstrip(":")] = int(p[1])
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
    raw = (_nsenter(["cat", "/proc/net/dev"]) if _ROOT else "") or _read("/proc/net/dev")
    rx = tx = 0
    for line in raw.splitlines()[2:]:
        p = line.split()
        if len(p) >= 10 and p[0].rstrip(":") not in ("lo", ""):
            rx += int(p[1])
            tx += int(p[9])
    return {"rx_bytes": rx, "tx_bytes": tx}


def get_disk() -> dict:
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
    return {
        "cpu": get_cpu(),
        "memory": get_memory(),
        "network": get_network(),
        "disk": get_disk(),
    }
