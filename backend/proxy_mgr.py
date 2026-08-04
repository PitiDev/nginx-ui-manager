import re

from backend import nginx

_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _pick_display_name(server_names: list[str], filename: str) -> str:
    """A bare IP as server_name (common on a catch-all/default block that
    matches internal IP-only requests) isn't a useful label — prefer the
    first name that actually looks like a domain, and only fall back to a
    raw IP if there's truly no better option than the config's filename.
    """
    for name in server_names:
        if not _IP_RE.match(name):
            return name
    return filename


def _parse(text: str) -> dict:
    info: dict = {
        "server_names": [],
        "listen_ports": [],
        "ssl": False,
        "locations": [],
    }

    # server_name — collect unique names, skip catch-all "_"
    seen_names: set[str] = set()
    for m in re.finditer(r"server_name\s+([^;]+);", text):
        for part in m.group(1).split():
            if part != "_" and part not in seen_names:
                info["server_names"].append(part)
                seen_names.add(part)

    # listen ports — handle IPv6 [::]:port and plain port, strip ssl/http2 words
    seen_ports: set[str] = set()
    for m in re.finditer(r"listen\s+(?:\[::\]:)?(\d+)", text):
        port = m.group(1)
        if port not in seen_ports:
            info["listen_ports"].append(port)
            seen_ports.add(port)

    # SSL — cert directive or ssl keyword on listen line
    if re.search(r"ssl_certificate\b", text) or re.search(r"listen\s+\S*443\S*\s+ssl", text):
        info["ssl"] = True

    # Location blocks — only those with a proxy_pass directive
    for m in re.finditer(r"location\s+([^\s{]+)\s*\{([^}]*)\}", text, re.DOTALL):
        path = m.group(1).rstrip("/") or "/"
        body = m.group(2)
        pp   = re.search(r"proxy_pass\s+(https?://[^\s;]+)\s*;", body)
        if pp:
            info["locations"].append({
                "path":     path,
                "upstream": pp.group(1),
            })

    return info


def list_proxies() -> list[dict]:
    results: list[dict] = []
    for site in nginx.list_sites():
        content = nginx.get_config(site["name"]) or ""
        info = _parse(content)
        results.append({
            "name":         site["name"],
            "enabled":      site["enabled"],
            "size":         site["size"],
            "server_names": info["server_names"],
            "listen_ports": info["listen_ports"],
            "ssl":          info["ssl"],
            "locations":    info["locations"],
            "has_proxy":    len(info["locations"]) > 0,
            "display_name": _pick_display_name(info["server_names"], site["name"]),
            "content":      content,
        })
    return results
