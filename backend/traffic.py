import hashlib
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from backend.logs import get_access_log_json
from backend import proxy_mgr

BUCKET_SECONDS = 10
NUM_BUCKETS = 30  # 5 minute rolling window

_SERVER_RE = re.compile(r"\bserver\s*\{")
_SERVER_NAME_RE = re.compile(r"server_name\s+([^;]+);")
_LOCATION_RE = re.compile(r"location\s+([^\s{]+)\s*\{([^}]*)\}", re.DOTALL)
_PROXY_PASS_RE = re.compile(r"proxy_pass\s+(https?://[^\s;]+)\s*;")


def _split_server_blocks(text: str) -> list[str]:
    """Split raw nginx config text into individual top-level `server {...}`
    blocks by brace-depth counting. A regex alone can't isolate these
    because each server block contains its own nested `{}` from location
    blocks — a naive `[^}]*` match stops at the *first* closing brace.
    """
    blocks = []
    n = len(text)
    for m in _SERVER_RE.finditer(text):
        start = m.end() - 1  # position of the opening '{'
        depth = 0
        j = start
        while j < n:
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        blocks.append(text[start:j + 1])
    return blocks


def _flatten_upstreams(configs: list) -> list:
    """Turn raw site config files into a flat list of {path, target, site}
    location→proxy_pass mappings, sorted longest-path-first for nginx-style
    prefix matching. Parses *per server{} block* rather than per file —
    one file commonly bundles several `server{}` blocks for entirely
    different domains (e.g. gitlab.example.com, grafana.example.com in the
    same file), and treating the whole file as a single "site" would mislabel
    every location in it with just whichever server_name happened to be
    parsed first, or worse, silently blend unrelated domains into one.
    """
    flat = []
    for cfg in configs or []:
        if not cfg.get("enabled"):
            continue
        for block in _split_server_blocks(cfg.get("content", "")):
            server_names, seen = [], set()
            for m in _SERVER_NAME_RE.finditer(block):
                for part in m.group(1).split():
                    if part != "_" and part not in seen:
                        server_names.append(part)
                        seen.add(part)
            site = proxy_mgr._pick_display_name(server_names, cfg.get("name", ""))
            for m in _LOCATION_RE.finditer(block):
                path = m.group(1).rstrip("/") or "/"
                pp = _PROXY_PASS_RE.search(m.group(2))
                if pp:
                    flat.append({"path": path, "target": pp.group(1), "site": site})
    flat.sort(key=lambda u: len(u["path"]), reverse=True)
    return flat


def _match_candidates(path: str, flat_upstreams: list) -> list:
    """All locations that match `path` at the longest (most specific)
    prefix length. Nginx itself disambiguates same-path locations across
    multiple sites using the Host header — but the standard combined
    access-log format doesn't record Host, so from the log alone we can't
    tell which site actually handled a request when two+ sites share a
    location (most commonly a bare "/" catch-all on each). Returning every
    tied candidate lets the caller fall back to a fair split instead of
    always crediting whichever site happens to sort first.
    """
    path = path or "/"
    matches = [u for u in flat_upstreams
               if u["path"] == "/" or path == u["path"] or path.startswith(u["path"] + "/")]
    if not matches:
        return []
    best_len = max(len(u["path"]) for u in matches)
    return [u for u in matches if len(u["path"]) == best_len]


def _pick_upstream(entry: dict, candidates: list):
    """Resolve a (possibly ambiguous) match list to one upstream. Ties are
    split via a stable hash of the log line itself, so the same historical
    request always resolves the same way across polls/restarts, while
    spreading load roughly evenly across tied sites over many requests —
    rather than one site silently absorbing 100% of a shared route.
    """
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    key = entry.get("raw") or f"{entry.get('ip','')}|{entry.get('dt_iso','')}|{entry.get('path','')}"
    h = int(hashlib.md5(key.encode()).hexdigest(), 16)
    return candidates[h % len(candidates)]


def compute_stats(entries: list, proxies: list | None = None,
                   bucket_seconds: int = BUCKET_SECONDS, num_buckets: int = NUM_BUCKETS) -> dict:
    """Aggregate parsed access-log entries (see logs._parse_access) into
    live traffic-monitor stats: rate, status/method mix, top paths/IPs,
    upstream (proxy_pass) routing, a rolling request/byte time series, and
    the most recent requests.
    """
    parsed = [e for e in entries if not e.get("unparsed")]
    total = len(parsed)

    flat_upstreams = _flatten_upstreams(proxies)
    upstream_counts = Counter()
    ambiguous_targets = set()
    for e in parsed:
        candidates = _match_candidates(e.get("path", "/"), flat_upstreams)
        u = _pick_upstream(e, candidates)
        e["upstream_target"] = u["target"] if u else None
        e["upstream_path"] = u["path"] if u else None
        e["upstream_shared"] = len(candidates) > 1
        upstream_counts[u["target"] if u else None] += 1
        if len(candidates) > 1:
            ambiguous_targets.update(c["target"] for c in candidates)

    upstream_summary = []
    seen_targets = set()
    for u in flat_upstreams:
        if u["target"] in seen_targets:
            continue
        seen_targets.add(u["target"])
        upstream_summary.append({
            "target": u["target"],
            "path": u["path"],
            "site": u["site"],
            "count": upstream_counts.get(u["target"], 0),
            "ambiguous": u["target"] in ambiguous_targets,
        })

    now = datetime.now(timezone.utc)
    buckets = [{"requests": 0, "bytes": 0} for _ in range(num_buckets)]
    window_seconds = bucket_seconds * num_buckets

    for e in parsed:
        dt_iso = e.get("dt_iso")
        if not dt_iso:
            continue
        try:
            dt = datetime.fromisoformat(dt_iso)
        except ValueError:
            continue
        age = (now - dt).total_seconds()
        if age < 0 or age >= window_seconds:
            continue
        idx = num_buckets - 1 - int(age // bucket_seconds)
        if 0 <= idx < num_buckets:
            buckets[idx]["requests"] += 1
            buckets[idx]["bytes"] += e.get("bytes", 0)

    latest_bucket = buckets[-1]
    requests_per_sec = round(latest_bucket["requests"] / bucket_seconds, 2)
    bytes_per_sec = round(latest_bucket["bytes"] / bucket_seconds, 1)

    status_classes = Counter(e.get("status", 0) // 100 for e in parsed)
    status_summary = {f"{n}xx": status_classes.get(n, 0) for n in (1, 2, 3, 4, 5)}
    error_count = status_summary["4xx"] + status_summary["5xx"]
    error_rate = round(error_count / total * 100, 2) if total else 0.0

    method_counts = Counter(e.get("method", "-") for e in parsed)
    path_counts = Counter(e.get("path", "-") for e in parsed)
    ip_counts = Counter(e.get("ip", "-") for e in parsed)
    total_bytes = sum(e.get("bytes", 0) for e in parsed)

    recent = list(reversed(parsed[-25:]))

    return {
        "total_requests": total,
        "requests_per_sec": requests_per_sec,
        "bytes_per_sec": bytes_per_sec,
        "total_bytes": total_bytes,
        "error_rate": error_rate,
        "status_summary": status_summary,
        "methods": dict(method_counts.most_common(6)),
        "top_paths": [{"path": p, "count": c} for p, c in path_counts.most_common(8)],
        "top_ips": [{"ip": ip, "count": c} for ip, c in ip_counts.most_common(8)],
        "timeseries": [{"requests": b["requests"], "bytes": b["bytes"]} for b in buckets],
        "bucket_seconds": bucket_seconds,
        "recent": recent,
        "upstreams": upstream_summary,
    }


def get_local_stats(lines: int = 4000) -> dict:
    from backend import system

    stats = compute_stats(get_access_log_json(lines), proxy_mgr.list_proxies())
    try:
        stats["cpu_percent"] = system.get_cpu().get("percent", 0.0)
    except Exception:
        stats["cpu_percent"] = None
    try:
        stats["ram_percent"] = system.get_memory().get("percent", 0.0)
    except Exception:
        stats["ram_percent"] = None
    return stats


def merge_stats(named_stats: list[tuple[str, dict]],
                 bucket_seconds: int = BUCKET_SECONDS, num_buckets: int = NUM_BUCKETS) -> dict:
    """Combine per-node compute_stats() results (each tagged with a node
    display name) into one fleet-wide view: summed counters, a per-bucket
    summed time series, a node-tagged & re-sorted recent-request feed, and
    a per-node breakdown (used to drive "All Nodes" mode in the flow diagram).
    """
    total_requests = 0
    total_bytes = 0
    status_summary = {f"{n}xx": 0 for n in (1, 2, 3, 4, 5)}
    methods = Counter()
    path_counts = Counter()
    ip_counts = Counter()
    timeseries = [{"requests": 0, "bytes": 0} for _ in range(num_buckets)]
    recent_all = []
    nodes_summary = []

    for name, stats in named_stats:
        reachable = not stats.get("error")
        total_requests += stats.get("total_requests", 0)
        total_bytes += stats.get("total_bytes", 0)
        for k in status_summary:
            status_summary[k] += stats.get("status_summary", {}).get(k, 0)
        for m, c in stats.get("methods", {}).items():
            methods[m] += c
        for p in stats.get("top_paths", []):
            path_counts[p["path"]] += p["count"]
        for ip in stats.get("top_ips", []):
            ip_counts[ip["ip"]] += ip["count"]
        ts = stats.get("timeseries", [])
        for i in range(min(len(ts), num_buckets)):
            timeseries[i]["requests"] += ts[i].get("requests", 0)
            timeseries[i]["bytes"] += ts[i].get("bytes", 0)
        for e in stats.get("recent", []):
            tagged = dict(e)
            tagged["node"] = name
            recent_all.append(tagged)
        nodes_summary.append({
            "name": name,
            "total_requests": stats.get("total_requests", 0),
            "error_rate": stats.get("error_rate", 0),
            "reachable": reachable,
            # per-node site/proxy_pass breakdown — drives the Node → Proxy
            # Domain level of the fleet-wide flow diagram, instead of
            # collapsing each node down to a single opaque total.
            "upstreams": stats.get("upstreams", []),
            "cpu_percent": stats.get("cpu_percent"),
            "ram_percent": stats.get("ram_percent"),
        })

    latest = timeseries[-1] if timeseries else {"requests": 0, "bytes": 0}
    requests_per_sec = round(latest["requests"] / bucket_seconds, 2)
    bytes_per_sec = round(latest["bytes"] / bucket_seconds, 1)
    error_count = status_summary["4xx"] + status_summary["5xx"]
    error_rate = round(error_count / total_requests * 100, 2) if total_requests else 0.0

    recent_all.sort(key=lambda e: e.get("dt_iso") or "", reverse=True)

    def _fleet_avg(key):
        values = [n[key] for n in nodes_summary if n.get(key) is not None]
        return round(sum(values) / len(values), 1) if values else None

    fleet_cpu_percent = _fleet_avg("cpu_percent")
    fleet_ram_percent = _fleet_avg("ram_percent")

    return {
        "total_requests": total_requests,
        "requests_per_sec": requests_per_sec,
        "bytes_per_sec": bytes_per_sec,
        "total_bytes": total_bytes,
        "error_rate": error_rate,
        "status_summary": status_summary,
        "methods": dict(sorted(methods.items(), key=lambda kv: -kv[1])[:6]),
        "top_paths": [{"path": p, "count": c} for p, c in path_counts.most_common(8)],
        "top_ips": [{"ip": ip, "count": c} for ip, c in ip_counts.most_common(8)],
        "timeseries": timeseries,
        "bucket_seconds": bucket_seconds,
        "recent": recent_all[:25],
        "cpu_percent": fleet_cpu_percent,
        "ram_percent": fleet_ram_percent,
        "upstreams": [],
        "nodes": nodes_summary,
    }


def get_fleet_stats(lines: int = 4000) -> dict:
    """Local + every configured remote node, merged into one view."""
    from backend import node_ssh, nodes as node_store

    named = [("Local", get_local_stats(lines))]
    for node in node_store.list_nodes():
        entries = node_ssh.get_remote_logs(node, "access", lines)
        # get_remote_logs() swallows SSH/auth failures into a single
        # {"unparsed": True, "raw": <exception>} entry rather than raising —
        # detect that shape so an unreachable node doesn't read as "reachable
        # with zero traffic" in the merged fleet view.
        if len(entries) == 1 and entries[0].get("unparsed"):
            named.append((node["name"], {"error": entries[0].get("raw", "unreachable")}))
            continue
        proxies = node_ssh.list_remote_proxies(node)
        stats = compute_stats(entries, proxies)
        try:
            remote = node_ssh.get_remote_stats(node)
            stats["cpu_percent"] = remote.get("cpu", {}).get("percent")
            stats["ram_percent"] = remote.get("memory", {}).get("percent")
        except Exception:
            stats["cpu_percent"] = None
            stats["ram_percent"] = None
        named.append((node["name"], stats))
    return merge_stats(named)
