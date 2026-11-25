"""Run a full scan over a validated target list. Shared by the CLI and the web UI."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Callable

from .checks import SENSITIVE_PATHS, scan_target
from .net import TOOL_NAME, TOOL_VERSION, AuditClient, PoliteGate, ScanCancelled, build_user_agent
from .report import summarize
from .scope import Target

MAX_CONCURRENT = 2
MIN_INTERVAL = 0.5
TIMEOUT = 10.0
REQUESTS_PER_HOST = 3 + len(SENSITIVE_PATHS)  # TLS, http redirect, landing page, probes

# on_progress(event, target, record_or_error) with event in {"start", "done", "error"}
ProgressFn = Callable[[str, Target, object], None]


def estimate(host_count: int) -> dict:
    n = REQUESTS_PER_HOST * host_count
    return {"requests": n, "min_seconds": round(n * MIN_INTERVAL)}


def run_scan(targets: list[Target], *, expiry_days: int = 30, contact: str | None = None,
             source: str = "authorized_domains.txt", on_progress: ProgressFn | None = None,
             cancel_event: threading.Event | None = None) -> dict:
    """Scan every target and return the report dict. Raises ScanCancelled if cancelled."""
    notify = on_progress or (lambda *a: None)
    ua = build_user_agent(contact)
    gate = PoliteGate(MAX_CONCURRENT, MIN_INTERVAL, cancel_event)
    client = AuditClient(gate, ua, TIMEOUT, allowed_hosts={t.host for t in targets})

    def work(t: Target) -> dict:
        notify("start", t, None)
        return scan_target(t, client, expiry_days)

    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    results: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT) as pool:
        futures = {pool.submit(work, t): t for t in targets}
        try:
            for fut in as_completed(futures):
                t = futures[fut]
                try:
                    rec = fut.result()
                except ScanCancelled:
                    raise
                except Exception as e:  # one host must never abort the whole run
                    notify("error", t, f"{type(e).__name__}: {e}")
                    continue
                results[t.label] = rec
                notify("done", t, rec)
        except ScanCancelled:
            for f in futures:
                f.cancel()
            raise
    if cancel_event is not None and cancel_event.is_set():
        raise ScanCancelled()

    domains = [results[t.label] for t in targets if t.label in results]
    return {
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION, "user_agent": ua},
        "generated_at": started.isoformat(timespec="seconds"),
        "duration_seconds": round(time.monotonic() - t0, 1),
        "request_count": gate.request_count,
        "scope": {"source": source, "hosts": [t.label for t in targets]},
        "limits": {"max_concurrent": MAX_CONCURRENT, "min_interval_ms": int(MIN_INTERVAL * 1000),
                   "timeout_seconds": TIMEOUT, "cert_expiry_warning_days": expiry_days},
        "summary": summarize(domains),
        "domains": domains,
    }
