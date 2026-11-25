"""Command-line interface. Run via `python3 audit.py` (see README)."""

import argparse
import sys
from datetime import datetime
from pathlib import Path

from .net import TOOL_NAME, TOOL_VERSION, build_user_agent
from .report import write_reports
from .runner import MAX_CONCURRENT, MIN_INTERVAL, TIMEOUT, estimate, run_scan
from .scope import ScopeError, load_targets

COLORS = {"CRITICAL": "\033[31m", "MEDIUM": "\033[33m", "LOW": "\033[34m", "PASS": "\033[32m"}
RESET = "\033[0m"


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="audit.py",
        description="Non-destructive security audit of organization-owned domains.",
        epilog="Only scan hosts your organization owns or has written authorization to test.",
    )
    p.add_argument("-d", "--domains", type=Path, default=Path("authorized_domains.txt"),
                   help="authorized target list, one host per line (default: ./authorized_domains.txt)")
    p.add_argument("-o", "--output", type=Path, default=Path("reports"),
                   help="report directory (default: ./reports)")
    p.add_argument("--expiry-days", type=int, default=30,
                   help="warn when the certificate expires within N days (default: 30)")
    p.add_argument("--contact", default=None,
                   help="contact (team mailbox or ticket ref) appended to the User-Agent so server owners can reach you")
    p.add_argument("--dry-run", action="store_true", help="validate scope and print the plan without sending traffic")
    p.add_argument("--fail-on-critical", action="store_true",
                   help="exit with status 2 if any CRITICAL finding is present (for CI / cron alerting)")
    p.add_argument("--no-color", action="store_true", help="disable coloured terminal output")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    color = sys.stderr.isatty() and not args.no_color

    def log(msg=""):
        print(msg, file=sys.stderr, flush=True)

    def paint(sev, text, on=True):
        return f"{COLORS[sev]}{text}{RESET}" if color and on else text

    try:
        targets = load_targets(args.domains)
    except ScopeError as e:
        log(f"REFUSING TO RUN: {e}")
        return 1

    est = estimate(len(targets))
    log(f"{TOOL_NAME} {TOOL_VERSION}")
    log(f"Scope    : {len(targets)} authorized host(s) from {args.domains}")
    for t in targets:
        log(f"           - {t.label}")
    log(f"Limits   : {MAX_CONCURRENT} concurrent, {int(MIN_INTERVAL * 1000)} ms spacing, {TIMEOUT:g}s timeout")
    log(f"Budget   : ~{est['requests']} requests (+ redirects), est. ≥ {est['min_seconds']}s")
    log(f"UA       : {build_user_agent(args.contact)}")
    if args.dry_run:
        log("\nDry run: no network traffic sent.")
        return 0
    log()

    def progress(event, t, payload):
        if event == "done":
            c = payload["counts"]
            tag = paint(payload["worst"], "[" + payload["worst"].ljust(8) + "]")
            log(f"  {tag} {t.label:<40} {c['CRITICAL']} critical, {c['MEDIUM']} medium, {c['LOW']} low, {c['PASS']} pass")
        elif event == "error":
            log(f"  [ERROR]    {t.label}: {payload}")

    report = run_scan(targets, expiry_days=args.expiry_days, contact=args.contact,
                      source=args.domains.name, on_progress=progress)
    json_path, html_path = write_reports(report, args.output, datetime.now())

    s = report["summary"]
    log()
    log(f"Done in {report['duration_seconds']}s, {report['request_count']} requests.")
    log(f"  Domains  : {s['total_domains']}")
    log(f"  Critical : {paint('CRITICAL', str(s['critical']), s['critical'] > 0)}")
    log(f"  Warnings : {s['warnings']} ({s['medium']} medium, {s['low']} low)")
    log(f"  Passed   : {s['passed']}")
    log(f"\n  JSON : {json_path}\n  HTML : {html_path}")

    return 2 if args.fail_on_critical and s["critical"] else 0
