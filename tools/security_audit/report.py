"""Write the JSON and standalone HTML reports."""

import json
from datetime import datetime
from pathlib import Path

from .checks import CRITICAL, LOW, MEDIUM, PASS

TEMPLATE = Path(__file__).with_name("report_template.html")


def summarize(domains: list[dict]) -> dict:
    totals = {CRITICAL: 0, MEDIUM: 0, LOW: 0, PASS: 0}
    for d in domains:
        for sev, n in d["counts"].items():
            totals[sev] += n
    return {
        "total_domains": len(domains),
        "critical": totals[CRITICAL],
        "medium": totals[MEDIUM],
        "low": totals[LOW],
        "warnings": totals[MEDIUM] + totals[LOW],
        "passed": totals[PASS],
        "total_checks": sum(totals.values()),
        "domains_with_critical": sum(1 for d in domains if d["counts"][CRITICAL]),
    }


def write_reports(report: dict, out_dir: Path, stamp: datetime) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    name = f"security-report-{stamp:%Y-%m-%d_%H%M%S}"
    json_path = out_dir / f"{name}.json"
    html_path = out_dir / f"{name}.html"

    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    # Embed as inert JSON. Escaping '<' prevents any value from closing the
    # <script> element; the page renders everything with textContent.
    payload = json.dumps(report, ensure_ascii=False).replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    html = TEMPLATE.read_text(encoding="utf-8").replace("__REPORT_JSON__", payload)
    html_path.write_text(html, encoding="utf-8")
    return json_path, html_path
