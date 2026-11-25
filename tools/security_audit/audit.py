#!/usr/bin/env python3
"""Authorized-domain security audit: CLI entry point.

Scans ONLY the hosts listed in authorized_domains.txt with read-only checks
(sensitive-file exposure, security headers, TLS health) and writes JSON + HTML
reports to ./reports/.

    python3 audit.py                       # uses ./authorized_domains.txt
    python3 audit.py -d my_domains.txt -o /srv/audit-reports
    python3 audit.py --dry-run             # show scope + request budget, no network
"""

import sys
from pathlib import Path

# Make the `security_audit` package importable when run as a plain script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from security_audit.cli import main
except ModuleNotFoundError as e:
    if e.name and not e.name.startswith("security_audit"):
        sys.exit(f"Missing dependency: {e.name}. Install with: "
                 f"pip install -r {Path(__file__).resolve().parent / 'requirements.txt'}")
    raise

if __name__ == "__main__":
    sys.exit(main())
