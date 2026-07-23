"""Generate a readable incident report from the WAF's alert export.

Usage:
    python generate_report.py
"""

from __future__ import annotations

import json
import logging
import os
from collections import Counter
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
EXPORTS_DIR = os.path.join(_PROJECT_ROOT, "exports")
ALERTS_FILE = os.path.join(EXPORTS_DIR, "waf_alerts.json")
STATS_FILE = os.path.join(EXPORTS_DIR, "waf_stats.json")
REPORT_FILE = os.path.join(EXPORTS_DIR, "waf_incident_report.txt")


def load_json(path: str, default: Any) -> Any:
    try:
        with open(path, "r") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def build_report(alerts: list[dict[str, Any]], stats: dict[str, Any]) -> str:
    attack_counts = Counter(a["attack"] for a in alerts)
    attacker_counts = Counter(a["src_ip"] for a in alerts)

    lines = []
    lines.append("=" * 50)
    lines.append("WEBSENTRY WAF — INCIDENT REPORT")
    lines.append("=" * 50)
    lines.append("")
    lines.append(f"Total Requests Seen:  {stats.get('total_requests', 0)}")
    lines.append(f"Requests Blocked:     {stats.get('blocked_requests', 0)}")
    lines.append(f"Requests Allowed:     {stats.get('allowed_requests', 0)}")
    lines.append("")
    lines.append("-" * 50)
    lines.append("ATTACK TYPE BREAKDOWN")
    lines.append("-" * 50)
    for attack, count in attack_counts.most_common():
        lines.append(f"  {attack}: {count}")
    lines.append("")
    lines.append("-" * 50)
    lines.append("TOP ATTACKER IPs")
    lines.append("-" * 50)
    for ip, count in attacker_counts.most_common(10):
        lines.append(f"  {ip}: {count} blocked request(s)")
    lines.append("")
    lines.append("-" * 50)
    lines.append("BLOCKED REQUEST LOG")
    lines.append("-" * 50)
    for alert in alerts:
        lines.append(
            f"[{alert['timestamp']}] {alert['attack']} — "
            f"{alert['method']} {alert['path']} from {alert['src_ip']} "
            f"(field: {alert['field']})"
        )
    lines.append("")
    lines.append("=" * 50)

    report_text = "\n".join(lines)
    with open(REPORT_FILE, "w") as file:
        file.write(report_text)

    return report_text


def main() -> None:
    alerts = load_json(ALERTS_FILE, [])
    stats = load_json(STATS_FILE, {})

    if not alerts:
        logger.warning("No alerts found in %s. Run the WAF first.", ALERTS_FILE)
        return

    report_text = build_report(alerts, stats)
    logger.info(report_text)
    logger.info("\nReport written to %s", REPORT_FILE)


if __name__ == "__main__":
    main()
