"""Live dashboard for WebSentry — reads the WAF's exported JSON and serves it.

Run this alongside target_app/app.py and waf/proxy.py:
    python dashboard/app.py
Then open http://localhost:5002
"""

from __future__ import annotations

import json
import logging
import os
import sys
from collections import Counter
from typing import Any

from flask import Flask, abort, jsonify, render_template, send_from_directory

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

EXPORTS_DIR = os.path.join(_PROJECT_ROOT, "exports")
ALERTS_FILE = os.path.join(EXPORTS_DIR, "waf_alerts.json")
STATS_FILE = os.path.join(EXPORTS_DIR, "waf_stats.json")

app = Flask(__name__)


def _load_json(path: str, default: Any) -> Any:
    try:
        with open(path, "r") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def build_dashboard_data() -> dict[str, Any]:
    alerts = _load_json(ALERTS_FILE, [])
    stats = _load_json(STATS_FILE, {"total_requests": 0, "blocked_requests": 0, "allowed_requests": 0})

    attack_counts = Counter(alert["attack"] for alert in alerts)
    attacker_counts = Counter(alert["src_ip"] for alert in alerts)

    return {
        "total_requests": stats.get("total_requests", 0),
        "blocked_requests": stats.get("blocked_requests", 0),
        "allowed_requests": stats.get("allowed_requests", 0),
        "attack_labels": list(attack_counts.keys()),
        "attack_values": list(attack_counts.values()),
        "top_attackers": attacker_counts.most_common(5),
        "alerts": list(reversed(alerts))[:30],  # most recent first
    }


@app.route("/")
def index():
    data = build_dashboard_data()
    return render_template("index.html", **data)


@app.route("/api/dashboard-data")
def dashboard_data():
    return jsonify(build_dashboard_data())


_DOWNLOADABLE_REPORTS = {"waf_incident_report.txt"}


@app.route("/api/generate-report", methods=["POST"])
def api_generate_report():
    from generate_report import build_report

    alerts = _load_json(ALERTS_FILE, [])
    stats = _load_json(STATS_FILE, {})
    if not alerts:
        return jsonify({"error": "No alerts yet to report on."}), 400

    build_report(alerts, stats)
    return jsonify({"status": "ok"})


@app.route("/reports/<path:filename>")
def download_report(filename: str):
    if filename not in _DOWNLOADABLE_REPORTS:
        abort(404)
    return send_from_directory(EXPORTS_DIR, filename, as_attachment=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False)
