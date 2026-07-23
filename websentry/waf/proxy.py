"""WebSentry WAF — reverse proxy that inspects and blocks malicious requests.

Sits in front of the target app: every request is scanned against the
signature rules in rules/patterns.py before being forwarded. Malicious
requests get blocked with a 403; clean ones are transparently forwarded
and the response is passed back to the client.

Run the target app first (port 5001), then this proxy (port 5000), and
send all your traffic to the proxy's port instead of the target directly:
    python target_app/app.py      # in one terminal
    python waf/proxy.py           # in another
    open http://localhost:5000
"""

from __future__ import annotations

import logging
import os

import requests
from flask import Flask, Response, jsonify, request

from logger import log_allowed, log_blocked, start_export_thread
from rate_limiter import is_rate_limited
from rules import inspect_inputs

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)

TARGET_URL = os.environ.get("WEBSENTRY_TARGET_URL", "http://127.0.0.1:5001")

# Headers that shouldn't be forwarded as-is between hops (standard reverse
# proxy hygiene — these are connection-specific, not request content).
_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-encoding",
    "content-length",
}


def _gather_inputs() -> dict[str, str]:
    """Flatten query args, form fields, and (best-effort) JSON body into one dict."""
    inputs: dict[str, str] = {}
    inputs.update(request.args.to_dict())
    inputs.update(request.form.to_dict())

    if request.is_json:
        try:
            body = request.get_json(silent=True) or {}
            if isinstance(body, dict):
                inputs.update({k: str(v) for k, v in body.items()})
        except Exception:
            pass

    return inputs


def _client_ip() -> str:
    # Respect X-Forwarded-For if present (e.g. behind another proxy/load
    # balancer), otherwise fall back to the direct connection's address.
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


@app.route(
    "/<path:path>",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
)
@app.route("/", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy(path: str = ""):
    src_ip = _client_ip()

    if is_rate_limited(src_ip):
        match = {"attack": "Rate Limit Exceeded / Possible Brute Force", "field": "n/a", "value": "n/a"}
        log_blocked(src_ip, request.path, request.method, match)
        logger.warning("BLOCKED %s %s from %s — rate limit exceeded", request.method, request.path, src_ip)
        return jsonify({"error": "Too many requests", "reason": match["attack"]}), 429

    inputs = _gather_inputs()

    match = inspect_inputs(inputs)
    if match:
        log_blocked(src_ip, request.path, request.method, match)
        logger.warning(
            "BLOCKED %s %s from %s — %s in field '%s'",
            request.method,
            request.path,
            src_ip,
            match["attack"],
            match["field"],
        )
        return (
            jsonify(
                {
                    "error": "Request blocked by WebSentry WAF",
                    "reason": match["attack"],
                }
            ),
            403,
        )

    log_allowed(src_ip, request.path, request.method)

    # Forward the clean request to the real target app.
    target = f"{TARGET_URL}/{path}"
    try:
        upstream = requests.request(
            method=request.method,
            url=target,
            params=request.args,
            data=request.form if request.form else request.get_data(),
            headers={k: v for k, v in request.headers if k.lower() != "host"},
            cookies=request.cookies,
            allow_redirects=False,
            timeout=5,
        )
    except requests.RequestException as exc:
        logger.error("Upstream request failed: %s", exc)
        return jsonify({"error": "Upstream target unreachable"}), 502

    response_headers = [
        (name, value)
        for name, value in upstream.headers.items()
        if name.lower() not in _HOP_BY_HOP_HEADERS
    ]
    return Response(upstream.content, status=upstream.status_code, headers=response_headers)


if __name__ == "__main__":
    start_export_thread()
    logger.info("WebSentry WAF proxying to %s", TARGET_URL)
    app.run(host="0.0.0.0", port=5000, debug=False)
