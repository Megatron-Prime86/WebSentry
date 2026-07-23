# WebSentry — Web Application Firewall

A real-time WAF built from scratch: a reverse proxy that inspects every
incoming HTTP request, blocks SQL injection, XSS, command injection, path
traversal, and rate-limit/brute-force attempts, and shows everything on a
live dashboard.

## How it works

```
Browser/attacker → WebSentry Proxy (port 5000) → Target App (port 5001)
                          │
                          ▼
                  exports/*.json → Dashboard (port 5002)
```

Every request first hits the proxy. The proxy checks:
1. **Rate limiting** — is this source sending too many requests too fast?
2. **Signature rules** — does any field (query string, form data, JSON body)
   match a known attack pattern (SQLi, XSS, command injection, path traversal)?

If either check trips, the request is blocked with a 403/429 and logged.
Otherwise it's transparently forwarded to the real app and the response is
relayed back to the client.

## Project structure

```
websentry/
├── target_app/         # Intentionally vulnerable demo app (the "protected" site)
│   └── app.py           # SQLi login, XSS search, command-injection ping tool
├── waf/
│   ├── proxy.py          # The reverse proxy — the core of the project
│   ├── rate_limiter.py   # Per-IP sliding-window rate limiting
│   ├── logger.py         # Tracks + exports blocked/allowed requests
│   └── rules/
│       ├── patterns.py    # Regex attack signatures
│       └── engine.py      # Scans request inputs against the signatures
├── dashboard/
│   ├── app.py            # Live dashboard (reads waf/'s JSON exports)
│   └── templates/index.html
├── generate_report.py    # Builds a readable incident report
└── exports/              # JSON + report files land here at runtime
```

## Setup

```bash
cd websentry
pip install -r target_app/requirements.txt -r waf/requirements.txt --break-system-packages
```

(If you're using a venv: `pip install -r ... ` without `--break-system-packages`,
inside the activated venv.)

## Running it (3 terminals)

```bash
# Terminal 1 — the vulnerable target app
python3 target_app/app.py

# Terminal 2 — the WAF proxy (sits in front of the target app)
python3 waf/proxy.py

# Terminal 3 — the live dashboard
python3 dashboard/app.py
```

Then open:
- **http://localhost:5000** — the site, *through* the WAF (use this one!)
- **http://localhost:5002** — the live dashboard

Do **not** browse to `:5001` directly if you want the WAF to actually see and
filter your traffic — that port is the unprotected target app itself.

## Testing it

Try these against `http://localhost:5000` (all should get blocked with a 403):

| Attack | Where | Payload |
|---|---|---|
| SQL Injection | `/login` username field | `' OR '1'='1' --` |
| XSS | `/search?q=` | `<script>alert(1)</script>` |
| Command Injection | `/ping` host field | `127.0.0.1; whoami` |
| Path Traversal | `/search?q=` | `../../etc/passwd` |
| Rate limiting | any endpoint | 20+ requests in 10 seconds from one source |

Then visit the dashboard to watch the pie chart and alert list update live,
and click **Download Report** for a full incident report.

## Notes / limitations

- The vulnerable target app is for demo/testing purposes only — never expose
  it (or this WAF) to the public internet.
- Detection is signature/regex-based, like a lightweight ModSecurity core
  rule set. It catches common, well-known payload patterns but — like any
  regex-based WAF — isn't a guarantee against every possible encoding or
  obfuscation an attacker might try. That's a real, honest limitation worth
  mentioning if you present this project, not a bug to hide.
- `exports/waf_alerts.json` is a rolling buffer (last 500 alerts) — the
  incident report only reflects whatever is currently in that buffer.
