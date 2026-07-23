"""Deliberately vulnerable target app — for WAF testing ONLY.

This app has three intentionally unsafe endpoints:
  /login   -> SQL injection   (unsanitized string-built query)
  /search  -> reflected XSS   (user input echoed into HTML with no escaping)
  /ping    -> command injection (user input passed straight to a shell command)

DO NOT deploy this anywhere reachable from the internet. It exists purely so
the WAF proxy has real vulnerable traffic to protect, in a fully sandboxed
environment you control.

Run directly on port 5001 (the WAF proxy will sit in front of this on 5000):
    python target_app/app.py
"""

from __future__ import annotations

import os
import sqlite3
import subprocess

from flask import Flask, render_template, request

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "users.db")


def init_db() -> None:
    """Create a small demo users table if it doesn't already exist."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, "
        "username TEXT, password TEXT)"
    )
    conn.execute("DELETE FROM users")
    conn.executemany(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [("admin", "supersecretpassword123"), ("guest", "guestpass")],
    )
    conn.commit()
    conn.close()


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """VULNERABLE ON PURPOSE: builds the SQL query via string formatting.

    A payload like `' OR '1'='1' --` in either field bypasses the check
    entirely, and UNION-based payloads can exfiltrate other tables.
    """
    result = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # --- VULNERABLE: raw string interpolation into SQL, no parameterization ---
        query = (
            f"SELECT * FROM users WHERE username = '{username}' "
            f"AND password = '{password}'"
        )
        try:
            cursor.execute(query)
            row = cursor.fetchone()
            result = f"Login successful: {row}" if row else "Login failed."
        except sqlite3.Error as exc:
            result = f"DB error: {exc}"
        finally:
            conn.close()

    return render_template("login.html", result=result)


@app.route("/search")
def search():
    """VULNERABLE ON PURPOSE: reflects the query straight into HTML, unescaped.

    A payload like `<script>alert(1)</script>` executes in the browser.
    """
    query = request.args.get("q", "")
    # --- VULNERABLE: `| safe` disables Jinja2's autoescaping ---
    return render_template("search.html", query=query)


@app.route("/ping", methods=["GET", "POST"])
def ping():
    """VULNERABLE ON PURPOSE: passes user input directly to a shell command.

    A payload like `127.0.0.1; ls` or `127.0.0.1 && cat /etc/passwd` runs
    arbitrary commands on the host.
    """
    output = None
    if request.method == "POST":
        host = request.form.get("host", "")
        try:
            # --- VULNERABLE: shell=True with unsanitized user input ---
            output = subprocess.check_output(
                f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT, text=True
            )
        except subprocess.CalledProcessError as exc:
            output = exc.output

    return render_template("ping.html", output=output)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5001, debug=True)
