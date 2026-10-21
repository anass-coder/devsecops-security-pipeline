"""Seed explicit API requests through ZAP before its baseline spider starts."""

import json
from pathlib import Path
from urllib.parse import urlsplit


REQUESTS = [
    ("GET", "/", "", 200),
    ("GET", "/health", "", 200),
    ("GET", "/users/1", "", 200),
    ("GET", "/users/99999", "", 404),
    ("POST", "/login", '{"username":"dast-user","password":"invalid"}', 401),
    ("POST", "/login", "{}", 400),
]


def zap_started(zap, target):
    host = urlsplit(target).netloc
    coverage = []
    for method, path, body, expected in REQUESTS:
        headers = [f"{method} {path} HTTP/1.1", f"Host: {host}", "Connection: close"]
        if method == "POST":
            headers.extend(["Content-Type: application/json", f"Content-Length: {len(body)}"])
        messages = zap.core.send_request("\r\n".join(headers) + "\r\n\r\n" + body, False)
        status = int(messages[-1]["responseHeader"].splitlines()[0].split()[1])
        if status != expected:
            raise RuntimeError(f"Unexpected {method} {path} status {status}; expected {expected}")
        coverage.append({"method": method, "path": path, "status": status})
    Path("/zap/wrk/coverage.json").write_text(json.dumps(coverage, indent=2), encoding="utf-8")
