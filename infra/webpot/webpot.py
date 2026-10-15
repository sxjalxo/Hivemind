"""A small low-interaction HTTP honeypot (checklist item 11).

It serves a staff sign-in page and believable 404s, and writes one JSON line per
request in Cowrie's shape (`eventid`, `src_ip`, `session`, `timestamp`, ...), so
Filebeat and the `cowrie-ecs` pipeline ingest it like any other honeypot. It is a
separate component from Cowrie on purpose: a web-telemetry source, not a second
shell emulator. Nothing here executes, stores or fetches anything an attacker
sends; the only output is the log line.

Standard library only, so the stock python image runs it with no build step.
"""

import html
import json
import os
import secrets
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

LOG_PATH = os.environ.get("WEBPOT_LOG", "/var/log/webpot/webpot.json")
PORT = int(os.environ.get("WEBPOT_PORT", "8080"))
SESSION_GAP_S = 30 * 60  # requests from one IP within this gap are one session
MAX_BODY = 8192
MAX_FIELD = 2048  # longest path, query or credential kept in the log
SERVER = "Apache/2.4.62 (Debian)"

LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Staff Portal - Sign in</title>
<style>body{{font-family:Arial,sans-serif;background:#eef1f4;margin:0}}
form{{width:300px;margin:12vh auto;background:#fff;padding:28px;border:1px solid #ccd3da}}
input{{width:100%;margin:6px 0 14px;padding:8px;box-sizing:border-box}}
.err{{color:#b00020;font-size:13px}}</style></head>
<body><form method="post" action="/login"><h2>Staff Portal</h2>{error}
<label>Username<input name="username" autocomplete="username"></label>
<label>Password<input name="password" type="password" autocomplete="current-password"></label>
<button type="submit">Sign in</button></form></body></html>"""

NOT_FOUND = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1>
<p>The requested URL was not found on this server.</p><hr>
<address>{server} Server at {host} Port 80</address></body></html>"""


def rotate(path: str, now: datetime) -> None:
    """Move a previous day's log aside as `<path>.YYYY-MM-DD`, as Cowrie does.

    Without it the log only ever grows; with it, `scripts/prune.py` can retire
    whole days that Filebeat has already shipped.
    """
    try:
        day = datetime.fromtimestamp(os.path.getmtime(path), UTC).date()
    except FileNotFoundError:
        return
    if day < now.date():
        os.replace(path, f"{path}.{day.isoformat()}")


class Sessions:
    """One session id per source IP, renewed after SESSION_GAP_S of silence."""

    def __init__(self, gap: float = SESSION_GAP_S) -> None:
        self.gap = gap
        self._seen: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    def id_for(self, ip: str, now: float) -> str:
        with self._lock:
            current = self._seen.get(ip)
            if current is None or now - current[1] > self.gap:
                current = (secrets.token_hex(6), now)
            self._seen[ip] = (current[0], now)
            # ponytail: unbounded per-IP dict, pruned only on the next visit;
            # sweep stale entries here if a scan from many IPs ever matters.
            return current[0]


def record(
    *,
    eventid: str,
    ip: str,
    port: int,
    session: str,
    method: str,
    target: str,
    status: int,
    user_agent: str | None,
    username: str | None = None,
    password: str | None = None,
) -> dict:
    """One log line in the shape the ingest pipeline expects. Pure."""
    parts = urlsplit(target)
    line = {
        "eventid": eventid,
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "src_ip": ip,
        "src_port": port,
        "dst_port": 80,
        "session": session,
        "network": {"protocol": "http"},
        "http": {"request": {"method": method[:16]}, "response": {"status_code": status}},
        "path": parts.path[:MAX_FIELD] or "/",
    }
    if parts.query:
        line["query"] = parts.query[:MAX_FIELD]
    if user_agent:
        line["user_agent"] = {"original": user_agent[:512]}
    if username is not None:
        line["username"] = username[:MAX_FIELD]
    if password is not None:
        line["password"] = password[:MAX_FIELD]
    return line


class Handler(BaseHTTPRequestHandler):
    timeout = 10  # a client that promises a body and never sends it is let go
    sessions = Sessions()
    _write_lock = threading.Lock()

    def version_string(self) -> str:
        # Not server_version + sys_version: that joins them with a space, and a
        # trailing space after "(Debian)" is a tell no real Apache sends.
        return SERVER

    def _log(self, **fields) -> None:
        ip, port = self.client_address[0], self.client_address[1]
        line = record(
            ip=ip,
            port=port,
            session=self.sessions.id_for(ip, time.time()),
            method=self.command or "",
            target=self.path,
            user_agent=self.headers.get("User-Agent") if self.headers else None,
            **fields,
        )
        with self._write_lock:
            rotate(LOG_PATH, datetime.now(UTC))
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(line) + "\n")

    def _send(self, status: int, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _page(self) -> tuple[int, str]:
        if urlsplit(self.path).path in ("/", "/login"):
            return 200, LOGIN_PAGE.format(error="")
        host = html.escape(self.headers.get("Host", "localhost").split(":")[0])
        return 404, NOT_FOUND.format(server=SERVER, host=host)

    def do_GET(self) -> None:  # noqa: N802 - http.server's naming
        status, body = self._page()
        self._log(eventid="web.request", status=status)
        self._send(status, body)

    do_HEAD = do_GET  # noqa: N815

    def do_POST(self) -> None:  # noqa: N802
        try:
            length = min(int(self.headers.get("Content-Length") or 0), MAX_BODY)
        except ValueError:
            length = 0
        body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""
        if urlsplit(self.path).path == "/login":
            form = parse_qs(body)
            self._log(
                eventid="web.login.failed",
                status=200,
                username=form.get("username", [""])[0],
                password=form.get("password", [""])[0],
            )
            error = '<p class="err">Invalid username or password.</p>'
            self._send(200, LOGIN_PAGE.format(error=error))
            return
        status, page = self._page()
        self._log(eventid="web.request", status=status)
        self._send(status, page)

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        pass  # the JSON log is the record; stderr chatter is not


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
