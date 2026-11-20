#!/usr/bin/env python3
"""Uptime Watch - uptime monitor with a dashboard and JSON API.

Standard library only. Runs on Render (or anywhere with Python 3.9+).
"""
import hmac
import http.client
import ipaddress
import json
import mimetypes
import os
import signal
import socket
import sys
import threading
import time
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

BASE = Path(__file__).resolve().parent
PUBLIC = (BASE / "public").resolve()
PORT = int(os.environ.get("PORT", "3000"))
API_KEY = os.environ.get("API_KEY", "")
DATA_FILE = Path(os.environ.get("DATA_FILE", str(BASE / "data.json")))

TICK = 5
TIMEOUT = 10
MAX_CHECKS = 500
MAX_MONITORS = 100
MIN_INTERVAL = 30
MAX_INTERVAL = 86400
DAY_MS = 24 * 60 * 60 * 1000
MAX_BODY = 16 * 1024

lock = threading.RLock()
file_lock = threading.Lock()
db = {"monitors": []}
in_flight = set()
dirty = threading.Event()
wake = threading.Event()
stop = threading.Event()


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def now_ms():
    return int(time.time() * 1000)


# ---------- persistence ----------

def load():
    global db
    try:
        raw = json.loads(DATA_FILE.read_text("utf-8"))
        if isinstance(raw, dict) and isinstance(raw.get("monitors"), list):
            db = raw
    except FileNotFoundError:
        pass
    except Exception as err:
        print("Could not read data file:", err, file=sys.stderr)
        try:
            DATA_FILE.replace(DATA_FILE.with_name(DATA_FILE.name + ".corrupt"))
        except OSError:
            pass


def persist():
    with lock:
        data = json.dumps(db)
    with file_lock:
        tmp = DATA_FILE.with_name(DATA_FILE.name + ".tmp")
        try:
            DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(data, "utf-8")
            os.replace(tmp, DATA_FILE)
        except OSError as err:
            print("Save failed:", err, file=sys.stderr)


# ---------- URL safety (blocks private/internal targets) ----------

def assert_public_url(raw):
    try:
        u = urlsplit(raw)
        port = u.port
    except ValueError:
        raise ApiError(400, "Invalid URL. Include https:// at the start.")
    if not u.scheme or not u.hostname:
        raise ApiError(400, "Invalid URL. Include https:// at the start.")
    if u.scheme not in ("http", "https"):
        raise ApiError(400, "Only http and https URLs are allowed.")

    host = u.hostname
    if host == "localhost" or host.endswith(".localhost"):
        raise ApiError(400, "Local addresses are not allowed.")

    try:
        infos = socket.getaddrinfo(
            host, port or (443 if u.scheme == "https" else 80), proto=socket.IPPROTO_TCP
        )
    except (socket.gaierror, UnicodeError):
        raise ApiError(400, "Host does not resolve.")

    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0].split("%")[0])
        except ValueError:
            raise ApiError(400, "Host does not resolve.")
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ip.is_global or ip.is_multicast:
            raise ApiError(400, "Private or internal addresses are not allowed.")
    return raw


# ---------- checks ----------

def fetch_status(url):
    u = urlsplit(url)
    path = quote(u.path or "/", safe="/%:@!$&'()*+,;=~-._")
    if u.query:
        path += "?" + quote(u.query, safe="/%:@!$&'()*+,;=~?-._")
    conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(u.hostname, u.port, timeout=TIMEOUT)
    try:
        # No redirect following: a redirect cannot lead a check into a private network.
        conn.request("GET", path, headers={"User-Agent": "UptimeWatch/1.0", "Accept": "*/*"})
        return conn.getresponse().status
    finally:
        conn.close()


def run_check(m):
    started = now_ms()
    ok = False
    status = None
    error = None
    try:
        target = assert_public_url(m["url"])
        status = fetch_status(target)
        ok = 200 <= status < 400  # any 2xx or 3xx counts as up
        if not ok:
            error = "HTTP %d" % status
    except ApiError as err:
        error = err.message
    except (socket.timeout, TimeoutError):
        error = "Timed out"
    except Exception as err:
        error = (str(err) or type(err).__name__)[:200]

    check = {"t": started, "ok": ok, "status": status, "ms": now_ms() - started, "error": error}
    with lock:
        m["checks"].append(check)
        if len(m["checks"]) > MAX_CHECKS:
            del m["checks"][: len(m["checks"]) - MAX_CHECKS]
        m["lastCheck"] = started
        m["nextCheck"] = now_ms() + m["interval"] * 1000
    dirty.set()
    return check


def execute(m):
    with lock:
        if m["id"] in in_flight:
            return None
        in_flight.add(m["id"])
    try:
        return run_check(m)
    finally:
        with lock:
            in_flight.discard(m["id"])


def safe_execute(m):
    try:
        execute(m)
    except Exception:
        traceback.print_exc()


def scheduler():
    while not stop.is_set():
        now = now_ms()
        with lock:
            due = [
                m for m in db["monitors"]
                if not m.get("paused") and m["nextCheck"] <= now and m["id"] not in in_flight
            ]
        for m in due:
            threading.Thread(target=safe_execute, args=(m,), daemon=True).start()
        if dirty.is_set():
            dirty.clear()
            persist()
        wake.wait(TICK)
        wake.clear()


# ---------- helpers ----------

def summarize(m, full=False):
    now = now_ms()
    checks = m["checks"]
    day = [c for c in checks if c["t"] >= now - DAY_MS]
    up = [c for c in day if c["ok"]]
    lat = [c["ms"] for c in up]
    last = checks[-1] if checks else None

    out = {
        "id": m["id"],
        "name": m["name"],
        "url": m["url"],
        "interval": m["interval"],
        "paused": bool(m.get("paused")),
        "status": "pending" if not last else ("up" if last["ok"] else "down"),
        "lastCheck": last["t"] if last else None,
        "nextCheck": m["nextCheck"],
        "lastError": last["error"] if last and not last["ok"] else None,
        "uptime24h": round(len(up) / len(day) * 100, 2) if day else None,
        "avgLatency24h": round(sum(lat) / len(lat)) if lat else None,
        "recent": [
            {"t": c["t"], "ok": c["ok"], "ms": c["ms"], "status": c["status"], "error": c["error"]}
            for c in checks[-60:]
        ],
    }
    if full:
        out["checks"] = list(reversed(checks[-100:]))
    return out


def get_monitor(mid):
    with lock:
        for m in db["monitors"]:
            if m["id"] == mid:
                return m
    raise ApiError(404, "Monitor not found")


def parse_interval(value):
    try:
        interval = int(float(value or 300))
    except (TypeError, ValueError, OverflowError):
        interval = 300
    if interval == 0:
        interval = 300
    return min(MAX_INTERVAL, max(MIN_INTERVAL, interval))


def create_monitor(body):
    raw_url = str(body.get("url") or "").strip()
    with lock:
        if len(db["monitors"]) >= MAX_MONITORS:
            raise ApiError(409, "Limit of %d monitors reached." % MAX_MONITORS)
    url = assert_public_url(raw_url)
    interval = parse_interval(body.get("interval"))
    name = str(body.get("name") or "").strip()[:60] or urlsplit(url).hostname

    monitor = {
        "id": str(uuid.uuid4()),
        "name": name,
        "url": url,
        "interval": interval,
        "paused": False,
        "createdAt": now_ms(),
        "nextCheck": now_ms(),
        "lastCheck": None,
        "checks": [],
    }
    with lock:
        if len(db["monitors"]) >= MAX_MONITORS:
            raise ApiError(409, "Limit of %d monitors reached." % MAX_MONITORS)
        db["monitors"].append(monitor)
        result = summarize(monitor)
    dirty.set()
    wake.set()
    return result


# ---------- HTTP ----------

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "UptimeWatch/1.0"
    timeout = 30

    def log_message(self, fmt, *args):
        pass

    def send_bytes(self, status, body, ctype):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, status, obj):
        self.send_bytes(status, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

    def read_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self.close_connection = True
            raise ApiError(400, "Invalid Content-Length header.")
        if length < 0 or length > MAX_BODY:
            self.close_connection = True
            raise ApiError(413, "Request body too large.")
        return self.rfile.read(length) if length else b""

    @staticmethod
    def parse_json(raw):
        if not raw.strip():
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "Request body must be valid JSON.")
        if not isinstance(data, dict):
            raise ApiError(400, "Request body must be a JSON object.")
        return data

    def require_key(self):
        if not API_KEY:
            return
        given = (self.headers.get("x-api-key") or "").encode("utf-8")
        if not hmac.compare_digest(given, API_KEY.encode("utf-8")):
            raise ApiError(401, "Invalid or missing x-api-key header")

    def handle_api(self):
        method = "GET" if self.command == "HEAD" else self.command
        path = urlsplit(self.path).path.rstrip("/") or "/"
        raw = self.read_body()
        parts = path.split("/")  # ['', 'api', 'monitors', id, action]

        if path == "/api/health":
            if method != "GET":
                raise ApiError(405, "Method not allowed")
            with lock:
                count = len(db["monitors"])
            self.send_json(200, {"ok": True, "monitors": count, "uptimeSeconds": round(time.monotonic() - STARTED)})

        elif path == "/api/monitors":
            if method == "GET":
                with lock:
                    monitors = [summarize(m) for m in db["monitors"]]
                self.send_json(200, {"monitors": monitors})
            elif method == "POST":
                self.require_key()
                self.send_json(201, create_monitor(self.parse_json(raw)))
            else:
                raise ApiError(405, "Method not allowed")

        elif parts[:3] == ["", "api", "monitors"] and len(parts) in (4, 5):
            mid = parts[3]
            action = parts[4] if len(parts) == 5 else None

            if action is None:
                if method == "GET":
                    m = get_monitor(mid)
                    with lock:
                        self.send_json(200, summarize(m, full=True))
                elif method == "DELETE":
                    self.require_key()
                    m = get_monitor(mid)
                    with lock:
                        db["monitors"] = [x for x in db["monitors"] if x["id"] != m["id"]]
                    dirty.set()
                    self.send_json(200, {"deleted": True})
                else:
                    raise ApiError(405, "Method not allowed")

            elif action == "check":
                if method != "POST":
                    raise ApiError(405, "Method not allowed")
                self.require_key()
                m = get_monitor(mid)
                check = execute(m)
                if check is None:
                    raise ApiError(409, "A check is already running.")
                with lock:
                    result = {"check": check, "monitor": summarize(m)}
                self.send_json(200, result)

            elif action == "pause":
                if method != "POST":
                    raise ApiError(405, "Method not allowed")
                self.require_key()
                m = get_monitor(mid)
                with lock:
                    m["paused"] = not m.get("paused")
                    if not m["paused"]:
                        m["nextCheck"] = now_ms()
                    result = summarize(m)
                dirty.set()
                wake.set()
                self.send_json(200, result)

            else:
                raise ApiError(404, "Not found")
        else:
            raise ApiError(404, "Not found")

    def serve_static(self):
        if self.command not in ("GET", "HEAD"):
            raise ApiError(405, "Method not allowed")
        self.read_body()
        try:
            rel = unquote(urlsplit(self.path).path).lstrip("/") or "index.html"
            target = (PUBLIC / rel).resolve()
            target.relative_to(PUBLIC)
            if target.is_dir():
                target = target / "index.html"
            body = target.read_bytes()
        except (OSError, ValueError):
            self.send_bytes(404, b"Not found", "text/plain; charset=utf-8")
            return
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"
        self.send_bytes(200, body, ctype)

    def dispatch(self):
        try:
            path = urlsplit(self.path).path
            if path == "/api" or path.startswith("/api/"):
                self.handle_api()
            else:
                self.serve_static()
        except ApiError as err:
            self.send_json(err.status, {"error": err.message})
        except (ConnectionError, TimeoutError):
            self.close_connection = True
        except Exception:
            traceback.print_exc()
            self.close_connection = True
            try:
                self.send_json(500, {"error": "Server error"})
            except Exception:
                pass

    do_GET = do_HEAD = do_POST = do_DELETE = do_PUT = do_PATCH = dispatch


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], (ConnectionError, TimeoutError)):
            return
        super().handle_error(request, client_address)


STARTED = time.monotonic()


def main():
    load()
    if not API_KEY:
        print("Warning: API_KEY is not set. Write endpoints are open to anyone.", file=sys.stderr)

    sched = threading.Thread(target=scheduler, daemon=True)
    sched.start()

    server = Server(("0.0.0.0", PORT), Handler)

    def shutdown(signum, frame):
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    print("Uptime Watch running on port %d" % PORT, flush=True)
    try:
        server.serve_forever()
    finally:
        stop.set()
        wake.set()
        sched.join(timeout=3)
        server.server_close()
        persist()


if __name__ == "__main__":
    main()
