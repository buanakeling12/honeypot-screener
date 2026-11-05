#!/usr/bin/env python3
"""Honeypot screener API — free tier (read-only, stdlib-only).

Wraps honeypot_screener.py (v2 scoring) as a tiny HTTP API so other agents
can query it. No wallet, no private key, no API key, no payment, no
transaction is ever created. This server only READS public data (GoPlus +
read-only eth_call fallback) and returns the screener's verdict.

Endpoints:
    GET  /health          -> {"status": "ok", ...}
    POST /check           -> {"address": "0x..."}  => verdict JSON
    GET  /                -> same as /health

Free-tier limit (MVP): DAILY_LIMIT queries per calendar day (UTC) per caller
IP, tracked in usage.json next to this script (IP + date + count only).
When the limit is hit the API answers 429; it never charges anything.
Per-IP limits are weak identification (shared NATs, rotating IPs) — they
exist to stop casual abuse of the free tier, not as real authentication.
API keys / paid tiers are a later step, not this file.
Behind a tunnel, every caller arrives via localhost, so the limit uses
CF-Connecting-IP first, then the first X-Forwarded-For hop, then the
direct peer address. Those headers are only trusted because the tunnel
itself sets them; direct localhost callers bypass them.

Security posture: binds 127.0.0.1 ONLY (localhost). Public exposure, if
wanted later, goes through a tunnel (e.g. cloudflared) that dials localhost
— this server itself never listens on a public interface. Only /health and
POST /check exist; every other path/method is rejected. Request bodies are
capped at 4 KB. The server never logs addresses or IPs beyond the daily
usage counter file.

Usage:
    python3 api_server.py            # localhost:8080, limit 10/day/IP
    HONEYPOT_API_PORT=8000 HONEYPOT_API_DAILY_LIMIT=50 python3 api_server.py

Run it next to honeypot_screener.py; it imports that module directly, so
the API always scores with exactly the same code as the CLI. No refactor
of the validated screener was needed: score_token() already returns
(verdict, points, lines, note).
"""

import json
import os
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import honeypot_screener as hs

PORT = int(os.environ.get("HONEYPOT_API_PORT", "8080"))
DAILY_LIMIT = int(os.environ.get("HONEYPOT_API_DAILY_LIMIT", "10"))
USAGE_FILE = os.environ.get(
    "HONEYPOT_API_USAGE_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "usage.json"),
)
MAX_BODY = 4096
usage_lock = threading.Lock()


def _today():
    return datetime.now(timezone.utc).date().isoformat()


def _load_usage():
    try:
        with open(USAGE_FILE) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_usage(data):
    tmp = USAGE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, USAGE_FILE)


def check_limit(ip):
    """Consume one free query for ip. Returns (allowed, remaining)."""
    with usage_lock:
        usage = _load_usage()
        entry = usage.get(ip) or {}
        if entry.get("date") != _today():
            entry = {"date": _today(), "count": 0}
        if entry["count"] >= DAILY_LIMIT:
            return False, 0
        entry["count"] += 1
        usage[ip] = entry
        _save_usage(usage)
        return True, DAILY_LIMIT - entry["count"]


def check_address(addr):
    """Mirror the CLI's report_one flow, but return data instead of printing."""
    info = None
    try:
        info = hs.fetch_goplus(addr)
    except Exception:
        info = None
    fb = {}
    if info is None:
        try:
            fb = hs.fallback_checks(addr)
        except Exception:
            fb = {}
    verdict, pts, lines, note = hs.score_token(addr, info, fb)
    return {
        "address": addr,
        "verdict": verdict,
        "points": pts,
        "signals": [{"status": s, "text": t, "points": p} for s, t, p in lines],
        "note": note,
        "source": "goplus" if info is not None else "fallback",
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep stdout clean
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/health"):
            self._json(200, {
                "status": "ok",
                "service": "honeypot-screener-api",
                "daily_limit_per_ip": DAILY_LIMIT,
            })
        else:
            self._json(404, {"error": "not found"})

    def _client_ip(self):
        # Behind a tunnel (e.g. cloudflared) every caller arrives via
        # localhost, so the per-IP limit must use the forwarded client IP.
        cf = self.headers.get("CF-Connecting-IP")
        if cf:
            return cf.strip()
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def do_POST(self):
        if self.path != "/check":
            self._json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY:
            self._json(413, {"error": "body too large"})
            return
        try:
            data = json.loads(self.rfile.read(length) if length else b"{}")
        except Exception:
            self._json(400, {"error": "invalid json"})
            return
        addr = (data.get("address") or "").strip()
        if not hs.valid_address(addr):
            self._json(400, {"error": "invalid address"})
            return
        ip = self._client_ip()
        allowed, remaining = check_limit(ip)
        if not allowed:
            self._json(429, {
                "error": "daily free limit reached",
                "limit": DAILY_LIMIT,
                "reset": "next UTC day",
            })
            return
        try:
            result = check_address(addr)
        except Exception as e:  # noqa: BLE001 - never crash the server
            self._json(502, {"error": f"check failed: {e}"})
            return
        result["rate_limit"] = {"limit": DAILY_LIMIT, "remaining": remaining}
        self._json(200, result)

    def do_PUT(self):
        self._json(405, {"error": "method not allowed"})

    do_DELETE = do_PUT
    do_PATCH = do_PUT


def main():
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"honeypot-screener-api listening on 127.0.0.1:{PORT} "
          f"(free limit {DAILY_LIMIT}/day/IP)")
    server.serve_forever()


if __name__ == "__main__":
    main()
