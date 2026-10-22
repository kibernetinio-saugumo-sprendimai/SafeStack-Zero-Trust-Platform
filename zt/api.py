"""Localhost-first dashboard and read-only JSON API with security headers."""
import html
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict
from urllib.parse import urlparse
from .store import Store


def snapshot(store: Store) -> Dict[str, Any]:
    """Capture consistent read-only snapshot of devices, policies, and decisions."""
    devices = [dict(x) for x in store.db.execute("SELECT * FROM devices ORDER BY name")]
    policies = [dict(x) for x in store.db.execute("SELECT * FROM policies ORDER BY id")]
    decisions = [dict(x) for x in store.db.execute("SELECT * FROM decisions ORDER BY id DESC LIMIT 100")]
    return {
        "devices": devices,
        "policies": policies,
        "decisions": decisions,
    }


def page(data: Dict[str, Any]) -> str:
    """Render a secure, lightweight, inline-styled Zero Trust control dashboard."""
    esc = lambda x: html.escape(str(x))
    cards = "".join(
        f"<article><b>{esc(k.title())}</b><strong>{len(v)}</strong></article>"
        for k, v in data.items()
    )
    rows = "".join(
        f"<tr><td>{esc(d.get('subject'))}</td><td>{esc(d.get('resource'))}</td>"
        f"<td class={'ok' if d.get('allowed') else 'bad'}>{'ALLOW' if d.get('allowed') else 'DENY'}</td>"
        f"<td>{esc(d.get('reason'))}</td></tr>"
        for d in data.get("decisions", [])[:20]
    )
    return (
        f'<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
        f'<title>SafeStack Zero Trust</title><style>'
        f"body{{margin:0;background:#0b1020;color:#e8eefc;font:15px system-ui}}"
        f"main{{max-width:1100px;margin:auto;padding:36px}}h1{{letter-spacing:.04em}}"
        f".accent{{color:#5eead4}}.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}}"
        f"article,section{{background:#121a30;border:1px solid #263657;border-radius:12px;padding:18px}}"
        f"strong{{display:block;font-size:32px;margin-top:8px}}table{{width:100%;border-collapse:collapse}}"
        f"td,th{{padding:10px;border-bottom:1px solid #263657;text-align:left}}"
        f".ok{{color:#5eead4}}.bad{{color:#fb7185}}small{{color:#91a4c5}}"
        f"</style><main><h1>SafeStack <span class=\"accent\">Zero Trust</span></h1>"
        f"<small>Local security control plane · default deny · read-only dashboard</small>"
        f"<div class=\"grid\">{cards}</div><section><h2>Recent decisions</h2>"
        f"<table><tr><th>Subject</th><th>Resource</th><th>Result</th><th>Reason</th></tr>"
        f"{rows}</table></section></main>"
    )


def create_handler(store: Store, token: str | None):
    """Factory creating an HTTP request handler configured with store and token."""

    class Handler(BaseHTTPRequestHandler):
        def send(self, body: str, content_type: str, status_code: int = 200) -> None:
            raw = body.encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            if token and not hmac.compare_digest(self.headers.get("Authorization", ""), f"Bearer {token}"):
                self.send_response(401)
                self.send_header("WWW-Authenticate", "Bearer")
                self.end_headers()
                return

            path = urlparse(self.path).path
            if path == "/health":
                self.send(json.dumps({"status": "ok", "service": "safestack-zero-trust"}), "application/json")
                return

            data = snapshot(store)
            if path == "/api/snapshot":
                self.send(json.dumps(data, default=str), "application/json")
                return
            if path == "/":
                self.send(page(data), "text/html; charset=utf-8")
                return

            self.send_error(404)

        def do_POST(self) -> None:
            self._method_not_allowed()

        def do_PUT(self) -> None:
            self._method_not_allowed()

        def do_DELETE(self) -> None:
            self._method_not_allowed()

        def _method_not_allowed(self) -> None:
            self.send_response(405)
            self.send_header("Allow", "GET")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args: Any) -> None:
            pass

    return Handler


def serve(
    db_path: str = "zero-trust.db",
    host: str = "127.0.0.1",
    port: int = 8787,
    allow_remote: bool = False,
    api_token: str | None = None,
) -> None:
    """Start HTTP server with security controls restricting exposure and binding."""
    if host not in ("127.0.0.1", "localhost", "::1") and not allow_remote:
        raise ValueError("remote binding requires explicit allow_remote=True")

    token = api_token or os.environ.get("SAFESTACK_API_TOKEN")
    if allow_remote and not token:
        raise ValueError("remote binding requires SAFESTACK_API_TOKEN")

    store = Store(db_path)
    handler_cls = create_handler(store, token)
    server = ThreadingHTTPServer((host, port), handler_cls)
    try:
        server.serve_forever()
    finally:
        store.close()
