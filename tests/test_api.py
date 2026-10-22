"""Tests for Zero Trust HTTP API and dashboard."""
import io
import json
import unittest
from urllib.request import Request, urlopen
from zt.api import create_handler, page, serve, snapshot
from zt.store import Store


class DummySocket:
    def __init__(self, request_bytes: bytes):
        self.rfile = io.BytesIO(request_bytes)
        self.wfile = io.BytesIO()

    def makefile(self, mode, *args, **kwargs):
        if "r" in mode:
            return self.rfile
        return self.wfile

    def sendall(self, data):
        self.wfile.write(data)

    def close(self):
        pass


class ApiTests(unittest.TestCase):
    def test_dashboard_escapes_data(self):
        out = page({
            "devices": [],
            "policies": [],
            "decisions": [{"subject": "<script>alert(1)</script>", "resource": "r", "allowed": 0, "reason": "deny"}],
        })
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", out)
        self.assertNotIn("<script>alert(1)</script>", out)
        self.assertIn("SafeStack", out)

    def test_remote_binding_requires_opt_in(self):
        with self.assertRaises(ValueError):
            serve("/tmp/zt-test.db", "0.0.0.0", 8787)

    def test_remote_binding_requires_token(self):
        with self.assertRaises(ValueError):
            serve("/tmp/zt-test.db", "0.0.0.0", 8787, allow_remote=True, api_token=None)

    def test_snapshot_structure(self):
        with Store(":memory:") as store:
            store.add_device(("d1", "node", "alice", "compliant", "now"))
            data = snapshot(store)
            self.assertIn("devices", data)
            self.assertIn("policies", data)
            self.assertIn("decisions", data)
            self.assertEqual(len(data["devices"]), 1)

    def test_handler_security_headers_and_status(self):
        with Store(":memory:") as store:
            handler_cls = create_handler(store, token=None)
            sock = DummySocket(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
            handler = handler_cls(sock, ("127.0.0.1", 12345), None)
            response = sock.wfile.getvalue().decode("utf-8")

            self.assertIn("HTTP/1.0 200 OK", response)
            self.assertIn("X-Content-Type-Options: nosniff", response)
            self.assertIn("X-Frame-Options: DENY", response)
            self.assertIn("Content-Security-Policy", response)
            self.assertIn("service", response)

    def test_handler_method_not_allowed(self):
        with Store(":memory:") as store:
            handler_cls = create_handler(store, token=None)
            sock = DummySocket(b"POST /api/snapshot HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
            handler = handler_cls(sock, ("127.0.0.1", 12345), None)
            response = sock.wfile.getvalue().decode("utf-8")

            self.assertIn("405", response)
            self.assertIn("Allow: GET", response)
