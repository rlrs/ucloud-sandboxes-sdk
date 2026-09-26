from __future__ import annotations

import http.client
import json
import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from ucloud_sandboxes_sdk import SandboxApiError, SandboxClient
from ucloud_sandboxes_sdk import _http


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args: object) -> None:
        pass

    def _reply(self, status: int, payload: object, *, close: bool = False) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self.server.peers.append(self.client_address)
        if self.path == "/v1/sandboxes/missing":
            self._reply(404, {"error": "sandbox not found"})
        elif self.path == "/v1/sandboxes/closing":
            self._reply(200, {"id": "closing"}, close=True)
        else:
            self._reply(200, {"id": self.path.rsplit("/", 1)[-1]})

    def do_POST(self) -> None:
        self.server.peers.append(self.client_address)
        length = int(self.headers.get("Content-Length", "0"))
        self.server.bodies.append(self.rfile.read(length))
        self._reply(200, {"sandboxes": []})


class SyncKeepaliveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.daemon_threads = True
        self.server.peers = []
        self.server.bodies = []
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.client = SandboxClient(self.url, timeout_seconds=10)
        self.pool = _http._ConnectionPool(5.0, 16)
        patcher = patch.object(_http, "_POOL", self.pool)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self._close_idle)

    def _close_idle(self) -> None:
        for idle in self.pool._idle.values():
            for conn, _ in idle:
                conn.close()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def get(self, name: str) -> dict:
        return self.client._request_json("GET", f"/v1/sandboxes/{name}")

    def test_sequential_requests_share_one_connection(self) -> None:
        for name in ("a", "b", "c"):
            self.assertEqual(self.get(name)["id"], name)
        self.assertEqual(len(set(self.server.peers)), 1)

    def test_error_response_is_read_and_connection_kept(self) -> None:
        with self.assertRaises(SandboxApiError) as caught:
            self.get("missing")
        self.assertEqual(caught.exception.status_code, 404)
        self.assertEqual(self.get("after")["id"], "after")
        self.assertEqual(len(set(self.server.peers)), 1)

    def test_server_close_and_idle_expiry_open_new_connections(self) -> None:
        self.get("closing")
        self.get("next")
        self.assertEqual(len(set(self.server.peers)), 2)
        self.pool.idle_seconds = 0.01
        time.sleep(0.05)
        self.get("later")
        self.assertEqual(len(set(self.server.peers)), 3)

    def test_post_bodies_are_sent_on_reused_connections(self) -> None:
        self.get("first")
        self.client._request_json("POST", "/v1/probe", payload={"n": 1})
        self.client._request_json("POST", "/v1/probe", payload={"n": 2})
        self.assertEqual([json.loads(body) for body in self.server.bodies], [{"n": 1}, {"n": 2}])
        self.assertEqual(len(set(self.server.peers)), 1)

    def test_peer_closed_idle_connection_is_dropped(self) -> None:
        local, peer = socket.socketpair()
        conn = http.client.HTTPConnection("127.0.0.1")
        conn.sock = local
        self.addCleanup(conn.close)
        self.assertFalse(_http._dropped(conn))
        peer.close()
        self.assertTrue(_http._dropped(conn))
        key = ("http", "127.0.0.1", 1)
        self.pool.give(key, conn)
        self.assertIsNone(self.pool.take(key))

    def test_connection_refused_is_a_pre_dispatch_failure(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        client = SandboxClient(self.url, timeout_seconds=1)
        with patch("ucloud_sandboxes_sdk.client._sleep_for_retry", return_value=False):
            with self.assertRaisesRegex(SandboxApiError, "connection failed"):
                client.get_sandbox("x")


if __name__ == "__main__":
    unittest.main()
