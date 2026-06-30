from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Lock, Thread
import unittest
from urllib.parse import parse_qs, urlparse

from ucloud_sandboxes_sdk import (
    AsyncRelayWorkerClient,
    ModelRelayConfig,
    RelayApiError,
    RelayWorkerClient,
    model_relay_env,
)


class ModelRelayConfigTests(unittest.TestCase):
    def test_builds_path_scoped_openai_environment(self) -> None:
        env = model_relay_env(
            "https://relay.example.org/",
            "run:001",
            api_key="sandbox-token",
        )

        self.assertEqual(env["VF_RELAY_ROLLOUT_ID"], "run:001")
        self.assertEqual(
            env["OPENAI_BASE_URL"],
            "https://relay.example.org/rollouts/run%3A001/v1",
        )
        self.assertEqual(env["OPENAI_API_KEY"], "sandbox-token")

    def test_can_build_plain_v1_environment_for_custom_header_transport(self) -> None:
        config = ModelRelayConfig(
            "https://relay.example.org",
            "run-001",
            path_scoped_base_url=False,
        )

        self.assertEqual(config.openai_base_url, "https://relay.example.org/v1")


class RelayWorkerClientTests(unittest.TestCase):
    def test_sync_worker_client_supports_full_lease_lifecycle(self) -> None:
        with running_relay() as relay:
            client = RelayWorkerClient(relay.base_url, worker_token="worker-token")

            health = client.health()
            registered = client.register_rollout(
                "run-001",
                metadata={"suite": "sync"},
            )
            heartbeat = client.heartbeat(
                "run-001",
                "worker-1",
                metadata={"host": "lumi"},
            )
            poll = client.poll(
                "run-001",
                worker_id="worker-1",
                timeout_seconds=0,
                limit=8,
                lease_seconds=600,
            )
            self.assertIsNotNone(poll.request)
            request = poll.request
            assert request is not None
            renewed = client.renew_request(
                request,
                worker_id="worker-1",
                lease_seconds=900,
            )
            responded = client.respond_to(
                renewed,
                {"choices": [{"message": {"content": "ok"}}]},
                headers={"X-Model": "local"},
            )
            errored = client.error_request(renewed, "model failed", status=503)
            stats = client.stats()
            rollouts = client.list_rollouts()
            unregistered = client.unregister_rollout("run-001")

        self.assertTrue(health["ok"])
        self.assertEqual(registered["rollout"]["metadata"], {"suite": "sync"})
        self.assertEqual(heartbeat["worker"]["worker_id"], "worker-1")
        self.assertEqual(request.request_id, "req-1")
        self.assertEqual(request.lease_id, "lease-1")
        self.assertEqual(request.body["model"], "test-model")
        self.assertEqual(renewed.lease_expires_at, 456.0)
        self.assertEqual(responded["request_id"], "req-1")
        self.assertFalse(responded["duplicate"])
        self.assertTrue(errored["duplicate"])
        self.assertEqual(stats["counters"]["lease_renewed"], 1)
        self.assertEqual(rollouts[0]["rollout_id"], "run-001")
        self.assertTrue(unregistered["existed"])
        self.assertEqual(relay.state.last_poll_query["limit"], ["8"])
        self.assertEqual(relay.state.last_poll_query["lease_seconds"], ["600"])
        self.assertEqual(relay.state.last_renew_payload["lease_seconds"], 900)
        self.assertEqual(relay.state.last_respond_payload["headers"], {"X-Model": "local"})
        self.assertEqual(relay.state.last_error_payload["status"], 503)

    def test_sync_worker_client_surfaces_auth_errors(self) -> None:
        with running_relay() as relay:
            client = RelayWorkerClient(relay.base_url)

            with self.assertRaises(RelayApiError) as raised:
                client.stats()

        self.assertEqual(raised.exception.status_code, HTTPStatus.UNAUTHORIZED)
        self.assertEqual(raised.exception.body, {"error": "unauthorized"})

    def test_async_worker_client_supports_lease_renewal(self) -> None:
        async def scenario(base_url: str) -> tuple[str, float | None, str]:
            async with AsyncRelayWorkerClient(
                base_url,
                worker_token="worker-token",
            ) as client:
                await client.register_rollout("run-async")
                poll = await client.poll(
                    "run-async",
                    worker_id="worker-async",
                    timeout_seconds=0,
                    lease_seconds=600,
                )
                assert poll.request is not None
                renewed = await client.renew_request(
                    poll.request,
                    worker_id="worker-async",
                    lease_seconds=1200,
                )
                response = await client.respond_to(renewed, {"choices": []})
                return renewed.request_id, renewed.lease_expires_at, response["request_id"]

        with running_relay() as relay:
            renewed_id, lease_expires_at, responded_id = asyncio.run(
                scenario(relay.base_url)
            )

        self.assertEqual(renewed_id, "req-1")
        self.assertEqual(lease_expires_at, 456.0)
        self.assertEqual(responded_id, "req-1")
        self.assertEqual(relay.state.last_renew_payload["lease_seconds"], 1200)


@contextmanager
def running_relay() -> Iterator["RelayHandle"]:
    state = FakeRelayState()

    class Handler(FakeRelayHandler):
        pass

    Handler.state = state
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield RelayHandle(base_url=f"http://{host}:{port}", state=state)
    finally:
        server.shutdown()
        server.server_close()


class RelayHandle:
    def __init__(self, *, base_url: str, state: "FakeRelayState") -> None:
        self.base_url = base_url
        self.state = state


class FakeRelayState:
    def __init__(self) -> None:
        self.lock = Lock()
        self.rollouts: dict[str, dict] = {}
        self.last_poll_query: dict[str, list[str]] = {}
        self.last_renew_payload: dict = {}
        self.last_respond_payload: dict = {}
        self.last_error_payload: dict = {}


class FakeRelayHandler(BaseHTTPRequestHandler):
    state: FakeRelayState
    server_version = "fake-ucloud-relay/0.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/healthz":
            self._write_json({"ok": True})
            return
        if not self._check_authorized():
            return
        if parsed.path == "/v1/relay/stats":
            self._write_json({"counters": {"lease_renewed": 1}})
            return
        if parsed.path == "/v1/relay/rollouts":
            with self.state.lock:
                rollouts = list(self.state.rollouts.values())
            self._write_json({"rollouts": rollouts})
            return
        if parsed.path == "/worker/poll":
            query = parse_qs(parsed.query)
            with self.state.lock:
                self.state.last_poll_query = query
            request = _relay_request(
                rollout_id=query.get("rollout_id", [""])[0],
                leased_by=query.get("worker_id", [""])[0],
            )
            self._write_json({"request": request, "requests": [request]})
            return
        self._write_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if not self._check_authorized():
            return
        parsed = urlparse(self.path)
        payload = self._read_json()
        if parsed.path == "/register_rollout":
            rollout_id = str(payload.get("rollout_id") or "")
            record = {
                "rollout_id": rollout_id,
                "metadata": dict(payload.get("metadata") or {}),
            }
            with self.state.lock:
                self.state.rollouts[rollout_id] = record
            self._write_json({"ok": True, "rollout": record}, status=HTTPStatus.CREATED)
            return
        if parsed.path == "/unregister_rollout":
            rollout_id = str(payload.get("rollout_id") or "")
            with self.state.lock:
                existed = self.state.rollouts.pop(rollout_id, None) is not None
            self._write_json({"ok": True, "rollout_id": rollout_id, "existed": existed})
            return
        if parsed.path == "/worker/heartbeat":
            self._write_json(
                {
                    "ok": True,
                    "worker": {
                        "rollout_id": payload.get("rollout_id"),
                        "worker_id": payload.get("worker_id"),
                        "metadata": payload.get("metadata") or {},
                    },
                }
            )
            return
        if parsed.path == "/worker/renew":
            with self.state.lock:
                self.state.last_renew_payload = dict(payload)
            self._write_json(
                {
                    "ok": True,
                    "request": _relay_request(
                        rollout_id="run-001",
                        leased_by=str(payload.get("worker_id") or ""),
                        lease_expires_at=456.0,
                    ),
                }
            )
            return
        if parsed.path == "/worker/respond":
            with self.state.lock:
                self.state.last_respond_payload = dict(payload)
            self._write_json(
                {
                    "ok": True,
                    "request_id": payload.get("request_id"),
                    "duplicate": False,
                }
            )
            return
        if parsed.path == "/worker/error":
            with self.state.lock:
                self.state.last_error_payload = dict(payload)
            self._write_json(
                {
                    "ok": True,
                    "request_id": payload.get("request_id"),
                    "duplicate": True,
                }
            )
            return
        self._write_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def _check_authorized(self) -> bool:
        if self.headers.get("Authorization") == "Bearer worker-token":
            return True
        self._write_json({"error": "unauthorized"}, status=HTTPStatus.UNAUTHORIZED)
        return False

    def _read_json(self) -> dict:
        raw = self.rfile.read(int(self.headers.get("Content-Length") or "0"))
        decoded = json.loads(raw.decode("utf-8")) if raw else {}
        return decoded if isinstance(decoded, dict) else {}

    def _write_json(
        self,
        payload: object,
        *,
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _relay_request(
    *,
    rollout_id: str,
    leased_by: str,
    lease_expires_at: float = 123.0,
) -> dict:
    return {
        "request_id": "req-1",
        "rollout_id": rollout_id,
        "endpoint": "/v1/chat/completions",
        "method": "POST",
        "headers": {"X-Relay": "yes"},
        "body": {"model": "test-model", "messages": []},
        "created_at": 1.0,
        "delivered_at": 2.0,
        "first_delivered_at": 2.0,
        "lease_id": "lease-1",
        "lease_expires_at": lease_expires_at,
        "leased_by": leased_by,
        "delivery_count": 1,
    }


if __name__ == "__main__":
    unittest.main()
