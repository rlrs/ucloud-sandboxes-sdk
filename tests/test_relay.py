from __future__ import annotations

import asyncio
import base64
from collections.abc import Iterator
from contextlib import contextmanager
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Lock, Thread
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import ucloud_sandboxes_sdk.relay as relay_module
from ucloud_sandboxes_sdk import (
    AsyncRelayWorkerClient,
    RelayApiError,
    RelayRequest,
    RelayWorkerClient,
    http_tunnel_url,
    model_relay_env,
)


REGISTRATION_TOKEN = "0123456789abcdef0123456789abcdef"


class RelayUrlConfigTests(unittest.TestCase):
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

    def test_builds_general_http_tunnel_url(self) -> None:
        self.assertEqual(
            http_tunnel_url("https://relay.example.org/", "run:001"),
            "https://relay.example.org/tunnels/run%3A001/",
        )
        self.assertEqual(
            http_tunnel_url("https://relay.example.org/", "run:001", "/api/items"),
            "https://relay.example.org/tunnels/run%3A001/api/items",
        )

    def test_builds_registration_scoped_tunnel_capability_url(self) -> None:
        expected = (
            "https://relay.example.org/tunnels/run%3A001/_relay/"
            f"{REGISTRATION_TOKEN}/"
        )
        self.assertEqual(
            http_tunnel_url(
                "https://relay.example.org/",
                "run:001",
                registration_token=REGISTRATION_TOKEN,
            ),
            expected,
        )

    def test_rejects_invalid_tunnel_registration_capability(self) -> None:
        with self.assertRaisesRegex(RelayApiError, "registration_token"):
            http_tunnel_url(
                "https://relay.example.org",
                "run-001",
                registration_token="not-a-capability",
            )


class RelayWorkerClientTests(unittest.TestCase):
    def test_relay_request_requires_exact_identity(self) -> None:
        valid = _relay_request(rollout_id="run-001", leased_by="worker-1")

        for field in ("request_id", "rollout_id", "registration_token", "lease_id"):
            with self.subTest(field=field):
                payload = dict(valid)
                payload[field] = 123
                with self.assertRaises(RelayApiError):
                    RelayRequest.from_payload(payload)

        for token in ("", "A" * 32, "g" * 32, "0" * 31):
            with self.subTest(token=token):
                payload = dict(valid)
                payload["registration_token"] = token
                with self.assertRaises(RelayApiError):
                    RelayRequest.from_payload(payload)

    def test_relay_request_requires_exact_tagged_body(self) -> None:
        valid = _relay_request(rollout_id="run-001", leased_by="worker-1")
        for body in (
            None,
            {"encoding": "json"},
            {"encoding": "json", "value": {}, "extra": True},
            {"encoding": "text", "value": "payload"},
            {"encoding": "base64", "value": "%%%"},
        ):
            with self.subTest(body=body):
                with self.assertRaises(RelayApiError):
                    RelayRequest.from_payload({**valid, "body": body})

    def test_registration_requires_matching_rollout_and_valid_token(self) -> None:
        with running_relay() as relay:
            client = RelayWorkerClient(relay.base_url, worker_token="worker-token")
            relay.state.registration_rollout_id = "wrong-rollout"
            with self.assertRaisesRegex(RelayApiError, "rollout_id does not match"):
                client.register_rollout("run-001")

            relay.state.registration_rollout_id = None
            relay.state.registration_token = "not-a-capability"
            with self.assertRaisesRegex(RelayApiError, "registration_token"):
                client.register_rollout("run-001")

    def test_poll_requires_requested_rollout_and_registration(self) -> None:
        with running_relay() as relay:
            client = RelayWorkerClient(relay.base_url, worker_token="worker-token")
            client.register_rollout("run-001")

            relay.state.poll_rollout_id = "wrong-rollout"
            with self.assertRaisesRegex(RelayApiError, "different rollout"):
                client.poll("run-001", timeout_seconds=0)

            relay.state.poll_rollout_id = None
            relay.state.poll_registration_token = "a" * 32
            with self.assertRaisesRegex(RelayApiError, "different registration"):
                client.poll("run-001", timeout_seconds=0)

    def test_poll_timeout_includes_server_wait_for_sync_and_async(self) -> None:
        async def poll_async(base_url: str) -> None:
            async with AsyncRelayWorkerClient(
                base_url,
                worker_token="worker-token",
                timeout_seconds=0.02,
            ) as client:
                await client.register_rollout("run-async")
                result = await client.poll("run-async", timeout_seconds=0.1)
                self.assertEqual(len(result.requests), 1)

        with running_relay() as relay:
            relay.state.poll_delay_seconds = 0.05
            sync_client = RelayWorkerClient(
                relay.base_url,
                worker_token="worker-token",
                timeout_seconds=0.02,
            )
            sync_client.register_rollout("run-sync")
            self.assertEqual(
                len(sync_client.poll("run-sync", timeout_seconds=0.1).requests),
                1,
            )
            asyncio.run(poll_async(relay.base_url))

    def test_relay_transport_does_not_follow_redirects(self) -> None:
        async def stats_async(base_url: str) -> RelayApiError:
            async with AsyncRelayWorkerClient(
                base_url, worker_token="worker-token"
            ) as client:
                with self.assertRaises(RelayApiError) as raised:
                    await client.stats()
                return raised.exception

        with running_relay() as relay:
            relay.state.stats_redirect = True
            sync_client = RelayWorkerClient(relay.base_url, worker_token="worker-token")
            with self.assertRaises(RelayApiError) as raised:
                sync_client.stats()
            async_error = asyncio.run(stats_async(relay.base_url))

        self.assertEqual(raised.exception.status_code, HTTPStatus.FOUND)
        self.assertEqual(async_error.status_code, HTTPStatus.FOUND)
        self.assertEqual(raised.exception.headers["X-Relay-Request-Id"], "relay-test")
        self.assertEqual(async_error.headers["X-Relay-Request-Id"], "relay-test")

    def test_relay_transport_bounds_json_requests_and_responses(self) -> None:
        async def oversized_request_async() -> None:
            client = AsyncRelayWorkerClient("https://relay.invalid")
            with self.assertRaisesRegex(RelayApiError, "request body exceeds"):
                await client.register_rollout("run", metadata={"value": "x" * 128})

        async def oversized_response_async(base_url: str) -> RelayApiError:
            async with AsyncRelayWorkerClient(
                base_url, worker_token="worker-token"
            ) as client:
                with self.assertRaises(RelayApiError) as raised:
                    await client.stats()
                return raised.exception

        with patch.object(relay_module, "MAX_RELAY_JSON_BYTES", 64):
            client = RelayWorkerClient("https://relay.invalid")
            with self.assertRaisesRegex(RelayApiError, "request body exceeds"):
                client.register_rollout("run", metadata={"value": "x" * 128})
            asyncio.run(oversized_request_async())

            with running_relay() as relay:
                relay.state.stats_body = json.dumps({"value": "x" * 128}).encode()
                client = RelayWorkerClient(relay.base_url, worker_token="worker-token")
                with self.assertRaises(RelayApiError) as raised:
                    client.stats()
                async_error = asyncio.run(oversized_response_async(relay.base_url))

        self.assertEqual(raised.exception.status_code, HTTPStatus.OK)
        self.assertIn("64 byte limit", str(raised.exception))
        self.assertEqual(async_error.status_code, HTTPStatus.OK)
        self.assertIn("64 byte limit", str(async_error))

    def test_successful_relay_response_must_be_json(self) -> None:
        async def stats_async(base_url: str) -> RelayApiError:
            async with AsyncRelayWorkerClient(
                base_url, worker_token="worker-token"
            ) as client:
                with self.assertRaises(RelayApiError) as raised:
                    await client.stats()
                return raised.exception

        with running_relay() as relay:
            relay.state.stats_body = b"not-json"
            client = RelayWorkerClient(relay.base_url, worker_token="worker-token")
            with self.assertRaisesRegex(RelayApiError, "invalid JSON") as raised:
                client.stats()
            async_error = asyncio.run(stats_async(relay.base_url))

        self.assertEqual(raised.exception.status_code, HTTPStatus.OK)
        self.assertIn("invalid JSON", str(async_error))
        self.assertEqual(async_error.status_code, HTTPStatus.OK)

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
            self.assertEqual(len(poll.requests), 1)
            request = poll.requests[0]
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
        self.assertEqual(
            relay.state.last_poll_query["registration_token"],
            [REGISTRATION_TOKEN],
        )
        self.assertEqual(
            relay.state.last_renew_payload["registration_token"],
            REGISTRATION_TOKEN,
        )
        self.assertEqual(relay.state.last_renew_payload["lease_seconds"], 900)
        self.assertEqual(
            relay.state.last_respond_payload["headers"], {"X-Model": "local"}
        )
        self.assertEqual(
            relay.state.last_respond_payload["registration_token"],
            REGISTRATION_TOKEN,
        )
        self.assertEqual(
            relay.state.last_respond_payload["body"],
            {
                "encoding": "json",
                "value": {"choices": [{"message": {"content": "ok"}}]},
            },
        )
        self.assertNotIn("response", relay.state.last_respond_payload)
        self.assertNotIn("body_base64", relay.state.last_respond_payload)
        self.assertEqual(relay.state.last_error_payload["status"], 503)

    def test_sync_worker_client_forwards_binary_http_request_and_response(self) -> None:
        with running_relay() as relay:
            client = RelayWorkerClient(relay.base_url, worker_token="worker-token")
            relay_request = RelayRequest.from_payload(
                _relay_request(
                    rollout_id="binary-tunnel",
                    leased_by="worker-1",
                    endpoint="/upstream/echo?x=1",
                    body=b"\x00\xffrequest",
                    content_type="application/octet-stream",
                )
            )

            result = client.forward_to(relay_request, relay.base_url)

        self.assertEqual(result["request_id"], "req-1")
        self.assertEqual(relay.state.upstream_method, "POST")
        self.assertEqual(relay.state.upstream_path, "/upstream/echo?x=1")
        self.assertEqual(relay.state.upstream_body, b"\x00\xffrequest")
        self.assertEqual(relay.state.last_respond_payload["status"], 207)
        self.assertEqual(
            base64.b64decode(relay.state.last_respond_payload["body"]["value"]),
            b"\xffresponse",
        )
        self.assertEqual(
            relay.state.last_respond_payload["body"]["encoding"],
            "base64",
        )

    def test_binary_response_limit_is_checked_before_base64_encoding(self) -> None:
        relay_request = RelayRequest.from_payload(
            _relay_request(rollout_id="bounded", leased_by="worker")
        )

        async def respond_async() -> None:
            client = AsyncRelayWorkerClient("https://relay.invalid")
            with self.assertRaisesRegex(RelayApiError, "4 byte limit"):
                await client.respond_to(relay_request, b"12345")

        with (
            patch.object(relay_module, "MAX_RELAY_HTTP_BODY_BYTES", 4),
            patch.object(relay_module.base64, "b64encode") as encode,
        ):
            client = RelayWorkerClient("https://relay.invalid")
            with self.assertRaisesRegex(RelayApiError, "4 byte limit"):
                client.respond_to(relay_request, b"12345")
            asyncio.run(respond_async())

        encode.assert_not_called()

    def test_forwarding_bounds_sync_and_async_upstream_responses(self) -> None:
        async def forward_async(base_url: str, relay_request: RelayRequest) -> None:
            async with AsyncRelayWorkerClient(
                base_url, worker_token="worker-token"
            ) as client:
                with self.assertRaisesRegex(RelayApiError, "4 byte limit"):
                    await client.forward_to(relay_request, base_url)

        with patch.object(relay_module, "MAX_RELAY_HTTP_BODY_BYTES", 4):
            relay_request = RelayRequest.from_payload(
                _relay_request(
                    rollout_id="bounded-tunnel",
                    leased_by="worker-1",
                    endpoint="/upstream/echo",
                    body=b"x",
                    content_type="application/octet-stream",
                )
            )
            with running_relay() as relay:
                relay.state.upstream_response_body = b"12345"
                client = RelayWorkerClient(relay.base_url, worker_token="worker-token")
                with self.assertRaisesRegex(RelayApiError, "4 byte limit"):
                    client.forward_to(relay_request, relay.base_url)
                asyncio.run(forward_async(relay.base_url, relay_request))

        self.assertEqual(relay.state.respond_attempts, 0)

    def test_sync_response_commit_retries_wake_pending_503(self) -> None:
        with running_relay() as relay:
            relay.state.respond_failures = 1
            client = RelayWorkerClient(relay.base_url, worker_token="worker-token")
            relay_request = RelayRequest.from_payload(
                _relay_request(rollout_id="retry", leased_by="worker")
            )
            result = client.commit_response_bytes_to(
                relay_request,
                b"committed",
                attempts=2,
                retry_delay_seconds=0,
            )

        self.assertEqual(result["request_id"], "req-1")
        self.assertEqual(relay.state.respond_attempts, 2)

    def test_sync_worker_client_surfaces_auth_errors(self) -> None:
        with running_relay() as relay:
            client = RelayWorkerClient(relay.base_url)

            with self.assertRaises(RelayApiError) as raised:
                client.stats()

        self.assertEqual(raised.exception.status_code, HTTPStatus.UNAUTHORIZED)
        self.assertEqual(raised.exception.body, {"error": "unauthorized"})
        self.assertEqual(raised.exception.headers["X-Relay-Request-Id"], "relay-test")

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
                self.assertEqual(len(poll.requests), 1)
                renewed = await client.renew_request(
                    poll.requests[0],
                    worker_id="worker-async",
                    lease_seconds=1200,
                )
                response = await client.respond_to(renewed, {"choices": []})
                return (
                    renewed.request_id,
                    renewed.lease_expires_at,
                    response["request_id"],
                )

        with running_relay() as relay:
            renewed_id, lease_expires_at, responded_id = asyncio.run(
                scenario(relay.base_url)
            )

        self.assertEqual(renewed_id, "req-1")
        self.assertEqual(lease_expires_at, 456.0)
        self.assertEqual(responded_id, "req-1")
        self.assertEqual(relay.state.last_renew_payload["lease_seconds"], 1200)

    def test_async_response_commit_retries_wake_pending_503(self) -> None:
        async def scenario(base_url: str) -> dict:
            async with AsyncRelayWorkerClient(
                base_url,
                worker_token="worker-token",
            ) as client:
                return await client.commit_response_bytes_to(
                    RelayRequest.from_payload(
                        _relay_request(rollout_id="retry", leased_by="worker")
                    ),
                    b"committed",
                    attempts=2,
                    retry_delay_seconds=0,
                )

        with running_relay() as relay:
            relay.state.respond_failures = 1
            result = asyncio.run(scenario(relay.base_url))

        self.assertEqual(result["request_id"], "req-1")
        self.assertEqual(relay.state.respond_attempts, 2)


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
        self.upstream_method = ""
        self.upstream_path = ""
        self.upstream_body = b""
        self.upstream_response_body = b"\xffresponse"
        self.respond_failures = 0
        self.respond_attempts = 0
        self.registration_rollout_id: str | None = None
        self.registration_token = REGISTRATION_TOKEN
        self.poll_rollout_id: str | None = None
        self.poll_registration_token: str | None = None
        self.poll_delay_seconds = 0.0
        self.stats_redirect = False
        self.stats_body: bytes | None = None


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
            if self.state.stats_redirect:
                self._write_bytes(
                    b"",
                    status=HTTPStatus.FOUND,
                    headers={"Location": "/redirect-target"},
                )
                return
            if self.state.stats_body is not None:
                self._write_bytes(
                    self.state.stats_body, content_type="application/json"
                )
                return
            self._write_json({"counters": {"lease_renewed": 1}})
            return
        if parsed.path == "/redirect-target":
            self._write_json({"redirected": True})
            return
        if parsed.path == "/v1/relay/rollouts":
            with self.state.lock:
                rollouts = list(self.state.rollouts.values())
            self._write_json({"rollouts": rollouts})
            return
        if parsed.path == "/worker/poll":
            query = parse_qs(parsed.query)
            if self.state.poll_delay_seconds:
                time.sleep(self.state.poll_delay_seconds)
            with self.state.lock:
                self.state.last_poll_query = query
            request = _relay_request(
                rollout_id=(
                    self.state.poll_rollout_id or query.get("rollout_id", [""])[0]
                ),
                leased_by=query.get("worker_id", [""])[0],
                registration_token=(
                    self.state.poll_registration_token
                    or query.get("registration_token", [""])[0]
                ),
            )
            self._write_json({"requests": [request]})
            return
        self._write_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/upstream/echo":
            body = self.rfile.read(int(self.headers.get("Content-Length") or "0"))
            with self.state.lock:
                self.state.upstream_method = "POST"
                self.state.upstream_path = self.path
                self.state.upstream_body = body
            self._write_bytes(
                self.state.upstream_response_body,
                status=207,
                content_type="application/octet-stream",
            )
            return
        if not self._check_authorized():
            return
        payload = self._read_json()
        if parsed.path == "/v1/relay/rollouts":
            rollout_id = str(payload.get("rollout_id") or "")
            record = {
                "rollout_id": self.state.registration_rollout_id or rollout_id,
                "registration_token": self.state.registration_token,
                "metadata": dict(payload.get("metadata") or {}),
            }
            with self.state.lock:
                self.state.rollouts[rollout_id] = record
            self._write_json({"ok": True, "rollout": record}, status=HTTPStatus.CREATED)
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
                self.state.respond_attempts += 1
                if self.state.respond_failures > 0:
                    self.state.respond_failures -= 1
                    self._write_json(
                        {"error": "response committed but wake is pending"},
                        status=HTTPStatus.SERVICE_UNAVAILABLE,
                    )
                    return
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

    def do_DELETE(self) -> None:
        parsed = urlparse(self.path)
        if not self._check_authorized():
            return
        self._read_json()
        prefix = "/v1/relay/rollouts/"
        if parsed.path.startswith(prefix):
            rollout_id = parsed.path.removeprefix(prefix)
            with self.state.lock:
                existed = self.state.rollouts.pop(rollout_id, None) is not None
            self._write_json({"ok": True, "rollout_id": rollout_id, "existed": existed})
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
        self._write_bytes(body, status=status, content_type="application/json")

    def _write_bytes(
        self,
        body: bytes,
        *,
        status: int = 200,
        content_type: str = "application/octet-stream",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Relay-Request-Id", "relay-test")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)


def _relay_request(
    *,
    rollout_id: str,
    leased_by: str,
    lease_expires_at: float = 123.0,
    endpoint: str = "/v1/chat/completions",
    body: bytes | None = None,
    content_type: str = "application/json",
    registration_token: str = REGISTRATION_TOKEN,
) -> dict:
    json_body = {"model": "test-model", "messages": []}
    raw_body = body if body is not None else json.dumps(json_body).encode("utf-8")
    return {
        "request_id": "req-1",
        "rollout_id": rollout_id,
        "registration_token": registration_token,
        "endpoint": endpoint,
        "method": "POST",
        "headers": {"X-Relay": "yes", "Content-Type": content_type},
        "body": (
            {"encoding": "json", "value": json_body}
            if body is None
            else {
                "encoding": "base64",
                "value": base64.b64encode(raw_body).decode("ascii"),
            }
        ),
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
