from __future__ import annotations

import asyncio
import base64
from collections.abc import Iterator
from contextlib import contextmanager
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Event, Lock, Thread
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import ucloud_sandboxes_sdk.relay as relay_module
from ucloud_sandboxes_sdk import (
    AsyncRelayWorkerClient,
    RelayApiError,
    RelayRequest,
    RelayResponse,
    RelayWorkerClient,
    http_tunnel_url,
    model_relay_env,
)


REGISTRATION_TOKEN = "0123456789abcdef0123456789abcdef"
RENEWAL_IDENTITY_MUTATIONS = (
    ("request_id", "request_id", "another-request"),
    ("rollout_id", "rollout_id", "another-rollout"),
    ("registration_token", "registration_token", "f" * 32),
    ("endpoint", "endpoint", "/v1/responses"),
    ("method", "method", "GET"),
    ("headers", "headers", {"X-Relay": "changed"}),
    (
        "JSON body",
        "body",
        {"encoding": "json", "value": {"model": "changed"}},
    ),
    (
        "body representation",
        "body",
        {
            "encoding": "base64",
            "value": base64.b64encode(b'{"model":"test-model","messages":[]}').decode(),
        },
    ),
    ("created_at", "created_at", 9.0),
    ("expires_at", "expires_at", 99.0),
    ("delivered_at", "delivered_at", 9.0),
    ("first_delivered_at", "first_delivered_at", 9.0),
    ("lease_id", "lease_id", "another-lease"),
    ("leased_by", "leased_by", "another-worker"),
    ("delivery_count", "delivery_count", 2),
    ("idempotency_key", "idempotency_key", "another-idempotency-key"),
    ("sandbox_id", "sandbox_id", "another-sandbox"),
    ("sandbox_generation", "sandbox_generation", 8),
)
RENEWAL_TRANSPORT_ROLLBACKS = (
    ("reattachable", {"reattachable": True}, {"reattachable": False}),
    (
        "accepted_notified_at",
        {"accepted_notified_at": 4.0},
        {"accepted_notified_at": 5.0},
    ),
    (
        "parked_transport_epoch",
        {"accepted_notified_at": 4.0, "parked_transport_epoch": "epoch-one"},
        {"parked_transport_epoch": "epoch-two"},
    ),
)


class RelayUrlConfigTests(unittest.TestCase):
    def test_builds_path_scoped_urls_and_openai_environment(self) -> None:
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
        self.assertEqual(
            http_tunnel_url("https://relay.example.org/", "run:001", "/api/items"),
            "https://relay.example.org/tunnels/run%3A001/api/items",
        )

    def test_rejects_invalid_tunnel_registration_capability(self) -> None:
        with self.assertRaisesRegex(RelayApiError, "registration_token"):
            http_tunnel_url(
                "https://relay.example.org",
                "run-001",
                registration_token="not-a-capability",
            )


class RelayWorkerClientTests(unittest.TestCase):
    def test_relay_error_and_environment_configuration_match_sandbox_semantics(
        self,
    ) -> None:
        error = RelayApiError(
            "busy",
            status_code=503,
            body={"retryable": True},
            headers={"Retry-After": "2.5"},
        )
        client = RelayWorkerClient.from_env(
            env={
                "UCLOUD_RELAY_URL": "https://relay.example/",
                "UCLOUD_RELAY_WORKER_TOKEN": "worker-secret",
                "UCLOUD_RELAY_TIMEOUT_SECONDS": "45",
            }
        )

        self.assertTrue(error.retryable)
        self.assertEqual(error.retry_after_seconds, 2.5)
        self.assertEqual(client.relay_url, "https://relay.example")
        self.assertEqual(client.timeout_seconds, 45.0)
        self.assertEqual(client.headers["Authorization"], "Bearer worker-secret")

    def test_managed_sync_session_renews_and_unregisters(self) -> None:
        cancel = Event()

        def handle(_request: RelayRequest) -> RelayResponse:
            cancel.set()
            Event().wait(0.04)
            return RelayResponse(
                {"choices": []},
                headers={"X-Model": "local"},
            )

        with running_relay() as relay:
            client = RelayWorkerClient(relay.base_url, worker_token="worker-token")
            with client.rollout_session("run-managed", worker_id="worker-1") as session:
                self.assertIn(REGISTRATION_TOKEN, session.base_url)
                self.assertTrue(session.openai_base_url.endswith("/v1"))
                session.run(
                    handler=handle,
                    cancel=cancel,
                    max_concurrency=1,
                    poll_timeout_seconds=0,
                    lease_seconds=0.06,
                    renewal_interval_seconds=0.01,
                )
                self.assertIn("run-managed", relay.state.rollouts)

            self.assertNotIn("run-managed", relay.state.rollouts)
            self.assertGreaterEqual(relay.state.renew_attempts, 1)
            self.assertEqual(relay.state.respond_attempts, 1)

    def test_managed_async_session_runs_handler_and_unregisters(self) -> None:
        async def scenario(base_url: str, state: FakeRelayState) -> None:
            cancel = asyncio.Event()

            async def handle(_request: RelayRequest) -> dict:
                cancel.set()
                await asyncio.sleep(0)
                return {"choices": []}

            async with AsyncRelayWorkerClient(
                base_url,
                worker_token="worker-token",
            ) as client:
                async with client.rollout_session(
                    "run-async-managed",
                    worker_id="worker-async",
                ) as session:
                    await session.run(
                        handler=handle,
                        cancel=cancel,
                        max_concurrency=1,
                        poll_timeout_seconds=0,
                        lease_seconds=1,
                        renewal_interval_seconds=0.1,
                    )
                    self.assertIn("run-async-managed", state.rollouts)
                self.assertNotIn("run-async-managed", state.rollouts)

        with running_relay() as relay:
            asyncio.run(scenario(relay.base_url, relay.state))

    def test_worker_rejects_streaming_model_requests_explicitly(self) -> None:
        cancel = Event()
        called = False

        def handle(_request: RelayRequest) -> dict:
            nonlocal called
            called = True
            return {}

        with running_relay() as relay:
            relay.state.poll_overrides = {
                "body": {
                    "encoding": "json",
                    "value": {"model": "test-model", "stream": True},
                }
            }
            relay.state.cancel_event = cancel
            client = RelayWorkerClient(relay.base_url, worker_token="worker-token")
            client.register_rollout("streaming-run")
            client.run_worker(
                "streaming-run",
                handler=handle,
                cancel=cancel,
                max_concurrency=1,
                poll_timeout_seconds=0,
                lease_seconds=1,
            )

        self.assertFalse(called)
        self.assertEqual(relay.state.last_error_payload["status"], 400)
        self.assertIn("streaming", relay.state.last_error_payload["error"])

    def test_agent_rollout_registration_binds_sandbox_generation(self) -> None:
        sandbox = SimpleNamespace(
            id="sandbox-agent",
            record={
                "generation": 7,
                "spec": {
                    "id": "sandbox-agent",
                    "parkable": True,
                    "managed_process": True,
                },
            },
        )
        with running_relay() as relay:
            client = RelayWorkerClient(relay.base_url, worker_token="worker-token")
            registered = client.register_agent_rollout(
                "run-agent",
                sandbox,
                metadata={"suite": "agent"},
            )

        self.assertEqual(
            registered["rollout"]["metadata"],
            {
                "_ucloud_agent_lifecycle": "managed-process-v1",
                "sandbox_generation": 7,
                "sandbox_id": "sandbox-agent",
                "suite": "agent",
            },
        )
        with self.assertRaisesRegex(RelayApiError, "conflicts"):
            RelayWorkerClient("https://relay.invalid").register_agent_rollout(
                "run-agent",
                sandbox,
                metadata={"sandbox_generation": 8},
            )

        with self.assertRaisesRegex(RelayApiError, "register_agent_rollout"):
            RelayWorkerClient("https://relay.invalid").register_rollout(
                "run-agent",
                metadata={
                    "sandbox_id": "sandbox-agent",
                    "sandbox_generation": 7,
                },
            )

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

    def test_sync_worker_client_supports_full_lease_lifecycle(self) -> None:
        with running_relay() as relay:
            client = RelayWorkerClient(relay.base_url, worker_token="worker-token")
            registered = client.register_rollout(
                "run-001",
                metadata={"suite": "sync"},
            )
            request = client.poll(
                "run-001",
                worker_id="worker-1",
                timeout_seconds=0,
                lease_seconds=600,
            ).requests[0]
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
            unregistered = client.unregister_rollout("run-001")

        self.assertEqual(registered["rollout"]["metadata"], {"suite": "sync"})
        self.assertEqual(request.request_id, "req-1")
        self.assertEqual(request.lease_id, "lease-1")
        self.assertEqual(request.body["model"], "test-model")
        self.assertEqual(renewed.lease_expires_at, 456.0)
        self.assertEqual(responded["request_id"], "req-1")
        self.assertFalse(responded["duplicate"])
        self.assertTrue(unregistered["existed"])

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

    def test_sync_worker_client_surfaces_auth_errors(self) -> None:
        with running_relay() as relay:
            client = RelayWorkerClient(relay.base_url)

            with self.assertRaises(RelayApiError) as raised:
                client.stats()

        self.assertEqual(raised.exception.status_code, HTTPStatus.UNAUTHORIZED)
        self.assertEqual(raised.exception.body, {"error": "unauthorized"})
        self.assertEqual(raised.exception.headers["X-Relay-Request-Id"], "relay-test")

    def test_sync_worker_rejects_mutated_renewal_delivery_contract(self) -> None:
        with running_relay() as relay:
            client = RelayWorkerClient(relay.base_url, worker_token="worker-token")
            client.register_rollout("expected-rollout")
            request = client.poll(
                "expected-rollout",
                worker_id="worker",
                timeout_seconds=0,
            ).requests[0]

            for label, field, value in RENEWAL_IDENTITY_MUTATIONS:
                with self.subTest(field=label):
                    relay.state.renew_overrides = {field: value}
                    with self.assertRaisesRegex(RelayApiError, "inconsistent renewed"):
                        client.renew_request(request, worker_id="worker")

            for label, poll_overrides, renew_overrides in RENEWAL_TRANSPORT_ROLLBACKS:
                with self.subTest(field=label):
                    relay.state.poll_overrides = poll_overrides
                    request = client.poll(
                        "expected-rollout",
                        worker_id="worker",
                        timeout_seconds=0,
                    ).requests[0]
                    relay.state.renew_overrides = renew_overrides
                    with self.assertRaisesRegex(RelayApiError, "inconsistent renewed"):
                        client.renew_request(request, worker_id="worker")

    def test_sync_worker_accepts_forward_transport_state_transition(self) -> None:
        with running_relay() as relay:
            client = RelayWorkerClient(relay.base_url, worker_token="worker-token")
            client.register_rollout("expected-rollout")
            request = client.poll(
                "expected-rollout",
                worker_id="worker",
                timeout_seconds=0,
            ).requests[0]
            relay.state.renew_overrides = {
                "reattachable": True,
                "accepted_notified_at": 4.0,
                "parked_transport_epoch": "epoch-one",
            }

            renewed = client.renew_request(request, worker_id="worker")

            self.assertTrue(renewed.reattachable)
            self.assertEqual(renewed.accepted_notified_at, 4.0)
            self.assertEqual(renewed.parked_transport_epoch, "epoch-one")


@contextmanager
def running_relay() -> Iterator["RelayHandle"]:
    state = FakeRelayState()

    class Handler(FakeRelayHandler):
        pass

    Handler.state = state
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.01},
        daemon=True,
    )
    thread.start()
    try:
        host, port = server.server_address
        yield RelayHandle(base_url=f"http://{host}:{port}", state=state)
    finally:
        server.shutdown()
        thread.join(timeout=1)
        server.server_close()


class RelayHandle:
    def __init__(self, *, base_url: str, state: "FakeRelayState") -> None:
        self.base_url = base_url
        self.state = state


class FakeRelayState:
    def __init__(self) -> None:
        self.lock = Lock()
        self.rollouts: dict[str, dict] = {}
        self.last_respond_payload: dict = {}
        self.upstream_method = ""
        self.upstream_path = ""
        self.upstream_body = b""
        self.upstream_response_body = b"\xffresponse"
        self.respond_attempts = 0
        self.renew_attempts = 0
        self.last_error_payload: dict = {}
        self.cancel_event: Event | None = None
        self.registration_rollout_id: str | None = None
        self.registration_token = REGISTRATION_TOKEN
        self.poll_rollout_id: str | None = None
        self.poll_registration_token: str | None = None
        self.polled_request: dict | None = None
        self.poll_overrides: dict[str, object] = {}
        self.renew_overrides: dict[str, object] = {}
        self.stats_redirect = False
        self.stats_body: bytes | None = None


class FakeRelayHandler(BaseHTTPRequestHandler):
    state: FakeRelayState
    server_version = "fake-ucloud-relay/0.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
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
        if parsed.path == "/worker/poll":
            query = parse_qs(parsed.query)
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
            with self.state.lock:
                request.update(self.state.poll_overrides)
                self.state.polled_request = request
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
        if parsed.path == "/worker/renew":
            with self.state.lock:
                self.state.renew_attempts += 1
                request = dict(
                    self.state.polled_request or _relay_request(rollout_id="run-001")
                )
                request["leased_by"] = str(payload.get("worker_id") or "")
                request["lease_expires_at"] = 456.0
                request.update(self.state.renew_overrides)
            self._write_json(
                {
                    "ok": True,
                    "request": request,
                }
            )
            return
        if parsed.path == "/worker/respond":
            with self.state.lock:
                self.state.last_respond_payload = dict(payload)
                self.state.respond_attempts += 1
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
                cancel_event = self.state.cancel_event
            if cancel_event is not None:
                cancel_event.set()
            self._write_json({"ok": True, "request_id": payload.get("request_id")})
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
        "expires_at": 60.0,
        "delivered_at": 2.0,
        "first_delivered_at": 2.0,
        "lease_id": "lease-1",
        "lease_expires_at": lease_expires_at,
        "leased_by": leased_by,
        "delivery_count": 1,
        "idempotency_key": "idempotency-one",
        "sandbox_id": "sandbox-one",
        "sandbox_generation": 7,
        "reattachable": False,
        "accepted_notified_at": None,
        "parked_transport_epoch": None,
    }


if __name__ == "__main__":
    unittest.main()
