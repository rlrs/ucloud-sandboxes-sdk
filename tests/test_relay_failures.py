import asyncio
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch
from urllib.error import URLError

from aiohttp import ClientSession, ClientTimeout, web

from ucloud_sandboxes_sdk import (
    AsyncRelayWorkerClient,
    RelayApiError,
    RelayRequest,
    RelayWorkerClient,
)
import ucloud_sandboxes_sdk.relay as relay_module
from tests.test_relay import _relay_request


def request_fixture():
    return RelayRequest.from_payload(
        _relay_request(rollout_id="test", leased_by="worker")
    )


class RelayForwardingConfigTests(unittest.TestCase):
    def test_sync_and_async_forward_budgets_are_independent_from_control_calls(self):
        for cls in (RelayWorkerClient, AsyncRelayWorkerClient):
            with self.subTest(client=cls.__name__):
                client = cls.from_env(
                    env={
                        "UCLOUD_RELAY_URL": "http://relay.invalid",
                        "UCLOUD_RELAY_TIMEOUT_SECONDS": "30",
                        "UCLOUD_RELAY_FORWARD_TIMEOUT_SECONDS": "1800",
                    }
                )
                self.assertEqual(client.timeout_seconds, 30)
                self.assertEqual(client.forward_timeout_seconds, 1800)
                self.assertEqual(
                    cls("http://relay.invalid").forward_timeout_seconds, 7200
                )
                override = cls.from_env(
                    env={
                        "UCLOUD_RELAY_URL": "http://relay.invalid",
                        "UCLOUD_RELAY_FORWARD_TIMEOUT_SECONDS": "1800",
                    },
                    forward_timeout_seconds=900,
                )
                self.assertEqual(override.forward_timeout_seconds, 900)

    def test_unbounded_or_nonpositive_forward_timeout_is_rejected(self):
        for cls in (RelayWorkerClient, AsyncRelayWorkerClient):
            for timeout in (0, -1, float("inf"), float("nan"), True):
                with self.subTest(client=cls.__name__, timeout=timeout):
                    with self.assertRaises(ValueError):
                        cls("http://relay.invalid", forward_timeout_seconds=timeout)

    def test_sync_forward_uses_its_budget_and_explicit_override(self):
        client = RelayWorkerClient("http://relay.invalid", forward_timeout_seconds=1800)
        client.commit_response_bytes_to = Mock(return_value={"ok": True})
        for override, expected in ((None, 1800), (600, 600)):
            with self.subTest(override=override):
                upstream = Mock(status=200, headers={})
                upstream.read.return_value = b"completed"
                with patch.object(
                    relay_module, "open_no_redirect", return_value=upstream
                ) as opened:
                    client.forward_to(
                        request_fixture(),
                        "http://model.invalid",
                        timeout_seconds=override,
                    )
                self.assertEqual(opened.call_args.kwargs["timeout"], expected)
                self.assertEqual(
                    client.commit_response_bytes_to.call_args.kwargs["status"], 200
                )
                upstream.close.assert_called_once()

    def test_sync_body_read_timeout_is_committed_with_a_useful_error(self):
        client = RelayWorkerClient("http://relay.invalid", forward_timeout_seconds=1800)
        client.commit_response_bytes_to = Mock(return_value={"ok": True})
        upstream = Mock(status=200, headers={})
        upstream.read.side_effect = TimeoutError()
        with patch.object(relay_module, "open_no_redirect", return_value=upstream):
            client.forward_to(request_fixture(), "http://model.invalid")
        call = client.commit_response_bytes_to.call_args
        self.assertEqual(call.kwargs["status"], 504)
        self.assertIn(b"1800", call.args[1])
        upstream.close.assert_called_once()

    def test_sync_wrapped_connection_timeout_is_reported_as_timeout(self):
        client = RelayWorkerClient("http://relay.invalid", forward_timeout_seconds=1800)
        client.commit_response_bytes_to = Mock(return_value={"ok": True})
        with patch.object(
            relay_module, "open_no_redirect", side_effect=URLError(TimeoutError())
        ):
            client.forward_to(request_fixture(), "http://model.invalid")
        call = client.commit_response_bytes_to.call_args
        self.assertEqual(call.kwargs["status"], 504)
        self.assertIn(b"timed out", call.args[1])


class RelayWorkerFailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_primary_failure_survives_other_request_cleanup_failure(self):
        primary = RelayApiError("original forwarding failure")
        secondary = RelayApiError("secondary cleanup failure")
        started = asyncio.Event()
        cleaned = asyncio.Event()
        first = request_fixture()
        second = replace(first, request_id="req-2")
        client = AsyncRelayWorkerClient("http://relay.invalid")
        client.poll = AsyncMock(return_value=SimpleNamespace(requests=(first, second)))

        async def handle(_client, request, **_kwargs):
            if request.request_id == first.request_id:
                await started.wait()
                raise primary
            started.set()
            try:
                await asyncio.sleep(0.1)
                raise secondary
            finally:
                cleaned.set()

        with patch.object(relay_module, "_handle_async_request", side_effect=handle):
            with self.assertRaises(RelayApiError) as raised:
                await client.run_worker(
                    "test", handler=lambda _: None, max_concurrency=2
                )
        self.assertIs(raised.exception, primary)
        self.assertTrue(cleaned.is_set())

    async def test_forwarding_failure_survives_lease_renewer_failure(self):
        primary = RelayApiError("original forwarding failure")
        secondary = RelayApiError("lease renewal failed")
        client = AsyncRelayWorkerClient("http://relay.invalid")
        client.forward_to = AsyncMock(side_effect=primary)
        with patch.object(relay_module, "_renew_async_lease", side_effect=secondary):
            with self.assertRaises(RelayApiError) as raised:
                await relay_module._handle_async_request(
                    client,
                    request_fixture(),
                    handler=None,
                    upstream_base_url="http://model.invalid",
                    worker_id="worker",
                    lease_seconds=120,
                    renewal_interval_seconds=30,
                )
        self.assertIs(raised.exception, primary)

    async def test_external_cancellation_drains_requests_and_stays_cancellation(self):
        started = asyncio.Event()
        cleaned = asyncio.Event()
        client = AsyncRelayWorkerClient("http://relay.invalid")
        client.poll = AsyncMock(
            return_value=SimpleNamespace(requests=(request_fixture(),))
        )

        async def handle(*_args, **_kwargs):
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                cleaned.set()

        with patch.object(relay_module, "_handle_async_request", side_effect=handle):
            worker = asyncio.create_task(
                client.run_worker("test", handler=lambda _: None, max_concurrency=1)
            )
            await started.wait()
            worker.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await worker
        self.assertTrue(cleaned.is_set())


class RelayForwardingTimeoutTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        async def generate(_request):
            await asyncio.sleep(0.05)
            return web.json_response({"choices": [{"text": "completed"}]})

        app = web.Application()
        app.router.add_post("/v1/chat/completions", generate)
        self.server = web.AppRunner(app)
        await self.server.setup()
        site = web.TCPSite(self.server, "127.0.0.1", 0)
        await site.start()
        self.url = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"

    async def asyncTearDown(self):
        await self.server.cleanup()

    async def test_slow_generation_outlives_injected_session_control_timeout(self):
        async with ClientSession(timeout=ClientTimeout(total=0.01)) as session:
            client = AsyncRelayWorkerClient(
                "http://relay.invalid", session=session, forward_timeout_seconds=0.5
            )
            client.commit_response_bytes_to = AsyncMock(return_value={"ok": True})
            await client.forward_to(request_fixture(), self.url)
            self.assertEqual(
                client.commit_response_bytes_to.call_args.kwargs["status"], 200
            )

    async def test_explicit_forwarding_deadline_returns_informative_timeout(self):
        async with ClientSession() as session:
            client = AsyncRelayWorkerClient(
                "http://relay.invalid", session=session, forward_timeout_seconds=0.5
            )
            client.commit_response_bytes_to = AsyncMock(return_value={"ok": True})
            await client.forward_to(request_fixture(), self.url, timeout_seconds=0.01)
            call = client.commit_response_bytes_to.call_args
            self.assertEqual(call.kwargs["status"], 504)
            self.assertIn(b"timed out", call.args[1])
            self.assertIn(b"0.01", call.args[1])
