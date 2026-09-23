import asyncio
from dataclasses import replace
from types import SimpleNamespace
from threading import Event
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


class RelayCommitRetryTests(unittest.TestCase):
    def test_sync_completed_renewal_after_successful_commit_keeps_worker_alive(self):
        for status, message, allowed in (
            (410, "request is already completed", True),
            (410, "registration expired", False),
            (409, "request lease is no longer active", False),
        ):
            with self.subTest(status=status, message=message):
                observed = Event()
                failure = RelayApiError(message, status_code=status, body={"error": message})
                client = RelayWorkerClient("http://relay.invalid")

                def renew(*_args, **_kwargs):
                    observed.set()
                    raise failure

                def commit(*_args, **_kwargs):
                    self.assertTrue(observed.wait(2))
                    return {"ok": True}

                client.renew_request = Mock(side_effect=renew)
                client.forward_to = Mock(side_effect=commit)
                def handle():
                    relay_module._handle_sync_request(
                        client, request_fixture(), handler=None,
                        upstream_base_url="http://model.invalid", worker_id="worker",
                        lease_seconds=120, renewal_interval_seconds=0.001,
                    )
                if allowed:
                    handle()
                else:
                    with self.assertRaises(RelayApiError) as raised:
                        handle()
                    self.assertIs(raised.exception, failure)

    def test_commit_retries_same_payload_after_transport_and_proxy_failures(self):
        for status in (None, 502, 504, 503):
            with self.subTest(status=status):
                client = RelayWorkerClient("http://relay.invalid")
                client.respond_to = Mock(side_effect=[RelayApiError("lost", status_code=status), {"ok": True}])
                item = request_fixture()
                result = client.commit_response_bytes_to(item, b"answer", attempts=2, retry_delay_seconds=0)
                self.assertTrue(result["ok"])
                self.assertEqual(client.respond_to.call_count, 2)
                self.assertEqual(client.respond_to.call_args_list[0], client.respond_to.call_args_list[1])

    def test_commit_preserves_terminal_errors_and_attempt_bound(self):
        cases = [(status, None, 1) for status in (400, 401, 403, 404, 409, 410, 422)]
        cases += [(503, {"retryable": False}, 1), (None, None, 2)]
        for status, body, expected_calls in cases:
            with self.subTest(status=status, body=body):
                client = RelayWorkerClient("http://relay.invalid")
                client.respond_to = Mock(side_effect=RelayApiError("lost", status_code=status, body=body))
                with self.assertRaises(RelayApiError):
                    client.commit_response_bytes_to(request_fixture(), b"answer", attempts=2, retry_delay_seconds=0)
                self.assertEqual(client.respond_to.call_count, expected_calls)


class AsyncRelayCommitRetryTests(unittest.IsolatedAsyncioTestCase):
    async def test_commit_retries_same_payload_after_transport_and_proxy_failures(self):
        for status in (None, 502, 504, 503):
            with self.subTest(status=status):
                client = AsyncRelayWorkerClient("http://relay.invalid")
                client.respond_to = AsyncMock(side_effect=[RelayApiError("lost", status_code=status), {"ok": True}])
                result = await client.commit_response_bytes_to(request_fixture(), b"answer", attempts=2, retry_delay_seconds=0)
                self.assertTrue(result["ok"])
                self.assertEqual(client.respond_to.await_args_list[0], client.respond_to.await_args_list[1])

    async def test_commit_preserves_terminal_errors_and_attempt_bound(self):
        for status, body, expected_calls in [(410, None, 1), (503, {"retryable": False}, 1), (None, None, 2)]:
            with self.subTest(status=status, body=body):
                client = AsyncRelayWorkerClient("http://relay.invalid")
                client.respond_to = AsyncMock(side_effect=RelayApiError("lost", status_code=status, body=body))
                with self.assertRaises(RelayApiError):
                    await client.commit_response_bytes_to(request_fixture(), b"answer", attempts=2, retry_delay_seconds=0)
                self.assertEqual(client.respond_to.await_count, expected_calls)


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
    async def test_completed_renewal_after_successful_commit_keeps_worker_alive(self):
        for status, message, allowed in (
            (410, "request is already completed", True),
            (410, "registration expired", False),
            (409, "request lease is no longer active", False),
        ):
            with self.subTest(status=status, message=message):
                observed = asyncio.Event()
                failure = RelayApiError(message, status_code=status, body={"error": message})
                client = AsyncRelayWorkerClient("http://relay.invalid")

                async def renew(*_args, **_kwargs):
                    observed.set()
                    raise failure

                async def commit(*_args, **_kwargs):
                    await asyncio.wait_for(observed.wait(), 2)
                    return {"ok": True}

                client.renew_request = AsyncMock(side_effect=renew)
                client.forward_to = AsyncMock(side_effect=commit)
                async def handle():
                    await relay_module._handle_async_request(
                        client, request_fixture(), handler=None,
                        upstream_base_url="http://model.invalid", worker_id="worker",
                        lease_seconds=120, renewal_interval_seconds=0.001,
                    )
                if allowed:
                    await handle()
                else:
                    with self.assertRaises(RelayApiError) as raised:
                        await handle()
                    self.assertIs(raised.exception, failure)

    async def test_completed_renewal_does_not_mask_commit_failure(self):
        client = AsyncRelayWorkerClient("http://relay.invalid")
        primary = RelayApiError("commit failed", status_code=409)
        client.forward_to = AsyncMock(side_effect=primary)
        completed = RelayApiError(
            "completed", status_code=410, body={"error": "request is already completed"}
        )
        with patch.object(relay_module, "_renew_async_lease", side_effect=completed):
            with self.assertRaises(RelayApiError) as raised:
                await relay_module._handle_async_request(
                    client, request_fixture(), handler=None,
                    upstream_base_url="http://model.invalid", worker_id="worker",
                    lease_seconds=120, renewal_interval_seconds=30,
                )
        self.assertIs(raised.exception, primary)

    async def test_primary_failure_survives_other_request_cleanup_failure(self):
        primary = RelayApiError("original forwarding failure")
        secondary = RelayApiError("secondary cleanup failure")
        started = asyncio.Event()
        cleaned = asyncio.Event()
        first = request_fixture()
        second = replace(first, request_id="req-2")
        client = AsyncRelayWorkerClient("http://relay.invalid")
        pending = [first, second]
        async def poll(*_args, limit, **_kwargs):
            batch = pending[:limit]
            del pending[:limit]
            return SimpleNamespace(requests=tuple(batch))
        client.poll = AsyncMock(side_effect=poll)

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
