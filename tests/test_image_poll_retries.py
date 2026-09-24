import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch

from ucloud_sandboxes_sdk.client import (
    AsyncSandboxClient,
    SandboxApiError,
    SandboxClient,
)


MODULE = "ucloud_sandboxes_sdk.client"
SUCCESS = {"build_id": "shared-build", "status": "succeeded"}


def read_timeout():
    exc = SandboxApiError("node-agent request failed: The read operation timed out")
    exc.__cause__ = TimeoutError("The read operation timed out")
    return exc


class ImagePollRetries(unittest.TestCase):
    def test_sync_transient_poll_does_not_resubmit(self):
        client = SandboxClient("http://gateway")
        client.get_image_build = Mock(
            side_effect=[
                read_timeout(),
                SandboxApiError("unavailable", status_code=503),
                SUCCESS,
            ]
        )
        client.submit_image_build = Mock()
        with patch(MODULE + ".time.sleep"):
            self.assertEqual(
                client.wait_for_image_build("shared-build", timeout_seconds=60), SUCCESS
            )
        self.assertEqual(client.get_image_build.call_count, 3)
        client.submit_image_build.assert_not_called()

    def test_sync_permanent_errors_propagate_without_retry(self):
        for exc in [
            SandboxApiError("unauthorized", status_code=401),
            SandboxApiError("missing", status_code=404),
            SandboxApiError("invalid response"),
            SandboxApiError("permanent", status_code=503, body={"retryable": False}),
        ]:
            client = SandboxClient("http://gateway")
            client.get_image_build = Mock(side_effect=exc)
            with self.assertRaises(SandboxApiError):
                client.wait_for_image_build("shared-build", timeout_seconds=60)
            self.assertEqual(client.get_image_build.call_count, 1)

    def test_deadline_preserved_and_error_identifies_shared_build(self):
        client = SandboxClient("http://gateway")
        now = [0.0]
        client.get_image_build = Mock(side_effect=read_timeout())

        def sleep(delay):
            now[0] += delay

        with (
            patch(MODULE + ".time.monotonic", side_effect=lambda: now[0]),
            patch(MODULE + ".time.sleep", side_effect=sleep),
        ):
            with self.assertRaisesRegex(TimeoutError, "shared-build"):
                client.wait_for_image_build("shared-build", timeout_seconds=1)
        self.assertEqual(now[0], 1.0)
        self.assertLessEqual(client.get_image_build.call_count, 2)

    def test_no_deadline_has_bounded_consecutive_failures(self):
        client = SandboxClient("http://gateway")
        client.get_image_build = Mock(side_effect=read_timeout())
        with patch(MODULE + ".time.sleep"), self.assertRaises(SandboxApiError):
            client.wait_for_image_build("shared-build")
        self.assertEqual(client.get_image_build.call_count, 7)

    def test_terminal_build_failure_is_not_retried(self):
        client = SandboxClient("http://gateway")
        failed = {"build_id": "shared-build", "status": "failed"}
        client.get_image_build = Mock(return_value=failed)
        self.assertEqual(client.wait_for_image_build("shared-build"), failed)
        client.get_image_build.assert_called_once()


class AsyncImagePollRetries(unittest.IsolatedAsyncioTestCase):
    async def test_eight_waiters_survive_shared_poll_timeouts(self):
        from aiohttp import ServerDisconnectedError

        client = AsyncSandboxClient("http://gateway")
        client.get_image_build = AsyncMock(
            side_effect=[asyncio.TimeoutError(), ServerDisconnectedError(), SUCCESS]
        )
        client.submit_image_build = AsyncMock()
        with patch(MODULE + ".asyncio.sleep", new_callable=AsyncMock):
            shared = asyncio.create_task(
                client.wait_for_image_build("shared-build", timeout_seconds=60)
            )

            async def waiter():
                return await asyncio.shield(shared)

            results = await asyncio.gather(*(waiter() for _ in range(8)))
        self.assertEqual(results, [SUCCESS] * 8)
        self.assertEqual(client.get_image_build.await_count, 3)
        client.submit_image_build.assert_not_called()

    async def test_cancellation_is_not_retried(self):
        client = AsyncSandboxClient("http://gateway")
        client.get_image_build = AsyncMock(side_effect=asyncio.CancelledError())
        with self.assertRaises(asyncio.CancelledError):
            await client.wait_for_image_build("shared-build", timeout_seconds=60)
        self.assertEqual(client.get_image_build.await_count, 1)

    async def test_async_deadline_and_retry_after(self):
        client = AsyncSandboxClient("http://gateway")
        now = [0.0]
        client.get_image_build = AsyncMock(
            side_effect=SandboxApiError(
                "busy", status_code=429, headers={"Retry-After": "10"}
            )
        )

        async def sleep(delay):
            now[0] += delay

        with (
            patch(MODULE + ".time.monotonic", side_effect=lambda: now[0]),
            patch(MODULE + ".asyncio.sleep", side_effect=sleep),
        ):
            with self.assertRaisesRegex(TimeoutError, "shared-build"):
                await client.wait_for_image_build("shared-build", timeout_seconds=1)
        self.assertEqual(now[0], 1.0)
        self.assertEqual(client.get_image_build.await_count, 1)
