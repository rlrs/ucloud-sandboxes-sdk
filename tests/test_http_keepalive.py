from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from ucloud_sandboxes_sdk import AsyncRelayWorkerClient, AsyncSandboxClient


class AsyncKeepaliveTests(unittest.IsolatedAsyncioTestCase):
    async def test_owned_clients_reuse_recent_connections_and_retire_idle_ones(self):
        from aiohttp import web

        transports = []

        async def response(request):
            transports.append(request.transport)
            return web.json_response({"ok": True})

        app = web.Application()
        app.router.add_post("/probe", response)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        url = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
        try:
            for cls, module in (
                (AsyncSandboxClient, "client"),
                (AsyncRelayWorkerClient, "relay"),
            ):
                with self.subTest(client=cls.__name__), patch(
                    f"ucloud_sandboxes_sdk.{module}.ASYNC_KEEPALIVE_TIMEOUT_SECONDS",
                    0.1,
                ):
                    client = cls(url)
                    session = await client._client()
                    try:
                        for delay in (0, 0, 0.2):
                            await asyncio.sleep(delay)
                            async with session.post(url + "/probe", json={}) as reply:
                                self.assertEqual(await reply.json(), {"ok": True})
                        self.assertIs(transports[-3], transports[-2])
                        self.assertIsNot(transports[-2], transports[-1])
                    finally:
                        await client.close()
                    self.assertTrue(session.closed)
        finally:
            await runner.cleanup()

    async def test_supplied_sessions_keep_their_transport_and_ownership(self):
        from aiohttp import ClientSession, TCPConnector

        async with ClientSession(connector=TCPConnector(keepalive_timeout=42)) as session:
            for cls in (AsyncSandboxClient, AsyncRelayWorkerClient):
                client = cls("http://gateway.invalid", session=session)
                self.assertIs(await client._client(), session)
                await client.close()
                self.assertFalse(session.closed)
                self.assertEqual(session.connector._keepalive_timeout, 42)

    def test_default_expires_before_public_proxy_idle_close(self):
        from ucloud_sandboxes_sdk._http import ASYNC_KEEPALIVE_TIMEOUT_SECONDS

        self.assertGreater(ASYNC_KEEPALIVE_TIMEOUT_SECONDS, 0)
        self.assertLessEqual(ASYNC_KEEPALIVE_TIMEOUT_SECONDS, 5)
