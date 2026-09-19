from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from ucloud_sandboxes_sdk import AsyncRelayWorkerClient, AsyncSandboxClient, RelayRequest


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
                if isinstance(client, AsyncRelayWorkerClient):
                    for purpose in ("poll", "forward"):
                        self.assertIs(await client._client(purpose=purpose), session)
                await client.close()
                self.assertFalse(session.closed)
                self.assertEqual(session.connector._keepalive_timeout, 42)

    def test_default_expires_before_public_proxy_idle_close(self):
        from ucloud_sandboxes_sdk._http import ASYNC_KEEPALIVE_TIMEOUT_SECONDS

        self.assertGreater(ASYNC_KEEPALIVE_TIMEOUT_SECONDS, 0)
        self.assertLessEqual(ASYNC_KEEPALIVE_TIMEOUT_SECONDS, 5)

    async def test_long_polls_and_slow_upstreams_do_not_starve_control(self):
        from aiohttp import web

        polls_ready, upstreams_ready = asyncio.Event(), asyncio.Event()
        release_polls, release_upstreams = asyncio.Event(), asyncio.Event()
        counts = {"poll": 0, "upstream": 0, "commit": 0}

        async def handle(request):
            if request.path == "/worker/poll":
                counts["poll"] += 1
                if counts["poll"] == 100:
                    polls_ready.set()
                await release_polls.wait()
                return web.json_response({"requests": []})
            if request.path == "/upstream":
                counts["upstream"] += 1
                if counts["upstream"] == 100:
                    upstreams_ready.set()
                await release_upstreams.wait()
                return web.Response(body=b"reply")
            if request.path == "/worker/respond":
                payload = await request.json()
                self.assertEqual(payload["body"]["value"], "cmVwbHk=")
                counts["commit"] += 1
            return web.json_response({"ok": True})

        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", handle)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        url = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
        client = AsyncRelayWorkerClient(url)
        tasks = []
        try:
            tasks.extend(
                asyncio.create_task(client._request_json("GET", "/worker/poll?wait=10"))
                for _ in range(100)
            )
            await asyncio.wait_for(polls_ready.wait(), 5)
            tasks.extend(
                asyncio.create_task(
                    client.forward_to(
                        RelayRequest(
                            request_id=str(index), rollout_id="rollout",
                            registration_token="a" * 32, endpoint="/upstream",
                            method="POST", headers={}, body=None, body_bytes=b"request",
                            lease_id="lease",
                        ),
                        url,
                    )
                )
                for index in range(100)
            )
            await asyncio.wait_for(upstreams_ready.wait(), 5)
            self.assertEqual(await asyncio.wait_for(client.health(), 2), {"ok": True})
            release_upstreams.set()
            await asyncio.wait_for(asyncio.gather(*tasks[100:]), 5)
            self.assertEqual(counts["commit"], 100)
            self.assertFalse(release_polls.is_set())
        finally:
            release_polls.set()
            release_upstreams.set()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            sessions = list(client._owned_sessions.values())
            await client.close()
            self.assertTrue(all(session.closed for session in sessions))
            await runner.cleanup()
