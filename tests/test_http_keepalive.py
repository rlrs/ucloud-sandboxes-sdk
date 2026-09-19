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

    async def test_bounded_polls_and_512_upstreams_do_not_starve_control(self):
        from aiohttp import web

        polls_ready, upstreams_ready = asyncio.Event(), asyncio.Event()
        release_polls, release_upstreams = asyncio.Event(), asyncio.Event()
        counts = {"poll": 0, "upstream": 0, "commit": 0}

        async def handle(request):
            if request.path == "/worker/poll":
                counts["poll"] += 1
                if counts["poll"] == 128:
                    polls_ready.set()
                await release_polls.wait()
                return web.json_response({"requests": []})
            if request.path == "/upstream":
                counts["upstream"] += 1
                if counts["upstream"] == 512:
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
        site = web.TCPSite(runner, "127.0.0.1", 0, backlog=1024)
        await site.start()
        url = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
        client = AsyncRelayWorkerClient(url)
        tasks = []
        try:
            tasks.extend(
                asyncio.create_task(client._request_json("GET", "/worker/poll?wait=10"))
                for _ in range(128)
            )
            await asyncio.wait_for(polls_ready.wait(), 20)
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
                for index in range(512)
            )
            await asyncio.wait_for(upstreams_ready.wait(), 20)
            self.assertEqual(await asyncio.wait_for(client.health(), 2), {"ok": True})
            release_upstreams.set()
            await asyncio.wait_for(asyncio.gather(*tasks[128:]), 20)
            self.assertEqual(counts["commit"], 512)
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

    async def test_relay_connection_limits_can_be_bounded_by_caller(self):
        client = AsyncRelayWorkerClient.from_env(env={
            "UCLOUD_RELAY_URL": "http://relay.invalid",
            "UCLOUD_RELAY_MAX_FORWARD_CONNECTIONS": "3",
            "UCLOUD_RELAY_MAX_POLL_CONNECTIONS": "7",
        }, max_forward_connections=5)
        try:
            self.assertEqual((await client._client(purpose="forward")).connector.limit, 5)
            self.assertEqual((await client._client(purpose="poll")).connector.limit, 7)
            self.assertEqual((await client._client()).connector.limit, 128)
        finally:
            await client.close()

    def test_unbounded_and_invalid_relay_connection_limits_are_rejected(self):
        for key in ("max_forward_connections", "max_poll_connections"):
            for value in (0, -1, True, 1.5, "3"):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    AsyncRelayWorkerClient("http://relay.invalid", **{key: value})
        for key in ("UCLOUD_RELAY_MAX_FORWARD_CONNECTIONS", "UCLOUD_RELAY_MAX_POLL_CONNECTIONS"):
            for value in ("0", "-1", "1.5", "invalid"):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    AsyncRelayWorkerClient.from_env(env={
                        "UCLOUD_RELAY_URL": "http://relay.invalid", key: value,
                    })

    async def test_512_idle_workers_rotate_through_bounded_poll_pool(self):
        from aiohttp import web

        seen = set()
        all_seen = asyncio.Event()
        active = peak = 0
        waits = []

        async def poll(request):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            seen.add(request.query["rollout_id"])
            if len(seen) == 512:
                all_seen.set()
            delay = float(request.query["timeout_seconds"])
            waits.append(delay)
            try:
                await asyncio.sleep(delay)
                return web.json_response({"requests": []})
            finally:
                active -= 1

        app = web.Application()
        app.router.add_get("/worker/poll", poll)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0, backlog=1024)
        await site.start()
        url = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
        client = AsyncRelayWorkerClient(url)
        tasks = [asyncio.create_task(client.run_worker(
            str(index), handler=lambda request: None,
            registration_token="a" * 32, poll_timeout_seconds=10,
        )) for index in range(512)]
        try:
            await asyncio.wait_for(all_seen.wait(), 12)
            self.assertLessEqual(peak, 128)
            self.assertTrue(all(0 < delay <= 1 for delay in waits))
            self.assertTrue(all(not task.done() for task in tasks))
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await client.close()
            await runner.cleanup()
        self.assertEqual(client._active_workers, 0)
