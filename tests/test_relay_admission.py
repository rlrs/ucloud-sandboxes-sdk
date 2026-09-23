import asyncio
from threading import Event, Thread
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ucloud_sandboxes_sdk._relay_admission import AsyncRequestBudget, SyncRequestBudget
from ucloud_sandboxes_sdk.relay import AsyncRelayWorkerClient, RelayWorkerClient


class AsyncAdmissionTests(unittest.IsolatedAsyncioTestCase):
    async def test_fifo_and_cancellation_restore_all_capacity(self):
        budget = AsyncRequestBudget(1)
        stop = asyncio.Event()
        self.assertEqual(await budget.acquire(stop), 1)
        first = asyncio.create_task(budget.acquire(stop))
        cancelled = asyncio.create_task(budget.acquire(stop))
        last = asyncio.create_task(budget.acquire(stop))
        await asyncio.sleep(0)
        cancelled.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await cancelled
        budget.release()
        self.assertEqual(await first, 1)
        self.assertFalse(last.done())
        budget.release()
        self.assertEqual(await last, 1)
        racing = asyncio.create_task(budget.acquire(stop))
        await asyncio.sleep(0)
        budget.release()
        racing.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await racing
        self.assertEqual(budget.available, 1)

    async def test_stop_while_waiting_does_not_lease_or_leak(self):
        budget = AsyncRequestBudget(1)
        stop = asyncio.Event()
        await budget.acquire(stop)
        waiting = asyncio.create_task(budget.acquire(stop))
        await asyncio.sleep(0)
        stop.set()
        self.assertEqual(await asyncio.wait_for(waiting, 1), 0)
        budget.release()
        self.assertEqual(budget.available, 1)

    async def test_two_sessions_never_poll_without_experiment_capacity(self):
        client = AsyncRelayWorkerClient('http://unused', max_inflight_requests=1)
        stop = asyncio.Event()
        first_started, finish = asyncio.Event(), asyncio.Event()
        polled = []
        async def poll(rollout, **options):
            polled.append((rollout, options['limit']))
            return SimpleNamespace(requests=[SimpleNamespace(rollout_id=rollout)])
        async def handle(_client, request, **options):
            if request.rollout_id == 'first':
                first_started.set()
                await finish.wait()
            else:
                stop.set()
        client.poll = poll
        with patch('ucloud_sandboxes_sdk.relay._handle_async_request', handle):
            first = asyncio.create_task(client.run_worker('first', handler=lambda _: None, cancel=stop, max_concurrency=1))
            await asyncio.wait_for(first_started.wait(), 1)
            second = asyncio.create_task(client.run_worker('second', handler=lambda _: None, cancel=stop, max_concurrency=1))
            await asyncio.sleep(.02)
            self.assertEqual(polled, [('first', 1)])
            finish.set()
            await asyncio.wait_for(asyncio.gather(first, second), 2)
        self.assertEqual(polled[1], ('second', 1))
        self.assertEqual(client._request_budget.available, 1)

    async def test_512_sessions_do_not_reserve_eight_idle_slots_each(self):
        client = AsyncRelayWorkerClient('http://unused', max_inflight_requests=512)
        stop, release_idle, first_wave = asyncio.Event(), asyncio.Event(), asyncio.Event()
        ready = {str(index) for index in range(504, 512)}
        completed, polls = set(), []
        async def poll(rollout, **options):
            polls.append((rollout, options['limit'], options['timeout_seconds']))
            if len(polls) == 128:
                first_wave.set()
            await release_idle.wait()
            if rollout in ready:
                ready.remove(rollout)
                return SimpleNamespace(requests=[SimpleNamespace(rollout_id=rollout)])
            await asyncio.sleep(.001)
            return SimpleNamespace(requests=[])
        async def handle(_client, request, **options):
            completed.add(request.rollout_id)
            if len(completed) == 8:
                stop.set()
        client.poll = poll
        with patch('ucloud_sandboxes_sdk.relay._handle_async_request', handle):
            workers = [asyncio.create_task(client.run_worker(str(i), handler=lambda _: None,
                       cancel=stop, max_concurrency=8)) for i in range(512)]
            try:
                await asyncio.wait_for(first_wave.wait(), 5)
                self.assertEqual(len(polls), 128)
                self.assertTrue(all(limit == 1 for _, limit, _ in polls))
                self.assertTrue(all(timeout <= 1 for _, _, timeout in polls))
                release_idle.set()
                await asyncio.wait_for(asyncio.gather(*workers), 10)
                self.assertEqual(completed, {str(i) for i in range(504, 512)})
                self.assertEqual(client._request_budget.available, 512)
                self.assertFalse(client._request_budget.waiters)
            finally:
                for worker in workers:
                    worker.cancel()
                await asyncio.gather(*workers, return_exceptions=True)

    async def test_poll_error_and_cancellation_release_reserved_capacity(self):
        client = AsyncRelayWorkerClient('http://unused', max_inflight_requests=3)
        entered = asyncio.Event()
        async def poll(*_args, **_kwargs):
            entered.set()
            await asyncio.Event().wait()
        client.poll = poll
        worker = asyncio.create_task(client.run_worker('r', handler=lambda _: None))
        await entered.wait()
        worker.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await worker
        self.assertEqual(client._request_budget.available, 3)
        async def failing(*_args, **_kwargs):
            raise ValueError('bad poll')
        client.poll = failing
        with self.assertRaisesRegex(ValueError, 'bad poll'):
            await client.run_worker('r', handler=lambda _: None)
        self.assertEqual(client._request_budget.available, 3)


class SyncAdmissionTests(unittest.TestCase):
    def test_fifo_and_stop(self):
        budget = SyncRequestBudget(2)
        stop = Event()
        self.assertEqual(budget.acquire(stop), 1)
        self.assertEqual(budget.acquire(stop), 1)
        granted = []
        first = Thread(target=lambda: granted.append(budget.acquire(stop)))
        first.start()
        deadline = time.monotonic() + 1
        while not budget.waiters and time.monotonic() < deadline:
            time.sleep(.001)
        stop.set()
        first.join(1)
        self.assertFalse(first.is_alive())
        self.assertEqual(granted, [0])
        budget.release(2)
        self.assertEqual(budget.available, 2)

    def test_shared_workers_and_poll_failure_release_capacity(self):
        client = RelayWorkerClient('http://unused', max_inflight_requests=1)
        stop, started, finish = Event(), Event(), Event()
        polled, errors = [], []
        def poll(rollout, **options):
            polled.append((rollout, options['limit']))
            return SimpleNamespace(requests=[SimpleNamespace(rollout_id=rollout)])
        def handle(_client, request, **options):
            if request.rollout_id == 'first':
                started.set()
                finish.wait(2)
            else:
                stop.set()
        def run(rollout):
            try:
                client.run_worker(rollout, handler=lambda _: None, cancel=stop, max_concurrency=1)
            except Exception as exc:
                errors.append(exc)
        client.poll = poll
        with patch('ucloud_sandboxes_sdk.relay._handle_sync_request', handle):
            first, second = Thread(target=run, args=('first',)), Thread(target=run, args=('second',))
            first.start()
            self.assertTrue(started.wait(1))
            second.start()
            time.sleep(.02)
            self.assertEqual(polled, [('first', 1)])
            finish.set()
            first.join(2)
            second.join(2)
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(polled[1], ('second', 1))
        self.assertEqual(client._request_budget.available, 1)
        def failed(*_args, **_kwargs):
            raise ValueError('bad poll')
        client.poll = failed
        with self.assertRaisesRegex(ValueError, 'bad poll'):
            client.run_worker('failed', handler=lambda _: None)
        self.assertEqual(client._request_budget.available, 1)

    def test_poll_rotation_uses_request_budget_when_smaller_than_transport_pool(self):
        for cls in (RelayWorkerClient, AsyncRelayWorkerClient):
            client = cls("http://unused", max_inflight_requests=64)
            client._active_workers = 512
            self.assertEqual(client._worker_poll_timeout(30), .5)

    def test_environment_and_invalid_limits_have_sync_async_parity(self):
        for cls in (RelayWorkerClient, AsyncRelayWorkerClient):
            client = cls.from_env(env={'UCLOUD_RELAY_URL': 'http://unused', 'UCLOUD_RELAY_MAX_INFLIGHT_REQUESTS': '17'})
            self.assertEqual(client._request_budget.available, 17)
            with self.assertRaises(ValueError):
                cls('http://unused', max_inflight_requests=0)
