"""FIFO request admission shared by all worker sessions of one client.

Reserve before polling, so a locally queued request never consumes a server
lease. This is an in-process experiment budget, not a fleet-wide rate limiter.
"""
from __future__ import annotations

import asyncio
from collections import deque
from threading import Condition, Event


class SyncRequestBudget:
    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self.available = capacity
        self.condition = Condition()
        self.waiters: deque[object] = deque()

    def acquire(self, stop: Event) -> int:
        ticket = object()
        with self.condition:
            self.waiters.append(ticket)
            try:
                while not stop.is_set():
                    if self.waiters[0] is ticket and self.available:
                        self.available -= 1
                        return 1
                    self.condition.wait(.05)
                return 0
            finally:
                self.waiters.remove(ticket)
                self.condition.notify_all()

    def release(self, count: int = 1) -> None:
        with self.condition:
            self.available += count
            self.condition.notify_all()


class AsyncRequestBudget:
    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self.available = capacity
        self.waiters: deque[asyncio.Future[int]] = deque()

    async def acquire(self, stop: asyncio.Event) -> int:
        future = asyncio.get_running_loop().create_future()
        self.waiters.append(future)
        self._drain()
        claimed = False
        stopped = asyncio.create_task(stop.wait())
        try:
            try:
                done, _ = await asyncio.wait((future, stopped), return_when=asyncio.FIRST_COMPLETED)
            finally:
                stopped.cancel()
                await asyncio.gather(stopped, return_exceptions=True)
            if stopped in done:
                return 0
            claimed = True
            return future.result()
        finally:
            if not future.done():
                future.cancel()
                self._drain()
            elif not future.cancelled() and not claimed:
                self.release(future.result())

    def release(self, count: int = 1) -> None:
        self.available += count
        self._drain()

    def _drain(self) -> None:
        while self.waiters:
            future = self.waiters[0]
            if future.cancelled():
                self.waiters.popleft()
                continue
            if not self.available:
                return
            self.waiters.popleft()
            self.available -= 1
            future.set_result(1)
