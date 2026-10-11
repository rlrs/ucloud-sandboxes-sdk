"""Managed-job long polls: get_job/read_job_logs waits, JobHandle.wait() and
follow(), against a fake gateway that holds reads (0.9.72), one that answers
at once (older gateways), and parked routes that answer with Retry-After."""

from __future__ import annotations

import asyncio
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Condition, Thread, Timer
import time
from typing import Any
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlsplit

import ucloud_sandboxes_sdk.client as client_module
from ucloud_sandboxes_sdk import (
    AsyncJobHandle,
    AsyncSandboxClient,
    JobHandle,
    JobOutputTruncatedError,
    SandboxApiError,
    SandboxClient,
    SandboxJobLogChunk,
    SandboxJobRecord,
)

SANDBOX = "agent-1"
JOB = "rollout-1"


class _JobGateway(ThreadingHTTPServer):
    """One managed job. ``holds`` serves 0.9.72 reads (cursor, carried job,
    wait_ms honoured); otherwise reads are answered at once without either.
    ``retry_after`` answers every read at once with that header (a parked
    sandbox)."""

    daemon_threads = True

    def __init__(self, *, holds: bool = True) -> None:
        super().__init__(("127.0.0.1", 0), _JobHandler)
        self.holds = holds
        self.retry_after: str | None = None
        self.changed = Condition()
        self.state = "running"
        self.exit_code: int | None = None
        self.sequence = 1
        self.logs = {"stdout": b"", "stderr": b""}
        self.truncated = {"stdout": False, "stderr": False}
        self.requests: list[tuple[float, str, dict[str, str]]] = []
        # Called with the request count before each answer; may change state.
        self.before_answer: Any = None
        self.thread = Thread(
            target=self.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )

    def __enter__(self) -> "_JobGateway":
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=5)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server_port}"

    def write(self, stream: str, data: bytes) -> None:
        with self.changed:
            self.logs[stream] += data
            self.changed.notify_all()

    def finish(self, exit_code: int = 0) -> None:
        with self.changed:
            self.state = "exited"
            self.exit_code = exit_code
            self.sequence += 1
            self.changed.notify_all()

    def truncate(self, stream: str) -> None:
        with self.changed:
            self.truncated[stream] = True
            self.sequence += 1
            self.changed.notify_all()

    def record(self) -> dict[str, Any]:
        record: dict[str, Any] = {
            "sandbox_id": SANDBOX,
            "sandbox_generation": 1,
            "job_id": JOB,
            "spec_sha256": "0" * 64,
            "state": self.state,
            "pid": 7,
            "exit_code": self.exit_code,
            "stdout_bytes": len(self.logs["stdout"]),
            "stderr_bytes": len(self.logs["stderr"]),
            "stdout_truncated": self.truncated["stdout"],
            "stderr_truncated": self.truncated["stderr"],
            "sequence": self.sequence,
        }
        if self.holds:
            record["cursor"] = (
                f"{self.sequence}.{record['stdout_bytes']}.{record['stderr_bytes']}"
            )
        return record

    def paths(self) -> list[str]:
        return [path for _at, path, _query in self.requests]

    def queries(self, suffix: str = "") -> list[dict[str, str]]:
        return [
            query
            for _at, path, query in self.requests
            if path.endswith(suffix) or not suffix
        ]


class _JobHandler(BaseHTTPRequestHandler):
    server: _JobGateway

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_GET(self) -> None:
        url = urlsplit(self.path)
        query = {key: values[0] for key, values in parse_qs(url.query).items()}
        parts = [unquote(part) for part in url.path.split("/") if part]
        gateway = self.server
        with gateway.changed:
            gateway.requests.append((time.monotonic(), url.path, query))
            count = len(gateway.requests)
        if gateway.before_answer is not None:
            gateway.before_answer(count)
        wait = (
            min(25.0, int(query["wait_ms"]) / 1000)
            if gateway.holds and gateway.retry_after is None and "wait_ms" in query
            else 0.0
        )
        if parts[:5] == ["v1", "sandboxes", SANDBOX, "jobs", JOB] and len(parts) == 5:
            after = query.get("after")
            with gateway.changed:
                gateway.changed.wait_for(
                    lambda: gateway.state != "running"
                    or gateway.record().get("cursor") != after,
                    timeout=wait,
                )
                body: dict[str, Any] = {"job": gateway.record()}
            self._answer(body)
            return
        if len(parts) == 7 and parts[5] == "logs":
            stream = parts[6]
            offset = int(query["offset"])
            limit = int(query["limit"])
            with gateway.changed:
                gateway.changed.wait_for(
                    lambda: gateway.state != "running"
                    or len(gateway.logs[stream]) > offset,
                    timeout=wait,
                )
                data = gateway.logs[stream][offset : offset + limit]
                body = {
                    "stream": stream,
                    "offset": offset,
                    "next_offset": offset + len(data),
                    "data": base64.b64encode(data).decode("ascii"),
                    "eof": offset + len(data) >= len(gateway.logs[stream]),
                }
                if gateway.holds:
                    body["job"] = gateway.record()
            self._answer(body)
            return
        self._answer({"error": "not found"}, status=404)

    def _answer(self, body: dict[str, Any], *, status: int = 200) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        if self.server.retry_after is not None:
            self.send_header("Retry-After", self.server.retry_after)
        self.end_headers()
        self.wfile.write(raw)


def _sync_job(gateway: _JobGateway) -> JobHandle:
    client = SandboxClient(gateway.base_url, timeout_seconds=10)
    with gateway.changed:
        record = SandboxJobRecord.from_payload(gateway.record())
    return JobHandle(client, SANDBOX, JOB, record)


async def _async_job(client: AsyncSandboxClient, gateway: _JobGateway) -> AsyncJobHandle:
    with gateway.changed:
        record = SandboxJobRecord.from_payload(gateway.record())
    return AsyncJobHandle(client, SANDBOX, JOB, record)


def _later(seconds: float, action: Any) -> Timer:
    timer = Timer(seconds, action)
    timer.daemon = True
    timer.start()
    return timer


def _gaps(gateway: _JobGateway) -> list[float]:
    times = [at for at, _path, _query in gateway.requests]
    return [later - earlier for earlier, later in zip(times, times[1:])]


class JobRecordWireTests(unittest.TestCase):
    def test_cursor_is_the_servers_or_computed_locally(self) -> None:
        payload = _JobGateway.record(_bare_gateway(holds=False))
        self.assertNotIn("cursor", payload)
        old = SandboxJobRecord.from_payload(dict(payload, stdout_bytes=5, sequence=3))
        self.assertEqual(old.cursor, "3.5.0")
        new = SandboxJobRecord.from_payload(dict(payload, cursor="opaque-9"))
        self.assertEqual(new.cursor, "opaque-9")
        built = SandboxJobRecord(
            sandbox_id=SANDBOX,
            sandbox_generation=1,
            job_id=JOB,
            spec_sha256="",
            state="running",
            stdout_bytes=2,
            stderr_bytes=4,
            sequence=1,
        )
        self.assertEqual(built.cursor, "1.2.4")

    def test_log_chunk_job_is_none_from_older_gateways(self) -> None:
        chunk = SandboxJobLogChunk.from_payload(
            {"stream": "stdout", "offset": 0, "next_offset": 0, "data": "", "eof": True}
        )
        self.assertIsNone(chunk.job)

    def test_read_job_logs_carries_the_record_and_sends_wait_ms(self) -> None:
        with _JobGateway() as gateway:
            gateway.write("stdout", b"hello")
            client = SandboxClient(gateway.base_url)
            chunk = client.read_job_logs(SANDBOX, JOB, offset=1, wait_seconds=2)
            self.assertEqual(chunk.data, b"ello")
            self.assertIsNotNone(chunk.job)
            self.assertEqual(chunk.job.stdout_bytes, 5)
            self.assertEqual(chunk.job.cursor, "1.5.0")
            self.assertEqual(
                gateway.queries()[-1],
                {"offset": "1", "limit": str(1024 * 1024), "wait_ms": "2000"},
            )
            plain = client.read_job_logs(SANDBOX, JOB, stream="stderr")
            self.assertNotIn("wait_ms", gateway.queries()[-1])
            self.assertEqual(plain.data, b"")

    def test_older_gateway_log_chunks_have_no_job(self) -> None:
        with _JobGateway(holds=False) as gateway:
            gateway.write("stdout", b"abc")
            client = SandboxClient(gateway.base_url)
            chunk = client.read_job_logs(SANDBOX, JOB, wait_seconds=5)
            self.assertEqual(chunk.data, b"abc")
            self.assertIsNone(chunk.job)

    def test_get_job_wait_sends_cursor_and_outlasts_the_wait(self) -> None:
        captured: list[float] = []
        real_open = client_module.open_no_redirect

        def open_capturing(req: Any, timeout: float) -> Any:
            captured.append(timeout)
            return real_open(req, timeout=timeout)

        with _JobGateway() as gateway, patch.object(
            client_module, "open_no_redirect", open_capturing
        ):
            client = SandboxClient(gateway.base_url, timeout_seconds=7)
            first = client.get_job(SANDBOX, JOB)
            self.assertEqual(gateway.queries()[-1], {})
            _later(0.2, lambda: gateway.write("stdout", b"x"))
            started = time.monotonic()
            changed = client.get_job(SANDBOX, JOB, wait_seconds=60, after=first.cursor)
            self.assertLess(time.monotonic() - started, 5)
            self.assertEqual(changed.cursor, "1.1.0")
            # wait_ms is clamped to the server's 25 s, and the request timeout
            # is the client's plus the wait.
            self.assertEqual(
                gateway.queries()[-1], {"wait_ms": "25000", "after": "1.0.0"}
            )
            self.assertEqual(len(captured), 2)
            self.assertAlmostEqual(captured[0], 7, places=1)
            self.assertAlmostEqual(captured[1], 32, places=1)

    def test_async_get_job_wait_outlasts_the_wait(self) -> None:
        captured: list[float] = []
        real_send = AsyncSandboxClient._send

        async def send_capturing(self: Any, *args: Any, **kwargs: Any) -> Any:
            captured.append(kwargs["timeout"])
            return await real_send(self, *args, **kwargs)

        async def scenario(gateway: _JobGateway) -> SandboxJobRecord:
            async with AsyncSandboxClient(gateway.base_url, timeout_seconds=7) as client:
                return await client.get_job(SANDBOX, JOB, wait_seconds=1.5, after="other")

        with _JobGateway() as gateway, patch.object(
            AsyncSandboxClient, "_send", send_capturing
        ):
            record = asyncio.run(scenario(gateway))
        self.assertEqual(record.cursor, "1.0.0")
        self.assertEqual(captured, [8.5])
        self.assertEqual(gateway.queries()[-1], {"wait_ms": "1500", "after": "other"})

    def test_carried_record_of_another_job_is_refused(self) -> None:
        with _JobGateway() as gateway:
            client = SandboxClient(gateway.base_url)
            with self.assertRaisesRegex(SandboxApiError, "another sandbox job"):
                client.read_job_logs(SANDBOX.upper(), JOB)


def _bare_gateway(*, holds: bool) -> _JobGateway:
    gateway = _JobGateway.__new__(_JobGateway)
    gateway.holds = holds
    gateway.state = "running"
    gateway.exit_code = None
    gateway.sequence = 1
    gateway.logs = {"stdout": b"", "stderr": b""}
    gateway.truncated = {"stdout": False, "stderr": False}
    return gateway


class JobWaitTests(unittest.TestCase):
    def test_wait_long_polls_with_the_cursor(self) -> None:
        with _JobGateway() as gateway:
            job = _sync_job(gateway)
            _later(0.2, lambda: gateway.write("stdout", b"out"))
            _later(0.4, gateway.finish)
            started = time.monotonic()
            # A poll_seconds pause anywhere would exceed the bound below.
            record = job.wait(poll_seconds=30)
            elapsed = time.monotonic() - started
        self.assertTrue(record.terminal)
        self.assertIs(job.record, record)
        self.assertLess(elapsed, 5)
        queries = gateway.queries()
        self.assertEqual(len(queries), 2)
        self.assertEqual(queries[0], {"wait_ms": "20000", "after": "1.0.0"})
        self.assertEqual(queries[1], {"wait_ms": "20000", "after": "1.3.0"})

    def test_wait_follows_retry_after(self) -> None:
        with _JobGateway() as gateway:
            gateway.retry_after = "0.3"
            gateway.before_answer = lambda count: count == 3 and gateway.finish()
            job = _sync_job(gateway)
            started = time.monotonic()
            record = job.wait(poll_seconds=30)
            elapsed = time.monotonic() - started
        self.assertTrue(record.terminal)
        self.assertEqual(len(gateway.requests), 3)
        self.assertTrue(all(gap >= 0.28 for gap in _gaps(gateway)), _gaps(gateway))
        self.assertLess(elapsed, 5)

    def test_wait_paces_an_older_gateway_with_poll_seconds(self) -> None:
        # Its answers come at once and carry no cursor, so even changed
        # answers (the job writing output) are paced.
        with _JobGateway(holds=False) as gateway:
            gateway.before_answer = lambda count: (
                gateway.write("stdout", b"x") if count < 4 else gateway.finish()
            )
            job = _sync_job(gateway)
            record = job.wait(poll_seconds=0.2)
        self.assertTrue(record.terminal)
        self.assertEqual(len(gateway.requests), 4)
        self.assertTrue(all(gap >= 0.18 for gap in _gaps(gateway)), _gaps(gateway))

    def test_wait_paces_unchanged_answers_that_come_back_early(self) -> None:
        # A cursor-sending server that does not hold this read.
        with _JobGateway() as gateway:
            gateway.holds = True
            gateway.before_answer = lambda count: count == 3 and gateway.finish()
            original = _JobHandler.do_GET

            def answer_at_once(handler: _JobHandler) -> None:
                handler.path = handler.path.replace("wait_ms", "ignored_ms")
                original(handler)

            with patch.object(_JobHandler, "do_GET", answer_at_once):
                record = _sync_job(gateway).wait(poll_seconds=0.2)
        self.assertTrue(record.terminal)
        self.assertEqual(len(gateway.requests), 3)
        self.assertTrue(all(gap >= 0.18 for gap in _gaps(gateway)), _gaps(gateway))

    def test_wait_timeout_bounds_the_held_read(self) -> None:
        with _JobGateway() as gateway:
            job = _sync_job(gateway)
            started = time.monotonic()
            with self.assertRaisesRegex(TimeoutError, JOB):
                job.wait(timeout_seconds=0.3, poll_seconds=30)
            self.assertLess(time.monotonic() - started, 3)
            gateway.finish()
        self.assertEqual(gateway.queries()[0]["after"], "1.0.0")
        self.assertLessEqual(int(gateway.queries()[0]["wait_ms"]), 300)

    def test_async_wait_long_polls_and_paces_older_gateways(self) -> None:
        async def scenario(gateway: _JobGateway, poll_seconds: float) -> SandboxJobRecord:
            async with AsyncSandboxClient(gateway.base_url) as client:
                job = await _async_job(client, gateway)
                return await job.wait(poll_seconds=poll_seconds)

        with _JobGateway() as gateway:
            _later(0.2, lambda: gateway.write("stderr", b"err"))
            _later(0.4, gateway.finish)
            started = time.monotonic()
            record = asyncio.run(scenario(gateway, 30))
            self.assertLess(time.monotonic() - started, 5)
        self.assertTrue(record.terminal)
        self.assertEqual(
            [query["after"] for query in gateway.queries()], ["1.0.0", "1.0.3"]
        )

        with _JobGateway(holds=False) as old:
            old.before_answer = lambda count: count == 3 and old.finish()
            record = asyncio.run(scenario(old, 0.2))
        self.assertTrue(record.terminal)
        self.assertTrue(all(gap >= 0.18 for gap in _gaps(old)), _gaps(old))

        with _JobGateway() as parked:
            parked.retry_after = "0.3"
            parked.before_answer = lambda count: count == 2 and parked.finish()
            record = asyncio.run(scenario(parked, 30))
        self.assertTrue(record.terminal)
        self.assertTrue(all(gap >= 0.28 for gap in _gaps(parked)), _gaps(parked))


class JobFollowTests(unittest.TestCase):
    def test_follow_reads_across_chunks_until_terminal(self) -> None:
        with _JobGateway() as gateway:
            gateway.write("stdout", b"0123456789")
            job = _sync_job(gateway)
            _later(0.2, lambda: gateway.write("stdout", b"abc"))
            _later(0.4, lambda: (gateway.write("stdout", b"def"), gateway.finish()))
            started = time.monotonic()
            chunks = list(job.follow(limit=4, poll_seconds=30))
            elapsed = time.monotonic() - started
        self.assertEqual(b"".join(chunks), b"0123456789abcdef")
        self.assertEqual(chunks[:3], [b"0123", b"4567", b"89"])
        self.assertTrue(all(len(chunk) <= 4 for chunk in chunks))
        self.assertLess(elapsed, 5)
        self.assertTrue(job.record.terminal)
        self.assertEqual(job.record.stdout_bytes, 16)
        log_queries = gateway.queries("/logs/stdout")
        self.assertTrue(all(q["wait_ms"] == "20000" for q in log_queries))
        # No status reads: every chunk carries the record.
        self.assertEqual(len(log_queries), len(gateway.requests))

    def test_follow_ends_at_the_terminal_byte_count(self) -> None:
        with _JobGateway() as gateway:
            gateway.write("stderr", b"tail")
            gateway.finish(exit_code=3)
            job = _sync_job(gateway)
            self.assertEqual(list(job.follow("stderr", offset=4)), [])
            self.assertEqual(len(gateway.requests), 1)
            self.assertEqual(list(job.follow("stderr", offset=1)), [b"ail"])
            self.assertEqual(list(job.follow("stdout")), [])
        self.assertEqual(job.record.exit_code, 3)

    def test_follow_raises_on_truncation(self) -> None:
        with _JobGateway() as gateway:
            gateway.write("stdout", b"kept")
            job = _sync_job(gateway)
            # A held stdout read answers once the job ends; its record shows
            # that stderr dropped output.
            _later(0.2, lambda: (gateway.truncate("stderr"), gateway.finish()))
            follower = job.follow()
            self.assertEqual(next(follower), b"kept")
            with self.assertRaises(JobOutputTruncatedError) as raised:
                next(follower)
        self.assertIsInstance(raised.exception, SandboxApiError)
        self.assertTrue(raised.exception.record.stderr_truncated)
        self.assertIn("stderr", str(raised.exception))

    def test_follow_rejects_an_unknown_stream_at_once(self) -> None:
        with _JobGateway() as gateway:
            with self.assertRaises(ValueError):
                _sync_job(gateway).follow("stdin")
        self.assertEqual(gateway.requests, [])

    def test_follow_on_an_older_gateway_reads_status_and_paces(self) -> None:
        with _JobGateway(holds=False) as gateway:
            gateway.write("stdout", b"abcdef")

            def progress(count: int) -> None:
                # Requests alternate log read, status read.
                if count == 3:
                    gateway.write("stdout", b"gh")
                if count == 6:
                    gateway.finish()

            gateway.before_answer = progress
            job = _sync_job(gateway)
            chunks = list(job.follow(limit=4, poll_seconds=0.2))
        self.assertEqual(b"".join(chunks), b"abcdefgh")
        paths = gateway.paths()
        status_path = f"/v1/sandboxes/{SANDBOX}/jobs/{JOB}"
        # A full page is followed at once without a status read; a short one
        # is followed by a status read and a poll_seconds pause.
        self.assertEqual(paths[0], f"{status_path}/logs/stdout")
        self.assertEqual(paths[1], f"{status_path}/logs/stdout")
        self.assertEqual(paths[2], status_path)
        self.assertEqual(paths[-1], status_path)
        times = [at for at, _path, _query in gateway.requests]
        self.assertLess(times[1] - times[0], 0.15)
        self.assertGreaterEqual(times[3] - times[2], 0.18)
        self.assertTrue(job.record.terminal)

    def test_follow_honours_retry_after_on_parked_reads(self) -> None:
        with _JobGateway() as gateway:
            gateway.retry_after = "0.3"

            def wake(count: int) -> None:
                if count == 3:
                    gateway.retry_after = None
                    gateway.write("stdout", b"woke")
                    gateway.finish()

            gateway.before_answer = wake
            started = time.monotonic()
            chunks = list(_sync_job(gateway).follow(poll_seconds=30))
            elapsed = time.monotonic() - started
        self.assertEqual(chunks, [b"woke"])
        self.assertEqual(len(gateway.requests), 3)
        self.assertTrue(all(gap >= 0.28 for gap in _gaps(gateway)), _gaps(gateway))
        self.assertLess(elapsed, 5)

    def test_async_follow_reads_across_chunks_and_older_gateways(self) -> None:
        async def follow(gateway: _JobGateway, **kwargs: Any) -> list[bytes]:
            async with AsyncSandboxClient(gateway.base_url) as client:
                job = await _async_job(client, gateway)
                chunks = [chunk async for chunk in job.follow(**kwargs)]
                self.assertTrue(job.record.terminal)
                return chunks

        with _JobGateway() as gateway:
            gateway.write("stdout", b"012345")
            _later(0.2, lambda: (gateway.write("stdout", b"6789"), gateway.finish()))
            started = time.monotonic()
            chunks = asyncio.run(follow(gateway, limit=4, poll_seconds=30))
            self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(b"".join(chunks), b"0123456789")

        with _JobGateway(holds=False) as old:
            old.write("stderr", b"err")
            old.before_answer = lambda count: count == 2 and old.finish()
            chunks = asyncio.run(follow(old, stream="stderr", poll_seconds=0.2))
        self.assertEqual(chunks, [b"err"])

        with _JobGateway() as truncated:
            truncated.write("stdout", b"x")
            truncated.truncate("stdout")
            with self.assertRaises(JobOutputTruncatedError):
                asyncio.run(follow(truncated))


if __name__ == "__main__":
    unittest.main()
