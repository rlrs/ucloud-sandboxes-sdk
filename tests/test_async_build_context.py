import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import multiprocessing
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import AsyncMock, patch

from tests import test_client as helpers
from ucloud_sandboxes_sdk import AsyncSandboxClient, Image
import ucloud_sandboxes_sdk.client as module


class RecordingClient(AsyncSandboxClient):
    def __init__(self, *, stop_at_probe=False):
        super().__init__('http://unused.invalid')
        self.requests = []
        self.uploads = []
        self.stop_at_probe = stop_at_probe
        self.probed = asyncio.Event()

    async def _request_json(self, method, path, **kwargs):
        self.requests.append((method, path, kwargs))
        if method == 'GET':
            self.probed.set()
            if self.stop_at_probe:
                await asyncio.Event().wait()
            return {}
        if method == 'PUT':
            self.uploads.append(kwargs['body'].read())
            return {}
        return {'build': {'build_id': 'owned-build', 'status': 'running'}}


class CountingExecutor(ThreadPoolExecutor):
    def __init__(self):
        super().__init__(max_workers=2)
        self.submitted = 0

    def submit(self, *args, **kwargs):
        self.submitted += 1
        return super().submit(*args, **kwargs)


async def until(predicate, timeout=2):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError('bounded test condition did not become true')
        await asyncio.sleep(.005)


def prepare_in_forked_child(context, result):
    async def scenario():
        image = Image.from_dockerfile(name='forked', context_path=context)
        async with module._async_image_build_request(image, deadline=module._deadline(2)) as (_, archive):
            return hashlib.sha256(archive.read()).hexdigest()
    try:
        result.send(('ok', asyncio.run(scenario())))
    except BaseException as error:
        result.send(('error', type(error).__name__))
    finally:
        result.close()


class AsyncBuildContextTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, 'fork'), 'requires POSIX fork')
    def test_fork_after_warmup_resets_executor_and_inherited_lock(self):
        async def warm(context):
            image = Image.from_dockerfile(name='parent', context_path=context)
            async with module._async_image_build_request(image, deadline=module._deadline(2)) as (_, archive):
                return hashlib.sha256(archive.read()).hexdigest()
        with helpers.docker_context() as context:
            expected = asyncio.run(warm(context))
            fork = multiprocessing.get_context('fork')
            receiver, sender = fork.Pipe(duplex=False)
            child = fork.Process(target=prepare_in_forked_child, args=(context, sender))
            try:
                # Also prove the child does not acquire a lock inherited in a
                # locked state; its owner might have vanished during the fork.
                with module._BUILD_CONTEXT_LIMITERS_LOCK:
                    child.start()
                sender.close()
                self.assertTrue(receiver.poll(5), 'forked preparation stalled')
                self.assertEqual(receiver.recv(), ('ok', expected))
                child.join(5)
                self.assertEqual(child.exitcode, 0)
            finally:
                if child.is_alive():
                    child.terminate()
                    child.join(5)
                receiver.close()
                sender.close()

    def test_completed_step_does_not_swallow_same_turn_cancellation(self):
        async def scenario():
            loop = asyncio.get_running_loop()
            ready = loop.create_future()
            ready.set_result('finished')
            task = asyncio.create_task(module._await_build_context_step(ready, module._deadline(1)))
            loop.call_soon(task.cancel)
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertEqual(ready.result(), 'finished')
        asyncio.run(scenario())

    def test_archive_bytes_and_payload_match_sync_including_links_and_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'Dockerfile').write_text('FROM scratch\nCOPY . /src\n')
            (root / 'dir').mkdir()
            (root / 'dir' / 'source').write_bytes(bytes(range(256)) * 100)
            (root / 'dir' / 'source').chmod(0o751)
            (root / 'link').symlink_to('dir/source')
            image = Image.from_dockerfile(name='same', context_path=root, build_args={'X': '1'})
            with module._image_build_request(image) as (payload, archive):
                expected_payload, expected_bytes = dict(payload), archive.read()

            async def scenario():
                async with module._async_image_build_request(image, deadline=module._deadline(5)) as (payload, archive):
                    self.assertEqual(payload, expected_payload)
                    self.assertEqual(archive.read(), expected_bytes)
                    return archive

            archive = asyncio.run(scenario())
            self.assertTrue(archive.closed)

    def test_packaging_runs_off_loop_and_keeps_heartbeat_responsive(self):
        entered, release = threading.Event(), threading.Event()
        original = module._build_context_archive_identity
        thread_ids = []

        def slow_identity(archive):
            thread_ids.append(threading.get_ident())
            entered.set()
            if not release.wait(2):
                raise AssertionError('event loop failed to release packaging worker')
            return original(archive)

        async def scenario(context):
            client = RecordingClient()
            task = asyncio.create_task(client.submit_image_build(Image.from_dockerfile(name='live', context_path=context)))
            try:
                await until(entered.is_set)
                for _ in range(10):
                    await asyncio.sleep(.005)
                self.assertFalse(task.done())
                self.assertEqual(client.requests, [])
                self.assertNotEqual(thread_ids, [threading.get_ident()])
            finally:
                release.set()
            await task

        with helpers.docker_context() as context, patch.object(module, '_build_context_archive_identity', slow_identity):
            asyncio.run(scenario(context))

    def test_five_hundred_callers_submit_only_two_preparations_and_cancel_waiters(self):
        release = threading.Event()
        entered = []
        lock = threading.Lock()
        original = module._prepare_image_build_request

        def blocked(image):
            with lock:
                entered.append(image.name)
            if not release.wait(5):
                raise AssertionError('preparation was not released')
            return original(image)

        async def scenario(context, executor):
            tasks = [asyncio.create_task(RecordingClient().submit_image_build(
                Image.from_dockerfile(name=f'build-{index}', context_path=context))) for index in range(500)]
            try:
                await until(lambda: len(entered) == 2)
                await asyncio.sleep(.03)
                self.assertEqual(executor.submitted, 2)
                deadline_client = RecordingClient()
                with self.assertRaises(TimeoutError):
                    await deadline_client.submit_image_build(
                        Image.from_dockerfile(name='queued-deadline', context_path=context),
                        timeout_seconds=.01,
                    )
                self.assertEqual(deadline_client.requests, [])
                self.assertEqual(executor.submitted, 2)
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                self.assertEqual(executor.submitted, 2)
                # Canceling active awaiters must not release their still-running
                # thread permits and fill the executor with stale work.
                next_task = asyncio.create_task(RecordingClient().submit_image_build(
                    Image.from_dockerfile(name='next', context_path=context)))
                await asyncio.sleep(.02)
                self.assertEqual(executor.submitted, 2)
                release.set()
                await next_task
                self.assertEqual(executor.submitted, 3)
            finally:
                release.set()
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

        with helpers.docker_context() as context, CountingExecutor() as executor, patch.object(module, '_BUILD_CONTEXT_EXECUTOR', executor), patch.object(module, '_prepare_image_build_request', blocked):
            asyncio.run(scenario(context, executor))

    def test_cancel_running_preparation_closes_late_archive_after_loop_shutdown(self):
        entered, release, closed = threading.Event(), threading.Event(), threading.Event()
        original = module._image_build_request
        archives = []

        @contextmanager
        def delayed(image):
            with original(image) as (payload, archive):
                archives.append(archive)
                entered.set()
                if not release.wait(3):
                    raise AssertionError('worker release missing')
                try:
                    yield payload, archive
                finally:
                    closed.set()

        async def scenario(context):
            client = RecordingClient()
            task = asyncio.create_task(client.submit_image_build(Image.from_dockerfile(name='cancel', context_path=context)))
            await until(entered.is_set)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertEqual(client.requests, [])
            self.assertFalse(archives[0].closed)

        with helpers.docker_context() as context, ThreadPoolExecutor(max_workers=2) as executor, patch.object(module, '_BUILD_CONTEXT_EXECUTOR', executor), patch.object(module, '_image_build_request', delayed):
            try:
                asyncio.run(scenario(context))
            finally:
                release.set()
            self.assertTrue(closed.wait(2))
        self.assertTrue(archives[0].closed)

    def test_preparation_deadline_cleans_up_without_sending_request(self):
        entered, release = threading.Event(), threading.Event()
        original = module._prepare_image_build_request
        archives = []

        def blocked(image):
            prepared = original(image)
            archives.append(prepared[1])
            entered.set()
            if not release.wait(3):
                prepared[2].close()
                raise AssertionError('worker release missing')
            return prepared

        async def scenario(context):
            client = RecordingClient()
            try:
                with self.assertRaises(TimeoutError):
                    await client.submit_image_build(Image.from_dockerfile(name='deadline', context_path=context), timeout_seconds=.1)
                self.assertTrue(entered.is_set())
                self.assertEqual(client.requests, [])
            finally:
                release.set()
            await until(lambda: bool(archives) and archives[0].closed)

        with helpers.docker_context() as context, patch.object(module, '_prepare_image_build_request', blocked):
            asyncio.run(scenario(context))

    def test_cancel_during_http_closes_prepared_archive(self):
        async def scenario(context):
            client = RecordingClient(stop_at_probe=True)
            archives = []
            original = module._prepare_image_build_request
            def capture(image):
                prepared = original(image)
                archives.append(prepared[1])
                return prepared
            with patch.object(module, '_prepare_image_build_request', capture):
                task = asyncio.create_task(client.submit_image_build(Image.from_dockerfile(name='http-cancel', context_path=context)))
                await client.probed.wait()
                self.assertFalse(archives[0].closed)
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                self.assertTrue(archives[0].closed)
        with helpers.docker_context() as context:
            asyncio.run(scenario(context))

    def test_admission_retries_reuse_one_prepared_archive(self):
        attempts = []
        def respond(method, url, kwargs, _call):
            if str(url).endswith('/v1/images/build'):
                attempts.append(dict(kwargs['json']))
                if len(attempts) <= 8:
                    return helpers._AsyncResponse('{"retryable":true,"error_code":"builder_busy"}', status=503)
                return helpers._AsyncResponse('{"build":{"build_id":"owned-build","status":"running"}}')
            return helpers._AsyncResponse('{}')
        async def scenario(context):
            session = helpers._ScriptedAsyncSession(respond)
            with patch.object(module, '_prepare_image_build_request', wraps=module._prepare_image_build_request) as prepare, patch.object(module, '_async_sleep_for_retry', AsyncMock(return_value=True)):
                client = AsyncSandboxClient('http://unused.invalid', session=session)
                await client.submit_image_build(Image.from_dockerfile(name='retry', context_path=context))
                self.assertEqual(prepare.call_count, 1)
                self.assertEqual(sum(method == 'PUT' for method, *_ in session.requests), 1)
            self.assertEqual(len(attempts), 9)
            self.assertTrue(all(value == attempts[0] for value in attempts))
        with helpers.docker_context() as context:
            asyncio.run(scenario(context))

    def test_later_submission_reads_changed_context_without_implicit_cache(self):
        async def scenario(context):
            image = Image.from_dockerfile(name='fresh', context_path=context)
            client = RecordingClient()
            await client.submit_image_build(image)
            (Path(context) / 'new-file').write_text('changed source')
            await client.submit_image_build(image)
            self.assertEqual(len(client.uploads), 2)
            self.assertNotEqual(*[hashlib.sha256(value).digest() for value in client.uploads])
        with helpers.docker_context() as context:
            asyncio.run(scenario(context))

    def test_invalid_preparation_preserves_error_and_releases_admission(self):
        async def scenario(context):
            client = RecordingClient()
            with self.assertRaises(TypeError):
                await client.submit_image_build('not-an-Image')
            result = await client.submit_image_build(Image.from_dockerfile(name='valid', context_path=context))
            self.assertEqual(result['build_id'], 'owned-build')
        with helpers.docker_context() as context:
            asyncio.run(scenario(context))
