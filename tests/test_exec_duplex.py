import asyncio
from threading import Event
import unittest
from unittest.mock import AsyncMock, Mock, patch

from ucloud_sandboxes_sdk import AsyncSandboxClient, SandboxClient


class ExecDuplexFailureTests(unittest.TestCase):
    def test_sync_failure_interrupts_peer_io_and_preserves_original_error(self):
        for failing in ('input', 'output'):
            with self.subTest(failing=failing):
                stopped, finished = Event(), Event()
                error = RuntimeError(f'{failing} failed')
                def fail(*args, **kwargs):
                    raise error
                def blocked(*args, **kwargs):
                    try:
                        if not stopped.wait(2):
                            raise TimeoutError('peer I/O was not interrupted')
                    finally:
                        finished.set()
                handle = Mock()
                handle.kill.side_effect = stopped.set
                handle.write_stdin.side_effect = fail if failing == 'input' else blocked
                handle.wait.side_effect = fail if failing == 'output' else blocked
                client = SandboxClient('http://unused')
                with patch.object(client, 'start_exec', return_value=handle):
                    with self.assertRaises(RuntimeError) as raised:
                        client.exec('one', ['cat'], input='payload', timeout_seconds=1)
                self.assertIs(raised.exception, error)
                handle.kill.assert_called_once()
                # A not-yet-started peer may be cancelled by executor shutdown.
                if (handle.wait if failing == 'input' else handle.write_stdin).called:
                    self.assertTrue(finished.wait(1))

    def test_async_failure_cancels_peer_io_and_preserves_original_error(self):
        async def run():
            for failing in ('input', 'output'):
                finished = asyncio.Event()
                error = RuntimeError(f'{failing} failed')
                async def fail(*args, **kwargs):
                    await asyncio.sleep(0)
                    raise error
                async def blocked(*args, **kwargs):
                    try:
                        await asyncio.Event().wait()
                    finally:
                        finished.set()
                handle = Mock()
                handle.kill = AsyncMock()
                handle.write_stdin = AsyncMock(side_effect=fail if failing == 'input' else blocked)
                handle.wait = AsyncMock(side_effect=fail if failing == 'output' else blocked)
                client = AsyncSandboxClient('http://unused')
                with patch.object(client, 'start_exec', new=AsyncMock(return_value=handle)):
                    with self.assertRaises(RuntimeError) as raised:
                        await client.exec('one', ['cat'], input='payload', timeout_seconds=1)
                self.assertIs(raised.exception, error)
                handle.kill.assert_awaited_once()
                self.assertTrue(finished.is_set())
        asyncio.run(run())

    def test_async_cancellation_closes_both_io_tasks(self):
        async def run():
            entered, ended = [], []
            async def block(name):
                entered.append(name)
                try:
                    await asyncio.Event().wait()
                finally:
                    ended.append(name)
            handle = Mock()
            handle.write_stdin = lambda *a, **kw: block('input')
            handle.wait = lambda *a, **kw: block('output')
            handle.kill = AsyncMock()
            client = AsyncSandboxClient('http://unused')
            with patch.object(client, 'start_exec', new=AsyncMock(return_value=handle)):
                operation = asyncio.create_task(client.exec('one', ['cat'], input='payload'))
                while len(entered) != 2:
                    await asyncio.sleep(0)
                operation.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await operation
            self.assertCountEqual(ended, ['input', 'output'])
            handle.kill.assert_awaited_once()
        asyncio.run(run())
