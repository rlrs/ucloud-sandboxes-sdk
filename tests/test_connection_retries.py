import asyncio
import errno
import io
import socket
import ssl
import unittest
from types import SimpleNamespace
from urllib.error import URLError
from unittest.mock import AsyncMock, Mock, patch

from aiohttp import ClientConnectorError, ClientConnectorCertificateError, ServerDisconnectedError
from ucloud_sandboxes_sdk.client import AsyncSandboxClient, SandboxClient, SandboxApiError

M = 'ucloud_sandboxes_sdk.client'
KEY = SimpleNamespace(host='gateway', port=443, ssl=True)


class ConnectionRetries(unittest.IsolatedAsyncioTestCase):
    async def test_async_connect_retries_rewind_mutation_body(self):
        session = Mock()
        body = io.BytesIO(b'payload')
        positions = []
        def fail(*args, **kwargs):
            positions.append(body.tell())
            body.seek(7)
            raise ClientConnectorError(KEY, ConnectionResetError())
        session.request.side_effect = fail
        client = AsyncSandboxClient('https://gateway', session=session)
        with patch(M + '._async_sleep_for_retry', new=AsyncMock(return_value=True)):
            with self.assertRaises(SandboxApiError) as caught:
                await client._send('POST', '/v1/exec/test/stdin', payload=None, body=body,
                                   headers={}, timeout=30, streamed=True, success_limit=1024)
        self.assertEqual(positions, [0] * 5)
        self.assertEqual(caught.exception.body['attempts'], 5)
        self.assertIn('ConnectionResetError', str(caught.exception))

    async def test_async_ambiguous_errors_tls_and_cancellation_not_retried(self):
        for exc in (ServerDisconnectedError(), asyncio.TimeoutError(), asyncio.CancelledError(),
                    ClientConnectorCertificateError(KEY, ssl.CertificateError('bad cert'))):
            session = Mock()
            session.request.side_effect = exc
            client = AsyncSandboxClient('https://gateway', session=session)
            with self.assertRaises(type(exc)):
                await client._request_json('POST', '/v1/exec/test/stdin', payload={})
            self.assertEqual(session.request.call_count, 1)

    async def test_async_deadline_stops_retries(self):
        session = Mock()
        session.request.side_effect = ClientConnectorError(KEY, OSError(errno.ECONNREFUSED, 'refused'))
        client = AsyncSandboxClient('https://gateway', session=session)
        with patch(M + '._async_sleep_for_retry', new=AsyncMock(return_value=False)):
            with self.assertRaises(SandboxApiError):
                await client._request_json('GET', '/healthz')
        self.assertEqual(session.request.call_count, 1)

    def test_sync_dns_retry_recovers_json_and_bytes(self):
        for binary in (False, True):
            response = Mock()
            response.status = 200
            response.headers = {}
            response.read.side_effect = [b'{}', b'']
            context = Mock()
            context.__enter__ = Mock(return_value=response)
            context.__exit__ = Mock(return_value=False)
            with patch(M + '.open_no_redirect', side_effect=[URLError(socket.gaierror(-3, 'temporary')), context]) as send, patch(M + '._sleep_for_retry', return_value=True):
                client = SandboxClient('https://gateway')
                result = client._request_bytes('GET', '/file') if binary else client._request_json('POST', '/v1/exec/test/stdin', payload={})
                self.assertEqual(result, b'{}' if binary else {})
                self.assertEqual(send.call_count, 2)

    def test_sync_ambiguous_read_failure_not_retried(self):
        with patch(M + '.open_no_redirect', side_effect=URLError(TimeoutError('read'))) as send:
            with self.assertRaises(SandboxApiError):
                SandboxClient('https://gateway')._request_json('POST', '/v1/exec/test/stdin', payload={})
            self.assertEqual(send.call_count, 1)
