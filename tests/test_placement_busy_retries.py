"""Exercise the production placement response through real HTTP transports."""
import asyncio
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Thread
import unittest
from unittest.mock import patch

from ucloud_sandboxes_sdk.client import AsyncSandboxClient, SandboxApiError, SandboxClient
from ucloud_sandboxes_sdk.client import Image, SandboxSpec


BUSY = {'error': 'gateway is busy reserving sandbox placement; retry shortly',
        'retryable': True}


@contextmanager
def gateway(*, failures=2):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            requests.append((self.path, payload))
            busy = len(requests) <= failures
            body = json.dumps(BUSY if busy else {'sandbox': {'spec': payload}}).encode()
            self.send_response(503 if busy else 201)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            if busy:
                self.send_header('Retry-After', '2')
                self.send_header('X-UCloud-Sandbox-Retryable', 'true')
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)


def spec():
    return SandboxSpec(id='placement-retry', image=Image.from_registry('busybox:latest'))


class PlacementBusyRetries(unittest.TestCase):
    def test_sync_exact_production_response_retries_same_create(self):
        with gateway() as (url, requests), patch('ucloud_sandboxes_sdk.client.random.random', return_value=0):
            result = SandboxClient(url).create_sandbox(spec(), request_timeout_seconds=20)
        self.assertEqual(result.id, 'placement-retry')
        self.assertEqual(len(requests), 3)
        self.assertTrue(all(request == requests[0] for request in requests))

    def test_async_exact_production_response_retries_same_create(self):
        async def run(url):
            client = AsyncSandboxClient(url)
            try:
                return await client.create_sandbox(spec(), request_timeout_seconds=20)
            finally:
                await client.close()
        with gateway() as (url, requests), patch('ucloud_sandboxes_sdk.client.random.random', return_value=0):
            result = asyncio.run(run(url))
        self.assertEqual(result.id, 'placement-retry')
        self.assertEqual(len(requests), 3)
        self.assertTrue(all(request == requests[0] for request in requests))

    def test_sync_insufficient_deadline_returns_the_same_503_without_retry(self):
        with gateway(failures=100) as (url, requests):
            with self.assertRaises(SandboxApiError) as caught:
                SandboxClient(url).create_sandbox(spec(), request_timeout_seconds=1)
        self.assertEqual(len(requests), 1)
        self.assertEqual(caught.exception.body, BUSY)
        self.assertEqual(caught.exception.status_code, 503)
        self.assertIn('retry budget exhausted after 1 HTTP attempt(s)', str(caught.exception))

    def test_async_insufficient_deadline_returns_the_same_503_without_retry(self):
        async def run(url):
            client = AsyncSandboxClient(url)
            try:
                return await client.create_sandbox(spec(), request_timeout_seconds=1)
            finally:
                await client.close()
        with gateway(failures=100) as (url, requests):
            with self.assertRaises(SandboxApiError) as caught:
                asyncio.run(run(url))
        self.assertEqual(len(requests), 1)
        self.assertEqual(caught.exception.body, BUSY)
        self.assertEqual(caught.exception.status_code, 503)
        self.assertIn('retry budget exhausted after 1 HTTP attempt(s)', str(caught.exception))

    def test_sync_exhaustion_reports_all_attempts(self):
        with gateway(failures=100) as (url, requests), patch(
            'ucloud_sandboxes_sdk.client._sleep_for_retry', side_effect=[True, True, False],
        ):
            with self.assertRaises(SandboxApiError) as caught:
                SandboxClient(url).create_sandbox(spec())
        self.assertEqual(len(requests), 3)
        self.assertEqual(caught.exception.body, BUSY)
        self.assertIn('retry budget exhausted after 3 HTTP attempt(s)', str(caught.exception))

    def test_async_exhaustion_reports_all_attempts(self):
        async def run(url):
            client = AsyncSandboxClient(url)
            try:
                return await client.create_sandbox(spec())
            finally:
                await client.close()
        with gateway(failures=100) as (url, requests), patch(
            'ucloud_sandboxes_sdk.client._async_sleep_for_retry', side_effect=[True, True, False],
        ):
            with self.assertRaises(SandboxApiError) as caught:
                asyncio.run(run(url))
        self.assertEqual(len(requests), 3)
        self.assertEqual(caught.exception.body, BUSY)
        self.assertIn('retry budget exhausted after 3 HTTP attempt(s)', str(caught.exception))
