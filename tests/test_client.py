from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import io
import hashlib
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Lock, Thread
import unittest
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, unquote, urlparse

import ucloud_sandboxes_sdk.client as client_module
from ucloud_sandboxes_sdk import (
    AsyncSandboxClient,
    ExecEventHistoryLostError,
    Image,
    SandboxApiError,
    SandboxClient,
    SandboxFilesystemSpec,
    SandboxSecuritySpec,
    SandboxSpec,
    SandboxSshSpec,
    sandbox_auth_headers,
)


class _SyncResponse:
    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.body = body
        self.status = status
        self.headers = headers or {}

    def __enter__(self) -> "_SyncResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _size: int | None = None) -> bytes:
        return self.body


class _AsyncResponse:
    def __init__(
        self,
        body: str,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.body = body
        self.status = status
        self.headers = headers or {}

    async def __aenter__(self) -> "_AsyncResponse":
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def text(self) -> str:
        return self.body


class _ScriptedAsyncSession:
    def __init__(
        self,
        responder: Callable[[str, object, dict[str, object], int], _AsyncResponse],
    ) -> None:
        self.responder = responder
        self.requests: list[tuple[str, object, dict[str, object]]] = []

    def request(
        self,
        method: object,
        url: object,
        **kwargs: object,
    ) -> _AsyncResponse:
        request = (str(method), url, dict(kwargs))
        self.requests.append(request)
        return self.responder(*request, len(self.requests))


class SandboxSdkTests(unittest.TestCase):
    def test_credentialed_clients_reject_redirects(self) -> None:
        with running_redirect_gateway() as gateway:
            sync_client = SandboxClient(gateway.base_url, api_token="secret-token")
            with self.assertRaises(SandboxApiError) as sync_raised:
                sync_client.health()

            async def scenario() -> None:
                async with AsyncSandboxClient(
                    gateway.base_url,
                    api_token="secret-token",
                ) as async_client:
                    with self.assertRaises(SandboxApiError) as async_raised:
                        await async_client.health()
                    self.assertEqual(async_raised.exception.status_code, 302)

            asyncio.run(scenario())

        self.assertEqual(sync_raised.exception.status_code, 302)
        self.assertEqual(gateway.state.redirected_hits, 0)
        self.assertEqual(
            gateway.state.initial_tokens,
            ["secret-token", "secret-token"],
        )
        self.assertEqual(
            sandbox_auth_headers(" secret-token "),
            {"X-UCloud-Sandbox-Token": "secret-token"},
        )

    def test_exec_wait_rejects_noncontiguous_event_history(self) -> None:
        class GapClient:
            def read_exec_events(self, *_args: object, **_kwargs: object) -> dict:
                return {
                    "events": [{"sequence": 2, "stream": "stdout", "data": "tail"}],
                    "session": {"status": "exited", "exit_code": 0},
                }

        handle = client_module.ExecHandle(GapClient(), "exec-gap", "sandbox-one")
        with self.assertRaises(ExecEventHistoryLostError) as raised:
            handle.wait(timeout_seconds=1)

        self.assertEqual(raised.exception.expected_sequence, 1)
        self.assertEqual(raised.exception.received_sequence, 2)

    def test_async_exec_wait_rejects_noncontiguous_event_history(self) -> None:
        class GapClient:
            async def read_exec_events(
                self,
                *_args: object,
                **_kwargs: object,
            ) -> dict:
                return {
                    "events": [{"sequence": 4, "stream": "stderr", "data": "tail"}],
                    "session": {"status": "failed", "exit_code": 1},
                }

        async def scenario() -> None:
            handle = client_module.AsyncExecHandle(
                GapClient(),
                "exec-async-gap",
                "sandbox-one",
            )
            with self.assertRaises(ExecEventHistoryLostError) as raised:
                await handle.wait(timeout_seconds=1)
            self.assertEqual(raised.exception.expected_sequence, 1)
            self.assertEqual(raised.exception.received_sequence, 4)

        asyncio.run(scenario())

    def test_request_and_local_file_uploads_are_bounded(self) -> None:
        client = SandboxClient("http://gateway.invalid")
        with patch.object(client_module, "MAX_FILE_BODY_BYTES", 3):
            with self.assertRaisesRegex(SandboxApiError, "request body exceeds"):
                client.upload_file("sandbox", "/workspace/data", b"four")
            with TemporaryDirectory() as raw_dir:
                path = Path(raw_dir) / "data"
                path.write_bytes(b"four")
                with self.assertRaisesRegex(SandboxApiError, "file exceeds"):
                    client.upload_file_from_path(
                        "sandbox",
                        path,
                        "/workspace/data",
                    )

    def test_sync_upload_rejects_a_mismatched_success_acknowledgement(self) -> None:
        client = SandboxClient("http://gateway.invalid")
        with patch.object(
            client,
            "_request_json",
            return_value={
                "ok": True,
                "sandbox_id": "sandbox",
                "path": "/workspace/harness.py",
                "size": 0,
            },
        ):
            with self.assertRaisesRegex(
                SandboxApiError,
                "invalid file upload acknowledgement",
            ):
                client.upload_file(
                    "sandbox",
                    "/workspace/harness.py",
                    b"# /// script\n# ///\n",
                )

    def test_async_upload_rejects_a_mismatched_success_acknowledgement(self) -> None:
        async def scenario() -> None:
            client = AsyncSandboxClient("http://gateway.invalid")
            with patch.object(
                client,
                "_request_json",
                new=AsyncMock(
                    return_value={
                        "ok": True,
                        "sandbox_id": "sandbox",
                        "path": "/workspace/harness.py",
                        "size": 0,
                    }
                ),
            ):
                with self.assertRaisesRegex(
                    SandboxApiError,
                    "invalid file upload acknowledgement",
                ):
                    await client.upload_file(
                        "sandbox",
                        "/workspace/harness.py",
                        b"# /// script\n# ///\n",
                    )

        asyncio.run(scenario())

    def test_sync_and_async_json_responses_are_bounded(self) -> None:
        with (
            patch.object(client_module, "MAX_JSON_RESPONSE_BYTES", 3),
            patch.object(
                client_module,
                "open_no_redirect",
                lambda *_args, **_kwargs: _SyncResponse(
                    b"four", headers={"Content-Length": "4"}
                ),
            ),
        ):
            with self.assertRaisesRegex(SandboxApiError, "response exceeds"):
                SandboxClient("http://gateway.invalid").health()

        async def scenario() -> None:
            client = AsyncSandboxClient(
                "http://gateway.invalid",
                session=_ScriptedAsyncSession(
                    lambda *_args: _AsyncResponse(
                        "four", headers={"Content-Length": "4"}
                    )
                ),
            )
            with self.assertRaisesRegex(SandboxApiError, "response exceeds"):
                await client.health()

        with patch.object(client_module, "MAX_JSON_RESPONSE_BYTES", 3):
            asyncio.run(scenario())

    def test_sync_client_lifecycle_and_exec(self) -> None:
        with running_gateway() as gateway:
            client = SandboxClient(gateway.base_url)

            health = client.health()
            handle = client.create_sandbox(
                SandboxSpec(
                    id="sdk-one",
                    image=Image.from_registry("busybox"),
                    command=["sleep", "300"],
                    memory_mb=128,
                    cpus=0.25,
                    disk_mb=64,
                    labels={"test": "sdk"},
                )
            )
            listed = client.list_sandboxes()
            result = handle.exec(["cat"], input="hello\n", timeout_seconds=2)
            uploaded = handle.upload_file(
                "/workspace/prompt.txt",
                b"prompt bytes\n",
            )
            downloaded = handle.download_file("/workspace/prompt.txt")
            ssh_target = handle.ssh()
            deleted = handle.delete()

        self.assertTrue(health["ok"])
        self.assertEqual(handle.id, "sdk-one")
        self.assertEqual(listed[0]["spec"]["id"], "sdk-one")
        self.assertTrue(result.success)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout, "stdout\n")
        self.assertEqual(result.stderr, "stderr\n")
        self.assertIn("stdin", [event["stream"] for event in result.events])
        self.assertEqual(uploaded["size"], 13)
        self.assertEqual(downloaded, b"prompt bytes\n")
        self.assertEqual(ssh_target.sandbox_id, "sdk-one")
        self.assertEqual(ssh_target.user, "sandbox")
        self.assertEqual(ssh_target.host, "127.0.0.1")
        self.assertEqual(ssh_target.port, 22000)
        self.assertEqual(ssh_target.command, "ssh -p 22000 sandbox@127.0.0.1")
        self.assertEqual(deleted["deleted"]["spec"]["id"], "sdk-one")

    def test_sync_client_image_cache_methods(self) -> None:
        with docker_context() as context, running_gateway() as gateway:
            client = SandboxClient(gateway.base_url)
            source = Image.from_dockerfile(
                name="python-base",
                context_path=context,
            )
            built = client.build_image(source)
            rebuilt = client.build_image(source)
            pulled = client.pull_image(
                Image.from_registry("busybox:latest"),
                image_id="busybox",
                count=2,
                cpus=1,
                memory_mb=512,
            )
            images = client.list_images()
            builds = client.list_image_builds()

        self.assertEqual(built["image"]["id"], "python-base")
        self.assertEqual(rebuilt["image"]["id"], "python-base")
        self.assertEqual(built["image"]["tag"], "")
        self.assertTrue(built["image"]["received_push"])
        self.assertGreater(built["image"]["received_archive_bytes"], 0)
        self.assertEqual(gateway.state.build_context_puts, 1)
        self.assertEqual(len(gateway.state.build_contexts), 1)
        self.assertEqual(builds[0]["status"], "succeeded")
        self.assertEqual(pulled["image"]["id"], "busybox")
        self.assertCountEqual(
            [image["id"] for image in images],
            ["busybox", "python-base"],
        )

    def test_sandbox_spec_nested_types_and_optional_fields(self) -> None:
        payload = SandboxSpec(
            id="typed-nested-specs",
            image=Image.from_registry("busybox"),
            security=SandboxSecuritySpec(user="0:0", cap_add=("NET_RAW",)),
            filesystem=SandboxFilesystemSpec(
                enforce_disk_quota=True,
                tmpfs_mb=32,
            ),
            ssh=SandboxSshSpec(enabled=True, user="root"),
            parkable=True,
        ).to_dict()
        self.assertEqual(payload["security"]["user"], "0:0")
        self.assertEqual(payload["security"]["cap_add"], ["NET_RAW"])
        self.assertTrue(payload["filesystem"]["enforce_disk_quota"])
        self.assertEqual(payload["filesystem"]["tmpfs_mb"], 32)
        self.assertTrue(payload["ssh"]["enabled"])
        self.assertEqual(payload["ssh"]["user"], "root")
        self.assertTrue(payload["parkable"])
        ordinary = SandboxSpec(
            id="ordinary", image=Image.from_registry("busybox")
        ).to_dict()
        self.assertNotIn("parkable", ordinary)
        self.assertEqual(ordinary["network"], "bridge")
        for field, value in (
            ("ssh", True),
            ("ssh", {}),
            ("security", {}),
            ("filesystem", True),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaises(TypeError):
                    SandboxSpec(
                        id="strict-nested-specs",
                        image=Image.from_registry("busybox"),
                        **{field: value},
                    )

    def test_sync_managed_job_handle_uses_durable_job_api(self) -> None:
        with running_gateway() as gateway:
            client = SandboxClient(gateway.base_url)
            sandbox = client.create_sandbox(
                SandboxSpec(
                    id="managed-sync",
                    image=Image.from_registry("busybox"),
                    memory_mb=128,
                    disk_mb=64,
                    parkable=True,
                    managed_process=True,
                )
            )
            job = sandbox.start_agent(
                ["/bin/sh", "-c", "run-harness"],
                job_id="rollout-1",
                env={"MODEL": "test"},
            )
            refreshed = job.refresh()
            logs = job.logs(limit=4)
            terminal = job.signal()

        self.assertTrue(sandbox.record["spec"]["managed_process"])
        self.assertEqual(refreshed.state, "running")
        self.assertEqual(logs.data, b"harn")
        self.assertEqual(logs.next_offset, 4)
        self.assertEqual(terminal.state, "signaled")
        self.assertEqual(terminal.signal, 15)
        self.assertTrue(terminal.terminal)

    def test_start_agent_rejects_non_managed_sandbox_before_request(self) -> None:
        client = SandboxClient("http://gateway.invalid")
        sandbox = client_module.SandboxHandle(
            client,
            "ordinary",
            record={
                "spec": {
                    "id": "ordinary",
                    "parkable": True,
                    "managed_process": False,
                }
            },
        )

        with self.assertRaisesRegex(ValueError, "managed_process=True"):
            sandbox.start_agent(["agent"])

    def test_managed_job_id_uses_the_server_ascii_grammar(self) -> None:
        with running_gateway() as gateway:
            client = SandboxClient(gateway.base_url)
            with self.assertRaisesRegex(ValueError, "job_id must match"):
                client.start_job("managed-sync", ["true"], job_id="röllout")

    def test_sync_create_sandbox_accepts_per_call_request_timeout(self) -> None:
        captured_timeouts: list[object] = []

        def fake_urlopen(req: object, timeout: object = None) -> _SyncResponse:
            captured_timeouts.append(timeout)
            return _SyncResponse(
                b'{"sandbox": {"spec": {"id": "timeout-one", "image": "busybox"}}}'
            )

        client = SandboxClient("http://gateway.invalid", timeout_seconds=11)
        with patch.object(client_module, "open_no_redirect", fake_urlopen):
            sandbox = client.create_sandbox(
                SandboxSpec(
                    id="timeout-one",
                    image=Image.from_registry("busybox"),
                    memory_mb=128,
                ),
                request_timeout_seconds=7,
            )

        self.assertEqual(sandbox.id, "timeout-one")
        self.assertEqual(len(captured_timeouts), 1)
        self.assertAlmostEqual(float(captured_timeouts[0]), 7, places=3)

    def test_sync_build_image_accepts_per_call_timeout(self) -> None:
        captured_timeouts: list[object] = []

        def fake_urlopen(req: object, timeout: object = None) -> _SyncResponse:
            captured_timeouts.append(timeout)
            url = getattr(req, "full_url", "")
            if str(url).endswith("/v1/images/build"):
                return _SyncResponse(
                    b'{"build": {"build_id": "build-slow", "image_id": "slow-build", "status": "running"}}'
                )
            return _SyncResponse(
                b'{"build": {"build_id": "build-slow", "image_id": "slow-build", "status": "succeeded", "image": {"id": "slow-build"}, "command": ["docker", "build"], "exit_code": 0}}'
            )

        client = SandboxClient("http://gateway.invalid", timeout_seconds=11)
        with (
            docker_context() as context,
            patch.object(client_module, "open_no_redirect", fake_urlopen),
        ):
            client.build_image(
                Image.from_dockerfile(
                    name="slow-build",
                    tag="registry.invalid/slow-build:latest",
                    context_path=context,
                ),
                timeout_seconds=123,
            )

        self.assertEqual(len(captured_timeouts), 4)
        for timeout in captured_timeouts[:3]:
            self.assertGreater(float(timeout), 120)
            self.assertLessEqual(float(timeout), 123)
        self.assertAlmostEqual(float(captured_timeouts[3]), 11, places=3)

    def test_sync_client_surfaces_api_errors(self) -> None:
        with docker_context() as context, running_gateway() as gateway:
            client = SandboxClient(gateway.base_url)

            with self.assertRaises(SandboxApiError) as raised:
                client.build_image(
                    Image.from_dockerfile(
                        name="denied",
                        tag="local/denied:latest",
                        context_path=context,
                    )
                )

        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(raised.exception.body, {"error": "image builds disabled"})

    def test_sync_client_retries_ucloud_unavailable_html(self) -> None:
        calls: list[str] = []
        html = b"<!doctype html><title>Job is unavailable | UCloud</title>"

        def fake_urlopen(req: object, timeout: object = None) -> _SyncResponse:
            calls.append(str(getattr(req, "full_url", "")))
            if len(calls) == 1:
                raise client_module.error.HTTPError(
                    calls[-1],
                    503,
                    "Service Unavailable",
                    {},
                    io.BytesIO(html),
                )
            return _SyncResponse(b'{"ok": true}')

        client = SandboxClient("http://gateway.invalid")
        with (
            patch.object(client_module, "open_no_redirect", fake_urlopen),
            patch.object(
                client_module.time,
                "sleep",
                lambda _delay: None,
            ),
        ):
            health = client.health()

        self.assertEqual(health, {"ok": True})
        self.assertEqual(len(calls), 2)

    def test_sync_client_does_not_replay_exec_on_ingress_html_503(self) -> None:
        calls = 0
        html = b"<!doctype html><title>Job is unavailable | UCloud</title>"

        def fake_urlopen(req: object, timeout: object = None) -> object:
            nonlocal calls
            calls += 1
            raise client_module.error.HTTPError(
                str(getattr(req, "full_url", "")),
                503,
                "Service Unavailable",
                {},
                io.BytesIO(html),
            )

        client = SandboxClient("http://gateway.invalid")
        with patch.object(client_module, "open_no_redirect", fake_urlopen):
            with self.assertRaises(SandboxApiError):
                client.start_exec("sandbox-one", ["true"])

        self.assertEqual(calls, 1)

    def test_sync_client_retries_structured_capacity_for_safe_read(self) -> None:
        calls = 0
        delays: list[float] = []

        def fake_urlopen(req: object, timeout: object = None) -> object:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise client_module.error.HTTPError(
                    str(getattr(req, "full_url", "")),
                    503,
                    "Service Unavailable",
                    {"Retry-After": "2"},
                    io.BytesIO(
                        b'{"error":"HTTP request capacity is exhausted; retry shortly",'
                        b'"retryable":true}'
                    ),
                )
            return _SyncResponse(b'{"sandboxes": []}')

        client = SandboxClient("http://gateway.invalid")
        with (
            patch.object(client_module, "open_no_redirect", fake_urlopen),
            patch.object(
                client_module.time,
                "sleep",
                delays.append,
            ),
        ):
            sandboxes = client.list_sandboxes()

        self.assertEqual(sandboxes, [])
        self.assertEqual(calls, 2)
        self.assertEqual(len(delays), 1)
        self.assertGreaterEqual(delays[0], 2)
        self.assertLessEqual(delays[0], 60)

    def test_api_error_exposes_retry_after_seconds(self) -> None:
        retry_at = datetime.now(timezone.utc) + timedelta(seconds=30)
        for header, minimum, maximum in (
            ("7", 7, 7),
            (format_datetime(retry_at, usegmt=True), 28, 30),
        ):
            with self.subTest(header=header):
                exc = SandboxApiError(
                    "busy",
                    status_code=503,
                    body={"retryable": True},
                    headers={"Retry-After": header},
                )
                self.assertGreaterEqual(exc.retry_after_seconds or 0, minimum)
                self.assertLessEqual(exc.retry_after_seconds or 0, maximum)

    def test_sync_client_retries_structured_capacity_for_stable_create(self) -> None:
        payloads: list[dict] = []
        timeouts: list[object] = []

        def fake_urlopen(req: object, timeout: object = None) -> object:
            payloads.append(json.loads(getattr(req, "data", b"{}")))
            timeouts.append(timeout)
            if len(payloads) == 1:
                raise client_module.error.HTTPError(
                    str(getattr(req, "full_url", "")),
                    503,
                    "Service Unavailable",
                    {"Retry-After": "0"},
                    io.BytesIO(
                        b'{"error":"HTTP request capacity is exhausted; retry shortly",'
                        b'"retryable":true}'
                    ),
                )
            return _SyncResponse(b'{"sandbox":{"spec":{"id":"tmax-task-one"}}}')

        client = SandboxClient("http://gateway.invalid")
        with (
            patch.object(client_module, "open_no_redirect", fake_urlopen),
            patch.object(
                client_module.time,
                "sleep",
                lambda _delay: None,
            ),
        ):
            sandbox = client.create_sandbox(
                SandboxSpec(
                    id="tmax-task-one",
                    image=Image.from_registry("busybox:latest"),
                )
            )

        self.assertEqual(sandbox.id, "tmax-task-one")
        self.assertEqual(len(payloads), 2)
        self.assertEqual(payloads[0], payloads[1])
        self.assertEqual(len(timeouts), 2)
        for timeout in timeouts:
            self.assertAlmostEqual(
                float(timeout),
                client_module.DEFAULT_CREATE_TIMEOUT_SECONDS,
                delta=0.01,
            )

    def test_sync_client_does_not_retry_structured_capacity_for_exec(self) -> None:
        calls = 0

        def fake_urlopen(req: object, timeout: object = None) -> object:
            nonlocal calls
            calls += 1
            raise client_module.error.HTTPError(
                str(getattr(req, "full_url", "")),
                503,
                "Service Unavailable",
                {"Retry-After": "0"},
                io.BytesIO(
                    b'{"error":"HTTP request capacity is exhausted; retry shortly",'
                    b'"retryable":true}'
                ),
            )

        client = SandboxClient("http://gateway.invalid")
        with patch.object(client_module, "open_no_redirect", fake_urlopen):
            with self.assertRaises(SandboxApiError):
                client.start_exec("sandbox-one", ["true"])

        self.assertEqual(calls, 1)

    def test_sync_client_retries_pre_dispatch_snapshot_fence_for_exec(self) -> None:
        calls = 0

        def fake_urlopen(req: object, timeout: object = None) -> object:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise client_module.error.HTTPError(
                    str(getattr(req, "full_url", "")),
                    503,
                    "Service Unavailable",
                    {"Retry-After": "0"},
                    io.BytesIO(
                        b'{"error":"parked snapshot publication is still in progress",'
                        b'"error_code":"snapshot_publication_pending",'
                        b'"retryable":true}'
                    ),
                )
            return _SyncResponse(b'{"session":{"id":"exec-one"}}')

        client = SandboxClient("http://gateway.invalid")
        with (
            patch.object(client_module, "open_no_redirect", fake_urlopen),
            patch.object(client_module.time, "sleep", lambda _delay: None),
        ):
            handle = client.start_exec("sandbox-one", ["true"])

        self.assertEqual(handle.session_id, "exec-one")
        self.assertEqual(calls, 2)

    def test_sync_client_rejects_legacy_image_patterns(self) -> None:
        client = SandboxClient("http://gateway.invalid")

        with self.assertRaises(TypeError):
            client.create_sandbox(
                id="legacy",
                image="busybox",
                memory_mb=128,
            )
        with self.assertRaises(TypeError):
            client.build_image(
                {
                    "id": "legacy",
                    "tag": "registry.invalid/legacy:latest",
                    "context_path": "/tmp/context",
                }
            )

    def test_async_client_lifecycle_and_exec(self) -> None:
        async def scenario(
            base_url: str,
        ) -> tuple[str, int | None, list[str], int, bytes, str]:
            async with AsyncSandboxClient(base_url) as client:
                handle = await client.create_sandbox(
                    SandboxSpec(
                        id="async-one",
                        image=Image.from_registry("busybox"),
                        memory_mb=128,
                    )
                )
                result = await handle.exec(["true"], timeout_seconds=2)
                uploaded = await handle.upload_file(
                    "/workspace/out.txt",
                    "async bytes\n",
                )
                downloaded = await handle.download_file("/workspace/out.txt")
                ssh_target = await handle.ssh()
                await handle.delete()
                return (
                    handle.id,
                    result.exit_code,
                    [event["stream"] for event in result.events],
                    uploaded["size"],
                    downloaded,
                    ssh_target.command,
                )

        with running_gateway() as gateway:
            sandbox_id, exit_code, streams, size, downloaded, ssh_command = asyncio.run(
                scenario(gateway.base_url)
            )

        self.assertEqual(sandbox_id, "async-one")
        self.assertEqual(exit_code, 0)
        self.assertIn("stdout", streams)
        self.assertEqual(size, 12)
        self.assertEqual(downloaded, b"async bytes\n")
        self.assertEqual(ssh_command, "ssh -p 22000 sandbox@127.0.0.1")

    def test_async_build_image_accepts_per_call_timeout(self) -> None:
        async def scenario() -> list[object]:
            session = _ScriptedAsyncSession(
                lambda _method, url, _kwargs, _call: _AsyncResponse(
                    '{"build": {"build_id": "build-slow", "image_id": "slow-build", "status": "running"}}'
                    if str(url).endswith("/v1/images/build")
                    else '{"build": {"build_id": "build-slow", "image_id": "slow-build", "status": "succeeded", "image": {"id": "slow-build"}, "command": ["docker", "build"], "exit_code": 0}}'
                )
            )
            client = AsyncSandboxClient(
                "http://gateway.invalid",
                session=session,
                timeout_seconds=11,
            )
            with docker_context() as context:
                await client.build_image(
                    Image.from_dockerfile(
                        name="slow-build",
                        tag="registry.invalid/slow-build:latest",
                        context_path=context,
                    ),
                    timeout_seconds=123,
                )
            return [request[2].get("timeout") for request in session.requests]

        timeouts = asyncio.run(scenario())

        self.assertEqual(len(timeouts), 4)
        for timeout in timeouts[:3]:
            self.assertGreater(float(_timeout_total(timeout)), 120)
            self.assertLessEqual(float(_timeout_total(timeout)), 123)
        self.assertAlmostEqual(float(_timeout_total(timeouts[3])), 11, places=3)

    def test_async_client_retries_ucloud_unavailable_html(self) -> None:
        async def no_sleep(_delay: float) -> None:
            return None

        async def scenario() -> tuple[dict, int]:
            session = _ScriptedAsyncSession(
                lambda _method, _url, _kwargs, call: _AsyncResponse(
                    "<!doctype html><title>Job is unavailable | UCloud</title>"
                    if call == 1
                    else '{"ok": true}',
                    status=503 if call == 1 else 200,
                )
            )
            client = AsyncSandboxClient("http://gateway.invalid", session=session)
            with patch.object(client_module.asyncio, "sleep", no_sleep):
                health = await client.health()
            return health, len(session.requests)

        health, calls = asyncio.run(scenario())

        self.assertEqual(health, {"ok": True})
        self.assertEqual(calls, 2)

    def test_async_client_retries_structured_capacity_for_stable_create(self) -> None:
        async def no_sleep(_delay: float) -> None:
            return None

        async def scenario() -> tuple[str, list[dict]]:
            session = _ScriptedAsyncSession(
                lambda _method, _url, _kwargs, call: _AsyncResponse(
                    '{"error":"HTTP request capacity is exhausted; retry shortly",'
                    '"retryable":true}'
                    if call == 1
                    else '{"sandbox":{"spec":{"id":"tmax-task-async"}}}',
                    status=503 if call == 1 else 201,
                    headers={"Retry-After": "0"},
                )
            )
            client = AsyncSandboxClient("http://gateway.invalid", session=session)
            with patch.object(client_module.asyncio, "sleep", no_sleep):
                sandbox = await client.create_sandbox(
                    SandboxSpec(
                        id="tmax-task-async",
                        image=Image.from_registry("busybox:latest"),
                    )
                )
            return sandbox.id, [
                dict(request[2].get("json") or {}) for request in session.requests
            ]

        sandbox_id, payloads = asyncio.run(scenario())

        self.assertEqual(sandbox_id, "tmax-task-async")
        self.assertEqual(len(payloads), 2)
        self.assertEqual(payloads[0], payloads[1])

    def test_async_client_retries_pre_dispatch_snapshot_fence_for_exec(self) -> None:
        async def no_sleep(_delay: float) -> None:
            return None

        async def scenario() -> tuple[str, int]:
            session = _ScriptedAsyncSession(
                lambda _method, _url, _kwargs, call: _AsyncResponse(
                    '{"error":"parked snapshot publication is still in progress",'
                    '"error_code":"snapshot_publication_pending",'
                    '"retryable":true}'
                    if call == 1
                    else '{"session":{"id":"exec-async"}}',
                    status=503 if call == 1 else 201,
                    headers={"Retry-After": "0"},
                )
            )
            client = AsyncSandboxClient("http://gateway.invalid", session=session)
            with patch.object(client_module.asyncio, "sleep", no_sleep):
                handle = await client.start_exec("sandbox-one", ["true"])
            return handle.session_id, len(session.requests)

        session_id, calls = asyncio.run(scenario())

        self.assertEqual(session_id, "exec-async")
        self.assertEqual(calls, 2)


def _timeout_total(timeout: object) -> object:
    return getattr(timeout, "total", timeout)


class RedirectGatewayState:
    def __init__(self) -> None:
        self.initial_tokens: list[str] = []
        self.redirected_hits = 0


class RedirectGatewayHandle:
    def __init__(self, base_url: str, state: RedirectGatewayState) -> None:
        self.base_url = base_url
        self.state = state


@contextmanager
def running_redirect_gateway() -> Iterator[RedirectGatewayHandle]:
    state = RedirectGatewayState()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format: str, *_args: object) -> None:
            return

        def do_GET(self) -> None:
            if self.path == "/healthz":
                state.initial_tokens.append(
                    self.headers.get("X-UCloud-Sandbox-Token") or ""
                )
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/redirected")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path == "/redirected":
                state.redirected_hits += 1
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "12")
                self.end_headers()
                self.wfile.write(b'{"ok": true}')
                return
            self.send_error(HTTPStatus.NOT_FOUND)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.01},
        daemon=True,
    )
    thread.start()
    try:
        host, port = server.server_address
        yield RedirectGatewayHandle(f"http://{host}:{port}", state)
    finally:
        server.shutdown()
        thread.join(timeout=1)
        server.server_close()


@contextmanager
def running_gateway() -> Iterator["GatewayHandle"]:
    state = FakeGatewayState()

    class Handler(FakeGatewayHandler):
        pass

    Handler.state = state
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.01},
        daemon=True,
    )
    thread.start()
    try:
        host, port = server.server_address
        yield GatewayHandle(base_url=f"http://{host}:{port}", state=state)
    finally:
        server.shutdown()
        thread.join(timeout=1)
        server.server_close()


@contextmanager
def docker_context() -> Iterator[str]:
    with TemporaryDirectory() as raw_dir:
        context = Path(raw_dir)
        (context / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        yield str(context)


class GatewayHandle:
    def __init__(self, *, base_url: str, state: "FakeGatewayState") -> None:
        self.base_url = base_url
        self.state = state


class FakeGatewayState:
    def __init__(self) -> None:
        self.lock = Lock()
        self.sandboxes: dict[str, dict] = {}
        self.images: dict[str, dict] = {}
        self.builds: dict[str, dict] = {}
        self.exec_sessions: dict[str, dict] = {}
        self.exec_events: dict[str, list[dict]] = {}
        self.jobs: dict[tuple[str, str], dict] = {}
        self.job_logs: dict[tuple[str, str, str], bytes] = {}
        self.files: dict[tuple[str, str], bytes] = {}
        self.build_contexts: dict[str, bytes] = {}
        self.build_context_puts = 0
        self.exec_counter = 0

    def next_exec_id(self) -> str:
        with self.lock:
            self.exec_counter += 1
            return f"exec-{self.exec_counter}"


class FakeGatewayHandler(BaseHTTPRequestHandler):
    state: FakeGatewayState
    server_version = "fake-ucloud-gateway/0.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/healthz":
            self._write_json({"ok": True})
            return
        if path == "/v1/sandboxes":
            with self.state.lock:
                sandboxes = list(self.state.sandboxes.values())
            self._write_json({"sandboxes": sandboxes})
            return
        if path == "/v1/images":
            with self.state.lock:
                images = [self.state.images[key] for key in sorted(self.state.images)]
            self._write_json({"images": images})
            return
        if path == "/v1/images/builds":
            with self.state.lock:
                builds = [self.state.builds[key] for key in sorted(self.state.builds)]
            self._write_json({"builds": builds})
            return
        context_digest = _image_context_digest_from_path(path)
        if context_digest is not None:
            with self.state.lock:
                content = self.state.build_contexts.get(context_digest)
            if content is None:
                self._write_json(
                    {"error": "build context not found"},
                    status=HTTPStatus.NOT_FOUND,
                )
                return
            self._write_json({"digest": context_digest, "size": len(content)})
            return
        build_key = _image_build_key_from_path(path)
        if build_key is not None:
            with self.state.lock:
                build = self.state.builds.get(build_key)
                if build is None:
                    build = next(
                        (
                            item
                            for item in self.state.builds.values()
                            if item.get("image_id") == build_key
                        ),
                        None,
                    )
            if build is None:
                self._write_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
                return
            self._write_json({"build": build})
            return
        job_path = _job_path(path)
        if job_path is not None and job_path[2] == "status":
            sandbox_id, job_id, _action = job_path
            with self.state.lock:
                job = self.state.jobs.get((sandbox_id, job_id))
            if job is None:
                self._write_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
                return
            self._write_json({"job": job})
            return
        if job_path is not None and job_path[2].startswith("logs:"):
            sandbox_id, job_id, action = job_path
            stream = action.split(":", 1)[1]
            query = parse_qs(parsed.query)
            offset = max(0, int(query.get("offset", ["0"])[0]))
            limit = max(1, int(query.get("limit", [str(1024 * 1024)])[0]))
            with self.state.lock:
                data = self.state.job_logs.get((sandbox_id, job_id, stream), b"")
            chunk = data[offset : offset + limit]
            self._write_json(
                {
                    "stream": stream,
                    "offset": offset,
                    "next_offset": offset + len(chunk),
                    "data": client_module.base64.b64encode(chunk).decode("ascii"),
                    "eof": offset + len(chunk) >= len(data),
                }
            )
            return
        sandbox_id = _sandbox_id_from_path(path)
        if sandbox_id is not None and path.endswith("/files"):
            file_path = _file_path(parsed)
            with self.state.lock:
                content = self.state.files.get((sandbox_id, file_path or ""))
            if content is None:
                self._write_json(
                    {"error": "file not found"}, status=HTTPStatus.NOT_FOUND
                )
                return
            self._write_bytes(
                content,
                "application/octet-stream",
                headers={"X-Sandbox-Path": file_path or ""},
            )
            return
        exec_id = _exec_id_from_path(path)
        if exec_id is not None and path.endswith("/events"):
            after = int(parse_qs(parsed.query).get("after", ["0"])[0] or 0)
            with self.state.lock:
                session = dict(self.state.exec_sessions.get(exec_id, {}))
                events = [
                    event
                    for event in self.state.exec_events.get(exec_id, [])
                    if int(event.get("sequence") or 0) > after
                ]
            self._write_json({"session": session, "events": events})
            return
        if exec_id is not None:
            with self.state.lock:
                session = self.state.exec_sessions.get(exec_id)
            if session is None:
                self._write_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
                return
            self._write_json({"session": session})
            return
        if sandbox_id is not None and path.endswith("/ssh"):
            self._write_json(
                {
                    "sandbox_id": sandbox_id,
                    "ssh": {
                        "host": "127.0.0.1",
                        "port": 22000,
                        "user": "sandbox",
                    },
                }
            )
            return
        self._write_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        payload = self._read_json()
        if path == "/v1/sandboxes":
            sandbox_id = str(payload.get("id") or "")
            record = {"spec": dict(payload), "state": "running"}
            with self.state.lock:
                self.state.sandboxes[sandbox_id] = record
            self._write_json({"sandbox": record}, status=HTTPStatus.CREATED)
            return
        if path == "/v1/images/build":
            if payload.get("id") == "denied":
                self._write_json(
                    {"error": "image builds disabled"},
                    status=HTTPStatus.FORBIDDEN,
                )
                return
            digest = str(payload.get("context_archive_digest") or "")
            with self.state.lock:
                archive = self.state.build_contexts.get(digest, b"")
            image = {
                "id": str(payload.get("id") or payload.get("tag") or "image"),
                "tag": str(payload.get("tag") or ""),
                "received_context_path": payload.get("context_path"),
                "received_archive_bytes": len(archive),
                "received_push": bool(payload.get("push")),
            }
            build = {
                "build_id": f"build-{image['id']}",
                "image_id": image["id"],
                "tag": image["tag"],
                "status": "succeeded",
                "image": image,
                "command": ["docker", "build"],
                "exit_code": 0,
                "log_tail": "build complete\n",
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:01+00:00",
            }
            with self.state.lock:
                self.state.images[image["id"]] = image
                self.state.builds[build["build_id"]] = build
            self._write_json(
                {
                    "build": build,
                    "started": True,
                },
                status=HTTPStatus.ACCEPTED,
            )
            return
        if path == "/v1/images/pull":
            image_id = str(payload.get("id") or payload.get("image"))
            image = {"id": image_id, "tag": str(payload.get("image") or "")}
            with self.state.lock:
                self.state.images[image_id] = image
            self._write_json({"image": image})
            return
        job_path = _job_path(path)
        if job_path is not None and job_path[2] == "collection":
            sandbox_id, _empty_job_id, _action = job_path
            job_id = str(payload.get("job_id") or "")
            job = {
                "sandbox_id": sandbox_id,
                "sandbox_generation": 1,
                "job_id": job_id,
                "spec_sha256": "a" * 64,
                "state": "running",
                "pid": 42,
                "started_at": "2026-08-03T00:00:00+00:00",
                "completed_at": "",
                "exit_code": None,
                "signal": 0,
                "stdout_bytes": 7,
                "stderr_bytes": 0,
                "stdout_truncated": False,
                "stderr_truncated": False,
                "sequence": 2,
                "updated_at": "2026-08-03T00:00:00+00:00",
            }
            with self.state.lock:
                self.state.jobs[(sandbox_id, job_id)] = job
                self.state.job_logs[(sandbox_id, job_id, "stdout")] = b"harness"
            self._write_json({"job": job}, status=HTTPStatus.CREATED)
            return
        if job_path is not None and job_path[2] == "signal":
            sandbox_id, job_id, _action = job_path
            with self.state.lock:
                job = self.state.jobs.get((sandbox_id, job_id))
                if job is not None:
                    job = dict(job)
                    job.update(
                        {
                            "state": "signaled",
                            "pid": 0,
                            "signal": int(payload.get("signal") or 15),
                            "completed_at": "2026-08-03T00:00:01+00:00",
                            "sequence": 3,
                        }
                    )
                    self.state.jobs[(sandbox_id, job_id)] = job
            if job is None:
                self._write_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)
                return
            self._write_json({"job": job})
            return
        sandbox_id = _sandbox_id_from_path(path)
        if sandbox_id is not None and path.endswith("/exec"):
            exec_id = self.state.next_exec_id()
            session = {
                "id": exec_id,
                "sandbox_id": sandbox_id,
                "status": "exited",
                "exit_code": 0,
            }
            events = [
                {"sequence": 1, "stream": "stdout", "data": "stdout\n"},
                {"sequence": 2, "stream": "stderr", "data": "stderr\n"},
                {"sequence": 3, "stream": "status", "status": "exited"},
            ]
            with self.state.lock:
                self.state.exec_sessions[exec_id] = session
                self.state.exec_events[exec_id] = events
            self._write_json({"session": session}, status=HTTPStatus.CREATED)
            return
        exec_id = _exec_id_from_path(path)
        if exec_id is not None and path.endswith("/stdin"):
            with self.state.lock:
                events = self.state.exec_events.setdefault(exec_id, [])
                events.append(
                    {
                        "sequence": len(events) + 1,
                        "stream": "stdin",
                        "data": str(payload.get("data") or ""),
                    }
                )
            self._write_json({"ok": True})
            return
        if exec_id is not None and path.endswith("/close-stdin"):
            self._write_json({"ok": True})
            return
        self._write_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_PUT(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        context_digest = _image_context_digest_from_path(path)
        if context_digest is not None:
            content = self._read_body()
            actual_digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
            if context_digest != actual_digest:
                self._write_json(
                    {"error": "build context digest mismatch"},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return
            with self.state.lock:
                deduplicated = context_digest in self.state.build_contexts
                self.state.build_contexts[context_digest] = content
                self.state.build_context_puts += 1
            self._write_json(
                {
                    "deduplicated": deduplicated,
                    "digest": context_digest,
                    "size": len(content),
                },
                status=HTTPStatus.OK if deduplicated else HTTPStatus.CREATED,
            )
            return
        sandbox_id = _sandbox_id_from_path(path)
        if sandbox_id is not None and path.endswith("/files"):
            file_path = _file_path(parsed)
            if not file_path:
                self._write_json(
                    {"error": "path query parameter is required"},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return
            content = self._read_body()
            with self.state.lock:
                self.state.files[(sandbox_id, file_path)] = content
            self._write_json(
                {
                    "ok": True,
                    "sandbox_id": sandbox_id,
                    "path": file_path,
                    "size": len(content),
                }
            )
            return
        self._write_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        sandbox_id = _sandbox_id_from_path(path)
        if sandbox_id is not None:
            with self.state.lock:
                deleted = self.state.sandboxes.pop(sandbox_id, None)
            self._write_json({"ok": True, "deleted": deleted})
            return
        self._write_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def _read_json(self) -> dict:
        raw = self._read_body().decode("utf-8")
        if not raw:
            return {}
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return b""
        return self.rfile.read(length)

    def _write_json(
        self,
        payload: dict,
        *,
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _write_bytes(
        self,
        body: bytes,
        content_type: str,
        *,
        status: HTTPStatus = HTTPStatus.OK,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)


def _sandbox_id_from_path(path: str) -> str | None:
    prefix = "/v1/sandboxes/"
    if not path.startswith(prefix):
        return None
    rest = path[len(prefix) :]
    if not rest:
        return None
    return unquote(rest.split("/", 1)[0])


def _job_path(path: str) -> tuple[str, str, str] | None:
    parts = [unquote(item) for item in path.split("/") if item]
    if len(parts) < 4 or parts[:2] != ["v1", "sandboxes"] or parts[3] != "jobs":
        return None
    if len(parts) == 4:
        return parts[2], "", "collection"
    if len(parts) == 5:
        return parts[2], parts[4], "status"
    if len(parts) == 6 and parts[5] == "signal":
        return parts[2], parts[4], "signal"
    if len(parts) == 7 and parts[5] == "logs":
        return parts[2], parts[4], f"logs:{parts[6]}"
    return None


def _exec_id_from_path(path: str) -> str | None:
    prefix = "/v1/exec/"
    if not path.startswith(prefix):
        return None
    rest = path[len(prefix) :]
    if not rest:
        return None
    return unquote(rest.split("/", 1)[0])


def _image_build_key_from_path(path: str) -> str | None:
    prefix = "/v1/images/builds/"
    if not path.startswith(prefix):
        return None
    rest = path[len(prefix) :]
    if not rest:
        return None
    return unquote(rest.split("/", 1)[0])


def _image_context_digest_from_path(path: str) -> str | None:
    prefix = "/v1/image-contexts/"
    if not path.startswith(prefix):
        return None
    digest = unquote(path[len(prefix) :])
    return digest or None


def _file_path(parsed) -> str | None:
    raw = parse_qs(parsed.query).get("path") or [""]
    value = raw[0].strip()
    return value or None


if __name__ == "__main__":
    unittest.main()
