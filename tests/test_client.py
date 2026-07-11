from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
import io
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Lock, Thread
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlparse

import ucloud_sandboxes_sdk.client as client_module
from ucloud_sandboxes_sdk import (
    AsyncSandboxClient,
    AsyncSandboxHandle,
    Image,
    SandboxApiError,
    SandboxClient,
    SandboxForkProtocolSpec,
    SandboxForkSpec,
    SandboxSpec,
    sandbox_auth_headers,
)


class SandboxSdkTests(unittest.TestCase):
    def test_api_token_uses_public_link_safe_header(self) -> None:
        with running_gateway() as gateway:
            client = SandboxClient(gateway.base_url, api_token="secret-token")

            health = client.health()

        self.assertTrue(health["ok"])
        lower_headers = {
            key.lower(): value for key, value in gateway.state.last_headers.items()
        }
        self.assertEqual(
            lower_headers.get("x-ucloud-sandbox-token"),
            "secret-token",
        )
        self.assertNotIn("authorization", lower_headers)
        self.assertEqual(
            sandbox_auth_headers(" secret-token "),
            {"X-UCloud-Sandbox-Token": "secret-token"},
        )

    def test_sync_client_lifecycle_and_exec(self) -> None:
        with running_gateway() as gateway:
            client = SandboxClient(gateway.base_url)

            health = client.health()
            handle = client.create_sandbox(
                id="sdk-one",
                image=Image.from_registry("busybox"),
                command=["sleep", "300"],
                memory_mb=128,
                cpus=0.25,
                disk_mb=64,
                labels={"test": "sdk"},
            )
            listed = client.list_sandboxes()
            result = handle.exec(["cat"], input="hello\n", timeout_seconds=2)
            uploaded = handle.upload_file(
                "/workspace/prompt.txt",
                b"prompt bytes\n",
            )
            downloaded = handle.download_file("/workspace/prompt.txt")
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
        self.assertEqual(deleted["deleted"]["spec"]["id"], "sdk-one")

    def test_sync_client_image_cache_methods(self) -> None:
        with running_gateway() as gateway:
            client = SandboxClient(gateway.base_url)

            built = client.build_image(
                Image.from_dockerfile(
                    name="python-base",
                    tag="gateway-private-host:5000/python-base:latest",
                    context_path="/tmp/context",
                )
            )
            pulled = client.pull_image(
                Image.from_registry("busybox:latest"),
                image_id="busybox",
                count=2,
                cpus=1,
                memory_mb=512,
            )
            sandbox = client.create_sandbox(
                id="snapshot-src",
                image=Image.from_registry("busybox"),
                memory_mb=128,
            )
            snapshot = sandbox.snapshot(
                Image.from_registry("local/snapshot-src:latest"),
                image_id="snap-one",
            )
            images = client.list_images()

        self.assertEqual(built["image"]["id"], "python-base")
        self.assertTrue(built["image"]["received_push"])
        self.assertEqual(pulled["image"]["id"], "busybox")
        self.assertEqual(snapshot["image"]["id"], "snap-one")
        self.assertEqual(
            [image["id"] for image in images],
            ["busybox", "python-base", "snap-one"],
        )

    def test_sync_client_accepts_sandbox_spec_with_image_helper(self) -> None:
        with running_gateway() as gateway:
            client = SandboxClient(gateway.base_url)

            sandbox = client.create_sandbox(
                SandboxSpec(
                    id="spec-one",
                    image=Image.from_registry("busybox"),
                    command=["sleep", "60"],
                    memory_mb=128,
                    cpus=0.25,
                    disk_mb=64,
                )
            )
            deleted = sandbox.delete()

        self.assertEqual(sandbox.id, "spec-one")
        self.assertEqual(deleted["deleted"]["spec"]["image"], "busybox")

    def test_sandbox_spec_only_sends_fork_fields_when_enabled(self) -> None:
        ordinary = SandboxSpec(
            id="ordinary",
            image=Image.from_registry("busybox"),
        ).to_dict()
        protocol = SandboxForkProtocolSpec(
            prepare_command=("fork-agent", "prepare"),
            ready_command=("fork-agent", "ready"),
            timeout_seconds=20,
        )
        forkable = SandboxSpec(
            id="forkable",
            image=Image.from_registry("busybox"),
            memory_mb=128,
            disk_mb=64,
            forkable=True,
            fork_protocol=protocol,
        ).to_dict()

        self.assertNotIn("forkable", ordinary)
        self.assertNotIn("fork_protocol", ordinary)
        self.assertTrue(forkable["forkable"])
        self.assertEqual(
            forkable["fork_protocol"],
            {
                "version": "agent-v1",
                "prepare_command": ["fork-agent", "prepare"],
                "ready_command": ["fork-agent", "ready"],
                "timeout_seconds": 20,
            },
        )

    def test_sync_client_forks_single_and_batch_from_handle(self) -> None:
        protocol = SandboxForkProtocolSpec(
            prepare_command=("fork-agent", "prepare"),
            ready_command=("fork-agent", "ready"),
        )
        with running_gateway() as gateway:
            client = SandboxClient(gateway.base_url)
            source = client.create_sandbox(
                SandboxSpec(
                    id="fork-source",
                    image=Image.from_registry("busybox"),
                    env={"SOURCE": "yes"},
                    labels={"tree": "root"},
                    memory_mb=128,
                    cpus=0.5,
                    disk_mb=64,
                    forkable=True,
                    fork_protocol=protocol,
                )
            )

            child = source.fork(
                id="fork-child",
                env={"BRANCH": "single"},
                labels={"leaf": "one"},
                ttl_seconds=300,
            )
            batch = source.fork_many(
                (
                    SandboxForkSpec(id="fork-child-a", env={"BRANCH": "a"}),
                    SandboxForkSpec(id="fork-child-b", cpus=0.25),
                )
            )

        self.assertEqual(child.id, "fork-child")
        self.assertEqual(child.record["creation_kind"], "restore")
        self.assertEqual(child.record["spec"]["env"]["SOURCE"], "yes")
        self.assertEqual(child.record["spec"]["env"]["BRANCH"], "single")
        self.assertEqual(child.record["spec"]["labels"]["leaf"], "one")
        self.assertEqual(child.fork_metadata["checkpoint_id"], "fork-set-sdk-test")
        self.assertTrue(child.create_response["intent_persisted"])
        self.assertEqual([item.id for item in batch], ["fork-child-a", "fork-child-b"])
        self.assertEqual(
            {item.fork_metadata["checkpoint_id"] for item in batch},
            {"fork-set-sdk-test"},
        )
        self.assertEqual(batch[1].record["spec"]["cpus"], 0.25)

    def test_sync_fork_error_exposes_durable_intent_state(self) -> None:
        with running_gateway() as gateway:
            client = SandboxClient(gateway.base_url)
            source = client.create_sandbox(
                id="fork-error-source",
                image=Image.from_registry("busybox"),
                memory_mb=128,
                disk_mb=64,
                forkable=True,
                fork_protocol=SandboxForkProtocolSpec(
                    prepare_command=("fork-agent", "prepare"),
                    ready_command=("fork-agent", "ready"),
                ),
            )
            with self.assertRaises(SandboxApiError) as raised:
                source.fork(id="fork-error")

        self.assertEqual(raised.exception.status_code, 409)
        self.assertTrue(raised.exception.retryable)
        self.assertTrue(raised.exception.intent_persisted)
        self.assertEqual(raised.exception.intents[0]["sandbox_id"], "fork-error")

    def test_sync_create_sandbox_accepts_per_call_request_timeout(self) -> None:
        class FakeResponse:
            status = 200

            def __init__(self, body: bytes) -> None:
                self.body = body

            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def read(self) -> bytes:
                return self.body

        captured_timeouts: list[object] = []

        def fake_urlopen(req: object, timeout: object = None) -> FakeResponse:
            captured_timeouts.append(timeout)
            return FakeResponse(
                b'{"sandbox": {"spec": {"id": "timeout-one", "image": "busybox"}}}'
            )

        client = SandboxClient("http://gateway.invalid", timeout_seconds=11)
        with patch.object(client_module.request, "urlopen", fake_urlopen):
            sandbox = client.create_sandbox(
                id="timeout-one",
                image=Image.from_registry("busybox"),
                memory_mb=128,
                request_timeout_seconds=7,
            )

        self.assertEqual(sandbox.id, "timeout-one")
        self.assertEqual(captured_timeouts, [7])

    def test_sync_fork_uses_long_default_request_timeout(self) -> None:
        class FakeResponse:
            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def read(self) -> bytes:
                return json.dumps(
                    {
                        "intent_persisted": True,
                        "sandbox": {
                            "id": "timeout-child",
                            "spec": {"id": "timeout-child"},
                        },
                        "fork": {
                            "sandbox_id": "timeout-child",
                            "checkpoint_id": "fork-timeout",
                            "restored": True,
                        },
                    }
                ).encode()

        captured_timeouts: list[object] = []

        def fake_urlopen(req: object, timeout: object = None) -> FakeResponse:
            captured_timeouts.append(timeout)
            return FakeResponse()

        client = SandboxClient("http://gateway.invalid", timeout_seconds=11)
        with patch.object(client_module.request, "urlopen", fake_urlopen):
            child = client.fork_sandbox("source", id="timeout-child")

        self.assertEqual(child.id, "timeout-child")
        self.assertEqual(captured_timeouts, [3600.0])

    def test_fork_batch_requires_unique_bounded_targets(self) -> None:
        client = SandboxClient("http://gateway.invalid")
        with self.assertRaisesRegex(ValueError, "batch size"):
            client.fork_sandboxes("source", ())
        with self.assertRaisesRegex(ValueError, "must be unique"):
            client.fork_sandboxes(
                "source",
                (SandboxForkSpec(id="same"), SandboxForkSpec(id="same")),
            )

    def test_sync_client_uploads_local_build_context(self) -> None:
        with TemporaryDirectory() as raw_dir:
            context = Path(raw_dir) / "context"
            context.mkdir()
            (context / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
            with running_gateway() as gateway:
                client = SandboxClient(gateway.base_url)

                built = client.build_image(
                    Image.from_dockerfile(
                        name="local-context",
                        tag="local/context:latest",
                        context_path=str(context),
                    )
                )

        self.assertEqual(built["image"]["id"], "local-context")
        self.assertEqual(built["image"]["received_context_path"], ".")
        self.assertGreater(built["image"]["received_archive_bytes"], 0)

    def test_sync_client_can_submit_and_poll_image_builds(self) -> None:
        with running_gateway() as gateway:
            client = SandboxClient(gateway.base_url)
            statuses: list[str] = []

            submitted = client.submit_image_build(
                Image.from_dockerfile(
                    name="python-base",
                    tag="gateway-private-host:5000/python-base:latest",
                    context_path="/tmp/context",
                )
            )
            listed = client.list_image_builds()
            completed = client.wait_for_image_build(
                "python-base",
                poll_interval_seconds=0.1,
                on_status=lambda build: statuses.append(str(build.get("status"))),
            )

        self.assertEqual(submitted["image_id"], "python-base")
        self.assertEqual(listed[0]["image_id"], "python-base")
        self.assertEqual(completed["status"], "succeeded")
        self.assertEqual(statuses, ["succeeded"])

    def test_sync_build_image_accepts_per_call_timeout(self) -> None:
        class FakeResponse:
            def __init__(self, body: bytes) -> None:
                self.body = body

            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def read(self) -> bytes:
                return self.body

        captured_timeouts: list[object] = []

        def fake_urlopen(req: object, timeout: object = None) -> FakeResponse:
            captured_timeouts.append(timeout)
            url = getattr(req, "full_url", "")
            if str(url).endswith("/v1/images/build"):
                return FakeResponse(
                    b'{"build": {"build_id": "build-slow", "image_id": "slow-build", "status": "running"}}'
                )
            return FakeResponse(
                b'{"build": {"build_id": "build-slow", "image_id": "slow-build", "status": "succeeded", "image": {"id": "slow-build"}, "command": ["docker", "build"], "exit_code": 0}}'
            )

        client = SandboxClient("http://gateway.invalid", timeout_seconds=11)
        with patch.object(client_module.request, "urlopen", fake_urlopen):
            client.build_image(
                Image.from_dockerfile(
                    name="slow-build",
                    tag="registry.invalid/slow-build:latest",
                    context_path="/tmp/context",
                ),
                timeout_seconds=123,
            )

        self.assertEqual(captured_timeouts, [123, 11])

    def test_sync_client_surfaces_api_errors(self) -> None:
        with running_gateway() as gateway:
            client = SandboxClient(gateway.base_url)

            with self.assertRaises(SandboxApiError) as raised:
                client.build_image(
                    Image.from_dockerfile(
                        name="denied",
                        tag="local/denied:latest",
                        context_path="/tmp/context",
                    )
                )

        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(raised.exception.body, {"error": "image builds disabled"})

    def test_sync_client_retries_ucloud_unavailable_html(self) -> None:
        class FakeResponse:
            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def read(self) -> bytes:
                return b'{"ok": true}'

        calls: list[str] = []
        html = b"<!doctype html><title>Job is unavailable | UCloud</title>"

        def fake_urlopen(req: object, timeout: object = None) -> FakeResponse:
            calls.append(str(getattr(req, "full_url", "")))
            if len(calls) == 1:
                raise client_module.error.HTTPError(
                    calls[-1],
                    503,
                    "Service Unavailable",
                    {},
                    io.BytesIO(html),
                )
            return FakeResponse()

        client = SandboxClient("http://gateway.invalid")
        with patch.object(client_module.request, "urlopen", fake_urlopen), patch.object(
            client_module.time,
            "sleep",
            lambda _delay: None,
        ):
            health = client.health()

        self.assertEqual(health, {"ok": True})
        self.assertEqual(len(calls), 2)

    def test_sync_client_does_not_retry_normal_json_503(self) -> None:
        calls: list[str] = []

        def fake_urlopen(req: object, timeout: object = None) -> object:
            calls.append(str(getattr(req, "full_url", "")))
            raise client_module.error.HTTPError(
                calls[-1],
                503,
                "Service Unavailable",
                {},
                io.BytesIO(b'{"error": "no ready node has resources"}'),
            )

        client = SandboxClient("http://gateway.invalid")
        with patch.object(client_module.request, "urlopen", fake_urlopen):
            with self.assertRaises(SandboxApiError) as raised:
                client.health()

        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(len(calls), 1)

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

    def test_sync_client_prepares_capacity(self) -> None:
        with running_gateway() as gateway:
            client = SandboxClient(gateway.base_url)

            prepared = client.prepare_capacity(
                prepare_id="sdk-prep",
                count=3,
                cpus=1,
                memory_mb=1024,
                disk_mb=2048,
                image=Image.from_registry("busybox:latest"),
                ttl_seconds=600,
            )
            listed = client.list_prepared_capacity()
            deleted = client.delete_prepared_capacity("sdk-prep")

        self.assertEqual(prepared["prepare"]["prepare_id"], "sdk-prep")
        self.assertEqual(prepared["prepare"]["image"], "busybox:latest")
        self.assertEqual(prepared["demand"]["prepared_resources"]["vcpu"], 3.0)
        self.assertEqual(listed["prepared"][0]["count"], 3)
        self.assertEqual(deleted["deleted"]["prepare_id"], "sdk-prep")
        self.assertEqual(deleted["demand"]["prepared_resources"]["vcpu"], 0.0)

    def test_sync_client_prepares_builder_capacity(self) -> None:
        with running_gateway() as gateway:
            client = SandboxClient(gateway.base_url)

            prepared = client.prepare_builder(
                prepare_id="sdk-builder-prep",
                count=2,
                ttl_seconds=600,
            )
            listed = client.list_prepared_builders()
            deleted = client.delete_prepared_builder("sdk-builder-prep")

        self.assertEqual(prepared["prepare"]["prepare_id"], "sdk-builder-prep")
        self.assertEqual(prepared["demand"]["prepared_builder_count"], 2)
        self.assertEqual(prepared["demand"]["desired_builders"], 2)
        self.assertEqual(listed["prepared_builders"][0]["count"], 2)
        self.assertEqual(deleted["deleted"]["prepare_id"], "sdk-builder-prep")
        self.assertEqual(deleted["demand"]["prepared_builder_count"], 0)

    def test_async_client_lifecycle_and_exec(self) -> None:
        async def scenario(base_url: str) -> tuple[str, int | None, list[str], int, bytes]:
            async with AsyncSandboxClient(base_url) as client:
                handle = await client.create_sandbox(
                    id="async-one",
                    image=Image.from_registry("busybox"),
                    memory_mb=128,
                )
                result = await handle.exec(["true"], timeout_seconds=2)
                uploaded = await handle.upload_file(
                    "/workspace/out.txt",
                    "async bytes\n",
                )
                downloaded = await handle.download_file("/workspace/out.txt")
                await handle.delete()
                return handle.id, result.exit_code, [
                    event["stream"] for event in result.events
                ], uploaded["size"], downloaded

        with running_gateway() as gateway:
            sandbox_id, exit_code, streams, size, downloaded = asyncio.run(
                scenario(gateway.base_url)
            )

        self.assertEqual(sandbox_id, "async-one")
        self.assertEqual(exit_code, 0)
        self.assertIn("stdout", streams)
        self.assertEqual(size, 12)
        self.assertEqual(downloaded, b"async bytes\n")

    def test_async_client_forks_single_and_batch_from_handle(self) -> None:
        async def scenario(
            base_url: str,
        ) -> tuple[AsyncSandboxHandle, tuple[AsyncSandboxHandle, ...]]:
            async with AsyncSandboxClient(base_url) as client:
                source = await client.create_sandbox(
                    id="async-fork-source",
                    image=Image.from_registry("busybox"),
                    memory_mb=128,
                    disk_mb=64,
                    forkable=True,
                    fork_protocol=SandboxForkProtocolSpec(
                        prepare_command=("fork-agent", "prepare"),
                        ready_command=("fork-agent", "ready"),
                    ),
                )
                child = await source.fork(
                    SandboxForkSpec(
                        id="async-fork-child",
                        env={"BRANCH": "single"},
                    )
                )
                batch = await source.fork_many(
                    (
                        SandboxForkSpec(id="async-fork-child-a"),
                        SandboxForkSpec(id="async-fork-child-b"),
                    )
                )
                return child, batch

        with running_gateway() as gateway:
            child, batch = asyncio.run(scenario(gateway.base_url))

        self.assertEqual(child.id, "async-fork-child")
        self.assertEqual(child.record["spec"]["env"]["BRANCH"], "single")
        self.assertTrue(child.fork_metadata["restored"])
        self.assertEqual(
            [item.id for item in batch],
            ["async-fork-child-a", "async-fork-child-b"],
        )

    def test_async_create_sandbox_accepts_per_call_request_timeout(self) -> None:
        class FakeResponse:
            status = 200

            async def __aenter__(self) -> "FakeResponse":
                return self

            async def __aexit__(self, *args: object) -> None:
                return None

            async def text(self) -> str:
                return '{"sandbox": {"spec": {"id": "timeout-one", "image": "busybox"}}}'

        class FakeSession:
            def __init__(self) -> None:
                self.timeouts: list[object] = []

            def request(self, _method: object, _url: object, **kwargs: object) -> FakeResponse:
                self.timeouts.append(kwargs.get("timeout"))
                return FakeResponse()

        async def scenario() -> tuple[str, list[object]]:
            session = FakeSession()
            client = AsyncSandboxClient(
                "http://gateway.invalid",
                session=session,
                timeout_seconds=11,
            )
            sandbox = await client.create_sandbox(
                id="timeout-one",
                image=Image.from_registry("busybox"),
                memory_mb=128,
                request_timeout_seconds=7,
            )
            return sandbox.id, session.timeouts

        sandbox_id, timeouts = asyncio.run(scenario())

        self.assertEqual(sandbox_id, "timeout-one")
        self.assertEqual([_timeout_total(timeout) for timeout in timeouts], [7])

    def test_async_fork_uses_long_default_request_timeout(self) -> None:
        class FakeResponse:
            status = 201

            async def __aenter__(self) -> "FakeResponse":
                return self

            async def __aexit__(self, *args: object) -> None:
                return None

            async def text(self) -> str:
                return json.dumps(
                    {
                        "intent_persisted": True,
                        "sandbox": {
                            "id": "async-timeout-child",
                            "spec": {"id": "async-timeout-child"},
                        },
                        "fork": {
                            "sandbox_id": "async-timeout-child",
                            "checkpoint_id": "fork-timeout",
                            "restored": True,
                        },
                    }
                )

        class FakeSession:
            def __init__(self) -> None:
                self.timeouts: list[object] = []

            def request(self, _method: object, _url: object, **kwargs: object) -> FakeResponse:
                self.timeouts.append(kwargs.get("timeout"))
                return FakeResponse()

        async def scenario() -> tuple[str, list[object]]:
            session = FakeSession()
            client = AsyncSandboxClient(
                "http://gateway.invalid",
                session=session,
                timeout_seconds=11,
            )
            child = await client.fork_sandbox(
                "source",
                id="async-timeout-child",
            )
            return child.id, session.timeouts

        sandbox_id, timeouts = asyncio.run(scenario())

        self.assertEqual(sandbox_id, "async-timeout-child")
        self.assertEqual(
            [_timeout_total(timeout) for timeout in timeouts],
            [3600.0],
        )

    def test_async_build_image_accepts_per_call_timeout(self) -> None:
        class FakeResponse:
            status = 200
            def __init__(self, body: str) -> None:
                self.body = body

            async def __aenter__(self) -> "FakeResponse":
                return self

            async def __aexit__(self, *args: object) -> None:
                return None

            async def text(self) -> str:
                return self.body

        class FakeSession:
            def __init__(self) -> None:
                self.timeouts: list[object] = []

            def request(self, _method: object, url: object, **kwargs: object) -> FakeResponse:
                self.timeouts.append(kwargs.get("timeout"))
                if str(url).endswith("/v1/images/build"):
                    return FakeResponse(
                        '{"build": {"build_id": "build-slow", "image_id": "slow-build", "status": "running"}}'
                    )
                return FakeResponse(
                    '{"build": {"build_id": "build-slow", "image_id": "slow-build", "status": "succeeded", "image": {"id": "slow-build"}, "command": ["docker", "build"], "exit_code": 0}}'
                )

        async def scenario() -> list[object]:
            session = FakeSession()
            client = AsyncSandboxClient(
                "http://gateway.invalid",
                session=session,
                timeout_seconds=11,
            )
            await client.build_image(
                Image.from_dockerfile(
                    name="slow-build",
                    tag="registry.invalid/slow-build:latest",
                    context_path="/tmp/context",
                ),
                timeout_seconds=123,
            )
            return session.timeouts

        timeouts = asyncio.run(scenario())

        self.assertEqual([_timeout_total(timeout) for timeout in timeouts], [123, 11])

    def test_async_client_retries_ucloud_unavailable_html(self) -> None:
        class FakeResponse:
            def __init__(self, status: int, body: str) -> None:
                self.status = status
                self.body = body

            async def __aenter__(self) -> "FakeResponse":
                return self

            async def __aexit__(self, *args: object) -> None:
                return None

            async def text(self) -> str:
                return self.body

        class FakeSession:
            def __init__(self) -> None:
                self.calls = 0

            def request(self, _method: object, _url: object, **_kwargs: object) -> FakeResponse:
                self.calls += 1
                if self.calls == 1:
                    return FakeResponse(
                        503,
                        "<!doctype html><title>Job is unavailable | UCloud</title>",
                    )
                return FakeResponse(200, '{"ok": true}')

        async def no_sleep(_delay: float) -> None:
            return None

        async def scenario() -> tuple[dict, int]:
            session = FakeSession()
            client = AsyncSandboxClient("http://gateway.invalid", session=session)
            with patch.object(client_module.asyncio, "sleep", no_sleep):
                health = await client.health()
            return health, session.calls

        health, calls = asyncio.run(scenario())

        self.assertEqual(health, {"ok": True})
        self.assertEqual(calls, 2)


def _timeout_total(timeout: object) -> object:
    return getattr(timeout, "total", timeout)


@contextmanager
def running_gateway() -> Iterator["GatewayHandle"]:
    state = FakeGatewayState()

    class Handler(FakeGatewayHandler):
        pass

    Handler.state = state
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield GatewayHandle(base_url=f"http://{host}:{port}", state=state)
    finally:
        server.shutdown()
        server.server_close()


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
        self.prepared: dict[str, dict] = {}
        self.prepared_builders: dict[str, dict] = {}
        self.files: dict[tuple[str, str], bytes] = {}
        self.exec_counter = 0
        self.last_headers: dict[str, str] = {}

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
        self._record_headers()
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/healthz":
            self._write_json({"ok": True})
            return
        if path == "/v1/heartbeat":
            self._write_json({"node_id": "fake-node"})
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
        if path == "/v1/capacity/prepare":
            with self.state.lock:
                prepared = list(self.state.prepared.values())
            self._write_json({"prepared": prepared, "demand": self._demand()})
            return
        if path == "/v1/builders/prepare":
            with self.state.lock:
                prepared_builders = list(self.state.prepared_builders.values())
            self._write_json(
                {
                    "prepared_builders": prepared_builders,
                    "demand": self._demand(),
                }
            )
            return
        sandbox_id = _sandbox_id_from_path(path)
        if sandbox_id is not None and path.endswith("/files"):
            file_path = _file_path(parsed)
            with self.state.lock:
                content = self.state.files.get((sandbox_id, file_path or ""))
            if content is None:
                self._write_json({"error": "file not found"}, status=HTTPStatus.NOT_FOUND)
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
                    "ssh": {
                        "host": "127.0.0.1",
                        "port": 22000,
                        "user": "sandbox",
                    }
                }
            )
            return
        self._write_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        self._record_headers()
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
        fork_source_id = _fork_source_id_from_path(path)
        if fork_source_id is not None:
            batch = isinstance(payload.get("sandboxes"), list)
            raw_targets = (
                payload.get("sandboxes")
                if batch
                else [payload.get("sandbox")]
            )
            targets = (
                [item for item in raw_targets if isinstance(item, dict)]
                if isinstance(raw_targets, list)
                else []
            )
            if len(targets) != len(raw_targets or []):
                self._write_json(
                    {"error": "invalid fork targets"},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return
            if any(item.get("id") == "fork-error" for item in targets):
                self._write_json(
                    {
                        "error": "fork restore outcome is ambiguous",
                        "intent_persisted": True,
                        "retryable": True,
                        "intents": [
                            {
                                "sandbox_id": str(item.get("id") or ""),
                                "intent_persisted": True,
                            }
                            for item in targets
                        ],
                    },
                    status=HTTPStatus.CONFLICT,
                )
                return
            with self.state.lock:
                source = self.state.sandboxes.get(fork_source_id)
            if not isinstance(source, dict):
                self._write_json(
                    {"error": "sandbox route not found"},
                    status=HTTPStatus.NOT_FOUND,
                )
                return
            source_spec = source.get("spec")
            if not isinstance(source_spec, dict):
                self._write_json(
                    {"error": "source spec missing"},
                    status=HTTPStatus.CONFLICT,
                )
                return
            checkpoint_id = "fork-set-sdk-test"
            records: list[dict] = []
            forks: list[dict] = []
            for target in targets:
                sandbox_id = str(target.get("id") or "")
                spec = dict(source_spec)
                spec["id"] = sandbox_id
                for key in ("ttl_seconds", "memory_mb", "cpus"):
                    if target.get(key) is not None:
                        spec[key] = target[key]
                for key in ("env", "labels"):
                    merged = dict(source_spec.get(key) or {})
                    if isinstance(target.get(key), dict):
                        merged.update(target[key])
                    spec[key] = merged
                record = {
                    "id": sandbox_id,
                    "sandbox_id": sandbox_id,
                    "spec": spec,
                    "state": "running",
                    "creation_kind": "restore",
                    "source_sandbox_id": fork_source_id,
                    "checkpoint_id": checkpoint_id,
                }
                fork = {
                    "sandbox_id": sandbox_id,
                    "checkpoint_id": checkpoint_id,
                    "restored": True,
                    "commands": [],
                }
                records.append(record)
                forks.append(fork)
                with self.state.lock:
                    self.state.sandboxes[sandbox_id] = record
            response = {"intent_persisted": True}
            if batch:
                response.update({"sandboxes": records, "forks": forks})
            else:
                response.update({"sandbox": records[0], "fork": forks[0]})
            self._write_json(response, status=HTTPStatus.CREATED)
            return
        if path == "/v1/images/build":
            if payload.get("id") == "denied":
                self._write_json(
                    {"error": "image builds disabled"},
                    status=HTTPStatus.FORBIDDEN,
                )
                return
            archive = payload.get("context_archive_base64")
            image = {
                "id": str(payload.get("id") or payload.get("tag") or "image"),
                "tag": str(payload.get("tag") or ""),
                "received_context_path": payload.get("context_path"),
                "received_archive_bytes": len(archive or ""),
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
        if path == "/v1/capacity/prepare":
            prepare_id = str(payload.get("id") or "prep-1")
            resources = _resources_from_prepare(payload)
            count = int(payload.get("count") or 1)
            item = {
                "prepare_id": prepare_id,
                "resources": resources,
                "count": count,
                "total_resources": _scale_resources(resources, count),
                "image": str(payload.get("image") or ""),
            }
            with self.state.lock:
                self.state.prepared[prepare_id] = item
            self._write_json(
                {"prepare": item, "demand": self._demand()},
                status=HTTPStatus.CREATED,
            )
            return
        if path == "/v1/builders/prepare":
            prepare_id = str(payload.get("id") or "builder-prep-1")
            count = int(payload.get("count") or 1)
            item = {
                "prepare_id": prepare_id,
                "count": count,
            }
            with self.state.lock:
                self.state.prepared_builders[prepare_id] = item
            self._write_json(
                {"prepare": item, "demand": self._demand()},
                status=HTTPStatus.CREATED,
            )
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
        if sandbox_id is not None and path.endswith("/snapshot"):
            image_id = str(payload.get("id") or payload.get("image"))
            image = {"id": image_id, "tag": str(payload.get("image") or "")}
            with self.state.lock:
                self.state.images[image_id] = image
            self._write_json({"image": image})
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
        self._record_headers()
        parsed = urlparse(self.path)
        path = parsed.path
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
                    "sandboxId": sandbox_id,
                    "path": file_path,
                    "size": len(content),
                }
            )
            return
        self._write_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_DELETE(self) -> None:
        self._record_headers()
        path = urlparse(self.path).path
        sandbox_id = _sandbox_id_from_path(path)
        if sandbox_id is not None:
            with self.state.lock:
                deleted = self.state.sandboxes.pop(sandbox_id, None)
            self._write_json({"ok": True, "deleted": deleted})
            return
        prepare_id = _prepare_id_from_path(path)
        if prepare_id is not None:
            with self.state.lock:
                deleted = self.state.prepared.pop(prepare_id, None)
            self._write_json(
                {"ok": True, "deleted": deleted, "demand": self._demand()}
            )
            return
        builder_prepare_id = _builder_prepare_id_from_path(path)
        if builder_prepare_id is not None:
            with self.state.lock:
                deleted = self.state.prepared_builders.pop(builder_prepare_id, None)
            self._write_json(
                {"ok": True, "deleted": deleted, "demand": self._demand()}
            )
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

    def _record_headers(self) -> None:
        with self.state.lock:
            self.state.last_headers = {
                str(key): str(value) for key, value in self.headers.items()
            }

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

    def _demand(self) -> dict:
        with self.state.lock:
            prepared = list(self.state.prepared.values())
            prepared_builders = list(self.state.prepared_builders.values())
        total = {"vcpu": 0.0, "memory_mb": 0, "disk_mb": 0}
        for item in prepared:
            total = _add_resources(total, item["total_resources"])
        prepared_builder_count = sum(int(item.get("count") or 0) for item in prepared_builders)
        return {
            "pending_resources": {"vcpu": 0.0, "memory_mb": 0, "disk_mb": 0},
            "prepared_resources": total,
            "desired_resources": total,
            "oldest_pending_seconds": 0,
            "pending_image_builds": 0,
            "prepared_builder_count": prepared_builder_count,
            "desired_builders": prepared_builder_count,
            "prepared_builders": prepared_builders,
        }


def _sandbox_id_from_path(path: str) -> str | None:
    prefix = "/v1/sandboxes/"
    if not path.startswith(prefix):
        return None
    rest = path[len(prefix):]
    if not rest:
        return None
    return unquote(rest.split("/", 1)[0])


def _fork_source_id_from_path(path: str) -> str | None:
    prefix = "/v1/sandboxes/"
    suffix = "/forks"
    if not path.startswith(prefix) or not path.endswith(suffix):
        return None
    encoded = path[len(prefix) : -len(suffix)]
    if not encoded or "/" in encoded:
        return None
    return unquote(encoded)


def _exec_id_from_path(path: str) -> str | None:
    prefix = "/v1/exec/"
    if not path.startswith(prefix):
        return None
    rest = path[len(prefix):]
    if not rest:
        return None
    return unquote(rest.split("/", 1)[0])


def _image_build_key_from_path(path: str) -> str | None:
    prefix = "/v1/images/builds/"
    if not path.startswith(prefix):
        return None
    rest = path[len(prefix):]
    if not rest:
        return None
    return unquote(rest.split("/", 1)[0])


def _prepare_id_from_path(path: str) -> str | None:
    prefix = "/v1/capacity/prepare/"
    if not path.startswith(prefix):
        return None
    rest = path[len(prefix):]
    if not rest:
        return None
    return unquote(rest.split("/", 1)[0])


def _builder_prepare_id_from_path(path: str) -> str | None:
    prefix = "/v1/builders/prepare/"
    if not path.startswith(prefix):
        return None
    rest = path[len(prefix):]
    if not rest:
        return None
    return unquote(rest.split("/", 1)[0])


def _file_path(parsed) -> str | None:
    raw = parse_qs(parsed.query).get("path") or [""]
    value = raw[0].strip()
    return value or None


def _resources_from_prepare(payload: dict) -> dict:
    nested = payload.get("resources")
    resources = dict(nested) if isinstance(nested, dict) else {}
    if payload.get("cpus") is not None:
        resources["vcpu"] = payload.get("cpus")
    if payload.get("vcpu") is not None:
        resources["vcpu"] = payload.get("vcpu")
    if payload.get("memory_mb") is not None:
        resources["memory_mb"] = payload.get("memory_mb")
    if payload.get("disk_mb") is not None:
        resources["disk_mb"] = payload.get("disk_mb")
    return {
        "vcpu": float(resources.get("vcpu") or 0.0),
        "memory_mb": int(resources.get("memory_mb") or 0),
        "disk_mb": int(resources.get("disk_mb") or 0),
    }


def _scale_resources(resources: dict, count: int) -> dict:
    return {
        "vcpu": float(resources.get("vcpu") or 0.0) * count,
        "memory_mb": int(resources.get("memory_mb") or 0) * count,
        "disk_mb": int(resources.get("disk_mb") or 0) * count,
    }


def _add_resources(left: dict, right: dict) -> dict:
    return {
        "vcpu": float(left.get("vcpu") or 0.0) + float(right.get("vcpu") or 0.0),
        "memory_mb": int(left.get("memory_mb") or 0) + int(right.get("memory_mb") or 0),
        "disk_mb": int(left.get("disk_mb") or 0) + int(right.get("disk_mb") or 0),
    }


if __name__ == "__main__":
    unittest.main()
