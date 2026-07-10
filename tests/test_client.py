from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
import hashlib
import io
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import tarfile
from tempfile import TemporaryDirectory
from threading import Lock, Thread
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlparse

import ucloud_sandboxes_sdk.client as client_module
from ucloud_sandboxes_sdk import (
    AsyncSandboxClient,
    ExecEventHistoryLostError,
    Image,
    SandboxApiError,
    SandboxClient,
    SandboxSpec,
    sandbox_auth_headers,
)


TEST_BUILD_CONTEXT = Path(__file__).parent


class SandboxSdkTests(unittest.TestCase):
    def test_api_token_uses_public_link_safe_header(self) -> None:
        with running_gateway() as gateway:
            client = SandboxClient(gateway.base_url, api_token="secret-token")

            health = client.health()
            nodes = client.list_nodes()

        self.assertTrue(health["ok"])
        self.assertEqual(nodes[0]["node_id"], "fake-node")
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
        self.assertEqual(gateway.state.initial_tokens, ["secret-token", "secret-token"])

    def test_exec_wait_rejects_evicted_event_history(self) -> None:
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

    def test_async_exec_wait_rejects_evicted_event_history(self) -> None:
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

    def test_async_client_rejects_malformed_success_json(self) -> None:
        class FakeResponse:
            status = 200
            headers: dict[str, str] = {}

            async def __aenter__(self) -> "FakeResponse":
                return self

            async def __aexit__(self, *args: object) -> None:
                del args

            async def text(self) -> str:
                return "<html>not json</html>"

        class FakeSession:
            def request(self, *_args: object, **_kwargs: object) -> FakeResponse:
                return FakeResponse()

        async def scenario() -> None:
            client = AsyncSandboxClient("http://gateway.invalid", session=FakeSession())
            with self.assertRaises(SandboxApiError) as raised:
                await client.health()
            self.assertEqual(raised.exception.status_code, 200)

        asyncio.run(scenario())

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
            with self.assertRaises(SandboxApiError) as refresh_error:
                handle.refresh()

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
        self.assertEqual(handle.record, {})
        self.assertEqual(refresh_error.exception.status_code, 404)

    def test_sync_client_image_cache_methods(self) -> None:
        with running_gateway() as gateway:
            client = SandboxClient(gateway.base_url)

            built = client.build_image(
                Image.from_dockerfile(
                    image_id="python-base",
                    tag="gateway-private-host:5000/python-base:latest",
                    context_path=TEST_BUILD_CONTEXT,
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
        self.assertEqual(built["status"], "succeeded")
        self.assertNotIn("build", built)
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
        with patch.object(client_module, "open_no_redirect", fake_urlopen):
            sandbox = client.create_sandbox(
                id="timeout-one",
                image=Image.from_registry("busybox"),
                memory_mb=128,
                request_timeout_seconds=7,
            )

        self.assertEqual(sandbox.id, "timeout-one")
        self.assertAlmostEqual(float(captured_timeouts[0]), 7, places=2)

    def test_sync_create_sandbox_waits_for_cold_capacity_with_stable_id(self) -> None:
        client = SandboxClient("http://gateway.invalid")
        payload_ids: list[str] = []

        def request_json(
            _method: str,
            _path: str,
            *,
            payload: dict | None = None,
            **_kwargs: object,
        ) -> dict:
            assert payload is not None
            payload_ids.append(str(payload["id"]))
            if len(payload_ids) < 3:
                raise SandboxApiError(
                    "cold capacity",
                    status_code=503,
                    body={
                        "error": "no ready node has resources for sandbox request",
                        "pending_resources": {"vcpu": 1},
                    },
                    headers={"Retry-After": "0"},
                )
            return {"sandbox": {"spec": dict(payload)}}

        with patch.object(client, "_request_json", side_effect=request_json), patch.object(
            client_module.time,
            "sleep",
            lambda _delay: None,
        ):
            sandbox = client.create_sandbox(
                id="stable-cold-sync",
                image=Image.from_registry("busybox"),
                memory_mb=128,
                start_timeout_seconds=1,
            )

        self.assertEqual(len(payload_ids), 3)
        self.assertEqual(payload_ids[0], "stable-cold-sync")
        self.assertEqual(len(set(payload_ids)), 1)
        self.assertEqual(sandbox.id, payload_ids[0])

    def test_sync_client_uploads_local_build_context(self) -> None:
        with TemporaryDirectory() as raw_dir:
            context = Path(raw_dir) / "context"
            context.mkdir()
            (context / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
            with running_gateway() as gateway:
                client = SandboxClient(gateway.base_url)

                built = client.build_image(
                    Image.from_dockerfile(
                        image_id="local-context",
                        tag="local/context:latest",
                        context_path=str(context),
                    )
                )

        self.assertEqual(built["image"]["id"], "local-context")
        self.assertEqual(built["image"]["received_context_path"], ".")
        self.assertGreater(built["image"]["received_archive_bytes"], 0)
        digest = built["image"]["received_context_digest"]
        self.assertRegex(digest, r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(
            built["image"]["received_context_size"],
            built["image"]["received_archive_bytes"],
        )
        self.assertEqual(gateway.state.build_context_upload_results, [True])

    def test_sync_build_wait_packages_and_uploads_context_once(self) -> None:
        with TemporaryDirectory() as raw_dir:
            context = Path(raw_dir) / "context"
            context.mkdir()
            (context / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
            image = Image.from_dockerfile(
                image_id="cold-builder",
                tag="registry.invalid/cold-builder:latest",
                context_path=context,
            )
            client = SandboxClient("http://gateway.invalid")
            packaged = 0
            uploads = 0
            submissions = 0
            real_packager = client_module._tar_gz_directory

            @contextmanager
            def counted_packager(path: Path) -> Iterator[object]:
                nonlocal packaged
                packaged += 1
                with real_packager(path) as archive:
                    yield archive

            def request_json(method: str, path: str, **kwargs: object) -> dict:
                nonlocal uploads, submissions
                if method == "GET" and path.startswith("/v1/image-contexts/"):
                    raise SandboxApiError("missing", status_code=404, body={})
                if method == "PUT" and path.startswith("/v1/image-contexts/"):
                    uploads += 1
                    return {"stored": True}
                if method == "POST" and path == "/v1/images/build":
                    submissions += 1
                    if submissions < 3:
                        raise SandboxApiError(
                            "cold builder",
                            status_code=503,
                            body={
                                "error": "no ready builder node is available",
                                "pending_image_builds": 1,
                            },
                            headers={"Retry-After": "0"},
                        )
                    return {
                        "build": {
                            "build_id": "build-cold",
                            "image_id": "cold-builder",
                            "status": "running",
                        }
                    }
                if method == "GET" and path == "/v1/images/builds/build-cold":
                    return {
                        "build": {
                            "build_id": "build-cold",
                            "image_id": "cold-builder",
                            "status": "succeeded",
                            "image": {
                                "id": "cold-builder",
                                "tag": "registry.invalid/cold-builder:latest",
                                "pushed": True,
                            },
                        }
                    }
                self.fail(f"unexpected request: {method} {path} {kwargs}")

            with patch.object(
                client_module,
                "_tar_gz_directory",
                counted_packager,
            ), patch.object(
                client,
                "_request_json",
                side_effect=request_json,
            ), patch.object(client_module.time, "sleep", lambda _delay: None):
                result = client.build_image(
                    image,
                    timeout_seconds=1,
                    retry_interval_seconds=0,
                )

        self.assertEqual(result["image"]["id"], "cold-builder")
        self.assertEqual(packaged, 1)
        self.assertEqual(uploads, 1)
        self.assertEqual(submissions, 3)

    def test_sync_client_accepts_deduplicated_build_context_upload(self) -> None:
        with TemporaryDirectory() as raw_dir:
            context = Path(raw_dir) / "context"
            context.mkdir()
            (context / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
            with running_gateway() as gateway:
                client = SandboxClient(gateway.base_url)
                image = Image.from_dockerfile(
                    image_id="deduplicated-context",
                    tag="local/deduplicated-context:latest",
                    context_path=str(context),
                )

                first = client.build_image(image)
                second = client.build_image(image)

        self.assertEqual(
            first["image"]["received_context_digest"],
            second["image"]["received_context_digest"],
        )
        self.assertEqual(gateway.state.build_context_upload_results, [True])
        self.assertEqual(len(gateway.state.build_contexts), 1)

    def test_sync_client_requires_content_addressed_context_upload(self) -> None:
        with TemporaryDirectory() as raw_dir:
            context = Path(raw_dir) / "context"
            context.mkdir()
            (context / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
            with running_gateway(build_context_uploads=False) as gateway:
                client = SandboxClient(gateway.base_url)
                with self.assertRaises(SandboxApiError) as raised:
                    client.build_image(
                        Image.from_dockerfile(
                            image_id="required-context-upload",
                            tag="local/required-context-upload:latest",
                            context_path=str(context),
                        )
                    )

        self.assertEqual(raised.exception.status_code, 404)

    def test_sync_client_rejects_build_context_over_file_limit(self) -> None:
        with TemporaryDirectory() as raw_dir:
            context = Path(raw_dir) / "context"
            context.mkdir()
            (context / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
            client = SandboxClient("http://gateway.invalid")

            def missing_context(req: object, timeout: object = None) -> object:
                del timeout
                url = str(getattr(req, "full_url", ""))
                raise client_module.error.HTTPError(
                    url,
                    404,
                    "Not Found",
                    {},
                    io.BytesIO(b'{"error": "not found"}'),
                )

            with patch.object(client_module, "MAX_FILE_BODY_BYTES", 1), patch.object(
                client_module,
                "open_no_redirect",
                missing_context,
            ):
                with self.assertRaisesRegex(SandboxApiError, "request body exceeds"):
                    client.submit_image_build(
                        Image.from_dockerfile(
                            image_id="oversized-context",
                            tag="local/oversized-context:latest",
                            context_path=str(context),
                        )
                    )

    def test_sync_build_context_retry_rewinds_stream(self) -> None:
        class FakeResponse:
            status = 200
            headers: dict[str, str] = {}

            def __init__(self, body: bytes) -> None:
                self.body = body

            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, *args: object) -> None:
                del args

            def read(self) -> bytes:
                return self.body

        uploads: list[bytes] = []

        def fake_urlopen(req: object, timeout: object = None) -> FakeResponse:
            del timeout
            url = str(getattr(req, "full_url", ""))
            method = str(getattr(req, "get_method")())
            if "/v1/image-contexts/" in url and method == "GET":
                raise client_module.error.HTTPError(
                    url,
                    404,
                    "Not Found",
                    {},
                    io.BytesIO(b'{"error": "not found"}'),
                )
            if "/v1/image-contexts/" in url and method == "PUT":
                source = getattr(req, "data")
                uploads.append(source.read())
                if len(uploads) == 1:
                    raise client_module.error.HTTPError(
                        url,
                        503,
                        "Service Unavailable",
                        {},
                        io.BytesIO(
                            b"<!doctype html><title>Job is unavailable | UCloud</title>"
                        ),
                    )
                return FakeResponse(b'{"stored": false}')
            return FakeResponse(
                b'{"build": {"build_id": "build-retry", "image_id": "retry", "status": "running"}}'
            )

        with TemporaryDirectory() as raw_dir:
            context = Path(raw_dir) / "context"
            context.mkdir()
            (context / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
            client = SandboxClient("http://gateway.invalid")
            with patch.object(client_module, "open_no_redirect", fake_urlopen), patch.object(
                client_module.time,
                "sleep",
                lambda _delay: None,
            ):
                client.submit_image_build(
                    Image.from_dockerfile(
                        image_id="retry",
                        tag="local/retry:latest",
                        context_path=str(context),
                    )
                )

        self.assertEqual(len(uploads), 2)
        self.assertGreater(len(uploads[0]), 0)
        self.assertEqual(uploads[0], uploads[1])

    def test_build_context_archive_is_deterministic(self) -> None:
        with TemporaryDirectory() as raw_dir:
            context = Path(raw_dir) / "context"
            nested = context / "nested"
            nested.mkdir(parents=True)
            (nested / "second.txt").write_text("second\n", encoding="utf-8")
            (context / "first.txt").write_text("first\n", encoding="utf-8")
            items = (context, nested, context / "first.txt", nested / "second.txt")
            for item in items:
                os.utime(item, (1_000_000_000, 1_000_000_000))

            with client_module._tar_gz_directory(context) as archive:
                first_archive = archive.read()

            # Filesystem timestamps and ownership are not build inputs and must
            # not perturb the compressed context bytes.
            for item in items:
                os.utime(item, (2_000_000_000, 2_000_000_000))

            with client_module._tar_gz_directory(context) as archive:
                second_archive = archive.read()

        self.assertEqual(first_archive, second_archive)

        with io.BytesIO(first_archive) as archive:
            digest, size = client_module._build_context_archive_identity(archive)
        expected_digest = f"sha256:{hashlib.sha256(first_archive).hexdigest()}"
        self.assertEqual(digest, expected_digest)
        self.assertEqual(size, len(first_archive))
        self.assertEqual(first_archive[4:8], b"\0\0\0\0")
        with tarfile.open(
            fileobj=io.BytesIO(first_archive),
            mode="r:gz",
        ) as archive:
            members = archive.getmembers()
            self.assertEqual(
                [member.name for member in members],
                ["first.txt", "nested", "nested/second.txt"],
            )
            self.assertTrue(all(member.mtime == 0 for member in members))
            self.assertTrue(all(member.uid == 0 for member in members))
            self.assertTrue(all(member.gid == 0 for member in members))

    def test_build_context_probe_requires_exact_digest_and_size(self) -> None:
        digest = "sha256:" + "a" * 64

        self.assertTrue(
            client_module._build_context_reference_matches(
                {"digest": digest, "size": 123},
                digest=digest,
                size=123,
            )
        )
        self.assertFalse(
            client_module._build_context_reference_matches(
                {"digest": "sha256:" + "b" * 64, "size": 123},
                digest=digest,
                size=123,
            )
        )
        self.assertFalse(
            client_module._build_context_reference_matches(
                {"digest": digest, "size": 122},
                digest=digest,
                size=123,
            )
        )

    def test_sync_client_can_submit_and_poll_image_builds(self) -> None:
        with running_gateway() as gateway:
            client = SandboxClient(gateway.base_url)
            statuses: list[str] = []

            submitted = client.submit_image_build(
                Image.from_dockerfile(
                    image_id="python-base",
                    tag="gateway-private-host:5000/python-base:latest",
                    context_path=TEST_BUILD_CONTEXT,
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
                b'{"build": {"build_id": "build-slow", "image_id": "slow-build", "status": "succeeded", "image": {"id": "slow-build", "tag": "registry.invalid/slow-build:latest", "pushed": true}, "command": ["docker", "build"], "exit_code": 0}}'
            )

        client = SandboxClient("http://gateway.invalid", timeout_seconds=11)
        with patch.object(client_module, "open_no_redirect", fake_urlopen):
            client.build_image(
                Image.from_dockerfile(
                    image_id="slow-build",
                    tag="registry.invalid/slow-build:latest",
                    context_path=TEST_BUILD_CONTEXT,
                ),
                timeout_seconds=123,
            )

        self.assertGreater(float(captured_timeouts[0]), 0)
        self.assertLessEqual(float(captured_timeouts[0]), 123)
        self.assertEqual(len(captured_timeouts), 4)
        self.assertAlmostEqual(float(captured_timeouts[-1]), 11, places=2)

    def test_sync_client_surfaces_api_errors(self) -> None:
        with running_gateway() as gateway:
            client = SandboxClient(gateway.base_url)

            with self.assertRaises(SandboxApiError) as raised:
                client.build_image(
                    Image.from_dockerfile(
                        image_id="denied",
                        tag="local/denied:latest",
                        context_path=TEST_BUILD_CONTEXT,
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
        with patch.object(client_module, "open_no_redirect", fake_urlopen), patch.object(
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
        with patch.object(client_module, "open_no_redirect", fake_urlopen):
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

    def test_image_api_uses_explicit_gateway_ids_and_local_build_contexts(self) -> None:
        image = Image.from_gateway_id("python-base")
        self.assertEqual(image.image_id, "python-base")
        self.assertEqual(image.reference, "python-base")
        self.assertFalse(hasattr(Image, "from_name"))
        self.assertFalse(hasattr(Image, "from_id"))
        with self.assertRaises(TypeError):
            Image("busybox")  # type: ignore[call-arg]

        client = SandboxClient("http://gateway.invalid")
        with self.assertRaisesRegex(ValueError, "existing local directory"):
            client.submit_image_build(
                Image.from_dockerfile(
                    image_id="missing-context",
                    tag="registry.invalid/missing-context:v1",
                    context_path="/definitely/not/a/local/build/context",
                )
            )

    def test_sandbox_create_requires_one_explicit_specification(self) -> None:
        client = SandboxClient("http://gateway.invalid")
        image = Image.from_registry("busybox")

        with self.assertRaisesRegex(ValueError, "sandbox id is required"):
            client.create_sandbox(image=image, memory_mb=128)
        with self.assertRaisesRegex(TypeError, "either SandboxSpec or sandbox fields"):
            client.create_sandbox(
                SandboxSpec(id="one", image=image),
                memory_mb=256,
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
                with self.assertRaises(SandboxApiError) as refresh_error:
                    await handle.refresh()
                self.assertEqual(handle.record, {})
                self.assertEqual(refresh_error.exception.status_code, 404)
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

    def test_async_client_streams_local_build_context(self) -> None:
        async def scenario(base_url: str, context: Path) -> dict:
            async with AsyncSandboxClient(base_url) as client:
                return await client.build_image(
                    Image.from_dockerfile(
                        image_id="async-context",
                        tag="local/async-context:latest",
                        context_path=str(context),
                    )
                )

        with TemporaryDirectory() as raw_dir:
            context = Path(raw_dir) / "context"
            context.mkdir()
            (context / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
            with running_gateway() as gateway:
                built = asyncio.run(scenario(gateway.base_url, context))

        self.assertRegex(
            built["image"]["received_context_digest"],
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertEqual(gateway.state.build_context_upload_results, [True])

    def test_async_client_skips_existing_build_context_upload(self) -> None:
        async def scenario(base_url: str, context: Path) -> tuple[dict, dict]:
            async with AsyncSandboxClient(base_url) as client:
                image = Image.from_dockerfile(
                    image_id="async-deduplicated-context",
                    tag="local/async-deduplicated-context:latest",
                    context_path=str(context),
                )
                return await client.build_image(image), await client.build_image(image)

        with TemporaryDirectory() as raw_dir:
            context = Path(raw_dir) / "context"
            context.mkdir()
            (context / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
            with running_gateway() as gateway:
                first, second = asyncio.run(scenario(gateway.base_url, context))

        self.assertEqual(
            first["image"]["received_context_digest"],
            second["image"]["received_context_digest"],
        )
        self.assertEqual(gateway.state.build_context_upload_results, [True])
        self.assertEqual(len(gateway.state.build_contexts), 1)

    def test_async_build_context_retry_rewinds_stream(self) -> None:
        class FakeResponse:
            headers: dict[str, str] = {}

            def __init__(
                self,
                session: "FakeSession",
                status: int,
                body: str,
                data: object,
            ) -> None:
                self.session = session
                self.status = status
                self.body = body
                self.data = data

            async def __aenter__(self) -> "FakeResponse":
                if hasattr(self.data, "__aiter__"):
                    chunks = [chunk async for chunk in self.data]
                    self.session.uploads.append(b"".join(chunks))
                return self

            async def __aexit__(self, *args: object) -> None:
                del args

            async def text(self) -> str:
                return self.body

        class FakeSession:
            def __init__(self) -> None:
                self.upload_attempts = 0
                self.uploads: list[bytes] = []

            def request(self, method: object, url: object, **kwargs: object) -> FakeResponse:
                if "/v1/image-contexts/" in str(url) and method == "GET":
                    return FakeResponse(
                        self,
                        404,
                        '{"error": "not found"}',
                        kwargs.get("data"),
                    )
                if "/v1/image-contexts/" in str(url) and method == "PUT":
                    self.upload_attempts += 1
                    if self.upload_attempts == 1:
                        return FakeResponse(
                            self,
                            503,
                            "<!doctype html><title>Job is unavailable | UCloud</title>",
                            kwargs.get("data"),
                        )
                    return FakeResponse(
                        self,
                        200,
                        '{"stored": false}',
                        kwargs.get("data"),
                    )
                return FakeResponse(
                    self,
                    202,
                    '{"build": {"build_id": "build-retry", "image_id": "retry", "status": "running"}}',
                    kwargs.get("data"),
                )

        async def no_sleep(_delay: float) -> None:
            return None

        async def scenario(context: Path) -> list[bytes]:
            session = FakeSession()
            client = AsyncSandboxClient(
                "http://gateway.invalid",
                session=session,
            )
            with patch.object(client_module.asyncio, "sleep", no_sleep):
                await client.submit_image_build(
                    Image.from_dockerfile(
                        image_id="retry",
                        tag="local/retry:latest",
                        context_path=str(context),
                    )
                )
            return session.uploads

        with TemporaryDirectory() as raw_dir:
            context = Path(raw_dir) / "context"
            context.mkdir()
            (context / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
            uploads = asyncio.run(scenario(context))

        self.assertEqual(len(uploads), 2)
        self.assertGreater(len(uploads[0]), 0)
        self.assertEqual(uploads[0], uploads[1])

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
        self.assertAlmostEqual(float(_timeout_total(timeouts[0])), 7, places=2)

    def test_async_create_sandbox_waits_for_cold_capacity(self) -> None:
        async def scenario() -> tuple[str, list[str]]:
            client = AsyncSandboxClient("http://gateway.invalid")
            payload_ids: list[str] = []

            async def request_json(
                _method: str,
                _path: str,
                *,
                payload: dict | None = None,
                **_kwargs: object,
            ) -> dict:
                assert payload is not None
                payload_ids.append(str(payload["id"]))
                if len(payload_ids) < 2:
                    raise SandboxApiError(
                        "cold capacity",
                        status_code=503,
                        body={"error": "no ready node", "pending_resources": {}},
                        headers={"Retry-After": "0"},
                    )
                return {"sandbox": {"spec": dict(payload)}}

            with patch.object(client, "_request_json", side_effect=request_json):
                sandbox = await client.create_sandbox(
                    id="stable-cold-async",
                    image=Image.from_registry("busybox"),
                    memory_mb=128,
                    start_timeout_seconds=1,
                )
            await client.close()
            return sandbox.id, payload_ids

        sandbox_id, payload_ids = asyncio.run(scenario())

        self.assertEqual(len(payload_ids), 2)
        self.assertEqual(payload_ids[0], "stable-cold-async")
        self.assertEqual(len(set(payload_ids)), 1)
        self.assertEqual(sandbox_id, payload_ids[0])

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
                    '{"build": {"build_id": "build-slow", "image_id": "slow-build", "status": "succeeded", "image": {"id": "slow-build", "tag": "registry.invalid/slow-build:latest", "pushed": true}, "command": ["docker", "build"], "exit_code": 0}}'
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
                    image_id="slow-build",
                    tag="registry.invalid/slow-build:latest",
                    context_path=TEST_BUILD_CONTEXT,
                ),
                timeout_seconds=123,
            )
            return session.timeouts

        timeouts = asyncio.run(scenario())

        self.assertGreater(float(_timeout_total(timeouts[0])), 0)
        self.assertLessEqual(float(_timeout_total(timeouts[0])), 123)
        self.assertEqual(len(timeouts), 4)
        self.assertAlmostEqual(float(_timeout_total(timeouts[-1])), 11, places=2)

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
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield RedirectGatewayHandle(f"http://{host}:{port}", state)
    finally:
        server.shutdown()
        server.server_close()


@contextmanager
def running_gateway(
    *,
    build_context_uploads: bool = True,
) -> Iterator["GatewayHandle"]:
    state = FakeGatewayState(build_context_uploads=build_context_uploads)

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
    def __init__(self, *, build_context_uploads: bool) -> None:
        self.lock = Lock()
        self.build_context_uploads = build_context_uploads
        self.build_contexts: dict[str, bytes] = {}
        self.build_context_upload_results: list[bool] = []
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
        context_prefix = "/v1/image-contexts/"
        if path.startswith(context_prefix):
            if not self.state.build_context_uploads:
                self._write_json(
                    {"error": "not found"},
                    status=HTTPStatus.NOT_FOUND,
                )
                return
            digest = unquote(path[len(context_prefix):])
            with self.state.lock:
                content = self.state.build_contexts.get(digest)
            if content is None:
                self._write_json(
                    {"error": "not found"},
                    status=HTTPStatus.NOT_FOUND,
                )
                return
            self._write_json({"digest": digest, "size": len(content)})
            return
        if path == "/v1/nodes":
            self._write_json({"nodes": [{"node_id": "fake-node"}]})
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
                    "sandboxId": sandbox_id,
                    "ssh": {
                        "host": "127.0.0.1",
                        "port": 22000,
                        "user": "sandbox",
                        "command": "ssh -p 22000 sandbox@127.0.0.1",
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
        if path == "/v1/images/build":
            if payload.get("id") == "denied":
                self._write_json(
                    {"error": "image builds disabled"},
                    status=HTTPStatus.FORBIDDEN,
                )
                return
            context_digest = payload.get("context_archive_digest")
            with self.state.lock:
                uploaded_archive = self.state.build_contexts.get(
                    str(context_digest or "")
                )
            image = {
                "id": str(payload.get("id") or payload.get("tag") or "image"),
                "tag": str(payload.get("tag") or ""),
                "received_context_path": payload.get("context_path"),
                "received_archive_bytes": (
                    len(uploaded_archive)
                    if uploaded_archive is not None
                    else 0
                ),
                "received_context_digest": context_digest,
                "received_context_size": payload.get("context_archive_size"),
                "received_push": bool(payload.get("push")),
                "pushed": bool(payload.get("push")),
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
        context_prefix = "/v1/image-contexts/"
        if path.startswith(context_prefix):
            if not self.state.build_context_uploads:
                self._write_json(
                    {"error": "not found"},
                    status=HTTPStatus.NOT_FOUND,
                )
                return
            digest = unquote(path[len(context_prefix):])
            content = self._read_body()
            actual_digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
            if digest != actual_digest:
                self._write_json(
                    {"error": "digest mismatch"},
                    status=HTTPStatus.BAD_REQUEST,
                )
                return
            if self.headers.get("Content-Type") != "application/gzip":
                self._write_json(
                    {"error": "invalid content type"},
                    status=HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                )
                return
            with self.state.lock:
                stored = digest not in self.state.build_contexts
                self.state.build_contexts.setdefault(digest, content)
                self.state.build_context_upload_results.append(stored)
            self._write_json(
                {"digest": digest, "size": len(content), "stored": stored},
                status=HTTPStatus.CREATED if stored else HTTPStatus.OK,
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
