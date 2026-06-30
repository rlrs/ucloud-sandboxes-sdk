from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Lock, Thread
import unittest
from urllib.parse import parse_qs, unquote, urlparse

from ucloud_sandboxes_sdk import AsyncSandboxClient, SandboxApiError, SandboxClient


class SandboxSdkTests(unittest.TestCase):
    def test_sync_client_lifecycle_and_exec(self) -> None:
        with running_gateway() as gateway:
            client = SandboxClient(gateway.base_url)

            health = client.health()
            handle = client.create_sandbox(
                id="sdk-one",
                image="busybox",
                command=["sleep", "300"],
                memory_mb=128,
                cpus=0.25,
                disk_mb=64,
                labels={"test": "sdk"},
            )
            listed = client.list_sandboxes()
            result = handle.exec(["cat"], input="hello\n", timeout_seconds=2)
            deleted = handle.delete()

        self.assertTrue(health["ok"])
        self.assertEqual(handle.id, "sdk-one")
        self.assertEqual(listed[0]["spec"]["id"], "sdk-one")
        self.assertTrue(result.success)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout, "stdout\n")
        self.assertEqual(result.stderr, "stderr\n")
        self.assertIn("stdin", [event["stream"] for event in result.events])
        self.assertEqual(deleted["deleted"]["spec"]["id"], "sdk-one")

    def test_sync_client_image_cache_methods(self) -> None:
        with running_gateway() as gateway:
            client = SandboxClient(gateway.base_url)

            built = client.build_image(
                id="python-base",
                tag="local/python-base:latest",
                context_path="/tmp/context",
            )
            pulled = client.pull_image("busybox:latest", image_id="busybox")
            sandbox = client.create_sandbox(
                id="snapshot-src",
                image="busybox",
                memory_mb=128,
            )
            snapshot = sandbox.snapshot("local/snapshot-src:latest", image_id="snap-one")
            images = client.list_images()

        self.assertEqual(built["image"]["id"], "python-base")
        self.assertEqual(pulled["image"]["id"], "busybox")
        self.assertEqual(snapshot["image"]["id"], "snap-one")
        self.assertEqual(
            [image["id"] for image in images],
            ["busybox", "python-base", "snap-one"],
        )

    def test_sync_client_uploads_local_build_context(self) -> None:
        with TemporaryDirectory() as raw_dir:
            context = Path(raw_dir) / "context"
            context.mkdir()
            (context / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
            with running_gateway() as gateway:
                client = SandboxClient(gateway.base_url)

                built = client.build_image(
                    id="local-context",
                    tag="local/context:latest",
                    context_path=str(context),
                )

        self.assertEqual(built["image"]["id"], "local-context")
        self.assertEqual(built["received_context_path"], ".")
        self.assertGreater(built["received_archive_bytes"], 0)

    def test_sync_client_surfaces_api_errors(self) -> None:
        with running_gateway() as gateway:
            client = SandboxClient(gateway.base_url)

            with self.assertRaises(SandboxApiError) as raised:
                client.build_image(
                    id="denied",
                    tag="local/denied:latest",
                    context_path="/tmp/context",
                    deny=True,
                )

        self.assertEqual(raised.exception.status_code, 403)
        self.assertEqual(raised.exception.body, {"error": "image builds disabled"})

    def test_sync_client_prepares_capacity(self) -> None:
        with running_gateway() as gateway:
            client = SandboxClient(gateway.base_url)

            prepared = client.prepare_capacity(
                prepare_id="sdk-prep",
                count=3,
                cpus=1,
                memory_mb=1024,
                disk_mb=2048,
                ttl_seconds=600,
            )
            listed = client.list_prepared_capacity()
            deleted = client.delete_prepared_capacity("sdk-prep")

        self.assertEqual(prepared["prepare"]["prepare_id"], "sdk-prep")
        self.assertEqual(prepared["demand"]["prepared_resources"]["vcpu"], 3.0)
        self.assertEqual(listed["prepared"][0]["count"], 3)
        self.assertEqual(deleted["deleted"]["prepare_id"], "sdk-prep")
        self.assertEqual(deleted["demand"]["prepared_resources"]["vcpu"], 0.0)

    def test_async_client_lifecycle_and_exec(self) -> None:
        async def scenario(base_url: str) -> tuple[str, int | None, list[str]]:
            async with AsyncSandboxClient(base_url) as client:
                handle = await client.create_sandbox(
                    id="async-one",
                    image="busybox",
                    memory_mb=128,
                )
                result = await handle.exec(["true"], timeout_seconds=2)
                await handle.delete()
                return handle.id, result.exit_code, [
                    event["stream"] for event in result.events
                ]

        with running_gateway() as gateway:
            sandbox_id, exit_code, streams = asyncio.run(scenario(gateway.base_url))

        self.assertEqual(sandbox_id, "async-one")
        self.assertEqual(exit_code, 0)
        self.assertIn("stdout", streams)


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
        self.exec_sessions: dict[str, dict] = {}
        self.exec_events: dict[str, list[dict]] = {}
        self.prepared: dict[str, dict] = {}
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
        if path == "/v1/capacity/prepare":
            with self.state.lock:
                prepared = list(self.state.prepared.values())
            self._write_json({"prepared": prepared, "demand": self._demand()})
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
        sandbox_id = _sandbox_id_from_path(path)
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
            if payload.get("deny"):
                self._write_json(
                    {"error": "image builds disabled"},
                    status=HTTPStatus.FORBIDDEN,
                )
                return
            image = {
                "id": str(payload.get("id") or payload.get("tag") or "image"),
                "tag": str(payload.get("tag") or ""),
            }
            archive = payload.get("context_archive_base64")
            with self.state.lock:
                self.state.images[image["id"]] = image
            self._write_json(
                {
                    "image": image,
                    "received_context_path": payload.get("context_path"),
                    "received_archive_bytes": len(archive or ""),
                }
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
            }
            with self.state.lock:
                self.state.prepared[prepare_id] = item
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

    def do_DELETE(self) -> None:
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
        self._write_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}

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

    def _demand(self) -> dict:
        with self.state.lock:
            prepared = list(self.state.prepared.values())
        total = {"vcpu": 0.0, "memory_mb": 0, "disk_mb": 0}
        for item in prepared:
            total = _add_resources(total, item["total_resources"])
        return {
            "pending_resources": {"vcpu": 0.0, "memory_mb": 0, "disk_mb": 0},
            "prepared_resources": total,
            "desired_resources": total,
            "oldest_pending_seconds": 0,
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


def _prepare_id_from_path(path: str) -> str | None:
    prefix = "/v1/capacity/prepare/"
    if not path.startswith(prefix):
        return None
    rest = path[len(prefix):]
    if not rest:
        return None
    return unquote(rest.split("/", 1)[0])


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
