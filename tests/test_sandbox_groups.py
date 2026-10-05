"""Group create (`/v1/sandboxes:batch`) through real HTTP transports."""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Thread
import unittest
from unittest.mock import patch

from ucloud_sandboxes_sdk import (
    AsyncSandboxClient,
    Image,
    SandboxClient,
    SandboxGroupError,
    SandboxGroupUnavailableError,
    SandboxSpec,
)


def member(index, status, *, created=False, group="g"):
    sandbox_id = f"{group}-{index:04d}"
    item = {"id": sandbox_id, "status": status}
    if status not in {"pending", "deleted"}:
        item.update(generation=1, node_id="worker-1")
    if created:
        item["sandbox"] = {"spec": {"id": sandbox_id}, "status": status}
    return item


def answer(*members, group="g", count=None):
    counts = {}
    for item in members:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    return {
        "group": {"id": group, "count": count or len(members), "state": "active",
                  "image": "busybox:latest", "placement": "pack"},
        "sandboxes": list(members),
        "counts": counts,
    }


INCOMPLETE = {
    **answer(member(0, "running", created=True), member(1, "pending")),
    "error": "some group members are not placed yet; repeat the request",
    "error_code": "node_startup_busy",
    "retryable": True,
}
RETRY = {"Retry-After": "0.01", "X-UCloud-Sandbox-Retryable": "true"}


@contextmanager
def gateway(*script):
    """Answer each request with the next (status, body, headers) of `script`;
    the last entry repeats."""
    requests = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _answer(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length)) if length else None
            requests.append((self.command, self.path,
                             {k.lower(): v for k, v in self.headers.items()}, body))
            status, payload, headers = script[min(len(requests), len(script)) - 1]
            raw = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(raw)

        do_GET = do_POST = do_DELETE = _answer

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)


def spec():
    return SandboxSpec(id="ignored", image=Image.from_registry("busybox:latest"),
                       cpus=1, memory_mb=256)


def run_async(url, call):
    async def main():
        async with AsyncSandboxClient(url) as client:
            return await call(client)
    return asyncio.run(main())


class SandboxGroupCreate(unittest.TestCase):
    """Each case runs on the synchronous and the asynchronous client."""

    def both(self, script, sync_call, async_call):
        outcomes = []
        for name in ("sync", "async"):
            with gateway(*script) as (url, requests), patch(
                "ucloud_sandboxes_sdk.client.random.random", return_value=0,
            ):
                try:
                    if name == "sync":
                        result = sync_call(SandboxClient(url))
                    else:
                        result = run_async(url, async_call)
                except Exception as exc:  # noqa: BLE001 - returned for assertions
                    result = exc
            outcomes.append((result, requests))
        return outcomes

    def test_one_request_creates_every_member_with_ordinary_handles(self):
        created = answer(member(0, "running", created=True), member(1, "running", created=True))
        for handles, requests in self.both(
            [(201, created, {})],
            lambda client: client.create_sandbox_group("g", spec(), count=2),
            lambda client: client.create_sandbox_group("g", spec(), count=2),
        ):
            self.assertEqual([handle.id for handle in handles], ["g-0000", "g-0001"])
            self.assertEqual(handles[1].record, {"spec": {"id": "g-0001"}, "status": "running"})
            (method, path, headers, body), = requests
            self.assertEqual((method, path), ("POST", "/v1/sandboxes:batch"))
            self.assertEqual(headers["x-ucloud-image-reference-kind"], "registry")
            self.assertEqual((body["group_id"], body["count"], body["placement"]), ("g", 2, "pack"))
            self.assertNotIn("id", body["spec"])
            self.assertEqual(body["spec"]["image"], "busybox:latest")

    def test_a_retryable_answer_repeats_the_identical_request_and_reports_progress(self):
        done = answer(member(0, "running"), member(1, "running", created=True))
        progress = {"sync": [], "async": []}
        for handles, requests in self.both(
            [(503, INCOMPLETE, RETRY), (201, done, {})],
            lambda client: client.create_sandbox_group(
                "g", spec(), count=2, on_progress=progress["sync"].append),
            lambda client: client.create_sandbox_group(
                "g", spec(), count=2, on_progress=progress["async"].append),
        ):
            self.assertEqual(len(requests), 2)
            self.assertEqual(requests[0][3], requests[1][3])
            # The first answer's record survives the repeat that did not carry it.
            self.assertEqual([handle.record["spec"]["id"] for handle in handles], ["g-0000", "g-0001"])
        for seen in progress.values():
            self.assertEqual([status.counts for status in seen],
                             [{"running": 1, "pending": 1}, {"running": 2}])
            self.assertEqual([m.placed for m in seen[0].members], [True, False])

    def test_ranked_placement_and_old_gateways_create_nothing(self):
        unavailable = {"error": "group create requires gateway_create_placement power_of_k",
                       "error_code": "sandbox_group_create_unavailable", "retryable": False}
        for status in (501, 404):
            for error, requests in self.both(
                [(status, unavailable, {})],
                lambda client: client.create_sandbox_group("g", spec(), count=2),
                lambda client: client.create_sandbox_group("g", spec(), count=2),
            ):
                self.assertIsInstance(error, SandboxGroupUnavailableError)
                self.assertEqual(error.status_code, status)
                self.assertEqual(len(requests), 1)

    def test_a_worker_failure_is_not_retried_and_lists_the_placed_members(self):
        failed = {**answer(member(0, "running", created=True),
                           {"id": "g-0001", "status": "failed", "status_code": 500}),
                  "retryable": False}
        for error, requests in self.both(
            [(502, failed, {})],
            lambda client: client.create_sandbox_group("g", spec(), count=2),
            lambda client: client.create_sandbox_group("g", spec(), count=2),
        ):
            self.assertIsInstance(error, SandboxGroupError)
            self.assertNotIsInstance(error, SandboxGroupUnavailableError)
            self.assertEqual(len(requests), 1)
            self.assertEqual([(m.id, m.status) for m in error.group.members],
                             [("g-0000", "running"), ("g-0001", "failed")])

    def test_an_insufficient_deadline_reports_the_last_answer(self):
        slow = {"Retry-After": "5", "X-UCloud-Sandbox-Retryable": "true"}
        for error, requests in self.both(
            [(503, INCOMPLETE, slow)],
            lambda client: client.create_sandbox_group(
                "g", spec(), count=2, request_timeout_seconds=1),
            lambda client: client.create_sandbox_group(
                "g", spec(), count=2, request_timeout_seconds=1),
        ):
            self.assertIsInstance(error, SandboxGroupError)
            self.assertEqual(len(requests), 1)
            self.assertIn("retry budget exhausted after 1 HTTP attempt(s)", str(error))
            self.assertEqual(error.group.counts, {"running": 1, "pending": 1})

    def test_get_and_delete(self):
        listed = answer(member(0, "running"), member(1, "deleted"))
        for (status, missing, deleted), requests in self.both(
            [(200, listed, {}), (404, {"error": "sandbox group not found"}, {}),
             (503, {**listed, "retryable": True}, {"Retry-After": "0"}),
             (200, {**listed, "deleted": []}, {})],
            lambda client: (client.get_sandbox_group("g"), client.get_sandbox_group("none"),
                            client.delete_sandbox_group("g")),
            lambda client: _gather(client.get_sandbox_group("g"), client.get_sandbox_group("none"),
                                   client.delete_sandbox_group("g")),
        ):
            self.assertEqual([(m.id, m.status) for m in status.members],
                             [("g-0000", "running"), ("g-0001", "deleted")])
            self.assertIsNone(missing)
            self.assertEqual(deleted["deleted"], [])
            self.assertEqual([(method, path) for method, path, *_ in requests], [
                ("GET", "/v1/sandboxes:batch/g"), ("GET", "/v1/sandboxes:batch/none"),
                ("DELETE", "/v1/sandboxes:batch/g"), ("DELETE", "/v1/sandboxes:batch/g")])

    def test_invalid_requests_are_refused_before_any_request(self):
        client = SandboxClient("http://127.0.0.1:9")
        for group_id, count, placement in (("-g", 1, "pack"), ("g" * 60, 1, "pack"),
                                           ("g", 0, "pack"), ("g", 513, "pack"),
                                           ("g", True, "pack"), ("g", 1, "random")):
            with self.subTest(group_id=group_id, count=count, placement=placement):
                with self.assertRaises(ValueError):
                    client.create_sandbox_group(group_id, spec(), count=count, placement=placement)
        with self.assertRaises(ValueError):
            client.get_sandbox_group("a/b")


async def _gather(*calls):
    return tuple([await call for call in calls])


if __name__ == "__main__":
    unittest.main()
