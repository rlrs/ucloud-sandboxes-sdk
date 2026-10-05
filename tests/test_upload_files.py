"""upload_files (`PUT /v1/sandboxes/<id>/archive`) through real HTTP transports."""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
import tarfile
from threading import Thread
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import ucloud_sandboxes_sdk.client as client_module
from ucloud_sandboxes_sdk import (
    AsyncSandboxClient,
    AsyncSandboxHandle,
    SandboxApiError,
    SandboxClient,
    SandboxHandle,
)


def members(body):
    """(name, mode, size, content) of each member of a gzip-compressed tar."""
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(body))) as tar:
        return [
            (info.name, info.mode, info.size, tar.extractfile(info).read())
            for info in tar.getmembers()
        ]


def archive_ack(sandbox_id, query, body):
    files = [info for info in members(body)]
    return {
        "ok": True, "sandbox_id": sandbox_id, "path": query["path"][0],
        "files": len(files), "directories": 0,
        "bytes": sum(size for _, _, size, _ in files), "size": len(body),
    }


def file_ack(sandbox_id, query, body):
    return {"ok": True, "sandbox_id": sandbox_id, "path": query["path"][0],
            "size": len(body)}


def worker(archive=None):
    """A gateway that answers the archive route with `archive` (a list of
    (status, body, headers), the last one repeating) and single files with
    their acknowledgement."""
    script = archive or [(200, archive_ack, {})]
    seen = []

    def respond(route, sandbox_id, query, body):
        if route == "files":
            return 200, file_ack(sandbox_id, query, body), {}
        status, payload, headers = script[min(len(seen), len(script)) - 1]
        if callable(payload):
            payload = payload(sandbox_id, query, body)
        return status, payload, headers

    return respond, seen


@contextmanager
def gateway(respond, seen):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_PUT(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length)
            parsed = urlparse(self.path)
            _, _, _, sandbox_id, route = parsed.path.split("/")
            query = parse_qs(parsed.query)
            requests.append((route, query["path"][0],
                             self.headers.get("Content-Type"), body))
            if route == "archive":
                seen.append(body)
            status, payload, headers = respond(route, sandbox_id, query, body)
            raw = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, args=(0.01,), daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)


HARNESS = {
    "/workspace/harness/run.py": "print('run')\n",
    "harness/lib/util.py": b"X = 1\n",
    "./notes.txt": b"",
}


class UploadFiles(unittest.TestCase):
    """Each case runs on the four entry points: both clients and both handles."""

    def calls(self, files, **kwargs):
        def sync_client(client):
            return client.upload_files("sb", files, **kwargs)

        def sync_handle(client):
            return SandboxHandle(client, "sb").upload_files(files, **kwargs)

        async def async_client(client):
            return await client.upload_files("sb", files, **kwargs)

        async def async_handle(client):
            return await AsyncSandboxHandle(client, "sb").upload_files(files, **kwargs)

        return {"sync client": sync_client, "sync handle": sync_handle,
                "async client": async_client, "async handle": async_handle}

    def each(self, files, archive=None, **kwargs):
        outcomes = []
        for name, call in self.calls(files, **kwargs).items():
            respond, seen = worker(archive)
            with gateway(respond, seen) as (url, requests):
                try:
                    if name.startswith("sync"):
                        result = call(SandboxClient(url))
                    else:
                        result = _run_async(url, call)
                except Exception as exc:  # noqa: BLE001 - returned for assertions
                    result = exc
            outcomes.append((result, requests))
        return outcomes

    def test_one_gzip_tar_request_writes_every_file(self):
        for result, requests in self.each(HARNESS, base_dir="/workspace/", mode=0o640):
            (route, path, content_type, body), = requests
            self.assertEqual((route, path, content_type),
                             ("archive", "/workspace", "application/gzip"))
            self.assertEqual(body[:2], b"\x1f\x8b")
            self.assertEqual(members(body), [
                ("harness/lib/util.py", 0o640, 6, b"X = 1\n"),
                ("harness/run.py", 0o640, 13, b"print('run')\n"),
                ("notes.txt", 0o640, 0, b""),
            ])
            self.assertEqual(result, {
                "ok": True, "sandbox_id": "sb", "path": "/workspace", "files": 3,
                "directories": 0, "bytes": 19, "size": len(body),
            })

    def test_the_archive_is_deterministic_pax_without_owners(self):
        files = {"/" + "d" * 120 + "/x": b"long", "/srv/ø.txt": "blåbær"}
        bodies = [requests[0][3] for _, requests in self.each(files)]
        self.assertEqual(len(set(bodies)), 1)
        raw = gzip.decompress(bodies[0])
        self.assertEqual(raw[257:265], b"ustar\x0000")
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
            infos = tar.getmembers()
        self.assertEqual([info.name for info in infos],
                         ["d" * 120 + "/x", "srv/ø.txt"])
        for info in infos:
            self.assertTrue(info.isreg())
            self.assertEqual((info.mode, info.uid, info.gid, info.uname, info.gname,
                              info.mtime), (0o600, 0, 0, "", "", 0))
        self.assertEqual(infos[1].size, len("blåbær".encode()))

    def test_an_empty_mapping_sends_nothing(self):
        for result, requests in self.each({}, base_dir="/workspace//"):
            self.assertEqual(requests, [])
            self.assertEqual(result, {"ok": True, "sandbox_id": "sb",
                                      "path": "/workspace", "files": 0, "bytes": 0})

    def test_older_gateways_workers_and_sandboxes_fall_back_to_single_files(self):
        answers = {
            403: {"error": "sandbox API key is not authorized for this endpoint"},
            404: {"error": "not found"},
            405: {"error": "method not allowed"},
            501: {"error": "the sandbox cannot extract archives",
                  "error_code": "archive_upload_unsupported"},
        }
        for status, payload in answers.items():
            for result, requests in self.each(
                HARNESS, archive=[(status, payload, {})], base_dir="/workspace", mode=0o755,
            ):
                self.assertEqual(
                    [(route, path, body) for route, path, _, body in requests[1:]], [
                        ("files", "/workspace/harness/lib/util.py", b"X = 1\n"),
                        ("files", "/workspace/harness/run.py", b"print('run')\n"),
                        ("files", "/workspace/notes.txt", b""),
                    ])
                self.assertEqual(requests[0][0], "archive")
                self.assertEqual(result, {
                    "ok": True, "sandbox_id": "sb", "path": "/workspace", "files": 3,
                    "bytes": 19, "fallback": "per_file",
                })

    def test_the_fallback_is_decided_per_call(self):
        respond, seen = worker([(501, {"error_code": "archive_upload_unsupported"}, {}),
                                (200, archive_ack, {})])
        with gateway(respond, seen) as (url, requests):
            client = SandboxClient(url)
            first = client.upload_files("sb", {"/a": b"1"})
            second = client.upload_files("sb", {"/a": b"1"})
        self.assertEqual(first["fallback"], "per_file")
        self.assertNotIn("fallback", second)
        self.assertEqual([route for route, *_ in requests], ["archive", "files", "archive"])

    def test_other_errors_propagate_without_a_fallback(self):
        for status, payload in (
            (400, {"error": "invalid archive"}),
            (409, {"error": "sandbox generation changed"}),
            (410, {"error": "sandbox deleted"}),
            (413, {"error": "archive too large"}),
            (503, {"error": "busy", "error_code": "node_startup_busy", "retryable": False}),
        ):
            for error, requests in self.each(HARNESS, archive=[(status, payload, {})]):
                self.assertIsInstance(error, SandboxApiError)
                self.assertEqual(error.status_code, status)
                self.assertEqual([route for route, *_ in requests], ["archive"])

    def test_retryable_admission_repeats_the_identical_archive(self):
        busy = {"error_code": "node_active_exec_deferred", "retryable": True}
        for result, requests in self.each(
            HARNESS,
            archive=[(503, busy, {"Retry-After": "0"}), (503, busy, {"Retry-After": "0"}),
                     (200, archive_ack, {})],
        ):
            self.assertTrue(result["ok"])
            self.assertEqual([route for route, *_ in requests], ["archive"] * 3)
            self.assertEqual(len({body for *_, body in requests}), 1)
        for code in ("node_startup_busy", "node_active_exec_deferred", "node_restore_busy"):
            body = {"error_code": code, "retryable": True}
            self.assertEqual(
                client_module._should_retry_ucloud_unavailable(
                    503, body, 3, method="PUT",
                    path="/v1/sandboxes/sb/archive?path=%2Fworkspace", max_attempts=None),
                client_module._should_retry_ucloud_unavailable(
                    503, body, 3, method="PUT",
                    path="/v1/sandboxes/sb/files?path=%2Fworkspace%2Fa", max_attempts=None),
            )
        self.assertEqual(
            client_module._ucloud_unavailable_retry_attempts(
                "PUT", "/v1/sandboxes/sb/archive?path=%2F"),
            client_module._ucloud_unavailable_retry_attempts(
                "PUT", "/v1/sandboxes/sb/files?path=%2Fa"),
        )

    def test_a_mismatched_acknowledgement_is_rejected(self):
        def ack(**changes):
            return lambda *args: {**archive_ack(*args), **changes}

        for changes in ({"ok": False}, {"sandbox_id": "other"}, {"path": "/"},
                        {"files": 2}, {"bytes": 18}, {"size": 1}):
            for error, _ in self.each(
                HARNESS, archive=[(200, ack(**changes), {})], base_dir="/workspace",
            ):
                self.assertIsInstance(error, SandboxApiError)
                self.assertIn("invalid archive upload acknowledgement", str(error))
                self.assertIsNone(error.status_code)


class UploadFilesValidation(unittest.TestCase):
    def assert_refused(self, error, files, **kwargs):
        def refuse(*_args, **_kwargs):
            raise AssertionError("no request may be sent")

        sync = SandboxClient("http://127.0.0.1:9")
        async_client = AsyncSandboxClient("http://127.0.0.1:9")
        with patch.object(sync, "_request_json", refuse), \
                patch.object(async_client, "_request_json", refuse):
            with self.assertRaises(error):
                sync.upload_files("sb", files, **kwargs)
            with self.assertRaises(error):
                asyncio.run(async_client.upload_files("sb", files, **kwargs))

    def test_invalid_paths_are_refused_before_any_request(self):
        cases = [
            ({"a": b""}, {"base_dir": "workspace"}),
            ({"a": b""}, {"base_dir": ""}),
            ({"a": b""}, {"base_dir": "/work/../etc"}),
            ({"a": b""}, {"base_dir": "/work\x00"}),
            ({"../a": b""}, {}),
            ({"/workspace/a/../../etc/passwd": b""}, {"base_dir": "/workspace"}),
            ({"a/\x1b[0m": b""}, {}),
            ({"a\x7f": b""}, {}),
            ({"": b""}, {}),
            ({"a/": b""}, {}),
            ({".": b""}, {}),
            ({"/workspace": b""}, {"base_dir": "/workspace"}),
            ({"/workspace/./": b""}, {"base_dir": "/workspace"}),
            ({"/etc/passwd": b""}, {"base_dir": "/workspace"}),
            ({"/workspacex/a": b""}, {"base_dir": "/workspace"}),
            ({"a/b": b"", "./a//b": b""}, {}),
            ({"/workspace/a": b"", "a": b""}, {"base_dir": "/workspace"}),
            ({"a": b"", "a/b/c": b""}, {}),
        ]
        for files, kwargs in cases:
            with self.subTest(files=files, **kwargs):
                self.assert_refused(ValueError, files, **kwargs)

    def test_invalid_modes_and_values_are_refused(self):
        for mode in (-1, 0o1000, 0o4755, True, "0o600", 1.0):
            with self.subTest(mode=mode):
                self.assert_refused(ValueError, {"a": b""}, mode=mode)
        for files in ({"a": bytearray(b"x")}, {"a": None}, {b"a": b"x"}):
            with self.subTest(files=files):
                self.assert_refused(TypeError, files)

    def test_file_count_and_byte_limits(self):
        with patch.object(client_module, "MAX_ARCHIVE_FILES", 2):
            self.assert_refused(ValueError, {"a": b"", "b": b"", "c": b""})
        with patch.object(client_module, "MAX_FILE_BODY_BYTES", 4):
            self.assert_refused(ValueError, {"a": b"123", "b": b"45"})
        # Incompressible content within the byte limit still exceeds it once
        # archived and compressed.
        with patch.object(client_module, "MAX_FILE_BODY_BYTES", 1000):
            self.assert_refused(ValueError, {"a": os.urandom(1000)})

    def test_large_async_archives_are_built_off_the_event_loop(self):
        files = {f"f{index}": os.urandom(1024) for index in range(3)}
        respond, seen = worker()
        with gateway(respond, seen) as (url, requests), \
                patch.object(client_module, "_INLINE_ARCHIVE_BYTES", 2048), \
                patch.object(client_module.asyncio, "to_thread",
                             wraps=asyncio.to_thread) as to_thread:
            result = _run_async(url, lambda client: client.upload_files("sb", files))
        self.assertIn("body", [call.args[0].__name__ for call in to_thread.call_args_list])
        self.assertEqual(result["files"], 3)
        self.assertEqual([content for *_, content in members(requests[0][3])],
                         [files["f0"], files["f1"], files["f2"]])


def _run_async(url, call):
    async def main():
        async with AsyncSandboxClient(url) as client:
            return await call(client)

    return asyncio.run(main())


if __name__ == "__main__":
    unittest.main()
