from __future__ import annotations

import asyncio
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
from threading import Thread
from typing import Any
import unittest
from unittest.mock import AsyncMock, Mock, patch
from urllib.parse import parse_qs, urlsplit

import ucloud_sandboxes_sdk.client as client_module
from ucloud_sandboxes_sdk import AsyncSandboxClient, SandboxApiError, SandboxClient


def status_record(sandbox_id: str = "agent-1") -> dict[str, Any]:
    return {
        "id": sandbox_id,
        "spec": {"id": sandbox_id},
        "generation": 2,
        "state": "unknown",
        "cached_state": "parked",
        "node": {
            "node_id": "worker-1",
            "job_id": "job-1",
            "node_url": "http://worker.invalid:8090",
            "fresh": False,
            "attached": True,
        },
        "created_at": "2026-09-28T12:00:00+00:00",
        "updated_at": "2026-09-28T12:01:00.123456+00:00",
    }


def status_payload(*records: dict[str, Any]) -> dict[str, Any]:
    return {
        "sandboxes": list(records),
        "cached": True,
        "refresh_supported": False,
        "view": "status",
    }


class _StatusGateway(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _StatusHandler)
        self.payload: Any = status_payload(status_record())
        self.response_status = 200
        self.requests: list[tuple[str, dict[str, str]]] = []

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server_port}"


class _StatusHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        gateway = self.server
        assert isinstance(gateway, _StatusGateway)
        gateway.requests.append((self.path, dict(self.headers.items())))
        body = json.dumps(gateway.payload).encode("utf-8")
        self.send_response(gateway.response_status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *args: object) -> None:
        pass


class SandboxStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.gateway = _StatusGateway()
        cls.server_thread = Thread(target=cls.gateway.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.gateway.shutdown()
        cls.gateway.server_close()
        cls.server_thread.join(timeout=5)

    def setUp(self) -> None:
        self.gateway.payload = status_payload(status_record())
        self.gateway.response_status = 200
        self.gateway.requests.clear()

    def call(self, flavor: str, method: str, *args: Any, **kwargs: Any) -> Any:
        options = {"api_token": "status-token", "headers": {"X-Test": "status"}}
        if flavor == "sync":
            client = SandboxClient(self.gateway.base_url, **options)
            return getattr(client, method)(*args, **kwargs)

        async def invoke() -> Any:
            client = AsyncSandboxClient(self.gateway.base_url, **options)
            try:
                return await getattr(client, method)(*args, **kwargs)
            finally:
                await client.close()

        return asyncio.run(invoke())

    def assert_query(self, expected_ids: list[str] | None = None) -> None:
        path, headers = self.gateway.requests[-1]
        parsed = urlsplit(path)
        self.assertEqual(parsed.path, "/v1/sandboxes")
        self.assertEqual(parsed.fragment, "")
        query = {"view": ["status"]}
        if expected_ids is not None:
            query["id"] = expected_ids
        self.assertEqual(parse_qs(parsed.query), query)
        self.assertTrue(path.isascii())
        lowered_headers = {key.lower(): value for key, value in headers.items()}
        self.assertEqual(lowered_headers["x-ucloud-sandbox-token"], "status-token")
        self.assertEqual(lowered_headers["x-test"], "status")

    def test_all_statuses_preserve_freshness_generation_and_raw_timestamps(self) -> None:
        records = [status_record("agent-1"), status_record("agent-2")]
        records[1].update(generation=99, state="creating", cached_state="creating")
        records[1]["created_at"] = None
        records[1]["updated_at"] = 12345.5
        self.gateway.payload = status_payload(*records)
        for flavor in ("sync", "async"):
            with self.subTest(flavor=flavor):
                self.assertEqual(self.call(flavor, "list_sandbox_statuses"), records)
                self.assert_query()
        self.assertEqual(len(self.gateway.requests), 2)

    def test_exact_id_filters_encode_reserved_unicode_values_and_canonicalize(self) -> None:
        ids = ["z/space +&?#=%", "节点😀", "comma,id", "alpha"]
        self.gateway.payload = status_payload(*(status_record(value) for value in sorted(ids)))
        for flavor in ("sync", "async"):
            with self.subTest(flavor=flavor):
                records = self.call(flavor, "list_sandbox_statuses", sandbox_ids=ids + ids[:2])
                self.assertEqual([record["id"] for record in records], sorted(ids))
                self.assert_query(sorted(ids))
        self.assertEqual(len(self.gateway.requests), 2)

    def test_single_status_uses_filter_and_missing_status_returns_none(self) -> None:
        sandbox_id = "single/节点?&=+"
        record = status_record(sandbox_id)
        for flavor in ("sync", "async"):
            with self.subTest(flavor=flavor):
                self.gateway.payload = status_payload(record)
                self.assertEqual(self.call(flavor, "get_sandbox_status", sandbox_id), record)
                self.assert_query([sandbox_id])
                self.gateway.payload = status_payload()
                self.assertIsNone(self.call(flavor, "get_sandbox_status", sandbox_id))
                self.assert_query([sandbox_id])
        self.assertEqual(len(self.gateway.requests), 4)

    def test_empty_filter_returns_empty_without_http(self) -> None:
        for flavor in ("sync", "async"):
            for ids in ([], ()):
                with self.subTest(flavor=flavor, ids=ids):
                    self.assertEqual(self.call(flavor, "list_sandbox_statuses", sandbox_ids=ids), [])
        self.assertEqual(self.gateway.requests, [])

    def test_invalid_filters_fail_before_http(self) -> None:
        cases = {
            "bare string": "agent-1",
            "bytes": b"agent-1",
            "number": 123,
            "mapping": {"agent-1": True},
            "set": {"agent-1"},
            "empty id": [""],
            "non-string id": ["valid", 1],
            "none id": [None],
            "nul id": ["before\0after"],
            "long id": ["x" * 513],
            "too many ids": [f"agent-{index}" for index in range(257)],
            "too many duplicate ids": ["agent-1"] * 257,
            "unicode command too large": [f"{index:03}" + "😀" * 509 for index in range(256)],
        }
        for flavor in ("sync", "async"):
            for name, ids in cases.items():
                with self.subTest(flavor=flavor, case=name):
                    with self.assertRaises((TypeError, ValueError)):
                        self.call(flavor, "list_sandbox_statuses", sandbox_ids=ids)
        self.assertEqual(self.gateway.requests, [])

    def test_invalid_single_ids_fail_before_http(self) -> None:
        for flavor in ("sync", "async"):
            for sandbox_id in (None, 123, "", "nul\0id", "x" * 513):
                with self.subTest(flavor=flavor, sandbox_id=sandbox_id):
                    with self.assertRaises((TypeError, ValueError)):
                        self.call(flavor, "get_sandbox_status", sandbox_id)
        self.assertEqual(self.gateway.requests, [])

    def test_maximum_filter_count_and_id_length_are_accepted(self) -> None:
        self.gateway.payload = status_payload()
        for flavor in ("sync", "async"):
            for ids in ([f"id-{index:03}" for index in range(256)], ["界" * 512]):
                with self.subTest(flavor=flavor, count=len(ids)):
                    self.assertEqual(self.call(flavor, "list_sandbox_statuses", sandbox_ids=tuple(ids)), [])
                    self.assert_query(ids)

    def test_old_gateway_ignoring_view_is_rejected_even_for_empty_inventory(self) -> None:
        for flavor in ("sync", "async"):
            for records in ([], [status_record()]):
                with self.subTest(flavor=flavor, records=bool(records)):
                    self.gateway.payload = {"sandboxes": records}
                    with self.assertRaises(SandboxApiError):
                        self.call(flavor, "list_sandbox_statuses")
        self.assertEqual(len(self.gateway.requests), 4)

    def test_malformed_envelopes_and_records_are_rejected(self) -> None:
        cases: dict[str, Any] = {
            "wrong view": {"view": "full", "sandboxes": []},
            "missing sandboxes": {"view": "status"},
            "null sandboxes": {"view": "status", "sandboxes": None},
            "mapping sandboxes": {"view": "status", "sandboxes": {}},
            "non-object record": {"view": "status", "sandboxes": [None]},
        }
        for field, bad_values in {
            "id": [None, "", 7],
            "spec": [None, {}, {"id": "another"}],
            "generation": [None, True, 0, -1, 1.5, "2"],
            "state": [None, 7],
            "cached_state": [None, 7],
            "node": [None, []],
        }.items():
            missing = status_record()
            del missing[field]
            cases[f"missing {field}"] = status_payload(missing)
            for index, bad_value in enumerate(bad_values):
                record = status_record()
                record[field] = bad_value
                cases[f"invalid {field} {index}"] = status_payload(record)
        for flavor in ("sync", "async"):
            for name, payload in cases.items():
                with self.subTest(flavor=flavor, case=name):
                    self.gateway.payload = payload
                    with self.assertRaises(SandboxApiError):
                        self.call(flavor, "list_sandbox_statuses")

    def test_duplicate_and_unrequested_records_are_rejected(self) -> None:
        for flavor in ("sync", "async"):
            for method in ("list_sandbox_statuses", "get_sandbox_status"):
                for records in (
                    [status_record("wanted"), status_record("wanted")],
                    [status_record("unrequested")],
                ):
                    with self.subTest(flavor=flavor, method=method, records=records):
                        self.gateway.payload = status_payload(*records)
                        with self.assertRaises(SandboxApiError):
                            if method == "list_sandbox_statuses":
                                self.call(flavor, method, sandbox_ids=["wanted"])
                            else:
                                self.call(flavor, method, "wanted")
            self.gateway.payload = status_payload(status_record(), status_record())
            with self.subTest(flavor=flavor, unfiltered=True):
                with self.assertRaises(SandboxApiError):
                    self.call(flavor, "list_sandbox_statuses")

    def test_full_inventory_methods_keep_their_existing_response_contract(self) -> None:
        full_record = deepcopy(status_record())
        full_record.pop("generation")
        full_record["spec"].update(image="registry/image:tag", cpus=4, memory_mb=8192)
        full_record.update(resources={"cpus": 4}, labels={"team": "compute"}, image={"id": "image-1"})
        self.gateway.payload = {"sandboxes": [full_record], "cached": True}
        for flavor in ("sync", "async"):
            with self.subTest(flavor=flavor):
                self.assertEqual(self.call(flavor, "list_sandboxes"), [full_record])
                self.assertEqual(self.call(flavor, "get_sandbox", "agent-1"), full_record)
                self.assertIsNone(self.call(flavor, "get_sandbox", "missing"))
        self.assertEqual([path for path, _headers in self.gateway.requests], ["/v1/sandboxes"] * 6)

    def test_authentication_errors_propagate_without_full_inventory_fallback(self) -> None:
        self.gateway.response_status = 401
        self.gateway.payload = {"error": "invalid status token"}
        for flavor in ("sync", "async"):
            with self.subTest(flavor=flavor):
                with self.assertRaises(SandboxApiError) as raised:
                    self.call(flavor, "get_sandbox_status", "agent-1")
                self.assertEqual(raised.exception.status_code, 401)
                self.assertEqual(raised.exception.body, self.gateway.payload)
                self.assert_query(["agent-1"])
        self.assertEqual(len(self.gateway.requests), 2)

    def test_transport_errors_are_not_treated_as_missing_sandboxes(self) -> None:
        for flavor, client_type, mock_type in (
            ("sync", SandboxClient, Mock),
            ("async", AsyncSandboxClient, AsyncMock),
        ):
            for method in ("list_sandbox_statuses", "get_sandbox_status"):
                with self.subTest(flavor=flavor, method=method):
                    failure = SandboxApiError("connection unavailable")
                    mocked = mock_type(side_effect=failure)
                    with patch.object(client_type, "_request_json", mocked):
                        with self.assertRaises(SandboxApiError) as raised:
                            if method == "get_sandbox_status":
                                self.call(flavor, method, "agent-1")
                            else:
                                self.call(flavor, method)
                    self.assertIs(raised.exception, failure)
                    self.assertEqual(mocked.call_count, 1)
        self.assertEqual(self.gateway.requests, [])

    def test_sync_status_read_needs_no_optional_dependencies(self) -> None:
        source_root = str(Path(client_module.__file__).resolve().parents[1])
        environment = dict(os.environ, PYTHONPATH=source_root)
        result = subprocess.run(
            [
                sys.executable,
                "-S",
                "-c",
                "import json, sys; "
                "from ucloud_sandboxes_sdk import SandboxClient; "
                "client = SandboxClient(sys.argv[1]); "
                "print(json.dumps(client.get_sandbox_status('agent-1'))); "
                "assert 'aiohttp' not in sys.modules",
                self.gateway.base_url,
            ],
            env=environment,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), status_record())
        self.assertEqual(len(self.gateway.requests), 1)
        self.assertEqual(
            parse_qs(urlsplit(self.gateway.requests[0][0]).query),
            {"view": ["status"], "id": ["agent-1"]},
        )


if __name__ == "__main__":
    unittest.main()
