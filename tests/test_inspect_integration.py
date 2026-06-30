from __future__ import annotations

import asyncio
import importlib.util
import unittest

from ucloud_sandboxes_sdk import Image, SandboxApiError, SandboxSpec


INSPECT_AVAILABLE = importlib.util.find_spec("inspect_ai") is not None


@unittest.skipUnless(INSPECT_AVAILABLE, "inspect-ai is not installed")
class InspectIntegrationTests(unittest.TestCase):
    def test_create_sandbox_waits_through_scale_up_503(self) -> None:
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        class FakeClient:
            def __init__(self) -> None:
                self.attempts = 0

            async def create_sandbox(self, payload):
                self.attempts += 1
                if self.attempts < 3:
                    raise SandboxApiError(
                        "pending",
                        status_code=503,
                        body={
                            "error": "no ready node has resources for sandbox request",
                            "pending_resources": {"vcpu": 1.0},
                        },
                    )
                return {"created": payload.id}

        client = FakeClient()
        settings = _settings(inspect_integration)

        result = asyncio.run(
            inspect_integration._create_sandbox_with_wait(
                client,
                _sandbox_spec(),
                settings=settings,
            )
        )

        self.assertEqual(result, {"created": "sandbox-one"})
        self.assertEqual(client.attempts, 3)

    def test_create_sandbox_does_not_retry_non_scale_up_errors(self) -> None:
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        class FakeClient:
            def __init__(self) -> None:
                self.attempts = 0

            async def create_sandbox(self, _payload):
                self.attempts += 1
                raise SandboxApiError(
                    "bad request",
                    status_code=400,
                    body={"error": "invalid sandbox"},
                )

        client = FakeClient()
        settings = _settings(inspect_integration)

        with self.assertRaises(SandboxApiError):
            asyncio.run(
                inspect_integration._create_sandbox_with_wait(
                    client,
                    _sandbox_spec(),
                    settings=settings,
                )
            )

        self.assertEqual(client.attempts, 1)

    def test_create_sandbox_retries_transient_gateway_errors(self) -> None:
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        class FakeClient:
            def __init__(self) -> None:
                self.attempts = 0

            async def create_sandbox(self, payload):
                self.attempts += 1
                if self.attempts == 1:
                    raise SandboxApiError(
                        "bad gateway",
                        status_code=502,
                        body={
                            "error": (
                                "node request failed: Remote end closed "
                                "connection without response"
                            ),
                        },
                    )
                if self.attempts == 2:
                    raise SandboxApiError(
                        "public link unavailable",
                        status_code=503,
                        body={"error": "Your job is currently unavailable"},
                    )
                return {"created": payload.id}

        client = FakeClient()
        settings = _settings(inspect_integration)

        result = asyncio.run(
            inspect_integration._create_sandbox_with_wait(
                client,
                _sandbox_spec(),
                settings=settings,
            )
        )

        self.assertEqual(result, {"created": "sandbox-one"})
        self.assertEqual(client.attempts, 3)

    def test_create_sandbox_retries_nested_node_pull_gateway_errors(self) -> None:
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        class FakeClient:
            def __init__(self) -> None:
                self.attempts = 0

            async def create_sandbox(self, payload):
                self.attempts += 1
                if self.attempts == 1:
                    raise SandboxApiError(
                        "bad gateway",
                        status_code=502,
                        body={
                            "error": (
                                "image is not available on selected sandbox "
                                "node; pull failed"
                            ),
                            "pull": {
                                "error": (
                                    "node request failed: [Errno -3] "
                                    "Temporary failure in name resolution"
                                )
                            },
                        },
                    )
                return {"created": payload.id}

        client = FakeClient()
        settings = _settings(inspect_integration)

        result = asyncio.run(
            inspect_integration._create_sandbox_with_wait(
                client,
                _sandbox_spec(),
                settings=settings,
            )
        )

        self.assertEqual(result, {"created": "sandbox-one"})
        self.assertEqual(client.attempts, 2)

    def test_sample_id_helpers_accept_numeric_metadata(self) -> None:
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        sandbox_id = inspect_integration._sandbox_id(
            "mbpp",
            {"__sample_id__": 0},
        )

        self.assertRegex(sandbox_id, r"^inspect-mbpp-0-[a-f0-9]{10}$")
        self.assertEqual(inspect_integration._label_value(601), "601")


def _settings(inspect_integration):
    return inspect_integration._InspectSettings(
        base_url="http://gateway.invalid",
        headers={},
        image=Image.from_registry("python:3.12-slim"),
        cpus=1.0,
        memory_mb=2048,
        disk_mb=10240,
        ttl_seconds=None,
        network="none",
        ssh_enabled=False,
        ssh_user="root",
        start_timeout_seconds=5,
        build_timeout_seconds=5,
        retry_interval_seconds=0.0,
    )


def _sandbox_spec() -> SandboxSpec:
    return SandboxSpec(
        id="sandbox-one",
        image=Image.from_registry("python:3.12-slim"),
        memory_mb=128,
    )


if __name__ == "__main__":
    unittest.main()
