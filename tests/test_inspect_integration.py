from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
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

    def test_single_service_compose_builds_image_and_uses_resources(self) -> None:
        from inspect_ai.util import ComposeBuild, ComposeConfig, ComposeService
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        class FakeClient:
            def __init__(self) -> None:
                self.images: list[Image] = []

            async def build_image(self, image, **_kwargs):
                self.images.append(image)
                return {"image": {"id": image.name}}

        with TemporaryDirectory() as tmp_dir:
            context = Path(tmp_dir) / "environment"
            context.mkdir()
            (context / "Dockerfile").write_text("FROM python:3.12-slim\n")
            sandbox_id = "s" * 59
            client = FakeClient()

            launch = asyncio.run(
                inspect_integration._sandbox_launch_plan(
                    client,
                    sandbox_id=sandbox_id,
                    config=ComposeConfig(
                        services={
                            "default": ComposeService(
                                build=ComposeBuild(context=str(context)),
                                command="tail -f /dev/null",
                                environment={"HARBOR": "1"},
                                cpus=2.0,
                                mem_limit="6144m",
                            )
                        }
                    ),
                    default_image=Image.from_registry("python:3.12-slim"),
                    settings=_settings(inspect_integration),
                )
            )

        self.assertEqual(len(client.images), 1)
        build = client.images[0].to_build_spec()
        self.assertLessEqual(len(build.id), 64)
        self.assertEqual(build.tag, f"ucloud-inspect/{sandbox_id}:latest")
        self.assertEqual(build.context_path, str(context.resolve()))
        self.assertEqual(build.dockerfile, "Dockerfile")
        self.assertEqual(launch.image, client.images[0])
        self.assertEqual(launch.command, ["sh", "-lc", "tail -f /dev/null"])
        self.assertEqual(launch.env, {"HARBOR": "1"})
        self.assertEqual(launch.cpus, 2.0)
        self.assertEqual(launch.memory_mb, 6144)

    def test_compose_yaml_build_context_is_resolved_from_compose_dir(self) -> None:
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        class FakeClient:
            def __init__(self) -> None:
                self.images: list[Image] = []

            async def build_image(self, image, **_kwargs):
                self.images.append(image)
                return {"image": {"id": image.name}}

        with TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            context = root / "env"
            context.mkdir()
            (context / "Dockerfile.custom").write_text("FROM python:3.12-slim\n")
            compose_file = root / "compose.yaml"
            compose_file.write_text(
                "\n".join(
                    [
                        "services:",
                        "  default:",
                        "    image: ucloud-sandbox-registry:5000/test/image:latest",
                        "    build:",
                        "      context: ./env",
                        "      dockerfile: Dockerfile.custom",
                        "    command: [sleep, infinity]",
                        "    environment:",
                        "      - A=B",
                        "    cpus: 4",
                        "    mem_limit: 2g",
                        "",
                    ]
                )
            )
            client = FakeClient()

            launch = asyncio.run(
                inspect_integration._sandbox_launch_plan(
                    client,
                    sandbox_id="inspect-task-sample-1234567890",
                    config=str(compose_file),
                    default_image=Image.from_registry("python:3.12-slim"),
                    settings=_settings(inspect_integration),
                )
            )

        self.assertEqual(len(client.images), 1)
        build = client.images[0].to_build_spec()
        self.assertEqual(build.context_path, str(context.resolve()))
        self.assertEqual(build.dockerfile, "Dockerfile.custom")
        self.assertEqual(build.tag, "ucloud-sandbox-registry:5000/test/image:latest")
        self.assertEqual(launch.command, ["sleep", "infinity"])
        self.assertEqual(launch.env, {"A": "B"})
        self.assertEqual(launch.cpus, 4.0)
        self.assertEqual(launch.memory_mb, 2048)

    def test_multi_service_compose_is_rejected_for_now(self) -> None:
        from inspect_ai.util import ComposeConfig, ComposeService
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        class FakeClient:
            async def build_image(self, image, **_kwargs):
                return {"image": {"id": image.name}}

        with self.assertRaises(NotImplementedError):
            asyncio.run(
                inspect_integration._sandbox_launch_plan(
                    FakeClient(),
                    sandbox_id="inspect-task-sample-1234567890",
                    config=ComposeConfig(
                        services={
                            "default": ComposeService(image="python:3.12-slim"),
                            "victim": ComposeService(image="nginx:latest"),
                        }
                    ),
                    default_image=Image.from_registry("python:3.12-slim"),
                    settings=_settings(inspect_integration),
                )
            )


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
