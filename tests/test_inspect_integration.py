from __future__ import annotations

import asyncio
import importlib.util
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from ucloud_sandboxes_sdk import Image, SandboxApiError, SandboxSecuritySpec, SandboxSpec


INSPECT_AVAILABLE = importlib.util.find_spec("inspect_ai") is not None


class _BuildCaptureClient:
    def __init__(self) -> None:
        self.images: list[Image] = []
        self.context_paths: list[str] = []
        self.dockerfiles: list[str] = []

    async def submit_image_build(self, image, **_kwargs):
        self.images.append(image)
        spec = image.to_build_spec()
        self.context_paths.append(spec.context_path)
        self.dockerfiles.append((Path(spec.context_path) / spec.dockerfile).read_text())
        return {"build_id": image.name}

    async def wait_for_image_build(self, build_id, **_kwargs):
        return {"status": "succeeded", "image": {"id": build_id}}


@unittest.skipUnless(INSPECT_AVAILABLE, "inspect-ai is not installed")
class InspectIntegrationTests(unittest.TestCase):
    def test_settings_from_env_parses_security_profile(self) -> None:
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        with patch.dict(
            os.environ,
            {
                "UCLOUD_SANDBOX_URL": "http://gateway.invalid",
                "UCLOUD_SANDBOX_SECURITY": (
                    '{"user":"0:0","cap_drop":[],"cap_add":["SYS_PTRACE"],'
                    '"no_new_privileges":false,"pids_limit":null,'
                    '"read_only_rootfs":true,"init":false}'
                ),
            },
            clear=True,
        ):
            settings = inspect_integration._settings_from_env()

        self.assertEqual(
            settings.security,
            SandboxSecuritySpec(
                user="0:0",
                cap_drop=(),
                cap_add=("SYS_PTRACE",),
                no_new_privileges=False,
                pids_limit=None,
                read_only_rootfs=True,
                init=False,
            ),
        )

    def test_settings_from_env_applies_security_field_overrides(self) -> None:
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        with patch.dict(
            os.environ,
            {
                "UCLOUD_SANDBOX_URL": "http://gateway.invalid",
                "UCLOUD_SANDBOX_SECURITY_USER": "",
                "UCLOUD_SANDBOX_SECURITY_CAP_DROP": "",
                "UCLOUD_SANDBOX_SECURITY_CAP_ADD": "SYS_PTRACE, NET_ADMIN",
                "UCLOUD_SANDBOX_SECURITY_NO_NEW_PRIVILEGES": "0",
                "UCLOUD_SANDBOX_SECURITY_PIDS_LIMIT": "none",
                "UCLOUD_SANDBOX_SECURITY_READ_ONLY_ROOTFS": "true",
                "UCLOUD_SANDBOX_SECURITY_INIT": "false",
            },
            clear=True,
        ):
            settings = inspect_integration._settings_from_env()

        self.assertEqual(
            settings.security,
            SandboxSecuritySpec(
                user=None,
                cap_drop=(),
                cap_add=("SYS_PTRACE", "NET_ADMIN"),
                no_new_privileges=False,
                pids_limit=None,
                read_only_rootfs=True,
                init=False,
            ),
        )

    def test_sample_init_passes_security_profile_to_create(self) -> None:
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        captured: dict[str, SandboxSpec] = {}

        class FakeClient:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

            async def close(self) -> None:
                pass

        async def fake_create(client, spec, *, settings):
            del client, settings
            captured["spec"] = spec
            return object()

        with (
            patch.object(inspect_integration, "AsyncSandboxClient", FakeClient),
            patch.object(inspect_integration, "_create_sandbox_with_wait", fake_create),
            patch.dict(
                os.environ,
                {
                    "UCLOUD_SANDBOX_URL": "http://gateway.invalid",
                    "UCLOUD_SANDBOX_SECURITY_USER": "",
                    "UCLOUD_SANDBOX_SECURITY_CAP_DROP": "",
                    "UCLOUD_SANDBOX_SECURITY_NO_NEW_PRIVILEGES": "false",
                },
                clear=True,
            ),
        ):
            asyncio.run(
                inspect_integration.UCloudSandboxEnvironment.sample_init(
                    "task",
                    None,
                    {"__sample_id__": 1},
                )
            )

        self.assertEqual(captured["spec"].security.user, None)
        self.assertEqual(captured["spec"].security.cap_drop, ())
        self.assertFalse(captured["spec"].security.no_new_privileges)

    def test_create_sandbox_waits_through_scale_up_503(self) -> None:
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        class FakeClient:
            def __init__(self) -> None:
                self.attempts = 0
                self.timeouts: list[float | None] = []

            async def create_sandbox(self, payload, *, request_timeout_seconds=None):
                self.attempts += 1
                self.timeouts.append(request_timeout_seconds)
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
        self.assertEqual(len(client.timeouts), 3)
        self.assertTrue(all(timeout is not None for timeout in client.timeouts))
        self.assertTrue(all(0 < timeout <= 5 for timeout in client.timeouts if timeout is not None))

    def test_create_sandbox_does_not_retry_non_scale_up_errors(self) -> None:
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        class FakeClient:
            def __init__(self) -> None:
                self.attempts = 0

            async def create_sandbox(self, _payload, *, request_timeout_seconds=None):
                del request_timeout_seconds
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

            async def create_sandbox(self, payload, *, request_timeout_seconds=None):
                del request_timeout_seconds
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

            async def create_sandbox(self, payload, *, request_timeout_seconds=None):
                del request_timeout_seconds
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

    def test_create_sandbox_retries_raw_aiohttp_disconnects(self) -> None:
        from aiohttp import ServerDisconnectedError
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        class FakeClient:
            def __init__(self) -> None:
                self.attempts = 0

            async def create_sandbox(self, payload, *, request_timeout_seconds=None):
                del request_timeout_seconds
                self.attempts += 1
                if self.attempts == 1:
                    raise ServerDisconnectedError("Server disconnected")
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

    def test_scale_up_retries_individual_attempt_timeouts(self) -> None:
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        class FakeClient:
            def __init__(self) -> None:
                self.attempts = 0
                self.timeouts: list[float | None] = []

            async def create_sandbox(self, payload, *, request_timeout_seconds=None):
                self.attempts += 1
                self.timeouts.append(request_timeout_seconds)
                if self.attempts == 1:
                    raise TimeoutError("single request timed out")
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
        self.assertEqual(len(client.timeouts), 2)
        self.assertTrue(all(timeout is not None for timeout in client.timeouts))

    def test_builder_timeout_is_not_resubmitted_by_scale_up_retry(self) -> None:
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        class FakeClient:
            def __init__(self) -> None:
                self.submit_attempts = 0
                self.wait_attempts = 0

            async def submit_image_build(self, image, **_kwargs):
                del image
                self.submit_attempts += 1
                return {"build_id": "build-timeout"}

            async def wait_for_image_build(self, build_id, **_kwargs):
                del build_id
                self.wait_attempts += 1
                raise TimeoutError("image build did not finish")

        client = FakeClient()
        settings = _settings(inspect_integration)

        with self.assertRaises(TimeoutError):
            asyncio.run(
                inspect_integration._build_image_with_wait(
                    client,
                    Image.from_dockerfile(
                        name="timeout-build",
                        tag="registry.invalid/timeout-build:latest",
                        context_path="/tmp/context",
                    ),
                    settings=settings,
                )
            )

        self.assertEqual(client.submit_attempts, 1)
        self.assertEqual(client.wait_attempts, 1)

    def test_builder_submit_retries_no_ready_builder_then_waits_by_build_id(self) -> None:
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        class FakeClient:
            def __init__(self) -> None:
                self.submit_attempts = 0
                self.wait_build_ids: list[str] = []

            async def submit_image_build(self, image, **_kwargs):
                del image
                self.submit_attempts += 1
                if self.submit_attempts == 1:
                    raise SandboxApiError(
                        "no builder",
                        status_code=503,
                        body={"error": "no ready builder node is available"},
                    )
                return {"build_id": "build-ready"}

            async def wait_for_image_build(self, build_id, **_kwargs):
                self.wait_build_ids.append(build_id)
                return {"status": "succeeded", "image": {"id": "built"}}

        client = FakeClient()
        settings = _settings(inspect_integration)

        build = asyncio.run(
            inspect_integration._build_image_with_wait(
                client,
                Image.from_dockerfile(
                    name="ready-build",
                    tag="registry.invalid/ready-build:latest",
                    context_path="/tmp/context",
                ),
                settings=settings,
            )
        )

        self.assertEqual(build["status"], "succeeded")
        self.assertEqual(client.submit_attempts, 2)
        self.assertEqual(client.wait_build_ids, ["build-ready"])

    def test_builder_wait_disconnect_is_not_resubmitted_by_scale_up_retry(self) -> None:
        from aiohttp import ServerDisconnectedError
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        class FakeClient:
            def __init__(self) -> None:
                self.submit_attempts = 0
                self.wait_attempts = 0

            async def submit_image_build(self, image, **_kwargs):
                del image
                self.submit_attempts += 1
                return {"build_id": "build-disconnect"}

            async def wait_for_image_build(self, build_id, **_kwargs):
                del build_id
                self.wait_attempts += 1
                raise ServerDisconnectedError("Server disconnected")

        client = FakeClient()
        settings = _settings(inspect_integration)

        with self.assertRaises(ServerDisconnectedError):
            asyncio.run(
                inspect_integration._build_image_with_wait(
                    client,
                    Image.from_dockerfile(
                        name="disconnect-build",
                        tag="registry.invalid/disconnect-build:latest",
                        context_path="/tmp/context",
                    ),
                    settings=settings,
                )
            )

        self.assertEqual(client.submit_attempts, 1)
        self.assertEqual(client.wait_attempts, 1)

    def test_inspect_builds_add_writable_harbor_harness_dirs(self) -> None:
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        with TemporaryDirectory() as tmp_dir:
            context = Path(tmp_dir)
            dockerfile = context / "Dockerfile"
            dockerfile.write_text("FROM python:3.12-slim\nUSER app\n")
            client = _BuildCaptureClient()

            asyncio.run(
                inspect_integration._build_image_with_wait(
                    client,
                    Image.from_dockerfile(
                        name="harbor-build",
                        tag="registry.invalid/harbor-build:latest",
                        context_path=context,
                    ),
                    settings=_settings(inspect_integration),
                )
            )

            original_dockerfile = dockerfile.read_text()

        self.assertEqual(original_dockerfile, "FROM python:3.12-slim\nUSER app\n")
        self.assertEqual(len(client.dockerfiles), 1)
        self.assertNotEqual(client.context_paths[0], str(context))
        self.assertIn("USER 0", client.dockerfiles[0])
        self.assertIn("mkdir -p /tests /logs/agent /logs/verifier /task /oracle", client.dockerfiles[0])
        self.assertIn("chmod -R 0777 /tests /logs /task /oracle", client.dockerfiles[0])
        self.assertTrue(client.dockerfiles[0].rstrip().endswith("USER app"))

    def test_harbor_harness_dockerfile_adapter_ignores_previous_stage_user(self) -> None:
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        adapted = inspect_integration._dockerfile_with_harbor_harness_dirs(
            "\n".join(
                [
                    "FROM python:3.12-slim AS builder",
                    "USER builder",
                    "RUN true",
                    "FROM python:3.12-slim",
                    "RUN true",
                    "",
                ]
            )
        )

        self.assertIn("USER 0", adapted)
        self.assertIn("mkdir -p /tests /logs/agent /logs/verifier /task /oracle", adapted)
        self.assertFalse(adapted.rstrip().endswith("USER builder"))

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

        with TemporaryDirectory() as tmp_dir:
            context = Path(tmp_dir) / "environment"
            context.mkdir()
            (context / "Dockerfile").write_text("FROM python:3.12-slim\n")
            sandbox_id = "s" * 59
            client = _BuildCaptureClient()

            with patch.dict("os.environ", {}, clear=True):
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
        self.assertEqual(
            build.tag,
            f"ucloud-sandbox-registry:5000/ucloud-inspect/{sandbox_id}:latest",
        )
        self.assertNotEqual(build.context_path, str(context.resolve()))
        self.assertEqual(build.dockerfile, "Dockerfile")
        self.assertEqual(launch.image.name, client.images[0].name)
        self.assertIn("mkdir -p /tests /logs/agent /logs/verifier /task /oracle", client.dockerfiles[0])
        self.assertEqual(launch.command, ["sh", "-lc", "tail -f /dev/null"])
        self.assertEqual(launch.env, {"HARBOR": "1"})
        self.assertEqual(launch.cpus, 2.0)
        self.assertEqual(launch.memory_mb, 6144)

    def test_compose_yaml_build_context_is_resolved_from_compose_dir(self) -> None:
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

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
            client = _BuildCaptureClient()

            with patch.dict("os.environ", {}, clear=True):
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
        self.assertNotEqual(build.context_path, str(context.resolve()))
        self.assertEqual(build.dockerfile, "Dockerfile.custom")
        self.assertEqual(build.tag, "ucloud-sandbox-registry:5000/test/image:latest")
        self.assertIn("mkdir -p /tests /logs/agent /logs/verifier /task /oracle", client.dockerfiles[0])
        self.assertEqual(launch.command, ["sleep", "infinity"])
        self.assertEqual(launch.env, {"A": "B"})
        self.assertEqual(launch.cpus, 4.0)
        self.assertEqual(launch.memory_mb, 2048)

    def test_generated_build_tag_uses_configured_private_registry_prefix(self) -> None:
        from inspect_ai.util import ComposeBuild, ComposeConfig, ComposeService
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        with TemporaryDirectory() as tmp_dir:
            context = Path(tmp_dir) / "environment"
            context.mkdir()
            (context / "Dockerfile").write_text("FROM python:3.12-slim\n")
            client = _BuildCaptureClient()
            with patch.dict(
                "os.environ",
                {"UCLOUD_SANDBOX_BUILD_IMAGE_PREFIX": "registry.local:5000/Inspect"},
                clear=True,
            ):
                asyncio.run(
                    inspect_integration._sandbox_launch_plan(
                        client,
                        sandbox_id="Inspect-Harbor-Sample-ABC123",
                        config=ComposeConfig(
                            services={
                                "default": ComposeService(
                                    build=ComposeBuild(context=str(context))
                                )
                            }
                        ),
                        default_image=Image.from_registry("python:3.12-slim"),
                        settings=_settings(inspect_integration),
                    )
                )

        build = client.images[0].to_build_spec()
        self.assertEqual(
            build.tag,
            "registry.local:5000/Inspect/inspect-harbor-sample-abc123:latest",
        )

    def test_multi_service_compose_is_rejected_for_now(self) -> None:
        from inspect_ai.util import ComposeConfig, ComposeService
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        class FakeClient:
            async def submit_image_build(self, image, **_kwargs):
                return {"build_id": image.name}

            async def wait_for_image_build(self, build_id, **_kwargs):
                return {"status": "succeeded", "image": {"id": build_id}}

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
        security=SandboxSecuritySpec(),
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
