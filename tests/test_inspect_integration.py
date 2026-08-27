from __future__ import annotations

import asyncio
from collections.abc import Iterator
from contextlib import contextmanager
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from aiohttp import ServerDisconnectedError
from inspect_ai.util import (
    ComposeBuild,
    ComposeConfig,
    ComposeService,
    OutputLimitExceededError,
    SandboxEnvironmentLimits,
)

from ucloud_sandboxes_sdk import (
    Image,
    SandboxApiError,
    SandboxExecResult,
    SandboxSecuritySpec,
    SandboxSpec,
)
from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration


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


class _CachedBuildClient(_BuildCaptureClient):
    def __init__(
        self, images: list[dict], image_builds: list[dict] | None = None
    ) -> None:
        super().__init__()
        self.cached_images = images
        self.image_builds = image_builds or []

    async def list_images(self):
        return list(self.cached_images)

    async def list_image_builds(self):
        return list(self.image_builds)


class _ScriptedCreateClient:
    """Public-boundary fake whose outcomes describe one create workflow."""

    def __init__(self, outcomes: list[object]) -> None:
        self.outcomes = list(outcomes)
        self.attempts = 0

    async def create_sandbox(self, payload, *, request_timeout_seconds=None):
        del request_timeout_seconds
        self.attempts += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return {"created": payload.id}


class _BuildRecoveryClient:
    """Script ambiguous submit/recovery outcomes without per-test fake classes."""

    def __init__(
        self,
        submit_outcomes: list[object],
        *,
        recovered: dict | None = None,
        existing_builds: list[dict] | None = None,
        wait_error: BaseException | None = None,
    ) -> None:
        self.submit_outcomes = list(submit_outcomes)
        self.recovered = recovered
        self.existing_builds = existing_builds or []
        self.wait_error = wait_error
        self.submit_attempts = 0
        self.get_build_ids: list[str] = []
        self.wait_build_ids: list[str] = []

    async def list_image_builds(self):
        return list(self.existing_builds)

    async def submit_image_build(self, image, **_kwargs):
        del image
        self.submit_attempts += 1
        outcome = self.submit_outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    async def get_image_build(self, build_id, **_kwargs):
        self.get_build_ids.append(build_id)
        if self.recovered is None:
            raise SandboxApiError(
                "image build not found",
                status_code=404,
                body={"error": "image build not found"},
            )
        return dict(self.recovered)

    async def wait_for_image_build(self, build_id, **_kwargs):
        self.wait_build_ids.append(build_id)
        if self.wait_error is not None:
            raise self.wait_error
        return {"build_id": build_id, "status": "succeeded", "image": {}}


def _exec_result(
    exit_code: int = 0,
    *,
    stdout: str = "",
    stderr: str = "",
) -> SandboxExecResult:
    return SandboxExecResult(
        session_id="session-one",
        status="exited",
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        events=(),
        session={},
    )


class _EnvironmentHandle:
    """Small in-memory fake for the public AsyncSandboxHandle boundary."""

    id = "sandbox-one"

    def __init__(self) -> None:
        self.command_result = _exec_result()
        self.exec_calls: list[tuple[list[str], object, object, object, object]] = []
        self.files: dict[str, bytes] = {}
        self.file_sizes: dict[str, int] = {}
        self.directories: set[str] = set()
        self.upload_failures: set[str] = set()
        self.download_failures: set[str] = set()
        self.uploads: list[tuple[str, bytes]] = []
        self.downloads: list[str] = []

    async def exec(
        self,
        command,
        *,
        input=None,
        env=None,
        working_dir=None,
        timeout_seconds=None,
    ) -> SandboxExecResult:
        command = list(command)
        self.exec_calls.append((command, input, env, working_dir, timeout_seconds))
        if command[:2] == ["mkdir", "-p"]:
            self.directories.add(command[2])
            return _exec_result()
        if command[:2] == ["test", "-d"]:
            return _exec_result(0 if command[2] in self.directories else 1)
        if command[:3] == ["stat", "-c", "%s"]:
            path = command[3]
            if path in self.file_sizes:
                return _exec_result(stdout=str(self.file_sizes[path]))
            if path in self.files:
                return _exec_result(stdout=str(len(self.files[path])))
            return _exec_result(1, stderr="not found")
        return self.command_result

    async def upload_file(self, path: str, content: bytes) -> dict:
        self.uploads.append((path, content))
        if path in self.directories or path in self.upload_failures:
            raise SandboxApiError("upload rejected")
        self.files[path] = content
        return {"ok": True}

    async def download_file(self, path: str) -> bytes:
        self.downloads.append(path)
        if path in self.download_failures or path not in self.files:
            raise SandboxApiError("download rejected")
        return self.files[path]


@contextmanager
def _build_context(
    dockerfile: str = "FROM python:3.12-slim\n",
) -> Iterator[Path]:
    with TemporaryDirectory() as tmp_dir:
        context = Path(tmp_dir) / "environment"
        context.mkdir()
        (context / "Dockerfile").write_text(dockerfile)
        yield context


def _compose_config(context: Path, **service: object) -> ComposeConfig:
    return ComposeConfig(
        services={
            "default": ComposeService(
                build=ComposeBuild(context=str(context)),
                **service,
            )
        }
    )


def _launch_plan(
    client: object,
    config: object,
    *,
    sandbox_id: str = "inspect-task-sample-1234567890",
):
    with patch.dict(os.environ, {}, clear=True):
        return asyncio.run(
            inspect_integration._sandbox_launch_plan(
                client,
                sandbox_id=sandbox_id,
                config=config,
                default_image=Image.from_registry("python:3.12-slim"),
                settings=_settings(inspect_integration),
            )
        )


class InspectEnvironmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.handle = _EnvironmentHandle()
        self.environment = inspect_integration.UCloudSandboxEnvironment(
            self.handle,
            object(),
        )

    def test_exec_forwards_options_and_translates_result(self) -> None:
        self.handle.command_result = _exec_result(
            7,
            stdout="partial output",
            stderr="command failed",
        )

        result = asyncio.run(
            self.environment.exec(
                ["sh", "-lc", "run task"],
                input=b"stdin",
                cwd="workspace",
                env={"MODE": "test"},
                timeout=9,
            )
        )

        self.assertFalse(result.success)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout, "partial output")
        self.assertEqual(result.stderr, "command failed")
        self.assertEqual(
            self.handle.exec_calls,
            [
                (
                    ["sh", "-lc", "run task"],
                    b"stdin",
                    {"MODE": "test"},
                    "/workspace",
                    9,
                )
            ],
        )

    def test_write_file_translates_directory_and_gateway_errors(self) -> None:
        self.handle.directories.add("/target-dir")
        with self.assertRaises(IsADirectoryError) as directory_error:
            asyncio.run(self.environment.write_file("/target-dir", b"data"))
        self.assertEqual(directory_error.exception.filename, "/target-dir")

        self.handle.upload_failures.add("/rejected.txt")
        with self.assertRaisesRegex(RuntimeError, "failed to write /rejected.txt"):
            asyncio.run(self.environment.write_file("/rejected.txt", b"data"))

    def test_read_file_enforces_size_and_translates_missing_files(self) -> None:
        too_large = "/work/too-large.bin"
        self.handle.file_sizes[too_large] = (
            SandboxEnvironmentLimits.MAX_READ_FILE_SIZE + 1
        )
        with self.assertRaises(OutputLimitExceededError):
            asyncio.run(self.environment.read_file(too_large, text=False))
        self.assertNotIn(too_large, self.handle.downloads)

        with self.assertRaises(FileNotFoundError) as stat_error:
            asyncio.run(self.environment.read_file("/work/missing.txt"))
        self.assertEqual(stat_error.exception.filename, "/work/missing.txt")

        raced = "/work/disappeared.txt"
        self.handle.file_sizes[raced] = 1
        self.handle.download_failures.add(raced)
        with self.assertRaises(FileNotFoundError) as download_error:
            asyncio.run(self.environment.read_file(raced))
        self.assertEqual(download_error.exception.filename, raced)


class InspectIntegrationTests(unittest.TestCase):
    def test_task_cleanup_retains_failed_sandbox_for_retry(self) -> None:
        from ucloud_sandboxes_sdk.integrations import inspect as inspect_integration

        class FakeClient:
            def __init__(self, *_args, **_kwargs) -> None:
                self.closed = False

            async def delete_sandbox(self, _sandbox_id):
                raise SandboxApiError(
                    "delete rejected",
                    status_code=400,
                    body={"error": "delete rejected"},
                )

            async def close(self) -> None:
                self.closed = True

        inspect_integration._running_sandboxes.set(
            [("http://gateway.invalid", "sandbox-one", {})]
        )
        with (
            patch.object(inspect_integration, "AsyncSandboxClient", FakeClient),
            self.assertRaisesRegex(RuntimeError, "sandbox-one"),
        ):
            asyncio.run(
                inspect_integration.UCloudSandboxEnvironment.task_cleanup(
                    "task",
                    None,
                    cleanup=True,
                )
            )

        self.assertEqual(
            inspect_integration.running_sandboxes(),
            [("http://gateway.invalid", "sandbox-one", {})],
        )

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

    def test_sample_init_uses_compose_network_mode_unless_env_overrides(self) -> None:
        captured: list[SandboxSpec] = []

        class FakeClient:
            def __init__(self, *_args, **_kwargs) -> None:
                pass

            async def close(self) -> None:
                pass

        async def fake_create(client, spec, *, settings):
            del client, settings
            captured.append(spec)
            return object()

        config = ComposeConfig(
            services={
                "default": ComposeService(
                    image="python:3.12-slim",
                    network_mode="bridge",
                )
            }
        )

        with (
            patch.object(inspect_integration, "AsyncSandboxClient", FakeClient),
            patch.object(inspect_integration, "_create_sandbox_with_wait", fake_create),
        ):
            with patch.dict(
                os.environ,
                {"UCLOUD_SANDBOX_URL": "http://gateway.invalid"},
                clear=True,
            ):
                asyncio.run(
                    inspect_integration.UCloudSandboxEnvironment.sample_init(
                        "task",
                        config,
                        {"__sample_id__": "compose-network"},
                    )
                )
            with patch.dict(
                os.environ,
                {
                    "UCLOUD_SANDBOX_URL": "http://gateway.invalid",
                    "UCLOUD_SANDBOX_NETWORK": "none",
                },
                clear=True,
            ):
                asyncio.run(
                    inspect_integration.UCloudSandboxEnvironment.sample_init(
                        "task",
                        config,
                        {"__sample_id__": "env-network"},
                    )
                )

        self.assertEqual(captured[0].network, "bridge")
        self.assertEqual(captured[1].network, "none")

    def test_create_retry_classification(self) -> None:
        retryable_capacity = SandboxApiError(
            "pending",
            status_code=503,
            body={
                "error": "no ready node has resources for sandbox request",
                "pending_resources": {"vcpu": 1.0},
            },
        )
        rejected = SandboxApiError(
            "bad request",
            status_code=400,
            body={"error": "invalid sandbox"},
        )
        cases = (
            ("capacity", [retryable_capacity, object()], True, 2),
            (
                "disconnect",
                [ServerDisconnectedError("disconnected"), object()],
                True,
                2,
            ),
            ("rejected", [rejected], False, 1),
        )

        for label, outcomes, succeeds, attempts in cases:
            with self.subTest(label=label):
                client = _ScriptedCreateClient(outcomes)
                operation = inspect_integration._create_sandbox_with_wait(
                    client,
                    _sandbox_spec(),
                    settings=_settings(inspect_integration),
                )
                if succeeds:
                    self.assertEqual(asyncio.run(operation), {"created": "sandbox-one"})
                else:
                    with self.assertRaises(SandboxApiError):
                        asyncio.run(operation)
                self.assertEqual(client.attempts, attempts)

    def test_image_build_submit_recovery_and_non_resubmission(self) -> None:
        image_id = "behavior-build"
        tag = "registry.invalid/behavior-build:latest"
        disconnected = ServerDisconnectedError("disconnected")
        no_builder = SandboxApiError(
            "no builder",
            status_code=503,
            body={"error": "no ready builder node is available"},
        )
        old = {
            "build_id": "old-failed-build",
            "image_id": image_id,
            "tag": tag,
            "status": "failed",
        }
        cases = (
            (
                "accepted ambiguous submit",
                _BuildRecoveryClient(
                    [disconnected],
                    recovered={
                        "build_id": "accepted-build",
                        "image_id": image_id,
                        "tag": tag,
                        "status": "running",
                    },
                ),
                1,
                "accepted-build",
                None,
            ),
            (
                "unaccepted ambiguous submit",
                _BuildRecoveryClient([disconnected, {"build_id": "resubmitted-build"}]),
                2,
                "resubmitted-build",
                None,
            ),
            (
                "old terminal build",
                _BuildRecoveryClient(
                    [disconnected, {"build_id": "new-build"}],
                    recovered=old,
                    existing_builds=[old],
                ),
                2,
                "new-build",
                None,
            ),
            (
                "definitely unaccepted capacity response",
                _BuildRecoveryClient([no_builder, {"build_id": "builder-ready"}]),
                2,
                "builder-ready",
                None,
            ),
            (
                "wait failure",
                _BuildRecoveryClient(
                    [{"build_id": "wait-failed"}],
                    wait_error=ServerDisconnectedError("wait disconnected"),
                ),
                1,
                "wait-failed",
                ServerDisconnectedError,
            ),
        )

        image = Image.from_dockerfile(
            name=image_id,
            tag=tag,
            context_path="/tmp/context",
        )
        for label, client, attempts, waited_build, error_type in cases:
            with self.subTest(label=label):
                operation = inspect_integration._build_image_with_wait(
                    client,
                    image,
                    settings=_settings(inspect_integration),
                )
                if error_type is None:
                    self.assertEqual(asyncio.run(operation)["status"], "succeeded")
                else:
                    with self.assertRaises(error_type):
                        asyncio.run(operation)
                self.assertEqual(client.submit_attempts, attempts)
                self.assertEqual(client.wait_build_ids, [waited_build])

    def test_single_service_compose_builds_image_and_uses_resources(self) -> None:
        with _build_context() as context:
            sandbox_id = "s" * 59
            client = _BuildCaptureClient()
            launch = _launch_plan(
                client,
                _compose_config(
                    context,
                    command="tail -f /dev/null",
                    environment={"HARBOR": "1"},
                    cpus=2.0,
                    mem_limit="6144m",
                    network_mode="bridge",
                ),
                sandbox_id=sandbox_id,
            )
        self.assertEqual(len(client.images), 1)
        build = client.images[0].to_build_spec()
        self.assertLessEqual(len(build.id), 64)
        self.assertRegex(build.id, r"^[a-z0-9][a-z0-9_.-]*$")
        self.assertIsNone(build.tag)
        self.assertEqual(build.context_path, str(context.resolve()))
        self.assertEqual(build.dockerfile, "Dockerfile")
        self.assertEqual(launch.image.name, client.images[0].name)
        self.assertEqual(client.dockerfiles, ["FROM python:3.12-slim\n"])
        self.assertEqual(launch.command, ["sh", "-lc", "tail -f /dev/null"])
        self.assertEqual(launch.env, {"HARBOR": "1"})
        self.assertEqual(launch.cpus, 2.0)
        self.assertEqual(launch.memory_mb, 6144)
        self.assertEqual(launch.network, "bridge")

    def test_generated_build_identity_is_stable_and_content_sensitive(self) -> None:
        with _build_context() as context:
            config = _compose_config(context)
            clients = [
                _BuildCaptureClient(),
                _BuildCaptureClient(),
                _BuildCaptureClient(),
            ]
            for client, sandbox_id in zip(
                clients[:2], ("inspect-task-a", "inspect-task-b")
            ):
                _launch_plan(client, config, sandbox_id=sandbox_id)
            (context / "Dockerfile").write_text(
                "FROM python:3.12-slim\nRUN echo changed\n"
            )
            _launch_plan(clients[2], config, sandbox_id="inspect-task-c")

        first = clients[0].images[0].to_build_spec()
        second = clients[1].images[0].to_build_spec()
        changed = clients[2].images[0].to_build_spec()
        self.assertEqual(first.id, second.id)
        self.assertNotEqual(first.id, changed.id)
        for build in (first, second, changed):
            self.assertLessEqual(len(build.id), 64)
            self.assertRegex(build.id, r"^[a-z0-9][a-z0-9_.-]*$")
            self.assertIsNone(build.tag)

    def test_compose_yaml_build_context_is_resolved_from_compose_dir(self) -> None:
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
            launch = _launch_plan(client, str(compose_file))
        self.assertEqual(len(client.images), 1)
        build = client.images[0].to_build_spec()
        self.assertEqual(build.context_path, str(context.resolve()))
        self.assertEqual(build.dockerfile, "Dockerfile.custom")
        self.assertIsNone(build.tag)
        self.assertLessEqual(len(build.id), 64)
        self.assertRegex(build.id, r"^[a-z0-9][a-z0-9_.-]*$")
        self.assertEqual(client.dockerfiles, ["FROM python:3.12-slim\n"])
        self.assertEqual(launch.command, ["sleep", "infinity"])
        self.assertEqual(launch.env, {"A": "B"})
        self.assertEqual(launch.cpus, 4.0)
        self.assertEqual(launch.memory_mb, 2048)

    def test_existing_active_generated_build_skips_duplicate_submit(self) -> None:
        with _build_context() as context:
            config = _compose_config(context)
            seed = _BuildCaptureClient()
            generated = _launch_plan(seed, config, sandbox_id="inspect-task-seed")
            image_id = generated.image.name
            tag = "sandbox-gateway-prod:5000/ucloud-managed/active:latest"
            client = _CachedBuildClient(
                [],
                image_builds=[
                    {
                        "build_id": "active-build",
                        "image_id": image_id,
                        "tag": tag,
                        "status": "running",
                        "created_at": "2026-07-04T12:00:00+00:00",
                    }
                ],
            )

            launch = _launch_plan(client, config)

        self.assertEqual(client.images, [])
        self.assertEqual(client.context_paths, [])
        self.assertEqual(launch.image.name, image_id)

    def test_multi_service_compose_is_rejected_for_now(self) -> None:
        with self.assertRaises(NotImplementedError):
            _launch_plan(
                _BuildCaptureClient(),
                ComposeConfig(
                    services={
                        "default": ComposeService(image="python:3.12-slim"),
                        "victim": ComposeService(image="nginx:latest"),
                    }
                ),
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
        network=None,
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
