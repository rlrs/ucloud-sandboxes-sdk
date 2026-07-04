from __future__ import annotations

import asyncio
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import errno
from logging import getLogger
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sys
from tempfile import TemporaryDirectory
import time
from typing import Any, Iterator, Literal, overload
from uuid import uuid4

from aiohttp import ClientError
from inspect_ai.util import (
    ComposeConfig,
    ExecResult,
    OutputLimitExceededError,
    SandboxEnvironment,
    SandboxEnvironmentConfigType,
    SandboxEnvironmentLimits,
    is_compose_yaml,
    is_dockerfile,
    parse_compose_yaml,
    sandboxenv,
    warn_once,
)
from inspect_ai.util._sandbox.environment import SandboxConnection

from ucloud_sandboxes_sdk import (
    AsyncSandboxClient,
    AsyncSandboxHandle,
    Image,
    SandboxApiError,
    SandboxSpec,
)


DEFAULT_INSPECT_IMAGE = "python:3.12-slim"
DEFAULT_INSPECT_CPUS = 1.0
DEFAULT_INSPECT_MEMORY_MB = 2048
DEFAULT_INSPECT_DISK_MB = 10_240
DEFAULT_START_TIMEOUT_SECONDS = 1800
DEFAULT_BUILD_TIMEOUT_SECONDS = 1800
DEFAULT_RETRY_INTERVAL_SECONDS = 10.0
DEFAULT_SCALE_UP_REQUEST_TIMEOUT_SECONDS = 30.0
DEFAULT_BUILD_IMAGE_PREFIX = "ucloud-sandbox-registry:5000/ucloud-inspect"
HARBOR_HARNESS_DIRS = ("/tests", "/logs/agent", "/logs/verifier", "/task", "/oracle")
INSPECT_CREATED_BY = "inspect-ai"
logger = getLogger(__name__)
_running_sandboxes: ContextVar[list[tuple[str, str, dict[str, str]]]] = ContextVar(
    "ucloud_running_sandboxes",
)


@dataclass(frozen=True)
class _InspectSettings:
    base_url: str
    headers: dict[str, str]
    image: Image
    cpus: float | None
    memory_mb: int | None
    disk_mb: int | None
    ttl_seconds: int | None
    network: str
    ssh_enabled: bool
    ssh_user: str
    start_timeout_seconds: int
    build_timeout_seconds: int
    retry_interval_seconds: float
    cpus_explicit: bool = False
    memory_mb_explicit: bool = False


@dataclass(frozen=True)
class _SandboxLaunchPlan:
    image: Image
    command: list[str]
    env: dict[str, str]
    cpus: float | None = None
    memory_mb: int | None = None
    working_dir: str | None = None


def sandbox_cleanup_startup() -> None:
    _running_sandboxes.set([])


def running_sandboxes() -> list[tuple[str, str, dict[str, str]]]:
    return _running_sandboxes.get([])


@sandboxenv(name="ucloud")
class UCloudSandboxEnvironment(SandboxEnvironment):
    def __init__(
        self,
        handle: AsyncSandboxHandle,
        client: AsyncSandboxClient,
    ) -> None:
        super().__init__()
        self.handle = handle
        self.client = client

    @classmethod
    def config_files(cls) -> list[str]:
        return [
            "compose.yaml",
            "compose.yml",
            "docker-compose.yaml",
            "docker-compose.yml",
            "Dockerfile",
        ]

    @classmethod
    def is_docker_compatible(cls) -> bool:
        return True

    @classmethod
    async def task_init(
        cls,
        task_name: str,
        config: SandboxEnvironmentConfigType | None,
    ) -> None:
        del task_name, config
        sandbox_cleanup_startup()

    @classmethod
    async def sample_init(
        cls,
        task_name: str,
        config: SandboxEnvironmentConfigType | None,
        metadata: dict[str, Any],
    ) -> dict[str, SandboxEnvironment]:
        settings = _settings_from_env()
        sandbox_id = _sandbox_id(task_name, metadata)
        client = AsyncSandboxClient(settings.base_url, headers=settings.headers)
        try:
            launch = await _sandbox_launch_plan(
                client,
                sandbox_id=sandbox_id,
                config=config,
                default_image=settings.image,
                settings=settings,
            )
            labels = {
                "created_by": INSPECT_CREATED_BY,
                "inspect_task": _label_value(task_name),
            }
            sample_id = metadata.get("__sample_id__")
            if sample_id is not None:
                labels["inspect_sample_id"] = _label_value(sample_id)
            network = settings.network
            if settings.ssh_enabled and network == "none":
                network = "bridge"
            handle = await _create_sandbox_with_wait(
                client,
                SandboxSpec(
                    id=sandbox_id,
                    image=launch.image,
                    command=launch.command or ["sh", "-lc", "sleep 2147483647"],
                    env=launch.env,
                    working_dir=launch.working_dir or "/tmp",
                    cpus=(
                        settings.cpus
                        if settings.cpus_explicit
                        else launch.cpus or settings.cpus
                    ),
                    memory_mb=(
                        settings.memory_mb
                        if settings.memory_mb_explicit
                        else launch.memory_mb or settings.memory_mb
                    ),
                    disk_mb=settings.disk_mb,
                    network=network,
                    ttl_seconds=settings.ttl_seconds,
                    ssh={
                        "enabled": settings.ssh_enabled,
                        "user": settings.ssh_user,
                    },
                    labels=labels,
                ),
                settings=settings,
            )
        except Exception:
            try:
                await client.delete_sandbox(sandbox_id)
            except SandboxApiError:
                pass
            await client.close()
            raise
        running_sandboxes().append((settings.base_url, sandbox_id, dict(settings.headers)))
        return {"default": cls(handle, client)}

    @classmethod
    async def sample_cleanup(
        cls,
        task_name: str,
        config: SandboxEnvironmentConfigType | None,
        environments: dict[str, SandboxEnvironment],
        interrupted: bool,
    ) -> None:
        del task_name, config
        if not environments or interrupted:
            return
        for env in environments.values():
            sandbox = env.as_type(UCloudSandboxEnvironment)
            try:
                await sandbox.handle.delete()
            finally:
                await sandbox.client.close()

    @classmethod
    async def task_cleanup(
        cls,
        task_name: str,
        config: SandboxEnvironmentConfigType | None,
        cleanup: bool,
    ) -> None:
        del task_name, config
        if not cleanup:
            return
        for base_url, sandbox_id, headers in running_sandboxes().copy():
            client = AsyncSandboxClient(base_url, headers=headers)
            try:
                await client.delete_sandbox(sandbox_id)
            except SandboxApiError:
                pass
            finally:
                await client.close()
        running_sandboxes().clear()

    @classmethod
    async def cli_cleanup(cls, id: str | None) -> None:
        settings = _settings_from_env()
        client = AsyncSandboxClient(settings.base_url, headers=settings.headers)
        try:
            if id is not None:
                await client.delete_sandbox(id)
                print(f"Deleted UCloud sandbox {id}")
                return
            deleted = 0
            for record in await client.list_sandboxes():
                spec = record.get("spec")
                labels = spec.get("labels") if isinstance(spec, dict) else None
                sandbox_id = spec.get("id") if isinstance(spec, dict) else None
                if (
                    isinstance(labels, dict)
                    and labels.get("created_by") == INSPECT_CREATED_BY
                    and isinstance(sandbox_id, str)
                ):
                    await client.delete_sandbox(sandbox_id)
                    deleted += 1
            print(f"Deleted {deleted} UCloud Inspect sandbox(es).")
        except Exception as exc:
            print(f"Error cleaning up UCloud sandboxes: {exc}", file=sys.stderr)
            sys.exit(1)
        finally:
            await client.close()

    async def exec(
        self,
        cmd: list[str],
        input: str | bytes | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        user: str | None = None,
        timeout: int | None = None,
        timeout_retry: bool = True,
        concurrency: bool = True,
    ) -> ExecResult[str]:
        del timeout_retry, concurrency
        if user is not None:
            warn_once(
                logger,
                "The 'user' parameter is ignored in UCloudSandboxEnvironment. "
                "Commands run as the sandbox container's configured user.",
            )
        workdir = cwd
        if workdir is not None and not PurePosixPath(workdir).is_absolute():
            workdir = f"/{workdir}"
        result = await self.handle.exec(
            cmd,
            input=input,
            env=env,
            working_dir=workdir,
            timeout_seconds=timeout,
        )
        return ExecResult(
            success=result.success,
            returncode=result.exit_code if result.exit_code is not None else 0,
            stdout=result.stdout,
            stderr=result.stderr,
        )

    async def write_file(self, file: str, contents: str | bytes) -> None:
        parent = str(PurePosixPath(file).parent)
        content_bytes = contents.encode("utf-8") if isinstance(contents, str) else contents
        if parent and parent not in {"/", "."}:
            result = await self.exec(["mkdir", "-p", parent])
            if not result.success:
                raise RuntimeError(result.stderr or f"failed to create {parent}")
        try:
            await self.handle.upload_file(file, content_bytes)
        except SandboxApiError as exc:
            if await self._is_directory(file):
                raise IsADirectoryError(errno.EISDIR, "Is a directory", file) from exc
            raise RuntimeError(f"failed to write {file}: {exc}") from exc

    @overload
    async def read_file(self, file: str, text: Literal[True] = True) -> str: ...

    @overload
    async def read_file(self, file: str, text: Literal[False]) -> bytes: ...

    async def read_file(self, file: str, text: bool = True) -> str | bytes:
        if await self._is_directory(file):
            raise IsADirectoryError(errno.EISDIR, "Is a directory", file)
        file_size = await self._get_file_size(file)
        if file_size > SandboxEnvironmentLimits.MAX_READ_FILE_SIZE:
            raise OutputLimitExceededError(
                limit_str=SandboxEnvironmentLimits.MAX_READ_FILE_SIZE_STR,
                truncated_output=None,
            )
        try:
            raw = await self.handle.download_file(file)
        except SandboxApiError as exc:
            raise FileNotFoundError(
                errno.ENOENT,
                "No such file or directory",
                file,
            ) from exc
        if not text:
            return raw
        return raw.decode("utf-8")

    async def connection(self, *, user: str | None = None) -> SandboxConnection:
        del user
        command = ""
        try:
            target = await self.handle.ssh()
            ssh = target.get("ssh")
            if isinstance(ssh, dict):
                command = str(ssh.get("command") or "")
        except SandboxApiError:
            command = ""
        return SandboxConnection(
            type="ucloud",
            command=command,
            container=self.handle.id,
        )

    async def _is_directory(self, file: str) -> bool:
        result = await self.exec(["test", "-d", file])
        return result.returncode == 0

    async def _get_file_size(self, file: str) -> int:
        result = await self.exec(["stat", "-c", "%s", file])
        if result.returncode != 0:
            raise FileNotFoundError(errno.ENOENT, "No such file or directory", file)
        try:
            return int(result.stdout.strip())
        except ValueError as exc:
            raise RuntimeError(f"Failed to parse file size for {file}") from exc


async def _sandbox_launch_plan(
    client: AsyncSandboxClient,
    *,
    sandbox_id: str,
    config: SandboxEnvironmentConfigType | None,
    default_image: Image,
    settings: _InspectSettings,
) -> _SandboxLaunchPlan:
    if config is None:
        return _SandboxLaunchPlan(default_image, [], {})
    if is_dockerfile(config):
        path = Path(str(config))
        image = Image.from_dockerfile(
            name=_compose_image_id(sandbox_id),
            tag=_generated_build_image_tag(sandbox_id),
            context_path=path.parent or Path("."),
            dockerfile=path.name,
            push=True,
        )
        await _build_image_with_wait(
            client,
            image,
            settings=settings,
        )
        return _SandboxLaunchPlan(image, [], {})
    if is_compose_yaml(config):
        compose_path = Path(str(config))
        return await _compose_launch_plan(
            client,
            sandbox_id=sandbox_id,
            config=parse_compose_yaml(config, multiple_services=False),
            default_image=default_image,
            settings=settings,
            compose_dir=compose_path.parent,
        )
    if isinstance(config, ComposeConfig):
        return await _compose_launch_plan(
            client,
            sandbox_id=sandbox_id,
            config=config,
            default_image=default_image,
            settings=settings,
            compose_dir=None,
        )
    raise ValueError(
        f"Unrecognized config: {config}. Expected a compose file, Dockerfile, "
        "ComposeConfig object, or None."
    )


async def _compose_launch_plan(
    client: AsyncSandboxClient,
    *,
    sandbox_id: str,
    config: ComposeConfig,
    default_image: Image,
    settings: _InspectSettings,
    compose_dir: Path | None,
) -> _SandboxLaunchPlan:
    services = getattr(config, "services", None)
    if not isinstance(services, dict) or not services:
        return _SandboxLaunchPlan(default_image, [], {})
    if len(services) > 1:
        raise NotImplementedError(
            "UCloud Inspect integration currently supports single-service Compose "
            "configs only. Multi-service Compose needs node-agent project support."
        )
    service_name, service = (
        ("default", services["default"])
        if "default" in services
        else next(iter(services.items()))
    )
    raw_image = getattr(service, "image", None)
    build = getattr(service, "build", None)
    if build:
        image = _compose_build_image(
            sandbox_id=sandbox_id,
            service_name=service_name,
            service=service,
            compose_dir=compose_dir,
        )
        await _build_image_with_wait(client, image, settings=settings)
    else:
        image = _registry_image(str(raw_image)) if raw_image else default_image
    return _SandboxLaunchPlan(
        image=image,
        command=_compose_command(getattr(service, "command", None)),
        env=_compose_env(getattr(service, "environment", None)),
        cpus=_compose_cpus(service),
        memory_mb=_compose_memory_mb(service),
        working_dir=getattr(service, "working_dir", None),
    )


def _compose_build_image(
    *,
    sandbox_id: str,
    service_name: str,
    service: object,
    compose_dir: Path | None,
) -> Image:
    build = getattr(service, "build", None)
    context, dockerfile = _compose_build_context_and_dockerfile(build)
    context_path = _resolve_compose_path(context, compose_dir)
    dockerfile_path = Path(dockerfile)
    if dockerfile_path.is_absolute():
        try:
            dockerfile = dockerfile_path.relative_to(context_path).as_posix()
        except ValueError as exc:
            raise ValueError(
                "Compose build.dockerfile must be inside build.context when "
                "uploading the build context to UCloud."
            ) from exc
    raw_image = getattr(service, "image", None)
    return Image.from_dockerfile(
        name=_compose_image_id(sandbox_id, service_name=service_name),
        tag=str(raw_image) if raw_image else _generated_build_image_tag(sandbox_id),
        context_path=context_path,
        dockerfile=dockerfile,
        push=True,
    )


def _compose_build_context_and_dockerfile(build: object) -> tuple[str, str]:
    if isinstance(build, str):
        return build, "Dockerfile"
    context = getattr(build, "context", None) or "."
    dockerfile = getattr(build, "dockerfile", None) or "Dockerfile"
    return str(context), str(dockerfile)


def _resolve_compose_path(path: str, compose_dir: Path | None) -> Path:
    raw = Path(path)
    if raw.is_absolute():
        return raw.resolve()
    base = compose_dir if compose_dir is not None else Path(".")
    return (base / raw).resolve()


def _compose_image_id(sandbox_id: str, *, service_name: str = "default") -> str:
    suffix = "image" if service_name == "default" else f"{service_name}-image"
    suffix = re.sub(r"[^A-Za-z0-9_.-]+", "-", suffix).strip("_.-") or "image"
    suffix = f"-{suffix}"[:63]
    return f"{sandbox_id[:64 - len(suffix)]}{suffix}"


def _generated_build_image_tag(sandbox_id: str) -> str:
    prefix = (
        os.environ.get("UCLOUD_SANDBOX_BUILD_IMAGE_PREFIX")
        or os.environ.get("UCLOUD_SANDBOX_REGISTRY_PREFIX")
        or DEFAULT_BUILD_IMAGE_PREFIX
    )
    return f"{prefix.rstrip('/')}/{_docker_repository_component(sandbox_id)}:latest"


def _docker_repository_component(value: str) -> str:
    component = re.sub(r"[^a-z0-9_.-]+", "-", value.lower()).strip("_.-")
    return component or "image"


def _compose_command(command: object) -> list[str]:
    if command is None:
        return []
    if isinstance(command, str):
        return ["sh", "-lc", command]
    if isinstance(command, list) and all(isinstance(item, str) for item in command):
        return list(command)
    return ["sh", "-lc", str(command)]


def _compose_env(environment: object) -> dict[str, str]:
    if environment is None:
        return {}
    if isinstance(environment, dict):
        return {str(key): str(value) for key, value in environment.items()}
    if isinstance(environment, list):
        items: dict[str, str] = {}
        for item in environment:
            if not isinstance(item, str) or "=" not in item:
                continue
            key, value = item.split("=", 1)
            items[key] = value
        return items
    return {}


def _compose_cpus(service: object) -> float | None:
    cpus = getattr(service, "cpus", None)
    if cpus is None:
        cpus = _deploy_resource_value(service, "cpus")
    if cpus is None:
        return None
    return float(cpus)


def _compose_memory_mb(service: object) -> int | None:
    memory = getattr(service, "mem_limit", None)
    if memory is None:
        memory = _deploy_resource_value(service, "memory")
    if memory is None:
        return None
    return _parse_memory_mb(memory)


def _deploy_resource_value(service: object, name: str) -> object:
    deploy = getattr(service, "deploy", None)
    resources = getattr(deploy, "resources", None)
    limits = getattr(resources, "limits", None)
    return getattr(limits, name, None)


def _parse_memory_mb(value: object) -> int:
    if isinstance(value, (int, float)):
        return max(1, math.ceil(float(value) / (1024 * 1024)))
    raw = str(value).strip().lower()
    match = re.match(r"^(\d+(?:\.\d+)?)\s*([kmgt]?i?b?|b)?$", raw)
    if match is None:
        raise ValueError(f"invalid Compose memory value: {value!r}")
    amount = float(match.group(1))
    unit = match.group(2) or "b"
    factors = {
        "": 1,
        "b": 1,
        "k": 1024,
        "kb": 1024,
        "ki": 1024,
        "kib": 1024,
        "m": 1024**2,
        "mb": 1024**2,
        "mi": 1024**2,
        "mib": 1024**2,
        "g": 1024**3,
        "gb": 1024**3,
        "gi": 1024**3,
        "gib": 1024**3,
        "t": 1024**4,
        "tb": 1024**4,
        "ti": 1024**4,
        "tib": 1024**4,
    }
    return max(1, math.ceil(amount * factors[unit] / (1024 * 1024)))


def _settings_from_env() -> _InspectSettings:
    base_url = os.environ.get("UCLOUD_SANDBOX_URL") or os.environ.get(
        "UCLOUD_SANDBOX_BASE_URL"
    )
    if not base_url:
        raise ValueError(
            "Set UCLOUD_SANDBOX_URL to the UCloud sandbox gateway or node-agent URL."
        )
    headers: dict[str, str] = {}
    token = os.environ.get("UCLOUD_SANDBOX_API_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    ssh_enabled = _bool_env("UCLOUD_SANDBOX_SSH", False)
    cpus = _float_env("UCLOUD_SANDBOX_CPUS")
    memory_mb = _int_env("UCLOUD_SANDBOX_MEMORY_MB")
    disk_mb = _int_env("UCLOUD_SANDBOX_DISK_MB")
    retry_interval = _float_env("UCLOUD_SANDBOX_RETRY_INTERVAL_SECONDS")
    return _InspectSettings(
        base_url=base_url,
        headers=headers,
        image=_registry_image(os.environ.get("UCLOUD_SANDBOX_IMAGE", DEFAULT_INSPECT_IMAGE)),
        cpus=cpus or DEFAULT_INSPECT_CPUS,
        memory_mb=memory_mb or DEFAULT_INSPECT_MEMORY_MB,
        disk_mb=disk_mb or DEFAULT_INSPECT_DISK_MB,
        ttl_seconds=_int_env("UCLOUD_SANDBOX_TTL_SECONDS"),
        network=os.environ.get("UCLOUD_SANDBOX_NETWORK", "none"),
        ssh_enabled=ssh_enabled,
        ssh_user=os.environ.get("UCLOUD_SANDBOX_SSH_USER", "root"),
        start_timeout_seconds=(
            _int_env("UCLOUD_SANDBOX_START_TIMEOUT_SECONDS")
            or DEFAULT_START_TIMEOUT_SECONDS
        ),
        build_timeout_seconds=(
            _int_env("UCLOUD_SANDBOX_BUILD_TIMEOUT_SECONDS")
            or DEFAULT_BUILD_TIMEOUT_SECONDS
        ),
        retry_interval_seconds=(
            retry_interval
            if retry_interval is not None
            else DEFAULT_RETRY_INTERVAL_SECONDS
        ),
        cpus_explicit=cpus is not None,
        memory_mb_explicit=memory_mb is not None,
    )


def _sandbox_id(task_name: str, metadata: dict[str, Any]) -> str:
    sample_id = metadata.get("__sample_id__", "sample")
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "-", f"inspect-{task_name}-{sample_id}").strip(
        "_.-"
    )
    if not stem:
        stem = "inspect"
    return f"{stem[:48]}-{uuid4().hex[:10]}"


def _label_value(value: object) -> str:
    return re.sub(r"[^A-Za-z0-9_.:@/-]+", "-", str(value))[:128]


async def _create_sandbox_with_wait(
    client: AsyncSandboxClient,
    spec: SandboxSpec,
    *,
    settings: _InspectSettings,
) -> AsyncSandboxHandle:
    return await _retry_scale_up(
        "sandbox node",
        timeout_seconds=settings.start_timeout_seconds,
        retry_interval_seconds=settings.retry_interval_seconds,
        retry_client_errors=True,
        retry_timeout_errors=True,
        operation=lambda timeout_seconds: client.create_sandbox(
            spec,
            request_timeout_seconds=min(
                DEFAULT_SCALE_UP_REQUEST_TIMEOUT_SECONDS,
                timeout_seconds,
            ),
        ),
    )


async def _build_image_with_wait(
    client: AsyncSandboxClient,
    image: Image,
    *,
    settings: _InspectSettings,
) -> dict[str, Any]:
    timeout_seconds = max(0, int(settings.build_timeout_seconds))
    deadline = time.monotonic() + timeout_seconds
    with _harbor_compatible_build_image(image) as build_image:
        submitted = await _retry_scale_up(
            "builder node",
            timeout_seconds=timeout_seconds,
            retry_interval_seconds=settings.retry_interval_seconds,
            retry_client_errors=False,
            retry_timeout_errors=False,
            operation=lambda request_timeout_seconds: client.submit_image_build(
                build_image,
                timeout_seconds=request_timeout_seconds,
            ),
        )
    build_id = str(submitted.get("build_id") or submitted.get("image_id") or "")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(f"image build did not finish: {build_id}")
    build = await client.wait_for_image_build(
        build_id,
        timeout_seconds=remaining,
    )
    if build.get("status") != "succeeded":
        raise SandboxApiError(
            f"image build failed: {build.get('error') or build.get('status')}",
            body={"build": build},
        )
    return build


@contextmanager
def _harbor_compatible_build_image(image: Image) -> Iterator[Image]:
    spec = image.to_build_spec()
    context_path = Path(spec.context_path)
    dockerfile = Path(spec.dockerfile)
    if dockerfile.is_absolute() or not context_path.is_dir():
        yield image
        return
    source_dockerfile = context_path / dockerfile
    if not source_dockerfile.is_file():
        yield image
        return
    with TemporaryDirectory(prefix="ucloud-inspect-build-") as raw_dir:
        adapted_context = Path(raw_dir) / "context"
        shutil.copytree(context_path, adapted_context, symlinks=True)
        adapted_dockerfile = adapted_context / dockerfile
        original = adapted_dockerfile.read_text(encoding="utf-8")
        adapted_dockerfile.write_text(
            _dockerfile_with_harbor_harness_dirs(original),
            encoding="utf-8",
        )
        yield Image.from_dockerfile(
            name=spec.id,
            tag=spec.tag,
            context_path=adapted_context,
            dockerfile=spec.dockerfile,
            push=spec.push,
            build_args=spec.build_args,
            labels=spec.labels,
        )


def _dockerfile_with_harbor_harness_dirs(dockerfile: str) -> str:
    final_user = _final_stage_user(dockerfile)
    harness_dirs = " ".join(HARBOR_HARNESS_DIRS)
    lines = [
        dockerfile.rstrip(),
        "",
        "# UCloud Inspect/Harbor harness compatibility.",
        "USER 0",
        f"RUN mkdir -p {harness_dirs} \\",
        " && chmod -R 0777 /tests /logs /task /oracle",
    ]
    if final_user:
        lines.append(f"USER {final_user}")
    return "\n".join(lines) + "\n"


def _final_stage_user(dockerfile: str) -> str | None:
    final_user: str | None = None
    for line in _dockerfile_logical_lines(dockerfile):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        instruction, _, argument = stripped.partition(" ")
        instruction = instruction.upper()
        if instruction == "FROM":
            final_user = None
        elif instruction == "USER":
            user = argument.strip()
            if user:
                final_user = user
    return final_user


def _dockerfile_logical_lines(dockerfile: str) -> list[str]:
    lines: list[str] = []
    current = ""
    for raw_line in dockerfile.splitlines():
        line = raw_line.rstrip()
        continued = line.endswith("\\")
        part = line[:-1].rstrip() if continued else line
        current = f"{current} {part.lstrip()}".strip() if current else part
        if not continued:
            lines.append(current)
            current = ""
    if current:
        lines.append(current)
    return lines


def _registry_image(reference: str) -> Image:
    return Image.from_registry(reference)


async def _retry_scale_up(
    label: str,
    *,
    timeout_seconds: int,
    retry_interval_seconds: float,
    retry_client_errors: bool,
    retry_timeout_errors: bool,
    operation: Any,
) -> Any:
    timeout_seconds = max(0, int(timeout_seconds))
    retry_interval_seconds = max(0.0, float(retry_interval_seconds))
    deadline = time.monotonic() + timeout_seconds
    attempts = 0
    last_error: BaseException | None = None
    while True:
        attempts += 1
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(
                f"Timed out waiting for UCloud {label} readiness "
                f"after {timeout_seconds}s and {attempts - 1} attempt(s): {last_error}"
            ) from last_error
        try:
            return await operation(max(0.001, remaining))
        except SandboxApiError as exc:
            last_error = exc
            if not _is_retryable_gateway_error(exc):
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"Timed out waiting for UCloud {label} readiness "
                    f"after {timeout_seconds}s and {attempts} attempt(s): {exc}"
                ) from exc
            await asyncio.sleep(min(retry_interval_seconds, remaining))
        except ClientError as exc:
            if not retry_client_errors:
                raise
            last_error = exc
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"Timed out waiting for UCloud {label} readiness "
                    f"after {timeout_seconds}s and {attempts} attempt(s): {exc}"
                ) from exc
            await asyncio.sleep(min(retry_interval_seconds, remaining))
        except TimeoutError as exc:
            if not retry_timeout_errors:
                raise
            last_error = exc
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"Timed out waiting for UCloud {label} readiness "
                    f"after {timeout_seconds}s and {attempts} attempt(s): {exc}"
                ) from exc
            await asyncio.sleep(min(retry_interval_seconds, remaining))


def _is_retryable_gateway_error(exc: SandboxApiError) -> bool:
    if not isinstance(exc.body, dict):
        return False
    if exc.status_code == 503 and _is_scale_up_pending_body(exc.body):
        return True
    if exc.status_code not in {502, 503, 504}:
        return False
    message = _body_text(exc.body).lower()
    return any(
        marker in message
        for marker in (
            "job is unavailable",
            "currently unavailable",
            "node request failed",
            "temporary failure in name resolution",
            "name resolution",
            "server disconnected",
            "remote end closed",
            "upstream",
            "gateway timeout",
        )
    )


def _is_scale_up_pending_body(body: dict[str, Any]) -> bool:
    if "pending_resources" in body or "pending_image_builds" in body:
        return True
    message = str(body.get("error") or "").lower()
    return "no ready node" in message or "no ready builder" in message


def _body_text(value: object) -> str:
    if isinstance(value, dict):
        return " ".join(_body_text(item) for item in value.values())
    if isinstance(value, list):
        return " ".join(_body_text(item) for item in value)
    return str(value)


def _int_env(name: str) -> int | None:
    value = os.environ.get(name)
    return int(value) if value else None


def _float_env(name: str) -> float | None:
    value = os.environ.get(name)
    return float(value) if value else None


def _bool_env(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}
