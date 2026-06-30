from __future__ import annotations

import asyncio
from contextvars import ContextVar
from dataclasses import dataclass
import errno
from logging import getLogger
import os
from pathlib import Path, PurePosixPath
import re
import sys
import time
from typing import Any, Literal, overload
from uuid import uuid4

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

from ucloud_sandboxes_sdk import AsyncSandboxClient, AsyncSandboxHandle, SandboxApiError


DEFAULT_INSPECT_IMAGE = "python:3.12-slim"
DEFAULT_INSPECT_CPUS = 1.0
DEFAULT_INSPECT_MEMORY_MB = 2048
DEFAULT_INSPECT_DISK_MB = 10_240
DEFAULT_START_TIMEOUT_SECONDS = 1800
DEFAULT_BUILD_TIMEOUT_SECONDS = 1800
DEFAULT_RETRY_INTERVAL_SECONDS = 10.0
INSPECT_CREATED_BY = "inspect-ai"
logger = getLogger(__name__)
_running_sandboxes: ContextVar[list[tuple[str, str, dict[str, str]]]] = ContextVar(
    "ucloud_running_sandboxes",
)


@dataclass(frozen=True)
class _InspectSettings:
    base_url: str
    headers: dict[str, str]
    image: str
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
            image, command, env = await _image_command_env(
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
                {
                    "id": sandbox_id,
                    "image": image,
                    "command": command or ["sh", "-lc", "sleep 2147483647"],
                    "env": env,
                    "working_dir": "/tmp",
                    "cpus": settings.cpus,
                    "memory_mb": settings.memory_mb,
                    "disk_mb": settings.disk_mb,
                    "network": network,
                    "ttl_seconds": settings.ttl_seconds,
                    "ssh": {
                        "enabled": settings.ssh_enabled,
                        "user": settings.ssh_user,
                    },
                    "labels": labels,
                },
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


async def _image_command_env(
    client: AsyncSandboxClient,
    *,
    sandbox_id: str,
    config: SandboxEnvironmentConfigType | None,
    default_image: str,
    settings: _InspectSettings,
) -> tuple[str, list[str], dict[str, str]]:
    if config is None:
        return default_image, [], {}
    if is_dockerfile(config):
        path = Path(str(config))
        image = f"ucloud-inspect/{sandbox_id}:latest"
        await _build_image_with_wait(
            client,
            {
                "id": f"{sandbox_id}-image",
                "tag": image,
                "context_path": str(path.parent or Path(".")),
                "dockerfile": path.name,
            },
            settings=settings,
        )
        return image, [], {}
    if is_compose_yaml(config):
        return _compose_image_command_env(parse_compose_yaml(config, multiple_services=False), default_image)
    if isinstance(config, ComposeConfig):
        return _compose_image_command_env(config, default_image)
    raise ValueError(
        f"Unrecognized config: {config}. Expected a compose file, Dockerfile, "
        "ComposeConfig object, or None."
    )


def _compose_image_command_env(
    config: ComposeConfig,
    default_image: str,
) -> tuple[str, list[str], dict[str, str]]:
    services = getattr(config, "services", None)
    if not isinstance(services, dict) or not services:
        return default_image, [], {}
    service = services.get("default") or next(iter(services.values()))
    image = str(getattr(service, "image", None) or default_image)
    return image, _compose_command(getattr(service, "command", None)), _compose_env(
        getattr(service, "environment", None)
    )


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
    retry_interval = _float_env("UCLOUD_SANDBOX_RETRY_INTERVAL_SECONDS")
    return _InspectSettings(
        base_url=base_url,
        headers=headers,
        image=os.environ.get("UCLOUD_SANDBOX_IMAGE", DEFAULT_INSPECT_IMAGE),
        cpus=_float_env("UCLOUD_SANDBOX_CPUS") or DEFAULT_INSPECT_CPUS,
        memory_mb=_int_env("UCLOUD_SANDBOX_MEMORY_MB") or DEFAULT_INSPECT_MEMORY_MB,
        disk_mb=_int_env("UCLOUD_SANDBOX_DISK_MB") or DEFAULT_INSPECT_DISK_MB,
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
    payload: dict[str, Any],
    *,
    settings: _InspectSettings,
) -> AsyncSandboxHandle:
    return await _retry_scale_up(
        "sandbox node",
        timeout_seconds=settings.start_timeout_seconds,
        retry_interval_seconds=settings.retry_interval_seconds,
        operation=lambda: client.create_sandbox(payload),
    )


async def _build_image_with_wait(
    client: AsyncSandboxClient,
    payload: dict[str, Any],
    *,
    settings: _InspectSettings,
) -> dict[str, Any]:
    return await _retry_scale_up(
        "builder node",
        timeout_seconds=settings.build_timeout_seconds,
        retry_interval_seconds=settings.retry_interval_seconds,
        operation=lambda: client.build_image(payload),
    )


async def _retry_scale_up(
    label: str,
    *,
    timeout_seconds: int,
    retry_interval_seconds: float,
    operation: Any,
) -> Any:
    timeout_seconds = max(0, int(timeout_seconds))
    retry_interval_seconds = max(0.0, float(retry_interval_seconds))
    deadline = time.monotonic() + timeout_seconds
    attempts = 0
    while True:
        attempts += 1
        try:
            return await operation()
        except SandboxApiError as exc:
            if not _is_retryable_gateway_error(exc):
                raise
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
