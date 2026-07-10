from __future__ import annotations

import asyncio
import base64
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
import gzip
import hashlib
import json
from pathlib import Path
import shlex
import tarfile
import tempfile
import time
from typing import Any, AsyncIterator, BinaryIO, Callable, Iterator, Mapping, Sequence
from urllib import error, parse, request
from uuid import uuid4
import warnings

from ._http import (
    ResponseTooLargeError,
    open_no_redirect,
    read_async_response,
    read_sync_response,
    response_headers,
)


JsonObject = dict[str, Any]
TERMINAL_EXEC_STATUSES = {"exited", "failed"}
SANDBOX_TOKEN_HEADER = "X-UCloud-Sandbox-Token"
UCLOUD_UNAVAILABLE_STATUS = 503
UCLOUD_UNAVAILABLE_RETRY_ATTEMPTS = 6
UCLOUD_UNAVAILABLE_RETRY_BASE_DELAY_SECONDS = 0.25
UCLOUD_UNAVAILABLE_RETRY_MAX_DELAY_SECONDS = 4.0
MAX_JSON_BODY_BYTES = 16 * 1024 * 1024
MAX_FILE_BODY_BYTES = 256 * 1024 * 1024
MAX_JSON_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_FILE_RESPONSE_BYTES = 256 * 1024 * 1024
BUILD_CONTEXT_SPOOL_MEMORY_BYTES = 8 * 1024 * 1024
BUILD_CONTEXT_BASE64_CHUNK_BYTES = 3 * 1024 * 1024
BUILD_CONTEXT_STREAM_CHUNK_BYTES = 1024 * 1024
DEFAULT_SCALE_UP_TIMEOUT_SECONDS = 1800.0
DEFAULT_SCALE_UP_RETRY_INTERVAL_SECONDS = 1.0


class SandboxApiError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        body: object | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body
        self.headers = dict(headers or {})


class ExecEventHistoryLostError(SandboxApiError):
    def __init__(
        self,
        session_id: str,
        *,
        expected_sequence: int,
        received_sequence: int,
    ) -> None:
        super().__init__(
            f"exec event history was truncated for {session_id}: expected sequence "
            f"{expected_sequence}, received {received_sequence}",
            body={
                "session_id": session_id,
                "expected_sequence": expected_sequence,
                "received_sequence": received_sequence,
            },
        )
        self.session_id = session_id
        self.expected_sequence = expected_sequence
        self.received_sequence = received_sequence


def sandbox_auth_headers(api_token: str | None) -> dict[str, str]:
    token = (api_token or "").strip()
    return {SANDBOX_TOKEN_HEADER: token} if token else {}


@dataclass(frozen=True)
class SandboxSecuritySpec:
    user: str | None = "1000:1000"
    cap_drop: tuple[str, ...] = ("ALL",)
    cap_add: tuple[str, ...] = ()
    no_new_privileges: bool = True
    pids_limit: int | None = 256
    read_only_rootfs: bool = False
    init: bool = True

    def to_dict(self) -> JsonObject:
        raw = asdict(self)
        raw["cap_drop"] = list(self.cap_drop)
        raw["cap_add"] = list(self.cap_add)
        return raw


@dataclass(frozen=True)
class SandboxFilesystemSpec:
    enforce_disk_quota: bool = False
    workspace_path: str = "/workspace"
    tmpfs_mb: int = 64
    run_tmpfs_mb: int = 16

    def to_dict(self) -> JsonObject:
        return asdict(self)


@dataclass(frozen=True)
class SandboxSshSpec:
    enabled: bool = False
    user: str = "root"
    host: str = "127.0.0.1"
    host_port: int | None = None
    container_port: int = 22
    authorized_keys: tuple[str, ...] = ()

    def to_dict(self) -> JsonObject:
        raw = asdict(self)
        raw["authorized_keys"] = list(self.authorized_keys)
        return raw


@dataclass(frozen=True)
class SandboxSshTarget:
    sandbox_id: str
    user: str
    host: str
    port: int
    command: str
    raw: JsonObject = field(default_factory=dict)

    @classmethod
    def from_payload(cls, sandbox_id: str, payload: JsonObject) -> "SandboxSshTarget":
        ssh = payload.get("ssh")
        if not isinstance(ssh, dict):
            raise SandboxApiError("gateway returned an invalid SSH payload", body=payload)
        host = ssh.get("host")
        port = ssh.get("port")
        user = ssh.get("user") or "root"
        if not isinstance(host, str) or not isinstance(port, int):
            raise SandboxApiError("gateway SSH payload is missing host/port", body=payload)
        return cls(
            sandbox_id=str(payload.get("sandboxId") or sandbox_id),
            user=str(user),
            host=host,
            port=port,
            command=str(ssh.get("command") or f"ssh -p {port} {user}@{host}"),
            raw=dict(payload),
        )

    def direct_argv(self) -> list[str]:
        return ["ssh", "-p", str(self.port), f"{self.user}@{self.host}"]


@dataclass(frozen=True)
class SandboxSpec:
    id: str
    image: "Image"
    command: Sequence[str] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    working_dir: str | None = None
    memory_mb: int | None = None
    cpus: float | None = None
    disk_mb: int | None = None
    network: str = "none"
    ttl_seconds: int | None = None
    ssh: SandboxSshSpec | Mapping[str, Any] | bool = SandboxSshSpec()
    security: SandboxSecuritySpec | Mapping[str, Any] | None = SandboxSecuritySpec()
    filesystem: SandboxFilesystemSpec | Mapping[str, Any] | None = SandboxFilesystemSpec()
    labels: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> JsonObject:
        return {
            "id": self.id,
            "image": _image_reference(self.image),
            "command": [str(item) for item in self.command],
            "env": dict(self.env),
            "working_dir": self.working_dir,
            "memory_mb": self.memory_mb,
            "cpus": self.cpus,
            "disk_mb": self.disk_mb,
            "network": self.network,
            "ttl_seconds": self.ttl_seconds,
            "ssh": _nested_payload(self.ssh),
            "security": _nested_payload(self.security),
            "filesystem": _nested_payload(self.filesystem),
            "labels": dict(self.labels),
        }


@dataclass(frozen=True)
class _ImageBuildSpec:
    id: str
    tag: str
    context_path: str
    dockerfile: str = "Dockerfile"
    push: bool = False
    build_args: Mapping[str, str] = field(default_factory=dict)
    labels: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> JsonObject:
        return {
            "id": self.id,
            "tag": self.tag,
            "context_path": self.context_path,
            "dockerfile": self.dockerfile,
            "push": self.push,
            "build_args": dict(self.build_args),
            "labels": dict(self.labels),
        }


@dataclass(frozen=True)
class Image:
    reference: str
    name: str | None = None
    tag: str | None = None
    build_spec: _ImageBuildSpec | None = None

    @classmethod
    def from_registry(cls, tag: str) -> "Image":
        tag = _non_empty_string("tag", tag)
        return cls(reference=tag, tag=tag)

    @classmethod
    def from_name(cls, name: str) -> "Image":
        name = _non_empty_string("name", name)
        return cls(reference=name, name=name)

    @classmethod
    def from_id(cls, image_id: str) -> "Image":
        return cls.from_name(image_id)

    @classmethod
    def from_dockerfile(
        cls,
        *,
        name: str,
        tag: str,
        context_path: str | Path,
        dockerfile: str = "Dockerfile",
        push: bool = True,
        build_args: Mapping[str, str] | None = None,
        labels: Mapping[str, str] | None = None,
    ) -> "Image":
        name = _non_empty_string("name", name)
        tag = _non_empty_string("tag", tag)
        build_spec = _ImageBuildSpec(
            id=name,
            tag=tag,
            context_path=str(context_path),
            dockerfile=dockerfile,
            push=push,
            build_args=dict(build_args or {}),
            labels=dict(labels or {}),
        )
        return cls(reference=name, name=name, tag=tag, build_spec=build_spec)

    def to_build_spec(self) -> _ImageBuildSpec:
        if self.build_spec is None:
            raise TypeError(
                "image does not include build metadata; use Image.from_dockerfile() "
                "before calling build_image()"
            )
        return self.build_spec

    def to_sandbox_image(self) -> str:
        return self.reference

    def to_dict(self) -> JsonObject:
        payload: JsonObject = {"reference": self.reference}
        if self.name is not None:
            payload["name"] = self.name
        if self.tag is not None:
            payload["tag"] = self.tag
        if self.build_spec is not None:
            payload["build"] = self.build_spec.to_dict()
        return payload


@dataclass(frozen=True)
class SandboxExecResult:
    session_id: str
    status: str
    exit_code: int | None
    stdout: str
    stderr: str
    events: tuple[JsonObject, ...]
    session: JsonObject

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and self.status == "exited"


@dataclass
class SandboxHandle:
    client: "SandboxClient"
    id: str
    record: JsonObject = field(default_factory=dict)
    create_response: JsonObject = field(default_factory=dict)

    def refresh(self) -> "SandboxHandle":
        record = self.client.get_sandbox(self.id)
        if record is not None:
            self.record = record
        return self

    def delete(self) -> JsonObject:
        return self.client.delete_sandbox(self.id)

    def start_exec(
        self,
        command: str | Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        working_dir: str | None = None,
        stdin: bool = False,
        tty: bool = False,
    ) -> "ExecHandle":
        return self.client.start_exec(
            self.id,
            command,
            env=env,
            working_dir=working_dir,
            stdin=stdin,
            tty=tty,
        )

    def exec(
        self,
        command: str | Sequence[str],
        *,
        input: str | bytes | None = None,
        env: Mapping[str, str] | None = None,
        working_dir: str | None = None,
        timeout_seconds: float | None = None,
        tty: bool = False,
    ) -> SandboxExecResult:
        return self.client.exec(
            self.id,
            command,
            input=input,
            env=env,
            working_dir=working_dir,
            timeout_seconds=timeout_seconds,
            tty=tty,
        )

    def ssh(self) -> JsonObject:
        return self.client.get_ssh_target(self.id)

    def ssh_target(self) -> SandboxSshTarget:
        return self.client.get_ssh_connection(self.id)

    def ssh_command(self) -> str:
        return self.ssh_target().command

    def ssh_proxy_command(
        self,
        *,
        token_env: str = "UCLOUD_SANDBOX_API_TOKEN",
        python: str = "python3",
    ) -> str:
        return self.client.ssh_proxy_command(
            self.id,
            token_env=token_env,
            python=python,
        )

    def upload_file(self, container_path: str, content: bytes | str) -> JsonObject:
        return self.client.upload_file(self.id, container_path, content)

    def upload_file_from_path(
        self,
        local_path: str | Path,
        container_path: str,
    ) -> JsonObject:
        return self.client.upload_file_from_path(self.id, local_path, container_path)

    def download_file(self, container_path: str) -> bytes:
        return self.client.download_file(self.id, container_path)

    def download_file_to_path(
        self,
        container_path: str,
        local_path: str | Path,
    ) -> Path:
        return self.client.download_file_to_path(self.id, container_path, local_path)

    def snapshot(self, image: Image, *, image_id: str | None = None) -> JsonObject:
        return self.client.snapshot_sandbox(self.id, image, image_id=image_id)


@dataclass
class ExecHandle:
    client: "SandboxClient"
    session_id: str
    sandbox_id: str
    session: JsonObject = field(default_factory=dict)
    last_sequence: int = 0

    def get(self) -> JsonObject:
        payload = self.client.get_exec_session(self.session_id)
        session = payload.get("session")
        if isinstance(session, dict):
            self.session = session
        return payload

    def write_stdin(self, data: str | bytes, *, eof: bool = False) -> JsonObject:
        return self.client.write_exec_stdin(self.session_id, _text_payload(data), eof=eof)

    def close_stdin(self) -> JsonObject:
        return self.client.close_exec_stdin(self.session_id)

    def events(
        self,
        *,
        wait_seconds: float = 30.0,
        limit: int = 100,
    ) -> Iterator[JsonObject]:
        while True:
            payload = self.client.read_exec_events(
                self.session_id,
                after=self.last_sequence,
                limit=limit,
                wait_seconds=wait_seconds,
            )
            raw_events = payload.get("events")
            events = _exec_event_payloads(self.session_id, raw_events)
            for event in events:
                self.last_sequence = _next_exec_sequence(
                    self.session_id,
                    self.last_sequence,
                    event,
                )
                yield event
            session = payload.get("session")
            if isinstance(session, dict):
                self.session = session
                if session.get("status") in TERMINAL_EXEC_STATUSES and not events:
                    return

    def wait(
        self,
        *,
        timeout_seconds: float | None = None,
        poll_wait_seconds: float = 1.0,
        settle_seconds: float = 0.2,
    ) -> SandboxExecResult:
        events: list[JsonObject] = []
        deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds
        terminal_seen = False
        empty_terminal_drains = 0

        while True:
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError(f"exec session timed out: {self.session_id}")
            wait_seconds = settle_seconds if terminal_seen else poll_wait_seconds
            if deadline is not None:
                wait_seconds = min(wait_seconds, max(0.0, deadline - time.monotonic()))
            payload = self.client.read_exec_events(
                self.session_id,
                after=self.last_sequence,
                limit=100,
                wait_seconds=wait_seconds,
            )
            raw_events = payload.get("events")
            new_events = _exec_event_payloads(self.session_id, raw_events)
            for event in new_events:
                self.last_sequence = _next_exec_sequence(
                    self.session_id,
                    self.last_sequence,
                    event,
                )
                events.append(event)
            session = payload.get("session")
            if isinstance(session, dict):
                self.session = session
            if self.session.get("status") in TERMINAL_EXEC_STATUSES:
                terminal_seen = True
                if new_events:
                    empty_terminal_drains = 0
                else:
                    empty_terminal_drains += 1
                    if empty_terminal_drains >= 1:
                        return _exec_result(self.session_id, self.session, events)


class SandboxClient:
    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 30.0,
        api_token: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.headers = sandbox_auth_headers(api_token)
        self.headers.update(dict(headers or {}))

    def health(self) -> JsonObject:
        return self._request_json("GET", "/healthz")

    def list_nodes(self) -> list[JsonObject]:
        payload = self._request_json("GET", "/v1/nodes")
        nodes = payload.get("nodes")
        return [dict(item) for item in nodes if isinstance(item, dict)] if isinstance(nodes, list) else []

    def heartbeat(self) -> JsonObject:
        warnings.warn(
            "SandboxClient.heartbeat() targets the internal node-agent API and is "
            "deprecated; use the public gateway and list_nodes() instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._request_json("GET", "/v1/heartbeat")

    def list_sandboxes(self) -> list[JsonObject]:
        payload = self._request_json("GET", "/v1/sandboxes")
        sandboxes = payload.get("sandboxes")
        return [item for item in sandboxes if isinstance(item, dict)] if isinstance(sandboxes, list) else []

    def list_prepared_capacity(self) -> JsonObject:
        return self._request_json("GET", "/v1/capacity/prepare")

    def prepare_capacity(
        self,
        *,
        count: int,
        cpus: float | None = None,
        memory_mb: int | None = None,
        disk_mb: int | None = None,
        resources: Mapping[str, Any] | None = None,
        image: Image | None = None,
        ttl_seconds: int = 900,
        prepare_id: str | None = None,
    ) -> JsonObject:
        return self._request_json(
            "POST",
            "/v1/capacity/prepare",
            payload=_prepare_capacity_payload(
                count=count,
                cpus=cpus,
                memory_mb=memory_mb,
                disk_mb=disk_mb,
                resources=resources,
                image=image,
                ttl_seconds=ttl_seconds,
                prepare_id=prepare_id,
            ),
        )

    def delete_prepared_capacity(self, prepare_id: str) -> JsonObject:
        return self._request_json(
            "DELETE",
            f"/v1/capacity/prepare/{_quote_segment(prepare_id)}",
        )

    def list_prepared_builders(self) -> JsonObject:
        return self._request_json("GET", "/v1/builders/prepare")

    def prepare_builder(
        self,
        *,
        count: int = 1,
        ttl_seconds: int = 900,
        prepare_id: str | None = None,
    ) -> JsonObject:
        return self._request_json(
            "POST",
            "/v1/builders/prepare",
            payload=_prepare_builder_payload(
                count=count,
                ttl_seconds=ttl_seconds,
                prepare_id=prepare_id,
            ),
        )

    def delete_prepared_builder(self, prepare_id: str) -> JsonObject:
        return self._request_json(
            "DELETE",
            f"/v1/builders/prepare/{_quote_segment(prepare_id)}",
        )

    def get_sandbox(self, sandbox_id: str) -> JsonObject | None:
        for record in self.list_sandboxes():
            spec = record.get("spec")
            if isinstance(spec, dict) and spec.get("id") == sandbox_id:
                return record
        return None

    def create_sandbox(
        self,
        spec: SandboxSpec | None = None,
        *,
        request_timeout_seconds: float | None = None,
        start_timeout_seconds: float = DEFAULT_SCALE_UP_TIMEOUT_SECONDS,
        retry_interval_seconds: float = DEFAULT_SCALE_UP_RETRY_INTERVAL_SECONDS,
        **kwargs: Any,
    ) -> SandboxHandle:
        payload = _sandbox_payload(spec, **kwargs)
        if not str(payload.get("id") or "").strip():
            payload["id"] = f"sdk-{uuid4().hex}"
        response = self._request_json_with_scale_up_wait(
            "/v1/sandboxes",
            payload,
            timeout_seconds=start_timeout_seconds,
            request_timeout_seconds=request_timeout_seconds,
            retry_interval_seconds=retry_interval_seconds,
        )
        record = response.get("sandbox")
        if not isinstance(record, dict):
            raise SandboxApiError("gateway returned an invalid sandbox payload", body=response)
        sandbox_spec = record.get("spec")
        sandbox_id = sandbox_spec.get("id") if isinstance(sandbox_spec, dict) else None
        if not isinstance(sandbox_id, str) or not sandbox_id:
            raise SandboxApiError("gateway sandbox payload is missing spec.id", body=response)
        return SandboxHandle(self, sandbox_id, record=record, create_response=response)

    def _request_json_with_scale_up_wait(
        self,
        path: str,
        payload: JsonObject,
        *,
        timeout_seconds: float,
        request_timeout_seconds: float | None,
        retry_interval_seconds: float,
    ) -> JsonObject:
        deadline = _deadline(max(0.0, timeout_seconds))
        last_error: SandboxApiError | None = None
        attempts = 0
        while True:
            remaining = _remaining_seconds(deadline)
            if attempts > 0 and remaining is not None and remaining <= 0:
                raise TimeoutError(_scale_up_timeout_message(path, last_error)) from last_error
            attempts += 1
            try:
                return self._request_json(
                    "POST",
                    path,
                    payload=payload,
                    timeout_seconds=_request_timeout_seconds(
                        remaining,
                        self.timeout_seconds
                        if request_timeout_seconds is None
                        else request_timeout_seconds,
                    ),
                )
            except SandboxApiError as exc:
                if not _is_retryable_scale_up_error(exc):
                    raise
                last_error = exc
                _sleep_for_scale_up_retry(
                    exc,
                    fallback_seconds=retry_interval_seconds,
                    deadline=deadline,
                )

    def create_ssh_sandbox(
        self,
        *,
        ssh_user: str = "sandbox",
        authorized_keys: Sequence[str] = (),
        **kwargs: Any,
    ) -> SandboxHandle:
        kwargs.setdefault("network", "bridge")
        kwargs["ssh"] = {
            "enabled": True,
            "user": ssh_user,
            "authorized_keys": list(authorized_keys),
        }
        return self.create_sandbox(**kwargs)

    def delete_sandbox(self, sandbox_id: str) -> JsonObject:
        return self._request_json("DELETE", f"/v1/sandboxes/{_quote_segment(sandbox_id)}")

    def upload_file(
        self,
        sandbox_id: str,
        container_path: str,
        content: bytes | str,
    ) -> JsonObject:
        return self._request_json(
            "PUT",
            _file_path(sandbox_id, container_path),
            body=_bytes_payload(content),
            content_type="application/octet-stream",
        )

    def upload_file_from_path(
        self,
        sandbox_id: str,
        local_path: str | Path,
        container_path: str,
    ) -> JsonObject:
        return self.upload_file(
            sandbox_id,
            container_path,
            _read_file_bytes(Path(local_path), limit=MAX_FILE_BODY_BYTES),
        )

    def download_file(self, sandbox_id: str, container_path: str) -> bytes:
        return self._request_bytes("GET", _file_path(sandbox_id, container_path))

    def download_file_to_path(
        self,
        sandbox_id: str,
        container_path: str,
        local_path: str | Path,
    ) -> Path:
        path = Path(local_path)
        path.write_bytes(self.download_file(sandbox_id, container_path))
        return path

    def start_exec(
        self,
        sandbox_id: str,
        command: str | Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        working_dir: str | None = None,
        stdin: bool = False,
        tty: bool = False,
    ) -> ExecHandle:
        payload = _exec_payload(
            command,
            env=env,
            working_dir=working_dir,
            stdin=stdin,
            tty=tty,
        )
        response = self._request_json(
            "POST",
            f"/v1/sandboxes/{_quote_segment(sandbox_id)}/exec",
            payload=payload,
        )
        session = response.get("session")
        if not isinstance(session, dict) or not isinstance(session.get("id"), str):
            raise SandboxApiError("gateway returned an invalid exec session payload", body=response)
        return ExecHandle(self, session["id"], sandbox_id, session=session)

    def exec(
        self,
        sandbox_id: str,
        command: str | Sequence[str],
        *,
        input: str | bytes | None = None,
        env: Mapping[str, str] | None = None,
        working_dir: str | None = None,
        timeout_seconds: float | None = None,
        tty: bool = False,
    ) -> SandboxExecResult:
        handle = self.start_exec(
            sandbox_id,
            command,
            env=env,
            working_dir=working_dir,
            stdin=input is not None,
            tty=tty,
        )
        if input is not None:
            handle.write_stdin(input, eof=True)
        return handle.wait(timeout_seconds=timeout_seconds)

    def get_exec_session(self, session_id: str) -> JsonObject:
        return self._request_json("GET", f"/v1/exec/{_quote_segment(session_id)}")

    def read_exec_events(
        self,
        session_id: str,
        *,
        after: int = 0,
        limit: int = 100,
        wait_seconds: float = 0.0,
    ) -> JsonObject:
        query = parse.urlencode(
            {
                "after": max(0, after),
                "limit": max(1, limit),
                "wait_seconds": max(0.0, wait_seconds),
            }
        )
        return self._request_json("GET", f"/v1/exec/{_quote_segment(session_id)}/events?{query}")

    def write_exec_stdin(
        self,
        session_id: str,
        data: str,
        *,
        eof: bool = False,
    ) -> JsonObject:
        return self._request_json(
            "POST",
            f"/v1/exec/{_quote_segment(session_id)}/stdin",
            payload={"data": data, "eof": eof},
        )

    def close_exec_stdin(self, session_id: str) -> JsonObject:
        return self._request_json("POST", f"/v1/exec/{_quote_segment(session_id)}/close-stdin")

    def get_ssh_target(self, sandbox_id: str) -> JsonObject:
        return self._request_json("GET", f"/v1/sandboxes/{_quote_segment(sandbox_id)}/ssh")

    def get_ssh_connection(self, sandbox_id: str) -> SandboxSshTarget:
        return SandboxSshTarget.from_payload(sandbox_id, self.get_ssh_target(sandbox_id))

    def ssh_proxy_argv(
        self,
        sandbox_id: str,
        *,
        token_env: str = "UCLOUD_SANDBOX_API_TOKEN",
        python: str = "python3",
    ) -> list[str]:
        return [
            python,
            "-m",
            "ucloud_sandboxes_sdk.ssh_proxy",
            "--gateway-url",
            self.base_url,
            "--sandbox-id",
            sandbox_id,
            "--token-env",
            token_env,
        ]

    def ssh_proxy_command(
        self,
        sandbox_id: str,
        *,
        token_env: str = "UCLOUD_SANDBOX_API_TOKEN",
        python: str = "python3",
    ) -> str:
        proxy = " ".join(
            shlex.quote(part)
            for part in self.ssh_proxy_argv(
                sandbox_id,
                token_env=token_env,
                python=python,
            )
        )
        return f"ssh -o ProxyCommand={shlex.quote(proxy)} sandbox@{sandbox_id}"

    def list_images(self) -> list[JsonObject]:
        payload = self._request_json("GET", "/v1/images")
        images = payload.get("images")
        return [item for item in images if isinstance(item, dict)] if isinstance(images, list) else []

    def list_image_builds(self) -> list[JsonObject]:
        payload = self._request_json("GET", "/v1/images/builds")
        builds = payload.get("builds")
        return [item for item in builds if isinstance(item, dict)] if isinstance(builds, list) else []

    def get_image_build(
        self,
        build_id_or_image_id: str,
        *,
        timeout_seconds: float | None = None,
    ) -> JsonObject:
        payload = self._request_json(
            "GET",
            f"/v1/images/builds/{_quote_segment(build_id_or_image_id)}",
            timeout_seconds=timeout_seconds,
        )
        build = payload.get("build")
        if not isinstance(build, dict):
            raise SandboxApiError("gateway returned an invalid image build payload", body=payload)
        return build

    def submit_image_build(
        self,
        image: Image,
        *,
        upload_context: bool = True,
        timeout_seconds: float | None = None,
    ) -> JsonObject:
        effective_timeout = (
            self.timeout_seconds if timeout_seconds is None else timeout_seconds
        )
        deadline = _deadline(effective_timeout)
        payload = self._prepare_image_build_payload(
            image,
            upload_context=upload_context,
            deadline=deadline,
        )
        submitted = self._request_json(
            "POST",
            "/v1/images/build",
            payload=payload,
            timeout_seconds=_remaining_seconds(deadline),
        )
        return _submitted_build_record(submitted)

    def _prepare_image_build_payload(
        self,
        image: Image,
        *,
        upload_context: bool,
        deadline: float | None,
    ) -> JsonObject:
        payload = _image_build_payload(image, upload_context=False)
        context_path = _local_build_context_path(payload) if upload_context else None
        if context_path is not None:
            with _tar_gz_directory(context_path) as archive:
                digest, size = _build_context_archive_identity(archive)
                context_path_url = f"/v1/image-contexts/{digest}"
                try:
                    existing = self._request_json(
                        "GET",
                        context_path_url,
                        timeout_seconds=_remaining_seconds(deadline),
                    )
                except SandboxApiError as exc:
                    if exc.status_code not in {404, 405}:
                        raise
                    existing = None

                use_context_reference = _build_context_reference_matches(
                    existing,
                    digest=digest,
                    size=size,
                )
                if not use_context_reference:
                    try:
                        self._request_json(
                            "PUT",
                            context_path_url,
                            body=archive,
                            body_size=size,
                            content_type="application/gzip",
                            timeout_seconds=_remaining_seconds(deadline),
                        )
                    except SandboxApiError as exc:
                        if exc.status_code not in {404, 405}:
                            raise
                        _attach_legacy_build_context_archive(payload, archive)
                    else:
                        use_context_reference = True
                if use_context_reference:
                    _attach_build_context_reference(
                        payload,
                        digest=digest,
                        size=size,
                    )
        payload["wait"] = False
        return payload

    def wait_for_image_build(
        self,
        build_id_or_image_id: str,
        *,
        timeout_seconds: float | None = None,
        poll_interval_seconds: float = 5.0,
        on_status: Callable[[JsonObject], object] | None = None,
    ) -> JsonObject:
        deadline = _deadline(timeout_seconds)
        last_seen: tuple[object, object, object] | None = None
        build: JsonObject | None = None
        while True:
            remaining = _remaining_seconds(deadline)
            if remaining is not None and remaining <= 0:
                raise TimeoutError(_image_build_timeout_message(build_id_or_image_id, build))
            build = self.get_image_build(
                build_id_or_image_id,
                timeout_seconds=_request_timeout_seconds(
                    remaining,
                    self.timeout_seconds,
                ),
            )
            seen = (
                build.get("status"),
                build.get("updated_at"),
                len(str(build.get("log_tail") or "")),
            )
            if on_status is not None and seen != last_seen:
                on_status(build)
            last_seen = seen
            if build.get("status") in {"succeeded", "failed"}:
                return build
            sleep_seconds = max(0.1, poll_interval_seconds)
            remaining = _remaining_seconds(deadline)
            if remaining is not None:
                if remaining <= 0:
                    raise TimeoutError(_image_build_timeout_message(build_id_or_image_id, build))
                sleep_seconds = min(sleep_seconds, remaining)
            time.sleep(sleep_seconds)

    def build_image(
        self,
        image: Image,
        *,
        upload_context: bool = True,
        timeout_seconds: float | None = DEFAULT_SCALE_UP_TIMEOUT_SECONDS,
        poll_interval_seconds: float = 5.0,
        retry_interval_seconds: float = DEFAULT_SCALE_UP_RETRY_INTERVAL_SECONDS,
        on_status: Callable[[JsonObject], object] | None = None,
    ) -> JsonObject:
        effective_timeout = (
            DEFAULT_SCALE_UP_TIMEOUT_SECONDS
            if timeout_seconds is None
            else max(0.0, timeout_seconds)
        )
        deadline = _deadline(effective_timeout)
        payload = self._prepare_image_build_payload(
            image,
            upload_context=upload_context,
            deadline=deadline,
        )
        submitted = _submitted_build_record(
            self._request_json_with_scale_up_wait(
                "/v1/images/build",
                payload,
                timeout_seconds=max(0.0, _remaining_seconds(deadline) or 0.0),
                request_timeout_seconds=effective_timeout,
                retry_interval_seconds=retry_interval_seconds,
            )
        )
        build = self.wait_for_image_build(
            str(submitted.get("build_id") or submitted.get("image_id") or ""),
            timeout_seconds=_remaining_seconds(deadline),
            poll_interval_seconds=poll_interval_seconds,
            on_status=on_status,
        )
        if build.get("status") != "succeeded":
            raise SandboxApiError(
                f"image build failed: {build.get('error') or build.get('status')}",
                body={"build": build},
            )
        return _completed_build_payload(build)

    def pull_image(
        self,
        image: Image,
        *,
        image_id: str | None = None,
        count: int = 1,
        cpus: float | None = None,
        memory_mb: int | None = None,
        disk_mb: int | None = None,
        resources: Mapping[str, Any] | None = None,
        sandbox_nodes_only: bool = True,
    ) -> JsonObject:
        payload = _image_pull_payload(
            image,
            image_id=image_id,
            count=count,
            cpus=cpus,
            memory_mb=memory_mb,
            disk_mb=disk_mb,
            resources=resources,
            sandbox_nodes_only=sandbox_nodes_only,
        )
        return self._request_json("POST", "/v1/images/pull", payload=payload)

    def snapshot_sandbox(
        self,
        sandbox_id: str,
        image: Image,
        *,
        image_id: str | None = None,
    ) -> JsonObject:
        payload: JsonObject = {"image": _image_pull_reference(image)}
        if image_id is not None:
            payload["id"] = image_id
        return self._request_json(
            "POST",
            f"/v1/sandboxes/{_quote_segment(sandbox_id)}/snapshot",
            payload=payload,
        )

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        payload: JsonObject | None = None,
        body: bytes | BinaryIO | None = None,
        body_size: int | None = None,
        content_type: str | None = None,
        timeout_seconds: float | None = None,
    ) -> JsonObject:
        raw_body = json.dumps(payload).encode("utf-8") if payload is not None else body
        body_limit = MAX_JSON_BODY_BYTES if payload is not None else MAX_FILE_BODY_BYTES
        known_body_size = (
            len(raw_body)
            if isinstance(raw_body, bytes)
            else body_size
        )
        if raw_body is not None and known_body_size is None:
            raise TypeError("body_size is required for streamed request bodies")
        if known_body_size is not None and known_body_size > body_limit:
            raise SandboxApiError(f"request body exceeds the {body_limit} byte limit")
        headers = dict(self.headers)
        if payload is not None:
            headers["Content-Type"] = "application/json"
        elif content_type is not None:
            headers["Content-Type"] = content_type
        if raw_body is not None and not isinstance(raw_body, bytes):
            headers["Content-Length"] = str(known_body_size)
        timeout = self.timeout_seconds if timeout_seconds is None else timeout_seconds
        deadline = _deadline(timeout)
        for attempt in range(UCLOUD_UNAVAILABLE_RETRY_ATTEMPTS):
            if raw_body is not None and not isinstance(raw_body, bytes):
                raw_body.seek(0)
            req = request.Request(
                self.base_url + path,
                data=raw_body,
                method=method,
                headers=headers,
            )
            try:
                with open_no_redirect(
                    req,
                    timeout=_request_timeout_seconds(
                        _remaining_seconds(deadline),
                        timeout,
                    ),
                ) as response:
                    raw = read_sync_response(
                        response,
                        limit=MAX_JSON_RESPONSE_BYTES,
                    ).decode("utf-8")
                    try:
                        decoded = json.loads(raw) if raw else {}
                    except json.JSONDecodeError as exc:
                        raise SandboxApiError(
                            f"gateway returned invalid JSON: {exc}",
                            status_code=int(getattr(response, "status", 200)),
                            body={"error": raw},
                            headers=response_headers(response),
                        ) from exc
            except error.HTTPError as exc:
                try:
                    raw = read_sync_response(
                        exc,
                        limit=MAX_JSON_RESPONSE_BYTES,
                    ).decode("utf-8", errors="replace")
                except ResponseTooLargeError as size_exc:
                    api_error = SandboxApiError(
                        str(size_exc),
                        status_code=exc.code,
                        headers=response_headers(exc),
                    )
                    exc.close()
                    raise api_error from size_exc
                decoded = _decode_json_error(raw)
                api_error = SandboxApiError(
                    f"gateway request failed ({exc.code}): {decoded}",
                    status_code=exc.code,
                    body=decoded,
                    headers=response_headers(exc),
                )
                exc.close()
                if _should_retry_ucloud_unavailable(exc.code, decoded, attempt):
                    if _sleep_for_retry(
                        _ucloud_unavailable_retry_delay(attempt),
                        deadline,
                    ):
                        continue
                raise api_error from exc
            except (OSError, ResponseTooLargeError) as exc:
                raise SandboxApiError(f"gateway request failed: {exc}") from exc
            if not isinstance(decoded, dict):
                raise SandboxApiError(
                    "gateway returned a non-object JSON payload",
                    body=decoded,
                )
            return decoded
        raise AssertionError("unreachable UCloud unavailable retry state")

    def _request_bytes(self, method: str, path: str) -> bytes:
        deadline = _deadline(self.timeout_seconds)
        for attempt in range(UCLOUD_UNAVAILABLE_RETRY_ATTEMPTS):
            req = request.Request(
                self.base_url + path,
                method=method,
                headers=dict(self.headers),
            )
            try:
                with open_no_redirect(
                    req,
                    timeout=_request_timeout_seconds(
                        _remaining_seconds(deadline),
                        self.timeout_seconds,
                    ),
                ) as response:
                    return read_sync_response(
                        response,
                        limit=MAX_FILE_RESPONSE_BYTES,
                    )
            except error.HTTPError as exc:
                try:
                    raw = read_sync_response(
                        exc,
                        limit=MAX_JSON_RESPONSE_BYTES,
                    ).decode("utf-8", errors="replace")
                except ResponseTooLargeError as size_exc:
                    api_error = SandboxApiError(
                        str(size_exc),
                        status_code=exc.code,
                        headers=response_headers(exc),
                    )
                    exc.close()
                    raise api_error from size_exc
                decoded = _decode_json_error(raw)
                api_error = SandboxApiError(
                    f"gateway request failed ({exc.code}): {decoded}",
                    status_code=exc.code,
                    body=decoded,
                    headers=response_headers(exc),
                )
                exc.close()
                if _should_retry_ucloud_unavailable(exc.code, decoded, attempt):
                    if _sleep_for_retry(
                        _ucloud_unavailable_retry_delay(attempt),
                        deadline,
                    ):
                        continue
                raise api_error from exc
            except (OSError, ResponseTooLargeError) as exc:
                raise SandboxApiError(f"gateway request failed: {exc}") from exc
        raise AssertionError("unreachable UCloud unavailable retry state")


@dataclass
class AsyncSandboxHandle:
    client: "AsyncSandboxClient"
    id: str
    record: JsonObject = field(default_factory=dict)
    create_response: JsonObject = field(default_factory=dict)

    async def refresh(self) -> "AsyncSandboxHandle":
        record = await self.client.get_sandbox(self.id)
        if record is not None:
            self.record = record
        return self

    async def delete(self) -> JsonObject:
        return await self.client.delete_sandbox(self.id)

    async def start_exec(
        self,
        command: str | Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        working_dir: str | None = None,
        stdin: bool = False,
        tty: bool = False,
    ) -> "AsyncExecHandle":
        return await self.client.start_exec(
            self.id,
            command,
            env=env,
            working_dir=working_dir,
            stdin=stdin,
            tty=tty,
        )

    async def exec(
        self,
        command: str | Sequence[str],
        *,
        input: str | bytes | None = None,
        env: Mapping[str, str] | None = None,
        working_dir: str | None = None,
        timeout_seconds: float | None = None,
        tty: bool = False,
    ) -> SandboxExecResult:
        return await self.client.exec(
            self.id,
            command,
            input=input,
            env=env,
            working_dir=working_dir,
            timeout_seconds=timeout_seconds,
            tty=tty,
        )

    async def ssh(self) -> JsonObject:
        return await self.client.get_ssh_target(self.id)

    async def ssh_target(self) -> SandboxSshTarget:
        return await self.client.get_ssh_connection(self.id)

    async def ssh_command(self) -> str:
        return (await self.ssh_target()).command

    def ssh_proxy_command(
        self,
        *,
        token_env: str = "UCLOUD_SANDBOX_API_TOKEN",
        python: str = "python3",
    ) -> str:
        return self.client.ssh_proxy_command(
            self.id,
            token_env=token_env,
            python=python,
        )

    async def upload_file(self, container_path: str, content: bytes | str) -> JsonObject:
        return await self.client.upload_file(self.id, container_path, content)

    async def upload_file_from_path(
        self,
        local_path: str | Path,
        container_path: str,
    ) -> JsonObject:
        return await self.client.upload_file_from_path(self.id, local_path, container_path)

    async def download_file(self, container_path: str) -> bytes:
        return await self.client.download_file(self.id, container_path)

    async def download_file_to_path(
        self,
        container_path: str,
        local_path: str | Path,
    ) -> Path:
        return await self.client.download_file_to_path(self.id, container_path, local_path)

    async def snapshot(self, image: Image, *, image_id: str | None = None) -> JsonObject:
        return await self.client.snapshot_sandbox(self.id, image, image_id=image_id)


@dataclass
class AsyncExecHandle:
    client: "AsyncSandboxClient"
    session_id: str
    sandbox_id: str
    session: JsonObject = field(default_factory=dict)
    last_sequence: int = 0

    async def get(self) -> JsonObject:
        payload = await self.client.get_exec_session(self.session_id)
        session = payload.get("session")
        if isinstance(session, dict):
            self.session = session
        return payload

    async def write_stdin(self, data: str | bytes, *, eof: bool = False) -> JsonObject:
        return await self.client.write_exec_stdin(self.session_id, _text_payload(data), eof=eof)

    async def close_stdin(self) -> JsonObject:
        return await self.client.close_exec_stdin(self.session_id)

    async def events(
        self,
        *,
        wait_seconds: float = 30.0,
        limit: int = 100,
    ) -> AsyncIterator[JsonObject]:
        while True:
            payload = await self.client.read_exec_events(
                self.session_id,
                after=self.last_sequence,
                limit=limit,
                wait_seconds=wait_seconds,
            )
            raw_events = payload.get("events")
            events = _exec_event_payloads(self.session_id, raw_events)
            for event in events:
                self.last_sequence = _next_exec_sequence(
                    self.session_id,
                    self.last_sequence,
                    event,
                )
                yield event
            session = payload.get("session")
            if isinstance(session, dict):
                self.session = session
                if session.get("status") in TERMINAL_EXEC_STATUSES and not events:
                    return

    async def wait(
        self,
        *,
        timeout_seconds: float | None = None,
        poll_wait_seconds: float = 1.0,
        settle_seconds: float = 0.2,
    ) -> SandboxExecResult:
        events: list[JsonObject] = []
        deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds
        terminal_seen = False
        empty_terminal_drains = 0

        while True:
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError(f"exec session timed out: {self.session_id}")
            wait_seconds = settle_seconds if terminal_seen else poll_wait_seconds
            if deadline is not None:
                wait_seconds = min(wait_seconds, max(0.0, deadline - time.monotonic()))
            payload = await self.client.read_exec_events(
                self.session_id,
                after=self.last_sequence,
                limit=100,
                wait_seconds=wait_seconds,
            )
            raw_events = payload.get("events")
            new_events = _exec_event_payloads(self.session_id, raw_events)
            for event in new_events:
                self.last_sequence = _next_exec_sequence(
                    self.session_id,
                    self.last_sequence,
                    event,
                )
                events.append(event)
            session = payload.get("session")
            if isinstance(session, dict):
                self.session = session
            if self.session.get("status") in TERMINAL_EXEC_STATUSES:
                terminal_seen = True
                if new_events:
                    empty_terminal_drains = 0
                else:
                    empty_terminal_drains += 1
                    if empty_terminal_drains >= 1:
                        return _exec_result(self.session_id, self.session, events)


class AsyncSandboxClient:
    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = 30.0,
        session: Any | None = None,
        api_token: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self._session = session
        self._owned_session: Any | None = None
        self.headers = sandbox_auth_headers(api_token)
        self.headers.update(dict(headers or {}))

    async def __aenter__(self) -> "AsyncSandboxClient":
        await self._client()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    async def close(self) -> None:
        if self._owned_session is not None:
            await self._owned_session.close()
            self._owned_session = None

    async def health(self) -> JsonObject:
        return await self._request_json("GET", "/healthz")

    async def list_nodes(self) -> list[JsonObject]:
        payload = await self._request_json("GET", "/v1/nodes")
        nodes = payload.get("nodes")
        return [dict(item) for item in nodes if isinstance(item, dict)] if isinstance(nodes, list) else []

    async def heartbeat(self) -> JsonObject:
        warnings.warn(
            "AsyncSandboxClient.heartbeat() targets the internal node-agent API "
            "and is deprecated; use the public gateway and list_nodes() instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return await self._request_json("GET", "/v1/heartbeat")

    async def list_sandboxes(self) -> list[JsonObject]:
        payload = await self._request_json("GET", "/v1/sandboxes")
        sandboxes = payload.get("sandboxes")
        return [item for item in sandboxes if isinstance(item, dict)] if isinstance(sandboxes, list) else []

    async def list_prepared_capacity(self) -> JsonObject:
        return await self._request_json("GET", "/v1/capacity/prepare")

    async def prepare_capacity(
        self,
        *,
        count: int,
        cpus: float | None = None,
        memory_mb: int | None = None,
        disk_mb: int | None = None,
        resources: Mapping[str, Any] | None = None,
        image: Image | None = None,
        ttl_seconds: int = 900,
        prepare_id: str | None = None,
    ) -> JsonObject:
        return await self._request_json(
            "POST",
            "/v1/capacity/prepare",
            payload=_prepare_capacity_payload(
                count=count,
                cpus=cpus,
                memory_mb=memory_mb,
                disk_mb=disk_mb,
                resources=resources,
                image=image,
                ttl_seconds=ttl_seconds,
                prepare_id=prepare_id,
            ),
        )

    async def delete_prepared_capacity(self, prepare_id: str) -> JsonObject:
        return await self._request_json(
            "DELETE",
            f"/v1/capacity/prepare/{_quote_segment(prepare_id)}",
        )

    async def list_prepared_builders(self) -> JsonObject:
        return await self._request_json("GET", "/v1/builders/prepare")

    async def prepare_builder(
        self,
        *,
        count: int = 1,
        ttl_seconds: int = 900,
        prepare_id: str | None = None,
    ) -> JsonObject:
        return await self._request_json(
            "POST",
            "/v1/builders/prepare",
            payload=_prepare_builder_payload(
                count=count,
                ttl_seconds=ttl_seconds,
                prepare_id=prepare_id,
            ),
        )

    async def delete_prepared_builder(self, prepare_id: str) -> JsonObject:
        return await self._request_json(
            "DELETE",
            f"/v1/builders/prepare/{_quote_segment(prepare_id)}",
        )

    async def get_sandbox(self, sandbox_id: str) -> JsonObject | None:
        for record in await self.list_sandboxes():
            spec = record.get("spec")
            if isinstance(spec, dict) and spec.get("id") == sandbox_id:
                return record
        return None

    async def create_sandbox(
        self,
        spec: SandboxSpec | None = None,
        *,
        request_timeout_seconds: float | None = None,
        start_timeout_seconds: float = DEFAULT_SCALE_UP_TIMEOUT_SECONDS,
        retry_interval_seconds: float = DEFAULT_SCALE_UP_RETRY_INTERVAL_SECONDS,
        **kwargs: Any,
    ) -> AsyncSandboxHandle:
        payload = _sandbox_payload(spec, **kwargs)
        if not str(payload.get("id") or "").strip():
            payload["id"] = f"sdk-{uuid4().hex}"
        response = await self._request_json_with_scale_up_wait(
            "/v1/sandboxes",
            payload,
            timeout_seconds=start_timeout_seconds,
            request_timeout_seconds=request_timeout_seconds,
            retry_interval_seconds=retry_interval_seconds,
        )
        record = response.get("sandbox")
        if not isinstance(record, dict):
            raise SandboxApiError("gateway returned an invalid sandbox payload", body=response)
        sandbox_spec = record.get("spec")
        sandbox_id = sandbox_spec.get("id") if isinstance(sandbox_spec, dict) else None
        if not isinstance(sandbox_id, str) or not sandbox_id:
            raise SandboxApiError("gateway sandbox payload is missing spec.id", body=response)
        return AsyncSandboxHandle(self, sandbox_id, record=record, create_response=response)

    async def _request_json_with_scale_up_wait(
        self,
        path: str,
        payload: JsonObject,
        *,
        timeout_seconds: float,
        request_timeout_seconds: float | None,
        retry_interval_seconds: float,
    ) -> JsonObject:
        deadline = _deadline(max(0.0, timeout_seconds))
        last_error: SandboxApiError | None = None
        attempts = 0
        while True:
            remaining = _remaining_seconds(deadline)
            if attempts > 0 and remaining is not None and remaining <= 0:
                raise TimeoutError(_scale_up_timeout_message(path, last_error)) from last_error
            attempts += 1
            try:
                return await self._request_json(
                    "POST",
                    path,
                    payload=payload,
                    timeout_seconds=_request_timeout_seconds(
                        remaining,
                        self.timeout_seconds
                        if request_timeout_seconds is None
                        else request_timeout_seconds,
                    ),
                )
            except SandboxApiError as exc:
                if not _is_retryable_scale_up_error(exc):
                    raise
                last_error = exc
                await _async_sleep_for_scale_up_retry(
                    exc,
                    fallback_seconds=retry_interval_seconds,
                    deadline=deadline,
                )

    async def create_ssh_sandbox(
        self,
        *,
        ssh_user: str = "sandbox",
        authorized_keys: Sequence[str] = (),
        **kwargs: Any,
    ) -> AsyncSandboxHandle:
        kwargs.setdefault("network", "bridge")
        kwargs["ssh"] = {
            "enabled": True,
            "user": ssh_user,
            "authorized_keys": list(authorized_keys),
        }
        return await self.create_sandbox(**kwargs)

    async def delete_sandbox(self, sandbox_id: str) -> JsonObject:
        return await self._request_json("DELETE", f"/v1/sandboxes/{_quote_segment(sandbox_id)}")

    async def upload_file(
        self,
        sandbox_id: str,
        container_path: str,
        content: bytes | str,
    ) -> JsonObject:
        return await self._request_json(
            "PUT",
            _file_path(sandbox_id, container_path),
            body=_bytes_payload(content),
            content_type="application/octet-stream",
        )

    async def upload_file_from_path(
        self,
        sandbox_id: str,
        local_path: str | Path,
        container_path: str,
    ) -> JsonObject:
        return await self.upload_file(
            sandbox_id,
            container_path,
            _read_file_bytes(Path(local_path), limit=MAX_FILE_BODY_BYTES),
        )

    async def download_file(self, sandbox_id: str, container_path: str) -> bytes:
        return await self._request_bytes("GET", _file_path(sandbox_id, container_path))

    async def download_file_to_path(
        self,
        sandbox_id: str,
        container_path: str,
        local_path: str | Path,
    ) -> Path:
        path = Path(local_path)
        path.write_bytes(await self.download_file(sandbox_id, container_path))
        return path

    async def start_exec(
        self,
        sandbox_id: str,
        command: str | Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        working_dir: str | None = None,
        stdin: bool = False,
        tty: bool = False,
    ) -> AsyncExecHandle:
        payload = _exec_payload(
            command,
            env=env,
            working_dir=working_dir,
            stdin=stdin,
            tty=tty,
        )
        response = await self._request_json(
            "POST",
            f"/v1/sandboxes/{_quote_segment(sandbox_id)}/exec",
            payload=payload,
        )
        session = response.get("session")
        if not isinstance(session, dict) or not isinstance(session.get("id"), str):
            raise SandboxApiError("gateway returned an invalid exec session payload", body=response)
        return AsyncExecHandle(self, session["id"], sandbox_id, session=session)

    async def exec(
        self,
        sandbox_id: str,
        command: str | Sequence[str],
        *,
        input: str | bytes | None = None,
        env: Mapping[str, str] | None = None,
        working_dir: str | None = None,
        timeout_seconds: float | None = None,
        tty: bool = False,
    ) -> SandboxExecResult:
        handle = await self.start_exec(
            sandbox_id,
            command,
            env=env,
            working_dir=working_dir,
            stdin=input is not None,
            tty=tty,
        )
        if input is not None:
            await handle.write_stdin(input, eof=True)
        return await handle.wait(timeout_seconds=timeout_seconds)

    async def get_exec_session(self, session_id: str) -> JsonObject:
        return await self._request_json("GET", f"/v1/exec/{_quote_segment(session_id)}")

    async def read_exec_events(
        self,
        session_id: str,
        *,
        after: int = 0,
        limit: int = 100,
        wait_seconds: float = 0.0,
    ) -> JsonObject:
        query = parse.urlencode(
            {
                "after": max(0, after),
                "limit": max(1, limit),
                "wait_seconds": max(0.0, wait_seconds),
            }
        )
        return await self._request_json("GET", f"/v1/exec/{_quote_segment(session_id)}/events?{query}")

    async def write_exec_stdin(
        self,
        session_id: str,
        data: str,
        *,
        eof: bool = False,
    ) -> JsonObject:
        return await self._request_json(
            "POST",
            f"/v1/exec/{_quote_segment(session_id)}/stdin",
            payload={"data": data, "eof": eof},
        )

    async def close_exec_stdin(self, session_id: str) -> JsonObject:
        return await self._request_json("POST", f"/v1/exec/{_quote_segment(session_id)}/close-stdin")

    async def get_ssh_target(self, sandbox_id: str) -> JsonObject:
        return await self._request_json("GET", f"/v1/sandboxes/{_quote_segment(sandbox_id)}/ssh")

    async def get_ssh_connection(self, sandbox_id: str) -> SandboxSshTarget:
        return SandboxSshTarget.from_payload(
            sandbox_id,
            await self.get_ssh_target(sandbox_id),
        )

    def ssh_proxy_argv(
        self,
        sandbox_id: str,
        *,
        token_env: str = "UCLOUD_SANDBOX_API_TOKEN",
        python: str = "python3",
    ) -> list[str]:
        return [
            python,
            "-m",
            "ucloud_sandboxes_sdk.ssh_proxy",
            "--gateway-url",
            self.base_url,
            "--sandbox-id",
            sandbox_id,
            "--token-env",
            token_env,
        ]

    def ssh_proxy_command(
        self,
        sandbox_id: str,
        *,
        token_env: str = "UCLOUD_SANDBOX_API_TOKEN",
        python: str = "python3",
    ) -> str:
        proxy = " ".join(
            shlex.quote(part)
            for part in self.ssh_proxy_argv(
                sandbox_id,
                token_env=token_env,
                python=python,
            )
        )
        return f"ssh -o ProxyCommand={shlex.quote(proxy)} sandbox@{sandbox_id}"

    async def list_images(self) -> list[JsonObject]:
        payload = await self._request_json("GET", "/v1/images")
        images = payload.get("images")
        return [item for item in images if isinstance(item, dict)] if isinstance(images, list) else []

    async def list_image_builds(self) -> list[JsonObject]:
        payload = await self._request_json("GET", "/v1/images/builds")
        builds = payload.get("builds")
        return [item for item in builds if isinstance(item, dict)] if isinstance(builds, list) else []

    async def get_image_build(
        self,
        build_id_or_image_id: str,
        *,
        timeout_seconds: float | None = None,
    ) -> JsonObject:
        payload = await self._request_json(
            "GET",
            f"/v1/images/builds/{_quote_segment(build_id_or_image_id)}",
            timeout_seconds=timeout_seconds,
        )
        build = payload.get("build")
        if not isinstance(build, dict):
            raise SandboxApiError("gateway returned an invalid image build payload", body=payload)
        return build

    async def submit_image_build(
        self,
        image: Image,
        *,
        upload_context: bool = True,
        timeout_seconds: float | None = None,
    ) -> JsonObject:
        effective_timeout = (
            self.timeout_seconds if timeout_seconds is None else timeout_seconds
        )
        deadline = _deadline(effective_timeout)
        payload = await self._prepare_image_build_payload(
            image,
            upload_context=upload_context,
            deadline=deadline,
        )
        submitted = await self._request_json(
            "POST",
            "/v1/images/build",
            payload=payload,
            timeout_seconds=_remaining_seconds(deadline),
        )
        return _submitted_build_record(submitted)

    async def _prepare_image_build_payload(
        self,
        image: Image,
        *,
        upload_context: bool,
        deadline: float | None,
    ) -> JsonObject:
        payload = _image_build_payload(image, upload_context=False)
        context_path = _local_build_context_path(payload) if upload_context else None
        if context_path is not None:
            with _tar_gz_directory(context_path) as archive:
                digest, size = _build_context_archive_identity(archive)
                context_path_url = f"/v1/image-contexts/{digest}"
                try:
                    existing = await self._request_json(
                        "GET",
                        context_path_url,
                        timeout_seconds=_remaining_seconds(deadline),
                    )
                except SandboxApiError as exc:
                    if exc.status_code not in {404, 405}:
                        raise
                    existing = None

                use_context_reference = _build_context_reference_matches(
                    existing,
                    digest=digest,
                    size=size,
                )
                if not use_context_reference:
                    try:
                        await self._request_json(
                            "PUT",
                            context_path_url,
                            body=archive,
                            body_size=size,
                            content_type="application/gzip",
                            timeout_seconds=_remaining_seconds(deadline),
                        )
                    except SandboxApiError as exc:
                        if exc.status_code not in {404, 405}:
                            raise
                        _attach_legacy_build_context_archive(payload, archive)
                    else:
                        use_context_reference = True
                if use_context_reference:
                    _attach_build_context_reference(
                        payload,
                        digest=digest,
                        size=size,
                    )
        payload["wait"] = False
        return payload

    async def wait_for_image_build(
        self,
        build_id_or_image_id: str,
        *,
        timeout_seconds: float | None = None,
        poll_interval_seconds: float = 5.0,
        on_status: Callable[[JsonObject], object] | None = None,
    ) -> JsonObject:
        deadline = _deadline(timeout_seconds)
        last_seen: tuple[object, object, object] | None = None
        build: JsonObject | None = None
        while True:
            remaining = _remaining_seconds(deadline)
            if remaining is not None and remaining <= 0:
                raise TimeoutError(_image_build_timeout_message(build_id_or_image_id, build))
            build = await self.get_image_build(
                build_id_or_image_id,
                timeout_seconds=_request_timeout_seconds(
                    remaining,
                    self.timeout_seconds,
                ),
            )
            seen = (
                build.get("status"),
                build.get("updated_at"),
                len(str(build.get("log_tail") or "")),
            )
            if on_status is not None and seen != last_seen:
                on_status(build)
            last_seen = seen
            if build.get("status") in {"succeeded", "failed"}:
                return build
            sleep_seconds = max(0.1, poll_interval_seconds)
            remaining = _remaining_seconds(deadline)
            if remaining is not None:
                if remaining <= 0:
                    raise TimeoutError(_image_build_timeout_message(build_id_or_image_id, build))
                sleep_seconds = min(sleep_seconds, remaining)
            await asyncio.sleep(sleep_seconds)

    async def build_image(
        self,
        image: Image,
        *,
        upload_context: bool = True,
        timeout_seconds: float | None = DEFAULT_SCALE_UP_TIMEOUT_SECONDS,
        poll_interval_seconds: float = 5.0,
        retry_interval_seconds: float = DEFAULT_SCALE_UP_RETRY_INTERVAL_SECONDS,
        on_status: Callable[[JsonObject], object] | None = None,
    ) -> JsonObject:
        effective_timeout = (
            DEFAULT_SCALE_UP_TIMEOUT_SECONDS
            if timeout_seconds is None
            else max(0.0, timeout_seconds)
        )
        deadline = _deadline(effective_timeout)
        payload = await self._prepare_image_build_payload(
            image,
            upload_context=upload_context,
            deadline=deadline,
        )
        submitted = _submitted_build_record(
            await self._request_json_with_scale_up_wait(
                "/v1/images/build",
                payload,
                timeout_seconds=max(0.0, _remaining_seconds(deadline) or 0.0),
                request_timeout_seconds=effective_timeout,
                retry_interval_seconds=retry_interval_seconds,
            )
        )
        build = await self.wait_for_image_build(
            str(submitted.get("build_id") or submitted.get("image_id") or ""),
            timeout_seconds=_remaining_seconds(deadline),
            poll_interval_seconds=poll_interval_seconds,
            on_status=on_status,
        )
        if build.get("status") != "succeeded":
            raise SandboxApiError(
                f"image build failed: {build.get('error') or build.get('status')}",
                body={"build": build},
            )
        return _completed_build_payload(build)

    async def pull_image(
        self,
        image: Image,
        *,
        image_id: str | None = None,
        count: int = 1,
        cpus: float | None = None,
        memory_mb: int | None = None,
        disk_mb: int | None = None,
        resources: Mapping[str, Any] | None = None,
        sandbox_nodes_only: bool = True,
    ) -> JsonObject:
        payload = _image_pull_payload(
            image,
            image_id=image_id,
            count=count,
            cpus=cpus,
            memory_mb=memory_mb,
            disk_mb=disk_mb,
            resources=resources,
            sandbox_nodes_only=sandbox_nodes_only,
        )
        return await self._request_json("POST", "/v1/images/pull", payload=payload)

    async def snapshot_sandbox(
        self,
        sandbox_id: str,
        image: Image,
        *,
        image_id: str | None = None,
    ) -> JsonObject:
        payload: JsonObject = {"image": _image_pull_reference(image)}
        if image_id is not None:
            payload["id"] = image_id
        return await self._request_json(
            "POST",
            f"/v1/sandboxes/{_quote_segment(sandbox_id)}/snapshot",
            payload=payload,
        )

    async def _client(self) -> Any:
        if self._session is not None:
            return self._session
        if self._owned_session is None:
            try:
                from aiohttp import ClientSession
            except ImportError as exc:
                raise RuntimeError(
                    "AsyncSandboxClient requires aiohttp. Install "
                    "ucloud-sandboxes-sdk[async] or ucloud-sandboxes-sdk[inspect]."
                ) from exc
            self._owned_session = ClientSession()
        return self._owned_session

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        payload: JsonObject | None = None,
        body: bytes | BinaryIO | None = None,
        body_size: int | None = None,
        content_type: str | None = None,
        timeout_seconds: float | None = None,
    ) -> JsonObject:
        raw_body = json.dumps(payload).encode("utf-8") if payload is not None else body
        body_limit = MAX_JSON_BODY_BYTES if payload is not None else MAX_FILE_BODY_BYTES
        known_body_size = (
            len(raw_body)
            if isinstance(raw_body, bytes)
            else body_size
        )
        if raw_body is not None and known_body_size is None:
            raise TypeError("body_size is required for streamed request bodies")
        if known_body_size is not None and known_body_size > body_limit:
            raise SandboxApiError(f"request body exceeds the {body_limit} byte limit")
        headers = dict(self.headers)
        if content_type is not None and payload is None:
            headers["Content-Type"] = content_type
        streamed_body = raw_body is not None and not isinstance(raw_body, bytes)
        if streamed_body:
            headers["Content-Length"] = str(known_body_size)
        client = await self._client()
        timeout = self.timeout_seconds if timeout_seconds is None else timeout_seconds
        deadline = _deadline(timeout)
        for attempt in range(UCLOUD_UNAVAILABLE_RETRY_ATTEMPTS):
            if streamed_body:
                raw_body.seek(0)
            async with client.request(
                method,
                self.base_url + path,
                json=payload,
                data=(
                    _async_file_chunks(raw_body)
                    if streamed_body
                    else body
                ),
                headers=headers,
                timeout=_aiohttp_timeout(
                    _request_timeout_seconds(
                        _remaining_seconds(deadline),
                        timeout,
                    )
                ),
                allow_redirects=False,
            ) as response:
                try:
                    raw = (
                        await read_async_response(
                            response,
                            limit=MAX_JSON_RESPONSE_BYTES,
                        )
                    ).decode("utf-8")
                except ResponseTooLargeError as exc:
                    raise SandboxApiError(
                        str(exc),
                        status_code=response.status,
                        headers=response_headers(response),
                    ) from exc
                try:
                    decoded = json.loads(raw) if raw else {}
                except json.JSONDecodeError as exc:
                    if 200 <= response.status < 300:
                        raise SandboxApiError(
                            f"gateway returned invalid JSON: {exc}",
                            status_code=response.status,
                            body={"error": raw},
                            headers=response_headers(response),
                        ) from exc
                    decoded = {"error": raw}
                if not 200 <= response.status < 300:
                    api_error = SandboxApiError(
                        f"gateway request failed ({response.status}): {decoded}",
                        status_code=response.status,
                        body=decoded,
                        headers=response_headers(response),
                    )
                    if _should_retry_ucloud_unavailable(
                        response.status,
                        decoded,
                        attempt,
                    ):
                        delay = _ucloud_unavailable_retry_delay(attempt)
                        remaining = _remaining_seconds(deadline)
                        if remaining is None or remaining > delay:
                            await asyncio.sleep(delay)
                            continue
                    raise api_error
            if not isinstance(decoded, dict):
                raise SandboxApiError(
                    "gateway returned a non-object JSON payload",
                    body=decoded,
                )
            return decoded
        raise AssertionError("unreachable UCloud unavailable retry state")

    async def _request_bytes(self, method: str, path: str) -> bytes:
        client = await self._client()
        deadline = _deadline(self.timeout_seconds)
        for attempt in range(UCLOUD_UNAVAILABLE_RETRY_ATTEMPTS):
            async with client.request(
                method,
                self.base_url + path,
                headers=dict(self.headers),
                timeout=_aiohttp_timeout(
                    _request_timeout_seconds(
                        _remaining_seconds(deadline),
                        self.timeout_seconds,
                    )
                ),
                allow_redirects=False,
            ) as response:
                try:
                    raw = await read_async_response(
                        response,
                        limit=MAX_FILE_RESPONSE_BYTES,
                    )
                except ResponseTooLargeError as exc:
                    raise SandboxApiError(
                        str(exc),
                        status_code=response.status,
                        headers=response_headers(response),
                    ) from exc
                if not 200 <= response.status < 300:
                    text = raw.decode("utf-8", errors="replace")
                    decoded = _decode_json_error(text)
                    api_error = SandboxApiError(
                        f"gateway request failed ({response.status}): {decoded}",
                        status_code=response.status,
                        body=decoded,
                        headers=response_headers(response),
                    )
                    if _should_retry_ucloud_unavailable(
                        response.status,
                        decoded,
                        attempt,
                    ):
                        delay = _ucloud_unavailable_retry_delay(attempt)
                        remaining = _remaining_seconds(deadline)
                        if remaining is None or remaining > delay:
                            await asyncio.sleep(delay)
                            continue
                    raise api_error
                return raw
        raise AssertionError("unreachable UCloud unavailable retry state")


def _sandbox_payload(
    spec: SandboxSpec | None,
    **kwargs: Any,
) -> JsonObject:
    payload = _object_payload(spec)
    overrides = {key: value for key, value in kwargs.items() if value is not None}
    payload.update(overrides)
    if "image" in payload:
        if not (
            isinstance(spec, SandboxSpec)
            and "image" not in overrides
            and isinstance(payload["image"], str)
        ):
            payload["image"] = _image_reference(payload["image"])
    else:
        raise TypeError("sandbox image is required and must be an Image")
    return payload


def _image_build_payload(
    image: Image,
    *,
    upload_context: bool = True,
) -> JsonObject:
    if not isinstance(image, Image):
        raise TypeError("build_image() requires an Image from Image.from_dockerfile()")
    payload = image.to_build_spec().to_dict()
    if upload_context:
        _attach_build_context_archive(payload)
    return payload


def _completed_build_payload(build: JsonObject) -> JsonObject:
    payload: JsonObject = {
        "build": dict(build),
        "image": build.get("image") if isinstance(build.get("image"), dict) else {},
        "command": list(build.get("command") or []),
        "exitCode": build.get("exit_code"),
    }
    if build.get("push_command"):
        payload["pushCommand"] = list(build.get("push_command") or [])
        payload["pushExitCode"] = build.get("push_exit_code")
    return payload


def _submitted_build_record(payload: JsonObject) -> JsonObject:
    build = payload.get("build")
    if not isinstance(build, dict):
        raise SandboxApiError(
            "gateway returned an invalid image build payload",
            body=payload,
        )
    return build


def _image_reference(image: object) -> str:
    if not isinstance(image, Image):
        raise TypeError("sandbox image must be an Image")
    return image.to_sandbox_image()


def _image_pull_reference(image: Image) -> str:
    if not isinstance(image, Image):
        raise TypeError("image must be an Image")
    return image.tag or image.reference


def _non_empty_string(name: str, value: object) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError(f"{name} cannot be empty")
    return text


def _object_payload(spec: object | None) -> JsonObject:
    if spec is None:
        return {}
    to_dict = getattr(spec, "to_dict", None)
    if callable(to_dict):
        raw = to_dict()
        if isinstance(raw, Mapping):
            return dict(raw)
    raise TypeError("spec must expose to_dict().")


def _nested_payload(value: object) -> object:
    if isinstance(value, Mapping):
        return dict(value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    return value


def _attach_build_context_archive(payload: JsonObject) -> None:
    if payload.get("context_archive_base64"):
        return
    context_path = payload.get("context_path")
    if not isinstance(context_path, str) or not context_path:
        return
    path = Path(context_path)
    if not path.is_dir():
        return
    with _tar_gz_directory(path) as archive:
        payload["context_archive_base64"] = _base64_ascii(archive)
    payload["context_archive_format"] = "tar.gz"
    payload["context_path"] = "."


def _local_build_context_path(payload: JsonObject) -> Path | None:
    context_path = payload.get("context_path")
    if not isinstance(context_path, str) or not context_path:
        return None
    path = Path(context_path)
    return path if path.is_dir() else None


def _build_context_archive_identity(source: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    source.seek(0)
    while chunk := source.read(BUILD_CONTEXT_STREAM_CHUNK_BYTES):
        digest.update(chunk)
        size += len(chunk)
    source.seek(0)
    return f"sha256:{digest.hexdigest()}", size


def _build_context_reference_matches(
    value: object,
    *,
    digest: str,
    size: int,
) -> bool:
    if not isinstance(value, dict):
        return False
    stored_size = value.get("size")
    return (
        value.get("digest") == digest
        and isinstance(stored_size, int)
        and not isinstance(stored_size, bool)
        and stored_size == size
    )


def _attach_build_context_reference(
    payload: JsonObject,
    *,
    digest: str,
    size: int,
) -> None:
    payload.pop("context_archive_base64", None)
    payload["context_archive_digest"] = digest
    payload["context_archive_format"] = "tar.gz"
    payload["context_archive_size"] = size
    payload["context_path"] = "."


def _attach_legacy_build_context_archive(
    payload: JsonObject,
    source: BinaryIO,
) -> None:
    payload.pop("context_archive_digest", None)
    payload.pop("context_archive_size", None)
    source.seek(0)
    payload["context_archive_base64"] = _base64_ascii(source)
    payload["context_archive_format"] = "tar.gz"
    payload["context_path"] = "."


async def _async_file_chunks(source: BinaryIO) -> AsyncIterator[bytes]:
    while chunk := await asyncio.to_thread(
        source.read,
        BUILD_CONTEXT_STREAM_CHUNK_BYTES,
    ):
        yield chunk


def _aiohttp_timeout(timeout_seconds: float | None) -> object:
    if timeout_seconds is None:
        return None
    try:
        from aiohttp import ClientTimeout
    except ImportError:
        return timeout_seconds
    return ClientTimeout(total=timeout_seconds)


def _deadline(timeout_seconds: float | None) -> float | None:
    if timeout_seconds is None:
        return None
    return time.monotonic() + max(0.0, float(timeout_seconds))


def _remaining_seconds(deadline: float | None) -> float | None:
    if deadline is None:
        return None
    return max(0.0, deadline - time.monotonic())


def _request_timeout_seconds(
    remaining_seconds: float | None,
    default_timeout_seconds: float,
) -> float:
    default_timeout_seconds = max(0.001, float(default_timeout_seconds))
    if remaining_seconds is None:
        return default_timeout_seconds
    return max(0.001, min(default_timeout_seconds, remaining_seconds))


def _image_build_timeout_message(
    build_id_or_image_id: str,
    build: JsonObject | None,
) -> str:
    if not isinstance(build, dict):
        return f"image build did not finish: {build_id_or_image_id}"
    details = [
        f"status={build.get('status')}",
        f"updated_at={build.get('updated_at')}",
    ]
    error = build.get("error")
    if error:
        details.append(f"error={error}")
    log_tail = str(build.get("log_tail") or "").strip()
    if log_tail:
        details.append(f"log_tail={log_tail[-500:]}")
    return f"image build did not finish: {build_id_or_image_id} ({', '.join(details)})"


@contextmanager
def _tar_gz_directory(path: Path) -> Iterator[BinaryIO]:
    """Yield a deterministic compressed context without retaining it in memory."""

    with tempfile.SpooledTemporaryFile(
        max_size=BUILD_CONTEXT_SPOOL_MEMORY_BYTES,
        mode="w+b",
    ) as buffer:
        # Gzip embeds the current timestamp and source filename by default. Both
        # must be fixed for identical contexts to produce identical bytes.
        with gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=buffer,
            mtime=0,
        ) as compressed:
            # Stream tar data into gzip. This avoids the former uncompressed tar
            # buffer and lets large compressed archives spill to a temporary file.
            with tarfile.open(
                fileobj=compressed,
                mode="w|",
                format=tarfile.PAX_FORMAT,
            ) as archive:
                for item in sorted(
                    path.rglob("*"),
                    key=lambda candidate: candidate.relative_to(path).as_posix(),
                ):
                    arcname = item.relative_to(path).as_posix()
                    info = archive.gettarinfo(str(item), arcname=arcname)
                    _normalize_build_context_tar_info(info)
                    if info.isfile():
                        with item.open("rb") as source:
                            archive.addfile(info, source)
                    else:
                        archive.addfile(info)
        buffer.seek(0)
        yield buffer


def _normalize_build_context_tar_info(info: tarfile.TarInfo) -> None:
    """Remove host-specific metadata that is irrelevant to a Docker build."""

    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.pax_headers = {}


def _base64_ascii(source: BinaryIO) -> str:
    """Encode a binary stream without first materializing the input bytes."""

    chunks: list[str] = []
    while chunk := source.read(BUILD_CONTEXT_BASE64_CHUNK_BYTES):
        # The chunk size is divisible by three, so only the final chunk is
        # padded and concatenating the independently encoded chunks is valid.
        chunks.append(base64.b64encode(chunk).decode("ascii"))
    return "".join(chunks)


def _exec_payload(
    command: str | Sequence[str],
    *,
    env: Mapping[str, str] | None,
    working_dir: str | None,
    stdin: bool,
    tty: bool,
) -> JsonObject:
    return {
        "command": _command_list(command),
        "env": dict(env or {}),
        "working_dir": working_dir,
        "stdin": stdin,
        "tty": tty,
    }


def _prepare_capacity_payload(
    *,
    count: int,
    cpus: float | None,
    memory_mb: int | None,
    disk_mb: int | None,
    resources: Mapping[str, Any] | None,
    image: Image | None,
    ttl_seconds: int,
    prepare_id: str | None,
) -> JsonObject:
    payload: JsonObject = {
        "count": count,
        "ttl_seconds": ttl_seconds,
    }
    if prepare_id is not None:
        payload["id"] = prepare_id
    if resources is not None:
        payload["resources"] = dict(resources)
    if cpus is not None:
        payload["cpus"] = cpus
    if memory_mb is not None:
        payload["memory_mb"] = memory_mb
    if disk_mb is not None:
        payload["disk_mb"] = disk_mb
    if image is not None:
        payload["image"] = _image_pull_reference(image)
    return payload


def _image_pull_payload(
    image: Image,
    *,
    image_id: str | None,
    count: int,
    cpus: float | None,
    memory_mb: int | None,
    disk_mb: int | None,
    resources: Mapping[str, Any] | None,
    sandbox_nodes_only: bool,
) -> JsonObject:
    payload: JsonObject = {
        "image": _image_pull_reference(image),
        "count": count,
        "sandbox_nodes_only": sandbox_nodes_only,
    }
    if image_id is not None:
        payload["id"] = image_id
    if resources is not None:
        payload["resources"] = dict(resources)
    if cpus is not None:
        payload["cpus"] = cpus
    if memory_mb is not None:
        payload["memory_mb"] = memory_mb
    if disk_mb is not None:
        payload["disk_mb"] = disk_mb
    return payload


def _prepare_builder_payload(
    *,
    count: int,
    ttl_seconds: int,
    prepare_id: str | None,
) -> JsonObject:
    payload: JsonObject = {
        "count": count,
        "ttl_seconds": ttl_seconds,
    }
    if prepare_id is not None:
        payload["id"] = prepare_id
    return payload


def _command_list(command: str | Sequence[str]) -> list[str]:
    if isinstance(command, str):
        return [command]
    return [str(item) for item in command]


def _quote_segment(value: str) -> str:
    return parse.quote(value, safe="")


def _file_path(sandbox_id: str, container_path: str) -> str:
    return (
        f"/v1/sandboxes/{_quote_segment(sandbox_id)}/files?"
        f"{parse.urlencode({'path': container_path})}"
    )


def _text_payload(data: str | bytes) -> str:
    if isinstance(data, bytes):
        return data.decode("utf-8")
    return data


def _bytes_payload(data: str | bytes) -> bytes:
    if isinstance(data, bytes):
        return data
    return data.encode("utf-8")


def _read_file_bytes(path: Path, *, limit: int) -> bytes:
    size = path.stat().st_size
    if size > limit:
        raise SandboxApiError(f"file exceeds the {limit} byte upload limit")
    data = path.read_bytes()
    if len(data) > limit:
        raise SandboxApiError(f"file exceeds the {limit} byte upload limit")
    return data


def _decode_json_error(raw: str) -> object:
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {"error": raw}


def _should_retry_ucloud_unavailable(
    status_code: int,
    body: object,
    attempt: int,
) -> bool:
    if attempt >= UCLOUD_UNAVAILABLE_RETRY_ATTEMPTS - 1:
        return False
    if status_code != UCLOUD_UNAVAILABLE_STATUS:
        return False
    text = _ucloud_unavailable_error_text(body).lower()
    return "job is unavailable" in text and "ucloud" in text


def _ucloud_unavailable_error_text(body: object) -> str:
    if isinstance(body, str):
        return body
    if isinstance(body, dict):
        values = []
        for key in ("error", "message", "detail", "upstream_body_preview"):
            value = body.get(key)
            if isinstance(value, str):
                values.append(value)
        return "\n".join(values)
    return ""


def _ucloud_unavailable_retry_delay(attempt: int) -> float:
    delay = UCLOUD_UNAVAILABLE_RETRY_BASE_DELAY_SECONDS * (2**attempt)
    return min(UCLOUD_UNAVAILABLE_RETRY_MAX_DELAY_SECONDS, delay)


def _sleep_for_retry(delay_seconds: float, deadline: float | None) -> bool:
    remaining = _remaining_seconds(deadline)
    if remaining is not None and remaining <= delay_seconds:
        return False
    time.sleep(delay_seconds)
    return True


def _is_retryable_scale_up_error(exc: SandboxApiError) -> bool:
    if not isinstance(exc.body, dict):
        return False
    if (
        exc.status_code in {408, 425, 429, 500, 502, 503, 504}
        and exc.body.get("retryable") is True
    ):
        return True
    if exc.status_code != 503:
        return False
    message = str(exc.body.get("error") or "").lower()
    return bool(
        "pending_resources" in exc.body
        or "pending_image_builds" in exc.body
        or "no ready node" in message
        or "no ready builder" in message
    )


def _scale_up_retry_delay(exc: SandboxApiError, fallback_seconds: float) -> float:
    raw = next(
        (
            value
            for key, value in exc.headers.items()
            if key.lower() == "retry-after"
        ),
        None,
    )
    if raw is not None:
        try:
            return max(0.0, min(60.0, float(raw)))
        except (TypeError, ValueError):
            pass
    return max(0.0, float(fallback_seconds))


def _sleep_for_scale_up_retry(
    exc: SandboxApiError,
    *,
    fallback_seconds: float,
    deadline: float | None,
) -> None:
    delay = _scale_up_retry_delay(exc, fallback_seconds)
    remaining = _remaining_seconds(deadline)
    if remaining is not None:
        delay = min(delay, max(0.0, remaining))
    time.sleep(delay)


async def _async_sleep_for_scale_up_retry(
    exc: SandboxApiError,
    *,
    fallback_seconds: float,
    deadline: float | None,
) -> None:
    delay = _scale_up_retry_delay(exc, fallback_seconds)
    remaining = _remaining_seconds(deadline)
    if remaining is not None:
        delay = min(delay, max(0.0, remaining))
    await asyncio.sleep(delay)


def _scale_up_timeout_message(
    path: str,
    last_error: SandboxApiError | None,
) -> str:
    label = "sandbox capacity" if path == "/v1/sandboxes" else "builder capacity"
    return f"timed out waiting for {label}: {last_error or 'no response'}"


def _exec_event_payloads(session_id: str, value: object) -> list[JsonObject]:
    if not isinstance(value, list):
        raise SandboxApiError(
            "gateway returned an invalid exec event payload",
            body={"session_id": session_id, "events": value},
        )
    if not all(isinstance(item, dict) for item in value):
        raise SandboxApiError(
            "gateway returned a malformed exec event",
            body={"session_id": session_id, "events": value},
        )
    return [dict(item) for item in value]


def _next_exec_sequence(
    session_id: str,
    previous_sequence: int,
    event: Mapping[str, Any],
) -> int:
    raw_sequence = event.get("sequence")
    if isinstance(raw_sequence, bool) or not isinstance(raw_sequence, int):
        raise SandboxApiError(
            "gateway returned an exec event with an invalid sequence",
            body={"session_id": session_id, "event": dict(event)},
        )
    expected = previous_sequence + 1
    if raw_sequence != expected:
        raise ExecEventHistoryLostError(
            session_id,
            expected_sequence=expected,
            received_sequence=raw_sequence,
        )
    return raw_sequence


def _exec_result(
    session_id: str,
    session: JsonObject,
    events: list[JsonObject],
) -> SandboxExecResult:
    stdout = "".join(str(event.get("data") or "") for event in events if event.get("stream") == "stdout")
    stderr = "".join(str(event.get("data") or "") for event in events if event.get("stream") == "stderr")
    return SandboxExecResult(
        session_id=session_id,
        status=str(session.get("status") or ""),
        exit_code=session.get("exit_code") if isinstance(session.get("exit_code"), int) else None,
        stdout=stdout,
        stderr=stderr,
        events=tuple(events),
        session=dict(session),
    )
