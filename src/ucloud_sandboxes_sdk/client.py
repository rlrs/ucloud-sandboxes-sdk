from __future__ import annotations

import asyncio
import base64
from contextlib import contextmanager
import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import gzip
import json
from pathlib import Path
import random
import re
import tarfile
import tempfile
import time
from typing import (
    Any,
    AsyncIterator,
    BinaryIO,
    Callable,
    Iterator,
    Mapping,
    Sequence,
)
from urllib import error, parse, request
import uuid

from ._http import (
    ResponseTooLargeError,
    open_no_redirect,
    read_async_response,
    read_sync_response,
    response_headers,
)


JsonObject = dict[str, Any]
TERMINAL_EXEC_STATUSES = {"exited", "failed"}
TERMINAL_JOB_STATES = {"exited", "signaled", "failed"}
SANDBOX_TOKEN_HEADER = "X-UCloud-Sandbox-Token"
UCLOUD_UNAVAILABLE_STATUS = 503
UCLOUD_UNAVAILABLE_RETRY_ATTEMPTS = 6
UCLOUD_CREATE_RETRY_ATTEMPTS = 16
UCLOUD_UNAVAILABLE_RETRY_BASE_DELAY_SECONDS = 0.25
UCLOUD_UNAVAILABLE_RETRY_MAX_DELAY_SECONDS = 4.0
UCLOUD_CREATE_RETRY_MAX_DELAY_SECONDS = 30.0
UCLOUD_RETRY_AFTER_JITTER_RATIO = 0.25
DEFAULT_CREATE_TIMEOUT_SECONDS = 10 * 60.0
MAX_JSON_BODY_BYTES = 16 * 1024 * 1024
MAX_FILE_BODY_BYTES = 256 * 1024 * 1024
MAX_JSON_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_FILE_RESPONSE_BYTES = 256 * 1024 * 1024
BUILD_CONTEXT_SPOOL_MEMORY_BYTES = 8 * 1024 * 1024
BUILD_CONTEXT_STREAM_CHUNK_BYTES = 1024 * 1024


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

    @property
    def retryable(self) -> bool | None:
        if not isinstance(self.body, dict) or not isinstance(
            self.body.get("retryable"), bool
        ):
            return None
        return self.body["retryable"]

    @property
    def retry_after_seconds(self) -> float | None:
        return _retry_after_seconds(self.headers)


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


class _DataclassPayload:
    def to_dict(self) -> JsonObject:
        return {
            key: list(value) if isinstance(value, tuple) else value
            for key, value in asdict(self).items()
        }


@dataclass(frozen=True)
class SandboxSecuritySpec(_DataclassPayload):
    user: str | None = "1000:1000"
    cap_drop: tuple[str, ...] = ("ALL",)
    cap_add: tuple[str, ...] = ()
    no_new_privileges: bool = True
    pids_limit: int | None = 256
    read_only_rootfs: bool = False
    init: bool = True


@dataclass(frozen=True)
class SandboxFilesystemSpec(_DataclassPayload):
    enforce_disk_quota: bool = False
    workspace_path: str = "/workspace"
    tmpfs_mb: int = 64
    run_tmpfs_mb: int = 16


@dataclass(frozen=True)
class SandboxSshSpec(_DataclassPayload):
    enabled: bool = False
    user: str = "root"
    host: str = "127.0.0.1"
    host_port: int | None = None
    container_port: int = 22
    authorized_keys: tuple[str, ...] = ()


@dataclass(frozen=True)
class SandboxSshTarget:
    sandbox_id: str
    user: str
    host: str
    port: int
    command: str

    @classmethod
    def from_payload(cls, sandbox_id: str, payload: JsonObject) -> "SandboxSshTarget":
        ssh = payload.get("ssh")
        response_sandbox_id = payload.get("sandbox_id")
        if not isinstance(ssh, dict) or response_sandbox_id != sandbox_id:
            raise SandboxApiError(
                "gateway returned an invalid SSH payload", body=payload
            )
        host = ssh.get("host")
        port = ssh.get("port")
        user = ssh.get("user") or "root"
        if not isinstance(host, str) or not isinstance(port, int):
            raise SandboxApiError(
                "gateway SSH payload is missing host/port", body=payload
            )
        return cls(
            sandbox_id=sandbox_id,
            user=str(user),
            host=host,
            port=port,
            command=str(ssh.get("command") or f"ssh -p {port} {user}@{host}"),
        )


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
    ssh: SandboxSshSpec = SandboxSshSpec()
    security: SandboxSecuritySpec | None = SandboxSecuritySpec()
    filesystem: SandboxFilesystemSpec | None = SandboxFilesystemSpec()
    labels: Mapping[str, str] = field(default_factory=dict)
    parkable: bool = False
    managed_process: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.ssh, SandboxSshSpec):
            raise TypeError("ssh must be a SandboxSshSpec")
        for name, value, expected in (
            ("security", self.security, SandboxSecuritySpec),
            ("filesystem", self.filesystem, SandboxFilesystemSpec),
        ):
            if value is not None and not isinstance(value, expected):
                raise TypeError(f"{name} must be a {expected.__name__} or None")

    def to_dict(self) -> JsonObject:
        if self.managed_process and not self.parkable:
            raise ValueError("managed_process requires parkable=True")
        if self.managed_process and self.command:
            raise ValueError("managed_process sandboxes are started with start_job()")
        payload = dict(vars(self))
        payload.update(
            image=_image_reference(self.image),
            command=[str(item) for item in self.command],
            env=dict(self.env),
            ssh=self.ssh.to_dict(),
            security=self.security.to_dict() if self.security is not None else None,
            filesystem=(
                self.filesystem.to_dict() if self.filesystem is not None else None
            ),
            labels=dict(self.labels),
        )
        if not self.parkable:
            payload.pop("parkable")
        if not self.managed_process:
            payload.pop("managed_process")
        return payload


@dataclass(frozen=True)
class _ImageBuildSpec:
    id: str
    context_path: str
    tag: str | None = None
    dockerfile: str = "Dockerfile"
    push: bool = False
    build_args: Mapping[str, str] = field(default_factory=dict)
    labels: Mapping[str, str] = field(default_factory=dict)


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
    def from_dockerfile(
        cls,
        *,
        name: str,
        tag: str | None = None,
        context_path: str | Path,
        dockerfile: str = "Dockerfile",
        push: bool = True,
        build_args: Mapping[str, str] | None = None,
        labels: Mapping[str, str] | None = None,
    ) -> "Image":
        name = _non_empty_string("name", name)
        if tag is not None:
            tag = _non_empty_string("tag", tag)
        build_spec = _ImageBuildSpec(
            id=name,
            context_path=str(context_path),
            tag=tag,
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


@dataclass(frozen=True)
class SandboxJobRecord:
    sandbox_id: str
    sandbox_generation: int
    job_id: str
    spec_sha256: str
    state: str
    pid: int = 0
    started_at: str = ""
    completed_at: str = ""
    exit_code: int | None = None
    signal: int = 0
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    sequence: int = 0
    updated_at: str = ""

    @classmethod
    def from_payload(cls, payload: object) -> "SandboxJobRecord":
        if not isinstance(payload, dict):
            raise SandboxApiError(
                "gateway returned an invalid job payload", body=payload
            )
        try:
            record = cls(
                sandbox_id=str(payload["sandbox_id"]),
                sandbox_generation=int(payload["sandbox_generation"]),
                job_id=str(payload["job_id"]),
                spec_sha256=str(payload["spec_sha256"]),
                state=str(payload["state"]),
                pid=max(0, int(payload.get("pid") or 0)),
                started_at=str(payload.get("started_at") or ""),
                completed_at=str(payload.get("completed_at") or ""),
                exit_code=(
                    int(payload["exit_code"])
                    if payload.get("exit_code") is not None
                    else None
                ),
                signal=max(0, int(payload.get("signal") or 0)),
                stdout_bytes=max(0, int(payload.get("stdout_bytes") or 0)),
                stderr_bytes=max(0, int(payload.get("stderr_bytes") or 0)),
                stdout_truncated=bool(payload.get("stdout_truncated", False)),
                stderr_truncated=bool(payload.get("stderr_truncated", False)),
                sequence=max(0, int(payload.get("sequence") or 0)),
                updated_at=str(payload.get("updated_at") or ""),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise SandboxApiError(
                "gateway returned an invalid job payload",
                body=payload,
            ) from exc
        if (
            not record.sandbox_id
            or record.sandbox_generation < 1
            or not record.job_id
            or record.state not in {"starting", "running", *TERMINAL_JOB_STATES}
        ):
            raise SandboxApiError(
                "gateway returned an invalid job payload", body=payload
            )
        return record

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL_JOB_STATES

    @property
    def success(self) -> bool:
        return self.state == "exited" and self.exit_code == 0


@dataclass(frozen=True)
class SandboxJobLogChunk:
    stream: str
    offset: int
    next_offset: int
    data: bytes
    eof: bool

    @classmethod
    def from_payload(cls, payload: object) -> "SandboxJobLogChunk":
        if not isinstance(payload, dict):
            raise SandboxApiError(
                "gateway returned an invalid job log payload", body=payload
            )
        try:
            stream = str(payload["stream"])
            offset = int(payload["offset"])
            next_offset = int(payload["next_offset"])
            data = base64.b64decode(str(payload.get("data") or ""), validate=True)
        except (KeyError, TypeError, ValueError) as exc:
            raise SandboxApiError(
                "gateway returned an invalid job log payload",
                body=payload,
            ) from exc
        if (
            stream not in {"stdout", "stderr"}
            or offset < 0
            or next_offset != offset + len(data)
        ):
            raise SandboxApiError(
                "gateway returned an invalid job log payload", body=payload
            )
        return cls(
            stream=stream,
            offset=offset,
            next_offset=next_offset,
            data=data,
            eof=bool(payload.get("eof", False)),
        )


class _DirectSandboxOperations:
    def health(self) -> JsonObject:
        return self._request_json("GET", "/healthz")

    def heartbeat(self) -> JsonObject:
        return self._request_json("GET", "/v1/heartbeat")

    def list_prepared_capacity(self) -> JsonObject:
        return self._request_json("GET", "/v1/capacity/prepare")

    def prepare_capacity(
        self,
        *,
        count: int,
        cpus: float | None = None,
        memory_mb: int | None = None,
        disk_mb: int | None = None,
        image: Image | None = None,
        parkable: bool = False,
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
                image=image,
                parkable=parkable,
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

    def delete_sandbox(self, sandbox_id: str) -> JsonObject:
        return self._request_json(
            "DELETE", f"/v1/sandboxes/{_quote_segment(sandbox_id)}"
        )

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
        return self._request_json(
            "GET",
            _exec_events_path(session_id, after, limit, wait_seconds),
        )

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
        return self._request_json(
            "POST", f"/v1/exec/{_quote_segment(session_id)}/close-stdin"
        )

    def pull_image(
        self,
        image: Image,
        *,
        image_id: str | None = None,
        count: int = 1,
        cpus: float | None = None,
        memory_mb: int | None = None,
        disk_mb: int | None = None,
        sandbox_nodes_only: bool = True,
    ) -> JsonObject:
        payload = _image_pull_payload(
            image,
            image_id=image_id,
            count=count,
            cpus=cpus,
            memory_mb=memory_mb,
            disk_mb=disk_mb,
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


@dataclass
class SandboxHandle:
    client: "SandboxClient"
    id: str
    record: JsonObject = field(default_factory=dict)
    create_response: JsonObject = field(default_factory=dict)

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

    def start_job(
        self,
        command: str | Sequence[str],
        *,
        job_id: str | None = None,
        env: Mapping[str, str] | None = None,
        working_dir: str | None = None,
        max_stdout_bytes: int | None = None,
        max_stderr_bytes: int | None = None,
    ) -> "JobHandle":
        return self.client.start_job(
            self.id,
            command,
            job_id=job_id,
            env=env,
            working_dir=working_dir,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
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

    def ssh(self) -> SandboxSshTarget:
        return SandboxSshTarget.from_payload(
            self.id,
            self.client._request_json(
                "GET", f"/v1/sandboxes/{_quote_segment(self.id)}/ssh"
            ),
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

    def snapshot(self, image: Image, *, image_id: str | None = None) -> JsonObject:
        return self.client.snapshot_sandbox(self.id, image, image_id=image_id)


class _ExecState:
    session_id: str
    session: JsonObject
    last_sequence: int

    def _accept_session(self, payload: JsonObject) -> None:
        session = payload.get("session")
        if isinstance(session, dict):
            self.session = session

    def _accept_events(self, payload: JsonObject) -> list[JsonObject]:
        events = _exec_event_payloads(self.session_id, payload.get("events"))
        for event in events:
            self.last_sequence = _next_exec_sequence(
                self.session_id,
                self.last_sequence,
                event,
            )
        self._accept_session(payload)
        return events

    def _result(self, events: list[JsonObject]) -> SandboxExecResult:
        return _exec_result(self.session_id, self.session, events)


@dataclass
class _ImageBuildWait:
    build_id: str
    deadline: float | None
    build: JsonObject | None = None
    last_seen: tuple[object, object, object] | None = None

    def request_timeout(self, default_timeout: float) -> float:
        remaining = self._remaining()
        return _request_timeout_seconds(remaining, default_timeout)

    def accept(
        self,
        build: JsonObject,
        on_status: Callable[[JsonObject], object] | None,
    ) -> bool:
        self.build = build
        seen = (
            build.get("status"),
            build.get("updated_at"),
            len(str(build.get("log_tail") or "")),
        )
        if on_status is not None and seen != self.last_seen:
            on_status(build)
        self.last_seen = seen
        return build.get("status") in {"succeeded", "failed"}

    def delay(self, poll_interval: float) -> float:
        remaining = self._remaining()
        return (
            max(0.1, poll_interval)
            if remaining is None
            else min(max(0.1, poll_interval), remaining)
        )

    def _remaining(self) -> float | None:
        remaining = _remaining_seconds(self.deadline)
        if remaining is not None and remaining <= 0:
            raise TimeoutError(_image_build_timeout_message(self.build_id, self.build))
        return remaining


@dataclass
class ExecHandle(_ExecState):
    client: "SandboxClient"
    session_id: str
    sandbox_id: str
    session: JsonObject = field(default_factory=dict)
    last_sequence: int = 0

    def get(self) -> JsonObject:
        payload = self.client.get_exec_session(self.session_id)
        self._accept_session(payload)
        return payload

    def write_stdin(self, data: str | bytes, *, eof: bool = False) -> JsonObject:
        return self.client.write_exec_stdin(
            self.session_id, _text_payload(data), eof=eof
        )

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
            events = self._accept_events(payload)
            for event in events:
                yield event
            if self.session.get("status") in TERMINAL_EXEC_STATUSES and not events:
                return

    def wait(
        self,
        *,
        timeout_seconds: float | None = None,
        poll_wait_seconds: float = 1.0,
        settle_seconds: float = 0.2,
    ) -> SandboxExecResult:
        events: list[JsonObject] = []
        deadline = _deadline(timeout_seconds)
        terminal_seen = False
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
            new_events = self._accept_events(payload)
            events.extend(new_events)
            if self.session.get("status") in TERMINAL_EXEC_STATUSES:
                terminal_seen = True
                if not new_events:
                    return self._result(events)


@dataclass
class JobHandle:
    client: "SandboxClient"
    sandbox_id: str
    job_id: str
    record: SandboxJobRecord

    def refresh(self) -> SandboxJobRecord:
        self.record = self.client.get_job(self.sandbox_id, self.job_id)
        return self.record

    def wait(
        self,
        *,
        timeout_seconds: float | None = None,
        poll_seconds: float = 1.0,
    ) -> SandboxJobRecord:
        deadline = _deadline(timeout_seconds)
        while True:
            record = self.refresh()
            if record.terminal:
                return record
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError(f"sandbox job timed out: {self.job_id}")
            delay = max(0.05, poll_seconds)
            if deadline is not None:
                delay = min(delay, max(0.0, deadline - time.monotonic()))
            time.sleep(delay)

    def logs(
        self,
        stream: str = "stdout",
        *,
        offset: int = 0,
        limit: int = 1024 * 1024,
    ) -> SandboxJobLogChunk:
        return self.client.read_job_logs(
            self.sandbox_id,
            self.job_id,
            stream=stream,
            offset=offset,
            limit=limit,
        )

    def signal(self, signal: int = 15) -> SandboxJobRecord:
        self.record = self.client.signal_job(
            self.sandbox_id,
            self.job_id,
            signal=signal,
        )
        return self.record


class SandboxClient(_DirectSandboxOperations):
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

    def list_sandboxes(self) -> list[JsonObject]:
        return _records(self._request_json("GET", "/v1/sandboxes"), "sandboxes")

    def get_sandbox(self, sandbox_id: str) -> JsonObject | None:
        for record in self.list_sandboxes():
            spec = record.get("spec")
            if isinstance(spec, dict) and spec.get("id") == sandbox_id:
                return record
        return None

    def create_sandbox(
        self,
        spec: SandboxSpec,
        *,
        request_timeout_seconds: float | None = None,
    ) -> SandboxHandle:
        response = self._request_json(
            "POST",
            "/v1/sandboxes",
            payload=spec.to_dict(),
            timeout_seconds=(
                DEFAULT_CREATE_TIMEOUT_SECONDS
                if request_timeout_seconds is None
                else request_timeout_seconds
            ),
        )
        sandbox_id, record = _sandbox_record(response)
        return SandboxHandle(self, sandbox_id, record=record, create_response=response)

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
        session = _exec_session(response)
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

    def start_job(
        self,
        sandbox_id: str,
        command: str | Sequence[str],
        *,
        job_id: str | None = None,
        env: Mapping[str, str] | None = None,
        working_dir: str | None = None,
        max_stdout_bytes: int | None = None,
        max_stderr_bytes: int | None = None,
    ) -> JobHandle:
        resolved_job_id = _job_id(job_id)
        response = self._request_json(
            "POST",
            f"/v1/sandboxes/{_quote_segment(sandbox_id)}/jobs",
            payload=_job_payload(
                command,
                job_id=resolved_job_id,
                env=env,
                working_dir=working_dir,
                max_stdout_bytes=max_stdout_bytes,
                max_stderr_bytes=max_stderr_bytes,
            ),
        )
        record = _checked_job(response, sandbox_id, resolved_job_id)
        return JobHandle(self, sandbox_id, resolved_job_id, record)

    def get_job(self, sandbox_id: str, job_id: str) -> SandboxJobRecord:
        response = self._request_json(
            "GET",
            f"/v1/sandboxes/{_quote_segment(sandbox_id)}/jobs/{_quote_segment(job_id)}",
        )
        return _checked_job(response, sandbox_id, job_id)

    def read_job_logs(
        self,
        sandbox_id: str,
        job_id: str,
        *,
        stream: str = "stdout",
        offset: int = 0,
        limit: int = 1024 * 1024,
    ) -> SandboxJobLogChunk:
        if stream not in {"stdout", "stderr"}:
            raise ValueError("job log stream must be stdout or stderr")
        query = parse.urlencode(
            {"offset": max(0, int(offset)), "limit": max(1, int(limit))}
        )
        response = self._request_json(
            "GET",
            f"/v1/sandboxes/{_quote_segment(sandbox_id)}/jobs/"
            f"{_quote_segment(job_id)}/logs/{stream}?{query}",
        )
        return SandboxJobLogChunk.from_payload(response)

    def signal_job(
        self,
        sandbox_id: str,
        job_id: str,
        *,
        signal: int = 15,
    ) -> SandboxJobRecord:
        response = self._request_json(
            "POST",
            f"/v1/sandboxes/{_quote_segment(sandbox_id)}/jobs/"
            f"{_quote_segment(job_id)}/signal",
            payload={"signal": int(signal)},
        )
        return _checked_job(response, sandbox_id, job_id)

    def list_images(self) -> list[JsonObject]:
        return _records(self._request_json("GET", "/v1/images"), "images")

    def list_image_builds(self) -> list[JsonObject]:
        return _records(self._request_json("GET", "/v1/images/builds"), "builds")

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
        return _image_build_response(payload)

    def submit_image_build(
        self,
        image: Image,
        *,
        timeout_seconds: float | None = None,
    ) -> JsonObject:
        deadline = _deadline(
            self.timeout_seconds if timeout_seconds is None else timeout_seconds
        )
        with _image_build_request(image) as (payload, archive):
            digest = str(payload["context_archive_digest"])
            size = int(payload["context_archive_size"])
            context_path = f"/v1/image-contexts/{_quote_segment(digest)}"
            try:
                existing = self._request_json(
                    "GET",
                    context_path,
                    timeout_seconds=_remaining_seconds(deadline),
                )
            except SandboxApiError as exc:
                if exc.status_code != 404:
                    raise
                existing = None
            if not _build_context_reference_matches(
                existing,
                digest=digest,
                size=size,
            ):
                self._request_json(
                    "PUT",
                    context_path,
                    body=archive,
                    body_size=size,
                    content_type="application/gzip",
                    timeout_seconds=_remaining_seconds(deadline),
                )
            payload["wait"] = False
            submitted = self._request_json(
                "POST",
                "/v1/images/build",
                payload=payload,
                timeout_seconds=_remaining_seconds(deadline),
            )
        return _image_build_response(submitted)

    def wait_for_image_build(
        self,
        build_id_or_image_id: str,
        *,
        timeout_seconds: float | None = None,
        poll_interval_seconds: float = 5.0,
        on_status: Callable[[JsonObject], object] | None = None,
    ) -> JsonObject:
        state = _ImageBuildWait(build_id_or_image_id, _deadline(timeout_seconds))
        while True:
            build = self.get_image_build(
                build_id_or_image_id,
                timeout_seconds=state.request_timeout(self.timeout_seconds),
            )
            if state.accept(build, on_status):
                return build
            time.sleep(state.delay(poll_interval_seconds))

    def build_image(
        self,
        image: Image,
        *,
        timeout_seconds: float | None = None,
        poll_interval_seconds: float = 5.0,
        on_status: Callable[[JsonObject], object] | None = None,
    ) -> JsonObject:
        deadline = _deadline(timeout_seconds)
        submitted = self.submit_image_build(
            image,
            timeout_seconds=timeout_seconds,
        )
        build = self.wait_for_image_build(
            submitted["build_id"],
            timeout_seconds=_remaining_seconds(deadline),
            poll_interval_seconds=poll_interval_seconds,
            on_status=on_status,
        )
        return _successful_image_build(build)

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
        raw_body, headers, streamed_body = _node_request_content(
            self.headers,
            payload,
            body,
            body_size,
            content_type,
        )
        timeout = self.timeout_seconds if timeout_seconds is None else timeout_seconds
        deadline = _deadline(timeout)
        retry_attempts = _ucloud_unavailable_retry_attempts(method, path)
        for attempt in range(retry_attempts):
            request_timeout = _request_timeout_seconds(
                _required_remaining_seconds(deadline),
                timeout,
            )
            if streamed_body:
                raw_body.seek(0)
            req = request.Request(
                self.base_url + path,
                data=raw_body,
                method=method,
                headers=headers,
            )
            try:
                with open_no_redirect(req, timeout=request_timeout) as response:
                    raw = read_sync_response(
                        response,
                        limit=MAX_JSON_RESPONSE_BYTES,
                    ).decode("utf-8")
                    return _decode_node_json(
                        raw,
                        status=int(getattr(response, "status", 200)),
                        headers=response_headers(response),
                    )
            except error.HTTPError as exc:
                api_error = _sync_node_error(exc)
                delay = _retry_error(
                    api_error,
                    attempt,
                    method=method,
                    path=path,
                    max_attempts=retry_attempts,
                )
                if delay is not None and _sleep_for_retry(delay, deadline):
                    continue
                raise api_error from exc
            except ResponseTooLargeError as exc:
                raise SandboxApiError(str(exc)) from exc
            except OSError as exc:
                raise SandboxApiError(f"node-agent request failed: {exc}") from exc
        raise AssertionError("unreachable UCloud unavailable retry state")

    def _request_bytes(self, method: str, path: str) -> bytes:
        deadline = _deadline(self.timeout_seconds)
        retry_attempts = _ucloud_unavailable_retry_attempts(method, path)
        for attempt in range(retry_attempts):
            req = request.Request(
                self.base_url + path,
                method=method,
                headers=dict(self.headers),
            )
            try:
                with open_no_redirect(
                    req,
                    timeout=_request_timeout_seconds(
                        _required_remaining_seconds(deadline),
                        self.timeout_seconds,
                    ),
                ) as response:
                    return read_sync_response(
                        response,
                        limit=MAX_FILE_RESPONSE_BYTES,
                    )
            except error.HTTPError as exc:
                api_error = _sync_node_error(exc)
                delay = _retry_error(
                    api_error,
                    attempt,
                    method=method,
                    path=path,
                    max_attempts=retry_attempts,
                )
                if delay is not None and _sleep_for_retry(delay, deadline):
                    continue
                raise api_error from exc
            except ResponseTooLargeError as exc:
                raise SandboxApiError(str(exc)) from exc
            except OSError as exc:
                raise SandboxApiError(f"node-agent request failed: {exc}") from exc
        raise AssertionError("unreachable UCloud unavailable retry state")


@dataclass
class AsyncSandboxHandle:
    client: "AsyncSandboxClient"
    id: str
    record: JsonObject = field(default_factory=dict)
    create_response: JsonObject = field(default_factory=dict)

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

    async def start_job(
        self,
        command: str | Sequence[str],
        *,
        job_id: str | None = None,
        env: Mapping[str, str] | None = None,
        working_dir: str | None = None,
        max_stdout_bytes: int | None = None,
        max_stderr_bytes: int | None = None,
    ) -> "AsyncJobHandle":
        return await self.client.start_job(
            self.id,
            command,
            job_id=job_id,
            env=env,
            working_dir=working_dir,
            max_stdout_bytes=max_stdout_bytes,
            max_stderr_bytes=max_stderr_bytes,
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

    async def ssh(self) -> SandboxSshTarget:
        return SandboxSshTarget.from_payload(
            self.id,
            await self.client._request_json(
                "GET", f"/v1/sandboxes/{_quote_segment(self.id)}/ssh"
            ),
        )

    async def upload_file(
        self, container_path: str, content: bytes | str
    ) -> JsonObject:
        return await self.client.upload_file(self.id, container_path, content)

    async def upload_file_from_path(
        self,
        local_path: str | Path,
        container_path: str,
    ) -> JsonObject:
        return await self.client.upload_file_from_path(
            self.id, local_path, container_path
        )

    async def download_file(self, container_path: str) -> bytes:
        return await self.client.download_file(self.id, container_path)

    async def snapshot(
        self, image: Image, *, image_id: str | None = None
    ) -> JsonObject:
        return await self.client.snapshot_sandbox(self.id, image, image_id=image_id)


@dataclass
class AsyncExecHandle(_ExecState):
    client: "AsyncSandboxClient"
    session_id: str
    sandbox_id: str
    session: JsonObject = field(default_factory=dict)
    last_sequence: int = 0

    async def get(self) -> JsonObject:
        payload = await self.client.get_exec_session(self.session_id)
        self._accept_session(payload)
        return payload

    async def write_stdin(self, data: str | bytes, *, eof: bool = False) -> JsonObject:
        return await self.client.write_exec_stdin(
            self.session_id, _text_payload(data), eof=eof
        )

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
            events = self._accept_events(payload)
            for event in events:
                yield event
            if self.session.get("status") in TERMINAL_EXEC_STATUSES and not events:
                return

    async def wait(
        self,
        *,
        timeout_seconds: float | None = None,
        poll_wait_seconds: float = 1.0,
        settle_seconds: float = 0.2,
    ) -> SandboxExecResult:
        events: list[JsonObject] = []
        deadline = _deadline(timeout_seconds)
        terminal_seen = False
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
            new_events = self._accept_events(payload)
            events.extend(new_events)
            if self.session.get("status") in TERMINAL_EXEC_STATUSES:
                terminal_seen = True
                if not new_events:
                    return self._result(events)


@dataclass
class AsyncJobHandle:
    client: "AsyncSandboxClient"
    sandbox_id: str
    job_id: str
    record: SandboxJobRecord

    async def refresh(self) -> SandboxJobRecord:
        self.record = await self.client.get_job(self.sandbox_id, self.job_id)
        return self.record

    async def wait(
        self,
        *,
        timeout_seconds: float | None = None,
        poll_seconds: float = 1.0,
    ) -> SandboxJobRecord:
        deadline = _deadline(timeout_seconds)
        while True:
            record = await self.refresh()
            if record.terminal:
                return record
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError(f"sandbox job timed out: {self.job_id}")
            delay = max(0.05, poll_seconds)
            if deadline is not None:
                delay = min(delay, max(0.0, deadline - time.monotonic()))
            await asyncio.sleep(delay)

    async def logs(
        self,
        stream: str = "stdout",
        *,
        offset: int = 0,
        limit: int = 1024 * 1024,
    ) -> SandboxJobLogChunk:
        return await self.client.read_job_logs(
            self.sandbox_id,
            self.job_id,
            stream=stream,
            offset=offset,
            limit=limit,
        )

    async def signal(self, signal: int = 15) -> SandboxJobRecord:
        self.record = await self.client.signal_job(
            self.sandbox_id,
            self.job_id,
            signal=signal,
        )
        return self.record


class AsyncSandboxClient(_DirectSandboxOperations):
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
        return await super().health()

    async def heartbeat(self) -> JsonObject:
        return await super().heartbeat()

    async def list_sandboxes(self) -> list[JsonObject]:
        return _records(
            await self._request_json("GET", "/v1/sandboxes"),
            "sandboxes",
        )

    async def list_prepared_capacity(self) -> JsonObject:
        return await super().list_prepared_capacity()

    async def prepare_capacity(
        self,
        *,
        count: int,
        cpus: float | None = None,
        memory_mb: int | None = None,
        disk_mb: int | None = None,
        image: Image | None = None,
        parkable: bool = False,
        ttl_seconds: int = 900,
        prepare_id: str | None = None,
    ) -> JsonObject:
        return await super().prepare_capacity(
            count=count,
            cpus=cpus,
            memory_mb=memory_mb,
            disk_mb=disk_mb,
            image=image,
            parkable=parkable,
            ttl_seconds=ttl_seconds,
            prepare_id=prepare_id,
        )

    async def delete_prepared_capacity(self, prepare_id: str) -> JsonObject:
        return await super().delete_prepared_capacity(prepare_id)

    async def list_prepared_builders(self) -> JsonObject:
        return await super().list_prepared_builders()

    async def prepare_builder(
        self,
        *,
        count: int = 1,
        ttl_seconds: int = 900,
        prepare_id: str | None = None,
    ) -> JsonObject:
        return await super().prepare_builder(
            count=count, ttl_seconds=ttl_seconds, prepare_id=prepare_id
        )

    async def delete_prepared_builder(self, prepare_id: str) -> JsonObject:
        return await super().delete_prepared_builder(prepare_id)

    async def get_sandbox(self, sandbox_id: str) -> JsonObject | None:
        for record in await self.list_sandboxes():
            spec = record.get("spec")
            if isinstance(spec, dict) and spec.get("id") == sandbox_id:
                return record
        return None

    async def create_sandbox(
        self,
        spec: SandboxSpec,
        *,
        request_timeout_seconds: float | None = None,
    ) -> AsyncSandboxHandle:
        response = await self._request_json(
            "POST",
            "/v1/sandboxes",
            payload=spec.to_dict(),
            timeout_seconds=(
                DEFAULT_CREATE_TIMEOUT_SECONDS
                if request_timeout_seconds is None
                else request_timeout_seconds
            ),
        )
        sandbox_id, record = _sandbox_record(response)
        return AsyncSandboxHandle(
            self, sandbox_id, record=record, create_response=response
        )

    async def delete_sandbox(self, sandbox_id: str) -> JsonObject:
        return await super().delete_sandbox(sandbox_id)

    async def upload_file(
        self,
        sandbox_id: str,
        container_path: str,
        content: bytes | str,
    ) -> JsonObject:
        return await super().upload_file(sandbox_id, container_path, content)

    async def upload_file_from_path(
        self,
        sandbox_id: str,
        local_path: str | Path,
        container_path: str,
    ) -> JsonObject:
        return await super().upload_file_from_path(
            sandbox_id, local_path, container_path
        )

    async def download_file(self, sandbox_id: str, container_path: str) -> bytes:
        return await super().download_file(sandbox_id, container_path)

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
        session = _exec_session(response)
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

    async def start_job(
        self,
        sandbox_id: str,
        command: str | Sequence[str],
        *,
        job_id: str | None = None,
        env: Mapping[str, str] | None = None,
        working_dir: str | None = None,
        max_stdout_bytes: int | None = None,
        max_stderr_bytes: int | None = None,
    ) -> AsyncJobHandle:
        resolved_job_id = _job_id(job_id)
        response = await self._request_json(
            "POST",
            f"/v1/sandboxes/{_quote_segment(sandbox_id)}/jobs",
            payload=_job_payload(
                command,
                job_id=resolved_job_id,
                env=env,
                working_dir=working_dir,
                max_stdout_bytes=max_stdout_bytes,
                max_stderr_bytes=max_stderr_bytes,
            ),
        )
        record = _checked_job(response, sandbox_id, resolved_job_id)
        return AsyncJobHandle(self, sandbox_id, resolved_job_id, record)

    async def get_job(self, sandbox_id: str, job_id: str) -> SandboxJobRecord:
        response = await self._request_json(
            "GET",
            f"/v1/sandboxes/{_quote_segment(sandbox_id)}/jobs/{_quote_segment(job_id)}",
        )
        return _checked_job(response, sandbox_id, job_id)

    async def read_job_logs(
        self,
        sandbox_id: str,
        job_id: str,
        *,
        stream: str = "stdout",
        offset: int = 0,
        limit: int = 1024 * 1024,
    ) -> SandboxJobLogChunk:
        if stream not in {"stdout", "stderr"}:
            raise ValueError("job log stream must be stdout or stderr")
        query = parse.urlencode(
            {"offset": max(0, int(offset)), "limit": max(1, int(limit))}
        )
        response = await self._request_json(
            "GET",
            f"/v1/sandboxes/{_quote_segment(sandbox_id)}/jobs/"
            f"{_quote_segment(job_id)}/logs/{stream}?{query}",
        )
        return SandboxJobLogChunk.from_payload(response)

    async def signal_job(
        self,
        sandbox_id: str,
        job_id: str,
        *,
        signal: int = 15,
    ) -> SandboxJobRecord:
        response = await self._request_json(
            "POST",
            f"/v1/sandboxes/{_quote_segment(sandbox_id)}/jobs/"
            f"{_quote_segment(job_id)}/signal",
            payload={"signal": int(signal)},
        )
        return _checked_job(response, sandbox_id, job_id)

    async def get_exec_session(self, session_id: str) -> JsonObject:
        return await super().get_exec_session(session_id)

    async def read_exec_events(
        self,
        session_id: str,
        *,
        after: int = 0,
        limit: int = 100,
        wait_seconds: float = 0.0,
    ) -> JsonObject:
        return await super().read_exec_events(
            session_id, after=after, limit=limit, wait_seconds=wait_seconds
        )

    async def write_exec_stdin(
        self,
        session_id: str,
        data: str,
        *,
        eof: bool = False,
    ) -> JsonObject:
        return await super().write_exec_stdin(session_id, data, eof=eof)

    async def close_exec_stdin(self, session_id: str) -> JsonObject:
        return await super().close_exec_stdin(session_id)

    async def list_images(self) -> list[JsonObject]:
        return _records(await self._request_json("GET", "/v1/images"), "images")

    async def list_image_builds(self) -> list[JsonObject]:
        return _records(
            await self._request_json("GET", "/v1/images/builds"),
            "builds",
        )

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
        return _image_build_response(payload)

    async def submit_image_build(
        self,
        image: Image,
        *,
        timeout_seconds: float | None = None,
    ) -> JsonObject:
        deadline = _deadline(
            self.timeout_seconds if timeout_seconds is None else timeout_seconds
        )
        with _image_build_request(image) as (payload, archive):
            digest = str(payload["context_archive_digest"])
            size = int(payload["context_archive_size"])
            context_path = f"/v1/image-contexts/{_quote_segment(digest)}"
            try:
                existing = await self._request_json(
                    "GET",
                    context_path,
                    timeout_seconds=_remaining_seconds(deadline),
                )
            except SandboxApiError as exc:
                if exc.status_code != 404:
                    raise
                existing = None
            if not _build_context_reference_matches(
                existing,
                digest=digest,
                size=size,
            ):
                await self._request_json(
                    "PUT",
                    context_path,
                    body=archive,
                    body_size=size,
                    content_type="application/gzip",
                    timeout_seconds=_remaining_seconds(deadline),
                )
            payload["wait"] = False
            submitted = await self._request_json(
                "POST",
                "/v1/images/build",
                payload=payload,
                timeout_seconds=_remaining_seconds(deadline),
            )
        return _image_build_response(submitted)

    async def wait_for_image_build(
        self,
        build_id_or_image_id: str,
        *,
        timeout_seconds: float | None = None,
        poll_interval_seconds: float = 5.0,
        on_status: Callable[[JsonObject], object] | None = None,
    ) -> JsonObject:
        state = _ImageBuildWait(build_id_or_image_id, _deadline(timeout_seconds))
        while True:
            build = await self.get_image_build(
                build_id_or_image_id,
                timeout_seconds=state.request_timeout(self.timeout_seconds),
            )
            if state.accept(build, on_status):
                return build
            await asyncio.sleep(state.delay(poll_interval_seconds))

    async def build_image(
        self,
        image: Image,
        *,
        timeout_seconds: float | None = None,
        poll_interval_seconds: float = 5.0,
        on_status: Callable[[JsonObject], object] | None = None,
    ) -> JsonObject:
        deadline = _deadline(timeout_seconds)
        submitted = await self.submit_image_build(
            image,
            timeout_seconds=timeout_seconds,
        )
        build = await self.wait_for_image_build(
            submitted["build_id"],
            timeout_seconds=_remaining_seconds(deadline),
            poll_interval_seconds=poll_interval_seconds,
            on_status=on_status,
        )
        return _successful_image_build(build)

    async def pull_image(
        self,
        image: Image,
        *,
        image_id: str | None = None,
        count: int = 1,
        cpus: float | None = None,
        memory_mb: int | None = None,
        disk_mb: int | None = None,
        sandbox_nodes_only: bool = True,
    ) -> JsonObject:
        return await super().pull_image(
            image,
            image_id=image_id,
            count=count,
            cpus=cpus,
            memory_mb=memory_mb,
            disk_mb=disk_mb,
            sandbox_nodes_only=sandbox_nodes_only,
        )

    async def snapshot_sandbox(
        self,
        sandbox_id: str,
        image: Image,
        *,
        image_id: str | None = None,
    ) -> JsonObject:
        return await super().snapshot_sandbox(sandbox_id, image, image_id=image_id)

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
        _, headers, streamed_body = _node_request_content(
            self.headers,
            payload,
            body,
            body_size,
            content_type,
        )
        timeout = self.timeout_seconds if timeout_seconds is None else timeout_seconds
        raw, status, received_headers = await self._send(
            method,
            path,
            payload=payload,
            body=body,
            headers=headers,
            timeout=timeout,
            streamed=streamed_body,
            success_limit=MAX_JSON_RESPONSE_BYTES,
        )
        return _decode_node_json(
            raw.decode("utf-8", errors="replace"),
            status=status,
            headers=received_headers,
        )

    async def _request_bytes(self, method: str, path: str) -> bytes:
        raw, _, _ = await self._send(
            method,
            path,
            payload=None,
            body=None,
            headers=dict(self.headers),
            timeout=self.timeout_seconds,
            streamed=False,
            success_limit=MAX_FILE_RESPONSE_BYTES,
        )
        return raw

    async def _send(
        self,
        method: str,
        path: str,
        *,
        payload: JsonObject | None,
        body: bytes | BinaryIO | None,
        headers: Mapping[str, str],
        timeout: float,
        streamed: bool,
        success_limit: int,
    ) -> tuple[bytes, int, dict[str, str]]:
        client = await self._client()
        deadline = _deadline(timeout)
        retry_attempts = _ucloud_unavailable_retry_attempts(method, path)
        for attempt in range(retry_attempts):
            if streamed:
                body.seek(0)
            async with client.request(
                method,
                self.base_url + path,
                json=payload,
                data=_async_file_chunks(body) if streamed else body,
                headers=headers,
                timeout=_aiohttp_timeout(
                    _request_timeout_seconds(
                        _required_remaining_seconds(deadline),
                        timeout,
                    )
                ),
                allow_redirects=False,
            ) as response:
                try:
                    raw = await read_async_response(
                        response,
                        limit=(
                            MAX_JSON_RESPONSE_BYTES
                            if not 200 <= response.status < 300
                            else success_limit
                        ),
                    )
                except ResponseTooLargeError as exc:
                    raise SandboxApiError(
                        str(exc),
                        status_code=response.status,
                        headers=response_headers(response),
                    ) from exc
                if not 200 <= response.status < 300:
                    api_error = _node_error(
                        raw.decode("utf-8", errors="replace"),
                        status=response.status,
                        headers=response_headers(response),
                    )
                    delay = _retry_error(
                        api_error,
                        attempt,
                        method=method,
                        path=path,
                        max_attempts=retry_attempts,
                    )
                    if delay is not None and await _async_sleep_for_retry(
                        delay,
                        deadline,
                    ):
                        continue
                    raise api_error
                return raw, response.status, response_headers(response)
        raise AssertionError("unreachable UCloud unavailable retry state")


def _records(payload: JsonObject, field: str) -> list[JsonObject]:
    value = payload.get(field)
    return (
        [item for item in value if isinstance(item, dict)]
        if isinstance(value, list)
        else []
    )


def _sandbox_record(response: JsonObject) -> tuple[str, JsonObject]:
    record = response.get("sandbox")
    spec = record.get("spec") if isinstance(record, dict) else None
    sandbox_id = spec.get("id") if isinstance(spec, dict) else None
    if not isinstance(record, dict):
        raise SandboxApiError(
            "node-agent returned an invalid sandbox payload",
            body=response,
        )
    if not isinstance(sandbox_id, str) or not sandbox_id:
        raise SandboxApiError(
            "node-agent sandbox payload is missing spec.id",
            body=response,
        )
    return sandbox_id, record


def _exec_session(response: JsonObject) -> JsonObject:
    session = response.get("session")
    if not isinstance(session, dict) or not isinstance(session.get("id"), str):
        raise SandboxApiError(
            "node-agent returned an invalid exec session payload",
            body=response,
        )
    return session


def _checked_job(
    response: JsonObject,
    sandbox_id: str,
    job_id: str,
) -> SandboxJobRecord:
    record = _job_record(response)
    if record.sandbox_id != sandbox_id or record.job_id != job_id:
        raise SandboxApiError("gateway returned another sandbox job", body=response)
    return record


@contextmanager
def _image_build_request(
    image: Image,
) -> Iterator[tuple[JsonObject, BinaryIO]]:
    if not isinstance(image, Image):
        raise TypeError("build_image() requires an Image from Image.from_dockerfile()")
    spec = image.to_build_spec()
    payload = dict(vars(spec))
    payload["build_args"] = dict(spec.build_args)
    payload["labels"] = dict(spec.labels)
    if payload["tag"] is None:
        payload.pop("tag")
    context_path = Path(str(payload["context_path"]))
    if not context_path.is_dir():
        raise ValueError(f"image build context is not a directory: {context_path}")
    with _tar_gz_directory(context_path) as archive:
        digest, size = _build_context_archive_identity(archive)
        if size > MAX_FILE_BODY_BYTES:
            raise SandboxApiError(
                f"build context exceeds the {MAX_FILE_BODY_BYTES} byte upload limit"
            )
        payload.update(
            {
                "context_path": ".",
                "context_archive_digest": digest,
                "context_archive_size": size,
                "context_archive_format": "tar.gz",
            }
        )
        yield payload, archive


def _image_build_response(payload: JsonObject) -> JsonObject:
    build = payload.get("build")
    if (
        not isinstance(build, dict)
        or not isinstance(build.get("build_id"), str)
        or not build["build_id"]
    ):
        raise SandboxApiError(
            "gateway returned an invalid image build payload",
            body=payload,
        )
    return build


def _successful_image_build(build: JsonObject) -> JsonObject:
    if build.get("status") != "succeeded":
        raise SandboxApiError(
            f"image build failed: {build.get('error') or build.get('status')}",
            body={"build": build},
        )
    return build


def _image_reference(image: object) -> str:
    if not isinstance(image, Image):
        raise TypeError("sandbox image must be an Image")
    return image.reference


def _image_pull_reference(image: Image) -> str:
    if not isinstance(image, Image):
        raise TypeError("image must be an Image")
    return image.tag or image.reference


def _non_empty_string(name: str, value: object) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError(f"{name} cannot be empty")
    return text


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


def _required_remaining_seconds(deadline: float | None) -> float | None:
    remaining = _remaining_seconds(deadline)
    if remaining is not None and remaining <= 0:
        raise TimeoutError("node-agent request deadline expired")
    return remaining


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
    with tempfile.SpooledTemporaryFile(
        max_size=BUILD_CONTEXT_SPOOL_MEMORY_BYTES,
        mode="w+b",
    ) as buffer:
        with gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=buffer,
            mtime=0,
        ) as compressed:
            with tarfile.open(
                fileobj=compressed,
                mode="w|",
                format=tarfile.PAX_FORMAT,
            ) as archive:
                for item in sorted(
                    path.rglob("*"),
                    key=lambda candidate: candidate.relative_to(path).as_posix(),
                ):
                    info = archive.gettarinfo(
                        str(item),
                        arcname=item.relative_to(path).as_posix(),
                    )
                    _normalize_build_context_tar_info(info)
                    if info.isfile():
                        with item.open("rb") as source:
                            archive.addfile(info, source)
                    else:
                        archive.addfile(info)
        buffer.seek(0)
        yield buffer


def _normalize_build_context_tar_info(info: tarfile.TarInfo) -> None:
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.pax_headers = {}


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


async def _async_file_chunks(source: BinaryIO) -> AsyncIterator[bytes]:
    while chunk := await asyncio.to_thread(
        source.read,
        BUILD_CONTEXT_STREAM_CHUNK_BYTES,
    ):
        yield chunk


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


def _job_id(value: str | None) -> str:
    result = (value or f"job-{uuid.uuid4().hex}").strip()
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", result) is None:
        raise ValueError("job_id must match [A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
    return result


def _job_payload(
    command: str | Sequence[str],
    *,
    job_id: str,
    env: Mapping[str, str] | None,
    working_dir: str | None,
    max_stdout_bytes: int | None,
    max_stderr_bytes: int | None,
) -> JsonObject:
    return _present(
        {
            "job_id": job_id,
            "argv": _command_list(command),
            "env": dict(env or {}),
            "cwd": working_dir or "/workspace",
            "max_stdout_bytes": (
                int(max_stdout_bytes) if max_stdout_bytes is not None else None
            ),
            "max_stderr_bytes": (
                int(max_stderr_bytes) if max_stderr_bytes is not None else None
            ),
        }
    )


def _job_record(response: object) -> SandboxJobRecord:
    if not isinstance(response, dict):
        raise SandboxApiError("gateway returned an invalid job response", body=response)
    return SandboxJobRecord.from_payload(response.get("job"))


def _prepare_capacity_payload(
    *,
    count: int,
    cpus: float | None,
    memory_mb: int | None,
    disk_mb: int | None,
    image: Image | None,
    parkable: bool,
    ttl_seconds: int,
    prepare_id: str | None,
) -> JsonObject:
    return _present(
        {
            "count": count,
            "ttl_seconds": ttl_seconds,
            "id": prepare_id,
            "cpus": cpus,
            "memory_mb": memory_mb,
            "disk_mb": disk_mb,
            "image": _image_pull_reference(image) if image is not None else None,
            "parkable": True if parkable else None,
        }
    )


def _image_pull_payload(
    image: Image,
    *,
    image_id: str | None,
    count: int,
    cpus: float | None,
    memory_mb: int | None,
    disk_mb: int | None,
    sandbox_nodes_only: bool,
) -> JsonObject:
    return _present(
        {
            "image": _image_pull_reference(image),
            "count": count,
            "sandbox_nodes_only": sandbox_nodes_only,
            "id": image_id,
            "cpus": cpus,
            "memory_mb": memory_mb,
            "disk_mb": disk_mb,
        }
    )


def _prepare_builder_payload(
    *,
    count: int,
    ttl_seconds: int,
    prepare_id: str | None,
) -> JsonObject:
    return _present({"count": count, "ttl_seconds": ttl_seconds, "id": prepare_id})


def _present(values: JsonObject) -> JsonObject:
    return {key: value for key, value in values.items() if value is not None}


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


def _exec_events_path(
    session_id: str,
    after: int,
    limit: int,
    wait_seconds: float,
) -> str:
    query = parse.urlencode(
        {
            "after": max(0, after),
            "limit": max(1, limit),
            "wait_seconds": max(0.0, wait_seconds),
        }
    )
    return f"/v1/exec/{_quote_segment(session_id)}/events?{query}"


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


def _node_request_content(
    default_headers: Mapping[str, str],
    payload: JsonObject | None,
    body: bytes | BinaryIO | None,
    body_size: int | None,
    content_type: str | None,
) -> tuple[bytes | BinaryIO | None, dict[str, str], bool]:
    serialized = json.dumps(payload).encode("utf-8") if payload is not None else None
    request_body = serialized if serialized is not None else body
    known_size = len(request_body) if isinstance(request_body, bytes) else body_size
    if request_body is not None and known_size is None:
        raise TypeError("body_size is required for streamed request bodies")
    body_limit = MAX_JSON_BODY_BYTES if payload is not None else MAX_FILE_BODY_BYTES
    if known_size is not None and known_size > body_limit:
        raise SandboxApiError(f"request body exceeds the {body_limit} byte limit")
    headers = dict(default_headers)
    if payload is not None:
        headers["Content-Type"] = "application/json"
    elif content_type is not None:
        headers["Content-Type"] = content_type
    streamed = request_body is not None and not isinstance(request_body, bytes)
    if streamed:
        headers["Content-Length"] = str(known_size)
    return request_body, headers, streamed


def _decode_node_json(
    raw: str,
    *,
    status: int,
    headers: Mapping[str, str],
) -> JsonObject:
    try:
        decoded = json.loads(raw) if raw else {}
    except json.JSONDecodeError as exc:
        if 200 <= status < 300:
            raise SandboxApiError(
                f"node-agent returned invalid JSON: {exc}",
                status_code=status,
                body={"error": raw},
                headers=headers,
            ) from exc
        decoded = {"error": raw}
    if not 200 <= status < 300:
        raise SandboxApiError(
            f"node-agent request failed ({status}): {decoded}",
            status_code=status,
            body=decoded,
            headers=headers,
        )
    if not isinstance(decoded, dict):
        raise SandboxApiError(
            "node-agent returned a non-object JSON payload",
            body=decoded,
        )
    return decoded


def _sync_node_error(exc: error.HTTPError) -> SandboxApiError:
    headers = response_headers(exc)
    try:
        raw = read_sync_response(exc, limit=MAX_JSON_RESPONSE_BYTES).decode(
            "utf-8",
            errors="replace",
        )
    except ResponseTooLargeError as size_exc:
        raise SandboxApiError(
            str(size_exc),
            status_code=exc.code,
            headers=headers,
        ) from size_exc
    finally:
        exc.close()
    return _node_error(raw, status=exc.code, headers=headers)


def _node_error(
    raw: str,
    *,
    status: int,
    headers: Mapping[str, str],
) -> SandboxApiError:
    try:
        _decode_node_json(raw, status=status, headers=headers)
    except SandboxApiError as api_error:
        return api_error
    raise AssertionError("HTTP error decoded as success")


def _retry_error(
    api_error: SandboxApiError,
    attempt: int,
    *,
    method: str,
    path: str,
    max_attempts: int,
) -> float | None:
    status = api_error.status_code
    if status is None or not _should_retry_ucloud_unavailable(
        status,
        api_error.body,
        attempt,
        method=method,
        path=path,
        max_attempts=max_attempts,
    ):
        return None
    return _ucloud_unavailable_retry_delay(
        attempt,
        api_error.headers,
        method=method,
        path=path,
    )


def _should_retry_ucloud_unavailable(
    status_code: int,
    body: object,
    attempt: int,
    *,
    method: str = "GET",
    path: str = "",
    max_attempts: int = UCLOUD_UNAVAILABLE_RETRY_ATTEMPTS,
) -> bool:
    if attempt >= max_attempts - 1:
        return False
    normalized_method = method.upper()
    if (
        status_code in {408, 425, 429, 500, 502, 503, 504}
        and isinstance(body, dict)
        and body.get("retryable") is True
        and (
            normalized_method in {"GET", "HEAD", "OPTIONS"}
            or (normalized_method == "POST" and path == "/v1/sandboxes")
        )
    ):
        return True
    if status_code != UCLOUD_UNAVAILABLE_STATUS:
        return False
    text = _ucloud_unavailable_error_text(body).lower()
    return "job is unavailable" in text and "ucloud" in text


def _ucloud_unavailable_retry_attempts(method: str, path: str) -> int:
    if method.upper() == "POST" and path == "/v1/sandboxes":
        return UCLOUD_CREATE_RETRY_ATTEMPTS
    return UCLOUD_UNAVAILABLE_RETRY_ATTEMPTS


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


def _ucloud_unavailable_retry_delay(
    attempt: int,
    headers: object | None = None,
    *,
    method: str = "GET",
    path: str = "",
) -> float:
    max_delay = (
        UCLOUD_CREATE_RETRY_MAX_DELAY_SECONDS
        if method.upper() == "POST" and path == "/v1/sandboxes"
        else UCLOUD_UNAVAILABLE_RETRY_MAX_DELAY_SECONDS
    )
    client_backoff = min(
        max_delay,
        UCLOUD_UNAVAILABLE_RETRY_BASE_DELAY_SECONDS * (2**attempt),
    )
    retry_after = _retry_after_seconds(headers)
    if retry_after is not None:
        return min(
            60.0,
            max(retry_after, client_backoff)
            * (1.0 + random.random() * UCLOUD_RETRY_AFTER_JITTER_RATIO),
        )
    return client_backoff


def _retry_after_seconds(headers: object | None) -> float | None:
    items = getattr(headers, "items", None)
    if not callable(items):
        return None
    raw = next(
        (value for key, value in items() if str(key).lower() == "retry-after"),
        None,
    )
    if raw is None:
        return None
    try:
        return max(0.0, min(60.0, float(raw)))
    except (TypeError, ValueError):
        pass
    try:
        retry_at = parsedate_to_datetime(str(raw))
    except (TypeError, ValueError, OverflowError):
        return None
    if retry_at.tzinfo is None:
        retry_at = retry_at.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    return max(0.0, min(60.0, (retry_at - now).total_seconds()))


def _sleep_for_retry(delay_seconds: float, deadline: float | None) -> bool:
    remaining = _remaining_seconds(deadline)
    if remaining is not None and remaining <= delay_seconds:
        return False
    time.sleep(delay_seconds)
    return True


async def _async_sleep_for_retry(
    delay_seconds: float,
    deadline: float | None,
) -> bool:
    remaining = _remaining_seconds(deadline)
    if remaining is not None and remaining <= delay_seconds:
        return False
    await asyncio.sleep(delay_seconds)
    return True


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
    received = event.get("sequence")
    if isinstance(received, bool) or not isinstance(received, int):
        raise SandboxApiError(
            "gateway returned an exec event with an invalid sequence",
            body={"session_id": session_id, "event": dict(event)},
        )
    expected = previous_sequence + 1
    if received != expected:
        raise ExecEventHistoryLostError(
            session_id,
            expected_sequence=expected,
            received_sequence=received,
        )
    return received


def _exec_result(
    session_id: str,
    session: JsonObject,
    events: list[JsonObject],
) -> SandboxExecResult:
    stdout = "".join(
        str(event.get("data") or "")
        for event in events
        if event.get("stream") == "stdout"
    )
    stderr = "".join(
        str(event.get("data") or "")
        for event in events
        if event.get("stream") == "stderr"
    )
    return SandboxExecResult(
        session_id=session_id,
        status=str(session.get("status") or ""),
        exit_code=session.get("exit_code")
        if isinstance(session.get("exit_code"), int)
        else None,
        stdout=stdout,
        stderr=stderr,
        events=tuple(events),
        session=dict(session),
    )
