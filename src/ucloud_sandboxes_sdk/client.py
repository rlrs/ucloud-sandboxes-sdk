from __future__ import annotations

import asyncio
import base64
import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import gzip
import io
import json
from pathlib import Path
import random
import re
import shlex
import tarfile
import time
from typing import Any, AsyncIterator, Callable, Iterator, Mapping, Sequence
from urllib import error, parse, request
import uuid


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

    @property
    def intent_persisted(self) -> bool | None:
        if not isinstance(self.body, dict) or not isinstance(
            self.body.get("intent_persisted"), bool
        ):
            return None
        return self.body["intent_persisted"]

    @property
    def intents(self) -> tuple[JsonObject, ...]:
        if not isinstance(self.body, dict):
            return ()
        raw = self.body.get("intents")
        if not isinstance(raw, list):
            return ()
        return tuple(dict(item) for item in raw if isinstance(item, dict))


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
        response_sandbox_id = payload.get("sandbox_id")
        if not isinstance(ssh, dict) or response_sandbox_id != sandbox_id:
            raise SandboxApiError("gateway returned an invalid SSH payload", body=payload)
        host = ssh.get("host")
        port = ssh.get("port")
        user = ssh.get("user") or "root"
        if not isinstance(host, str) or not isinstance(port, int):
            raise SandboxApiError("gateway SSH payload is missing host/port", body=payload)
        return cls(
            sandbox_id=sandbox_id,
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
    parkable: bool = False
    managed_process: bool = False

    def to_dict(self) -> JsonObject:
        if self.managed_process and not self.parkable:
            raise ValueError("managed_process requires parkable=True")
        if self.managed_process and self.command:
            raise ValueError("managed_process sandboxes are started with start_job()")
        payload: JsonObject = {
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
        if self.parkable:
            payload["parkable"] = True
        if self.managed_process:
            payload["managed_process"] = True
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

    def to_dict(self) -> JsonObject:
        payload: JsonObject = {
            "id": self.id,
            "context_path": self.context_path,
            "dockerfile": self.dockerfile,
            "push": self.push,
            "build_args": dict(self.build_args),
            "labels": dict(self.labels),
        }
        if self.tag is not None:
            payload["tag"] = self.tag
        return payload


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
            raise SandboxApiError("gateway returned an invalid job payload", body=payload)
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
            raise SandboxApiError("gateway returned an invalid job payload", body=payload)
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
            raise SandboxApiError("gateway returned an invalid job log payload", body=payload)
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
        if stream not in {"stdout", "stderr"} or offset < 0 or next_offset != offset + len(data):
            raise SandboxApiError("gateway returned an invalid job log payload", body=payload)
        return cls(
            stream=stream,
            offset=offset,
            next_offset=next_offset,
            data=data,
            eof=bool(payload.get("eof", False)),
        )


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
            events = raw_events if isinstance(raw_events, list) else []
            for event in events:
                if not isinstance(event, dict):
                    continue
                self.last_sequence = max(self.last_sequence, int(event.get("sequence") or 0))
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
            new_events = [item for item in raw_events if isinstance(item, dict)] if isinstance(raw_events, list) else []
            for event in new_events:
                self.last_sequence = max(self.last_sequence, int(event.get("sequence") or 0))
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
        deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds
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

    def heartbeat(self) -> JsonObject:
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
        **kwargs: Any,
    ) -> SandboxHandle:
        payload = _sandbox_payload(spec, **kwargs)
        response = self._request_json(
            "POST",
            "/v1/sandboxes",
            payload=payload,
            timeout_seconds=(
                DEFAULT_CREATE_TIMEOUT_SECONDS
                if request_timeout_seconds is None
                else request_timeout_seconds
            ),
        )
        record = response.get("sandbox")
        if not isinstance(record, dict):
            raise SandboxApiError("node-agent returned an invalid sandbox payload", body=response)
        sandbox_spec = record.get("spec")
        sandbox_id = sandbox_spec.get("id") if isinstance(sandbox_spec, dict) else None
        if not isinstance(sandbox_id, str) or not sandbox_id:
            raise SandboxApiError("node-agent sandbox payload is missing spec.id", body=response)
        return SandboxHandle(self, sandbox_id, record=record, create_response=response)

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
            Path(local_path).read_bytes(),
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
            raise SandboxApiError("node-agent returned an invalid exec session payload", body=response)
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
        record = _job_record(response)
        if record.sandbox_id != sandbox_id or record.job_id != resolved_job_id:
            raise SandboxApiError("gateway returned another sandbox job", body=response)
        return JobHandle(self, sandbox_id, resolved_job_id, record)

    def get_job(self, sandbox_id: str, job_id: str) -> SandboxJobRecord:
        response = self._request_json(
            "GET",
            f"/v1/sandboxes/{_quote_segment(sandbox_id)}/jobs/{_quote_segment(job_id)}",
        )
        record = _job_record(response)
        if record.sandbox_id != sandbox_id or record.job_id != job_id:
            raise SandboxApiError("gateway returned another sandbox job", body=response)
        return record

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
        record = _job_record(response)
        if record.sandbox_id != sandbox_id or record.job_id != job_id:
            raise SandboxApiError("gateway returned another sandbox job", body=response)
        return record

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
        return _image_build_response(payload)

    def submit_image_build(
        self,
        image: Image,
        *,
        timeout_seconds: float | None = None,
    ) -> JsonObject:
        payload, archive = _image_build_request(image)
        self._request_json(
            "PUT",
            f"/v1/image-contexts/{_quote_segment(str(payload['context_archive_digest']))}",
            body=archive,
            content_type="application/gzip",
            timeout_seconds=timeout_seconds,
        )
        payload["wait"] = False
        submitted = self._request_json(
            "POST",
            "/v1/images/build",
            payload=payload,
            timeout_seconds=timeout_seconds,
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

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        payload: JsonObject | None = None,
        body: bytes | None = None,
        content_type: str | None = None,
        timeout_seconds: float | None = None,
    ) -> JsonObject:
        raw_body = json.dumps(payload).encode("utf-8") if payload is not None else body
        headers = dict(self.headers)
        if payload is not None:
            headers["Content-Type"] = "application/json"
        elif content_type is not None:
            headers["Content-Type"] = content_type
        timeout = self.timeout_seconds if timeout_seconds is None else timeout_seconds
        retry_attempts = _ucloud_unavailable_retry_attempts(method, path)
        for attempt in range(retry_attempts):
            req = request.Request(
                self.base_url + path,
                data=raw_body,
                method=method,
                headers=headers,
            )
            try:
                with request.urlopen(req, timeout=timeout) as response:
                    raw = response.read().decode("utf-8")
                    decoded = json.loads(raw) if raw else {}
            except error.HTTPError as exc:
                raw = exc.read().decode("utf-8", errors="replace")
                response_headers = getattr(exc, "headers", {})
                exc.close()
                decoded = _decode_json_error(raw)
                if _should_retry_ucloud_unavailable(
                    exc.code,
                    decoded,
                    attempt,
                    method=method,
                    path=path,
                    max_attempts=retry_attempts,
                ):
                    time.sleep(
                        _ucloud_unavailable_retry_delay(
                            attempt,
                            response_headers,
                            method=method,
                            path=path,
                        )
                    )
                    continue
                raise SandboxApiError(
                    f"node-agent request failed ({exc.code}): {decoded}",
                    status_code=exc.code,
                    body=decoded,
                    headers=dict(response_headers),
                ) from exc
            except (OSError, json.JSONDecodeError) as exc:
                raise SandboxApiError(f"node-agent request failed: {exc}") from exc
            if not isinstance(decoded, dict):
                raise SandboxApiError("node-agent returned a non-object JSON payload", body=decoded)
            return decoded
        raise AssertionError("unreachable UCloud unavailable retry state")

    def _request_bytes(self, method: str, path: str) -> bytes:
        retry_attempts = _ucloud_unavailable_retry_attempts(method, path)
        for attempt in range(retry_attempts):
            req = request.Request(
                self.base_url + path,
                method=method,
                headers=dict(self.headers),
            )
            try:
                with request.urlopen(req, timeout=self.timeout_seconds) as response:
                    return response.read()
            except error.HTTPError as exc:
                raw = exc.read().decode("utf-8", errors="replace")
                response_headers = getattr(exc, "headers", {})
                exc.close()
                decoded = _decode_json_error(raw)
                if _should_retry_ucloud_unavailable(
                    exc.code,
                    decoded,
                    attempt,
                    method=method,
                    path=path,
                    max_attempts=retry_attempts,
                ):
                    time.sleep(
                        _ucloud_unavailable_retry_delay(
                            attempt,
                            response_headers,
                            method=method,
                            path=path,
                        )
                    )
                    continue
                raise SandboxApiError(
                    f"node-agent request failed ({exc.code}): {decoded}",
                    status_code=exc.code,
                    body=decoded,
                    headers=dict(response_headers),
                ) from exc
            except OSError as exc:
                raise SandboxApiError(f"node-agent request failed: {exc}") from exc
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
            events = raw_events if isinstance(raw_events, list) else []
            for event in events:
                if not isinstance(event, dict):
                    continue
                self.last_sequence = max(self.last_sequence, int(event.get("sequence") or 0))
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
            new_events = [item for item in raw_events if isinstance(item, dict)] if isinstance(raw_events, list) else []
            for event in new_events:
                self.last_sequence = max(self.last_sequence, int(event.get("sequence") or 0))
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
        deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds
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

    async def heartbeat(self) -> JsonObject:
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
        image: Image | None = None,
        parkable: bool = False,
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
                image=image,
                parkable=parkable,
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
        **kwargs: Any,
    ) -> AsyncSandboxHandle:
        payload = _sandbox_payload(spec, **kwargs)
        response = await self._request_json(
            "POST",
            "/v1/sandboxes",
            payload=payload,
            timeout_seconds=(
                DEFAULT_CREATE_TIMEOUT_SECONDS
                if request_timeout_seconds is None
                else request_timeout_seconds
            ),
        )
        record = response.get("sandbox")
        if not isinstance(record, dict):
            raise SandboxApiError("node-agent returned an invalid sandbox payload", body=response)
        sandbox_spec = record.get("spec")
        sandbox_id = sandbox_spec.get("id") if isinstance(sandbox_spec, dict) else None
        if not isinstance(sandbox_id, str) or not sandbox_id:
            raise SandboxApiError("node-agent sandbox payload is missing spec.id", body=response)
        return AsyncSandboxHandle(self, sandbox_id, record=record, create_response=response)

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
            Path(local_path).read_bytes(),
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
            raise SandboxApiError("node-agent returned an invalid exec session payload", body=response)
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
        record = _job_record(response)
        if record.sandbox_id != sandbox_id or record.job_id != resolved_job_id:
            raise SandboxApiError("gateway returned another sandbox job", body=response)
        return AsyncJobHandle(self, sandbox_id, resolved_job_id, record)

    async def get_job(self, sandbox_id: str, job_id: str) -> SandboxJobRecord:
        response = await self._request_json(
            "GET",
            f"/v1/sandboxes/{_quote_segment(sandbox_id)}/jobs/{_quote_segment(job_id)}",
        )
        record = _job_record(response)
        if record.sandbox_id != sandbox_id or record.job_id != job_id:
            raise SandboxApiError("gateway returned another sandbox job", body=response)
        return record

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
        record = _job_record(response)
        if record.sandbox_id != sandbox_id or record.job_id != job_id:
            raise SandboxApiError("gateway returned another sandbox job", body=response)
        return record

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
        return _image_build_response(payload)

    async def submit_image_build(
        self,
        image: Image,
        *,
        timeout_seconds: float | None = None,
    ) -> JsonObject:
        payload, archive = _image_build_request(image)
        await self._request_json(
            "PUT",
            f"/v1/image-contexts/{_quote_segment(str(payload['context_archive_digest']))}",
            body=archive,
            content_type="application/gzip",
            timeout_seconds=timeout_seconds,
        )
        payload["wait"] = False
        submitted = await self._request_json(
            "POST",
            "/v1/images/build",
            payload=payload,
            timeout_seconds=timeout_seconds,
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
        body: bytes | None = None,
        content_type: str | None = None,
        timeout_seconds: float | None = None,
    ) -> JsonObject:
        headers = dict(self.headers)
        if content_type is not None and payload is None:
            headers["Content-Type"] = content_type
        client = await self._client()
        timeout = _aiohttp_timeout(
            self.timeout_seconds if timeout_seconds is None else timeout_seconds
        )
        retry_attempts = _ucloud_unavailable_retry_attempts(method, path)
        for attempt in range(retry_attempts):
            async with client.request(
                method,
                self.base_url + path,
                json=payload,
                data=body,
                headers=headers,
                timeout=timeout,
            ) as response:
                raw = await response.text()
                try:
                    decoded = json.loads(raw) if raw else {}
                except json.JSONDecodeError:
                    decoded = {"error": raw}
                if response.status >= 400:
                    if _should_retry_ucloud_unavailable(
                        response.status,
                        decoded,
                        attempt,
                        method=method,
                        path=path,
                        max_attempts=retry_attempts,
                    ):
                        await asyncio.sleep(
                            _ucloud_unavailable_retry_delay(
                                attempt,
                                getattr(response, "headers", {}),
                                method=method,
                                path=path,
                            )
                        )
                        continue
                    raise SandboxApiError(
                        f"node-agent request failed ({response.status}): {decoded}",
                        status_code=response.status,
                        body=decoded,
                        headers=dict(getattr(response, "headers", {})),
                    )
            if not isinstance(decoded, dict):
                raise SandboxApiError("node-agent returned a non-object JSON payload", body=decoded)
            return decoded
        raise AssertionError("unreachable UCloud unavailable retry state")

    async def _request_bytes(self, method: str, path: str) -> bytes:
        client = await self._client()
        retry_attempts = _ucloud_unavailable_retry_attempts(method, path)
        for attempt in range(retry_attempts):
            async with client.request(
                method,
                self.base_url + path,
                headers=dict(self.headers),
                timeout=_aiohttp_timeout(self.timeout_seconds),
            ) as response:
                raw = await response.read()
                if response.status >= 400:
                    text = raw.decode("utf-8", errors="replace")
                    decoded = _decode_json_error(text)
                    if _should_retry_ucloud_unavailable(
                        response.status,
                        decoded,
                        attempt,
                        method=method,
                        path=path,
                        max_attempts=retry_attempts,
                    ):
                        await asyncio.sleep(
                            _ucloud_unavailable_retry_delay(
                                attempt,
                                getattr(response, "headers", {}),
                                method=method,
                                path=path,
                            )
                        )
                        continue
                    raise SandboxApiError(
                        f"node-agent request failed ({response.status}): {decoded}",
                        status_code=response.status,
                        body=decoded,
                        headers=dict(getattr(response, "headers", {})),
                    )
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
    for nested_field in ("security", "filesystem", "ssh"):
        if payload.get(nested_field) is not None:
            payload[nested_field] = _nested_payload(payload[nested_field])
    if bool(payload.get("managed_process")) and not bool(payload.get("parkable")):
        raise ValueError("managed_process requires parkable=True")
    if bool(payload.get("managed_process")) and payload.get("command"):
        raise ValueError("managed_process sandboxes are started with start_job()")
    return payload


def _image_build_request(image: Image) -> tuple[JsonObject, bytes]:
    if not isinstance(image, Image):
        raise TypeError("build_image() requires an Image from Image.from_dockerfile()")
    payload = image.to_build_spec().to_dict()
    context_path = Path(str(payload["context_path"]))
    if not context_path.is_dir():
        raise ValueError(f"image build context is not a directory: {context_path}")
    archive = _tar_gz_directory(context_path)
    digest = f"sha256:{hashlib.sha256(archive).hexdigest()}"
    payload.update(
        {
            "context_path": ".",
            "context_archive_digest": digest,
            "context_archive_size": len(archive),
            "context_archive_format": "tar.gz",
        }
    )
    return payload, archive


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


def _completed_build_payload(build: JsonObject) -> JsonObject:
    payload: JsonObject = {
        "build": dict(build),
        "image": build.get("image") if isinstance(build.get("image"), dict) else {},
        "command": list(build.get("command") or []),
        "exit_code": build.get("exit_code"),
    }
    if build.get("push_command"):
        payload["push_command"] = list(build.get("push_command") or [])
        payload["push_exit_code"] = build.get("push_exit_code")
    return payload


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


def _tar_gz_directory(path: Path) -> bytes:
    tar_buffer = io.BytesIO()

    def normalize(info: tarfile.TarInfo) -> tarfile.TarInfo:
        info.mtime = 0
        info.uid = 0
        info.gid = 0
        info.uname = ""
        info.gname = ""
        return info

    with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
        for item in sorted(path.rglob("*")):
            archive.add(
                item,
                arcname=item.relative_to(path).as_posix(),
                recursive=False,
                filter=normalize,
            )
    return gzip.compress(tar_buffer.getvalue(), mtime=0)


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
    payload: JsonObject = {
        "job_id": job_id,
        "argv": _command_list(command),
        "env": dict(env or {}),
        "cwd": working_dir or "/workspace",
    }
    if max_stdout_bytes is not None:
        payload["max_stdout_bytes"] = int(max_stdout_bytes)
    if max_stderr_bytes is not None:
        payload["max_stderr_bytes"] = int(max_stderr_bytes)
    return payload


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
    payload: JsonObject = {
        "count": count,
        "ttl_seconds": ttl_seconds,
    }
    if prepare_id is not None:
        payload["id"] = prepare_id
    if cpus is not None:
        payload["cpus"] = cpus
    if memory_mb is not None:
        payload["memory_mb"] = memory_mb
    if disk_mb is not None:
        payload["disk_mb"] = disk_mb
    if image is not None:
        payload["image"] = _image_pull_reference(image)
    if parkable:
        payload["parkable"] = True
    return payload


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
    payload: JsonObject = {
        "image": _image_pull_reference(image),
        "count": count,
        "sandbox_nodes_only": sandbox_nodes_only,
    }
    if image_id is not None:
        payload["id"] = image_id
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


def _decode_json_error(raw: str) -> object:
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {"error": raw}


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
        (
            value
            for key, value in items()
            if str(key).lower() == "retry-after"
        ),
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
