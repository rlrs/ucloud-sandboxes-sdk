from __future__ import annotations

import asyncio
import base64
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import io
import json
from pathlib import Path
import random
import shlex
import tarfile
import time
from typing import Any, AsyncIterator, Callable, Iterator, Mapping, Sequence
from urllib import error, parse, request


JsonObject = dict[str, Any]
TERMINAL_EXEC_STATUSES = {"exited", "failed"}
SANDBOX_TOKEN_HEADER = "X-UCloud-Sandbox-Token"
UCLOUD_UNAVAILABLE_STATUS = 503
UCLOUD_UNAVAILABLE_RETRY_ATTEMPTS = 6
UCLOUD_CREATE_RETRY_ATTEMPTS = 16
UCLOUD_UNAVAILABLE_RETRY_BASE_DELAY_SECONDS = 0.25
UCLOUD_UNAVAILABLE_RETRY_MAX_DELAY_SECONDS = 4.0
UCLOUD_CREATE_RETRY_MAX_DELAY_SECONDS = 30.0
UCLOUD_RETRY_AFTER_JITTER_RATIO = 0.25
DEFAULT_CREATE_TIMEOUT_SECONDS = 10 * 60.0
DEFAULT_FORK_TIMEOUT_SECONDS = 3600.0
MAX_FORK_BATCH_SIZE = 64


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
class SandboxForkProtocolSpec:
    prepare_command: Sequence[str]
    ready_command: Sequence[str]
    version: str = "agent-v1"
    timeout_seconds: int = 30

    def to_dict(self) -> JsonObject:
        if self.version != "agent-v1":
            raise ValueError("fork protocol version must be 'agent-v1'")
        if isinstance(self.prepare_command, (str, bytes)) or isinstance(
            self.ready_command, (str, bytes)
        ):
            raise TypeError("fork protocol commands must be sequences of arguments")
        prepare = [str(item) for item in self.prepare_command]
        ready = [str(item) for item in self.ready_command]
        if not prepare or not ready or any(not item for item in (*prepare, *ready)):
            raise ValueError("fork protocol prepare and ready commands are required")
        if not 1 <= self.timeout_seconds <= 60:
            raise ValueError("fork protocol timeout_seconds must be in [1, 60]")
        return {
            "version": self.version,
            "prepare_command": prepare,
            "ready_command": ready,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass(frozen=True)
class SandboxForkSpec:
    id: str
    env: Mapping[str, str] = field(default_factory=dict)
    labels: Mapping[str, str] = field(default_factory=dict)
    ttl_seconds: int | None = None
    memory_mb: int | None = None
    cpus: float | None = None

    def to_dict(self) -> JsonObject:
        sandbox_id = self.id.strip()
        if not sandbox_id:
            raise ValueError("fork sandbox id cannot be empty")
        payload: JsonObject = {"id": sandbox_id}
        if self.env:
            payload["env"] = {str(key): str(value) for key, value in self.env.items()}
        if self.labels:
            payload["labels"] = {
                str(key): str(value) for key, value in self.labels.items()
            }
        if self.ttl_seconds is not None:
            payload["ttl_seconds"] = self.ttl_seconds
        if self.memory_mb is not None:
            payload["memory_mb"] = self.memory_mb
        if self.cpus is not None:
            payload["cpus"] = self.cpus
        return payload


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
    forkable: bool = False
    parkable: bool = False
    fork_protocol: SandboxForkProtocolSpec | Mapping[str, Any] | None = None

    def to_dict(self) -> JsonObject:
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
        if self.forkable:
            payload["forkable"] = True
        if self.parkable:
            payload["parkable"] = True
        if self.fork_protocol is not None:
            payload["fork_protocol"] = _nested_payload(self.fork_protocol)
        return payload


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
    fork_metadata: JsonObject = field(default_factory=dict)

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

    def fork(
        self,
        spec: SandboxForkSpec | None = None,
        *,
        id: str | None = None,
        env: Mapping[str, str] | None = None,
        labels: Mapping[str, str] | None = None,
        ttl_seconds: int | None = None,
        memory_mb: int | None = None,
        cpus: float | None = None,
        timeout_seconds: float = DEFAULT_FORK_TIMEOUT_SECONDS,
    ) -> "SandboxHandle":
        return self.client.fork_sandbox(
            self.id,
            spec,
            id=id,
            env=env,
            labels=labels,
            ttl_seconds=ttl_seconds,
            memory_mb=memory_mb,
            cpus=cpus,
            timeout_seconds=timeout_seconds,
        )

    def fork_many(
        self,
        sandboxes: Sequence[SandboxForkSpec],
        *,
        timeout_seconds: float = DEFAULT_FORK_TIMEOUT_SECONDS,
    ) -> tuple["SandboxHandle", ...]:
        return self.client.fork_sandboxes(
            self.id,
            sandboxes,
            timeout_seconds=timeout_seconds,
        )

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

    def fork_sandbox(
        self,
        source_sandbox_id: str,
        spec: SandboxForkSpec | None = None,
        *,
        id: str | None = None,
        env: Mapping[str, str] | None = None,
        labels: Mapping[str, str] | None = None,
        ttl_seconds: int | None = None,
        memory_mb: int | None = None,
        cpus: float | None = None,
        timeout_seconds: float = DEFAULT_FORK_TIMEOUT_SECONDS,
    ) -> SandboxHandle:
        target = _fork_sandbox_payload(
            spec,
            id=id,
            env=env,
            labels=labels,
            ttl_seconds=ttl_seconds,
            memory_mb=memory_mb,
            cpus=cpus,
        )
        response = self._request_json(
            "POST",
            f"/v1/sandboxes/{_quote_segment(source_sandbox_id)}/forks",
            payload={"sandbox": target},
            timeout_seconds=timeout_seconds,
        )
        items = _fork_response_items(response, (str(target["id"]),), batch=False)
        record, metadata = items[0]
        return SandboxHandle(
            self,
            str(target["id"]),
            record=record,
            create_response=response,
            fork_metadata=metadata,
        )

    def fork_sandboxes(
        self,
        source_sandbox_id: str,
        sandboxes: Sequence[SandboxForkSpec],
        *,
        timeout_seconds: float = DEFAULT_FORK_TIMEOUT_SECONDS,
    ) -> tuple[SandboxHandle, ...]:
        targets = _fork_batch_payload(sandboxes)
        expected_ids = tuple(str(item["id"]) for item in targets)
        response = self._request_json(
            "POST",
            f"/v1/sandboxes/{_quote_segment(source_sandbox_id)}/forks",
            payload={"sandboxes": targets},
            timeout_seconds=timeout_seconds,
        )
        items = _fork_response_items(response, expected_ids, batch=True)
        return tuple(
            SandboxHandle(
                self,
                sandbox_id,
                record=record,
                create_response=response,
                fork_metadata=metadata,
            )
            for sandbox_id, (record, metadata) in zip(expected_ids, items)
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
        payload = _image_build_payload(image, upload_context=upload_context)
        payload["wait"] = False
        submitted = self._request_json(
            "POST",
            "/v1/images/build",
            payload=payload,
            timeout_seconds=timeout_seconds,
        )
        build = submitted.get("build")
        if not isinstance(build, dict):
            raise SandboxApiError("gateway returned an invalid image build payload", body=submitted)
        return build

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
        timeout_seconds: float | None = None,
        poll_interval_seconds: float = 5.0,
        on_status: Callable[[JsonObject], object] | None = None,
    ) -> JsonObject:
        deadline = _deadline(timeout_seconds)
        submitted = self.submit_image_build(
            image,
            upload_context=upload_context,
            timeout_seconds=timeout_seconds,
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
    fork_metadata: JsonObject = field(default_factory=dict)

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

    async def fork(
        self,
        spec: SandboxForkSpec | None = None,
        *,
        id: str | None = None,
        env: Mapping[str, str] | None = None,
        labels: Mapping[str, str] | None = None,
        ttl_seconds: int | None = None,
        memory_mb: int | None = None,
        cpus: float | None = None,
        timeout_seconds: float = DEFAULT_FORK_TIMEOUT_SECONDS,
    ) -> "AsyncSandboxHandle":
        return await self.client.fork_sandbox(
            self.id,
            spec,
            id=id,
            env=env,
            labels=labels,
            ttl_seconds=ttl_seconds,
            memory_mb=memory_mb,
            cpus=cpus,
            timeout_seconds=timeout_seconds,
        )

    async def fork_many(
        self,
        sandboxes: Sequence[SandboxForkSpec],
        *,
        timeout_seconds: float = DEFAULT_FORK_TIMEOUT_SECONDS,
    ) -> tuple["AsyncSandboxHandle", ...]:
        return await self.client.fork_sandboxes(
            self.id,
            sandboxes,
            timeout_seconds=timeout_seconds,
        )

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

    async def fork_sandbox(
        self,
        source_sandbox_id: str,
        spec: SandboxForkSpec | None = None,
        *,
        id: str | None = None,
        env: Mapping[str, str] | None = None,
        labels: Mapping[str, str] | None = None,
        ttl_seconds: int | None = None,
        memory_mb: int | None = None,
        cpus: float | None = None,
        timeout_seconds: float = DEFAULT_FORK_TIMEOUT_SECONDS,
    ) -> AsyncSandboxHandle:
        target = _fork_sandbox_payload(
            spec,
            id=id,
            env=env,
            labels=labels,
            ttl_seconds=ttl_seconds,
            memory_mb=memory_mb,
            cpus=cpus,
        )
        response = await self._request_json(
            "POST",
            f"/v1/sandboxes/{_quote_segment(source_sandbox_id)}/forks",
            payload={"sandbox": target},
            timeout_seconds=timeout_seconds,
        )
        items = _fork_response_items(response, (str(target["id"]),), batch=False)
        record, metadata = items[0]
        return AsyncSandboxHandle(
            self,
            str(target["id"]),
            record=record,
            create_response=response,
            fork_metadata=metadata,
        )

    async def fork_sandboxes(
        self,
        source_sandbox_id: str,
        sandboxes: Sequence[SandboxForkSpec],
        *,
        timeout_seconds: float = DEFAULT_FORK_TIMEOUT_SECONDS,
    ) -> tuple[AsyncSandboxHandle, ...]:
        targets = _fork_batch_payload(sandboxes)
        expected_ids = tuple(str(item["id"]) for item in targets)
        response = await self._request_json(
            "POST",
            f"/v1/sandboxes/{_quote_segment(source_sandbox_id)}/forks",
            payload={"sandboxes": targets},
            timeout_seconds=timeout_seconds,
        )
        items = _fork_response_items(response, expected_ids, batch=True)
        return tuple(
            AsyncSandboxHandle(
                self,
                sandbox_id,
                record=record,
                create_response=response,
                fork_metadata=metadata,
            )
            for sandbox_id, (record, metadata) in zip(expected_ids, items)
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
        payload = _image_build_payload(image, upload_context=upload_context)
        payload["wait"] = False
        submitted = await self._request_json(
            "POST",
            "/v1/images/build",
            payload=payload,
            timeout_seconds=timeout_seconds,
        )
        build = submitted.get("build")
        if not isinstance(build, dict):
            raise SandboxApiError("gateway returned an invalid image build payload", body=submitted)
        return build

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
        timeout_seconds: float | None = None,
        poll_interval_seconds: float = 5.0,
        on_status: Callable[[JsonObject], object] | None = None,
    ) -> JsonObject:
        deadline = _deadline(timeout_seconds)
        submitted = await self.submit_image_build(
            image,
            upload_context=upload_context,
            timeout_seconds=timeout_seconds,
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
    if payload.get("fork_protocol") is not None:
        payload["fork_protocol"] = _nested_payload(payload["fork_protocol"])
    if bool(payload.get("forkable")) and not payload.get("fork_protocol"):
        raise ValueError("forkable sandboxes require fork_protocol")
    if payload.get("fork_protocol") and not bool(payload.get("forkable")):
        raise ValueError("fork_protocol requires forkable=True")
    return payload


def _fork_sandbox_payload(
    spec: SandboxForkSpec | None,
    *,
    id: str | None,
    env: Mapping[str, str] | None,
    labels: Mapping[str, str] | None,
    ttl_seconds: int | None,
    memory_mb: int | None,
    cpus: float | None,
) -> JsonObject:
    if spec is not None and not isinstance(spec, SandboxForkSpec):
        raise TypeError("fork spec must be a SandboxForkSpec")
    payload = spec.to_dict() if spec is not None else {}
    if id is not None:
        payload["id"] = id
    if env is not None:
        payload["env"] = {str(key): str(value) for key, value in env.items()}
    if labels is not None:
        payload["labels"] = {
            str(key): str(value) for key, value in labels.items()
        }
    if ttl_seconds is not None:
        payload["ttl_seconds"] = ttl_seconds
    if memory_mb is not None:
        payload["memory_mb"] = memory_mb
    if cpus is not None:
        payload["cpus"] = cpus
    sandbox_id = str(payload.get("id") or "").strip()
    if not sandbox_id:
        raise ValueError("fork sandbox id is required")
    payload["id"] = sandbox_id
    if payload.get("ttl_seconds") is not None and int(payload["ttl_seconds"]) <= 0:
        raise ValueError("fork ttl_seconds must be positive")
    if payload.get("memory_mb") is not None and int(payload["memory_mb"]) <= 0:
        raise ValueError("fork memory_mb must be positive")
    if payload.get("cpus") is not None and float(payload["cpus"]) <= 0:
        raise ValueError("fork cpus must be positive")
    return payload


def _fork_batch_payload(
    sandboxes: Sequence[SandboxForkSpec],
) -> list[JsonObject]:
    if not 1 <= len(sandboxes) <= MAX_FORK_BATCH_SIZE:
        raise ValueError(
            f"fork batch size must be in [1, {MAX_FORK_BATCH_SIZE}]"
        )
    payloads = [
        _fork_sandbox_payload(
            spec,
            id=None,
            env=None,
            labels=None,
            ttl_seconds=None,
            memory_mb=None,
            cpus=None,
        )
        for spec in sandboxes
    ]
    ids = [str(payload["id"]) for payload in payloads]
    if len(set(ids)) != len(ids):
        raise ValueError("fork batch sandbox ids must be unique")
    return payloads


def _fork_response_items(
    response: JsonObject,
    expected_ids: Sequence[str],
    *,
    batch: bool,
) -> tuple[tuple[JsonObject, JsonObject], ...]:
    if response.get("intent_persisted") is not True:
        raise SandboxApiError(
            "gateway fork response did not confirm durable intents",
            body=response,
        )
    raw_records = response.get("sandboxes") if batch else [response.get("sandbox")]
    raw_forks = response.get("forks") if batch else [response.get("fork")]
    if not isinstance(raw_records, list) or not isinstance(raw_forks, list):
        raise SandboxApiError("gateway returned an invalid fork payload", body=response)
    if len(raw_records) != len(expected_ids) or len(raw_forks) != len(expected_ids):
        raise SandboxApiError(
            "gateway fork response length does not match the request",
            body=response,
        )
    items: list[tuple[JsonObject, JsonObject]] = []
    checkpoint_id: str | None = None
    for expected_id, raw_record, raw_fork in zip(
        expected_ids,
        raw_records,
        raw_forks,
    ):
        if not isinstance(raw_record, dict) or not isinstance(raw_fork, dict):
            raise SandboxApiError(
                "gateway returned an invalid fork record",
                body=response,
            )
        record = dict(raw_record)
        metadata = dict(raw_fork)
        record_id = _sandbox_record_id(record)
        if record_id != expected_id or metadata.get("sandbox_id") != expected_id:
            raise SandboxApiError(
                "gateway fork response sandbox identity does not match the request",
                body=response,
            )
        item_checkpoint = metadata.get("checkpoint_id")
        if not isinstance(item_checkpoint, str) or not item_checkpoint:
            raise SandboxApiError(
                "gateway fork response is missing checkpoint identity",
                body=response,
            )
        if checkpoint_id is None:
            checkpoint_id = item_checkpoint
        elif checkpoint_id != item_checkpoint:
            raise SandboxApiError(
                "gateway batch fork response used multiple checkpoints",
                body=response,
            )
        if metadata.get("restored") is not True:
            raise SandboxApiError(
                "gateway fork response did not confirm restore",
                body=response,
            )
        items.append((record, metadata))
    return tuple(items)


def _sandbox_record_id(record: JsonObject) -> str:
    direct = record.get("id") or record.get("sandbox_id")
    if isinstance(direct, str) and direct:
        return direct
    spec = record.get("spec")
    nested = spec.get("id") if isinstance(spec, dict) else None
    return nested if isinstance(nested, str) else ""


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
    payload["context_archive_base64"] = base64.b64encode(
        _tar_gz_directory(path)
    ).decode("ascii")
    payload["context_archive_format"] = "tar.gz"
    payload["context_path"] = "."


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
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for item in sorted(path.rglob("*")):
            archive.add(item, arcname=item.relative_to(path).as_posix(), recursive=False)
    return buffer.getvalue()


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
