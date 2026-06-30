from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, field
import io
import json
from pathlib import Path
import tarfile
import time
from typing import Any, AsyncIterator, Iterator, Mapping, Sequence
from urllib import error, parse, request


JsonObject = dict[str, Any]
TERMINAL_EXEC_STATUSES = {"exited", "failed"}


class SandboxApiError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        body: object | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


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
class SandboxSpec:
    id: str
    image: str
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
            "image": self.image,
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
class ImageBuildSpec:
    id: str
    tag: str
    context_path: str
    dockerfile: str = "Dockerfile"
    build_args: Mapping[str, str] = field(default_factory=dict)
    labels: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> JsonObject:
        return {
            "id": self.id,
            "tag": self.tag,
            "context_path": self.context_path,
            "dockerfile": self.dockerfile,
            "build_args": dict(self.build_args),
            "labels": dict(self.labels),
        }


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

    def snapshot(self, image: str, *, image_id: str | None = None) -> JsonObject:
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
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.headers = dict(headers or {})

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
                ttl_seconds=ttl_seconds,
                prepare_id=prepare_id,
            ),
        )

    def delete_prepared_capacity(self, prepare_id: str) -> JsonObject:
        return self._request_json(
            "DELETE",
            f"/v1/capacity/prepare/{_quote_segment(prepare_id)}",
        )

    def get_sandbox(self, sandbox_id: str) -> JsonObject | None:
        for record in self.list_sandboxes():
            spec = record.get("spec")
            if isinstance(spec, dict) and spec.get("id") == sandbox_id:
                return record
        return None

    def create_sandbox(
        self,
        spec: SandboxSpec | Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> SandboxHandle:
        payload = _sandbox_payload(spec, **kwargs)
        response = self._request_json("POST", "/v1/sandboxes", payload=payload)
        record = response.get("sandbox")
        if not isinstance(record, dict):
            raise SandboxApiError("node-agent returned an invalid sandbox payload", body=response)
        sandbox_spec = record.get("spec")
        sandbox_id = sandbox_spec.get("id") if isinstance(sandbox_spec, dict) else None
        if not isinstance(sandbox_id, str) or not sandbox_id:
            raise SandboxApiError("node-agent sandbox payload is missing spec.id", body=response)
        return SandboxHandle(self, sandbox_id, record=record, create_response=response)

    def delete_sandbox(self, sandbox_id: str) -> JsonObject:
        return self._request_json("DELETE", f"/v1/sandboxes/{_quote_segment(sandbox_id)}")

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

    def list_images(self) -> list[JsonObject]:
        payload = self._request_json("GET", "/v1/images")
        images = payload.get("images")
        return [item for item in images if isinstance(item, dict)] if isinstance(images, list) else []

    def build_image(
        self,
        spec: ImageBuildSpec | Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> JsonObject:
        return self._request_json("POST", "/v1/images/build", payload=_image_build_payload(spec, **kwargs))

    def pull_image(self, image: str, *, image_id: str | None = None) -> JsonObject:
        payload: JsonObject = {"image": image}
        if image_id is not None:
            payload["id"] = image_id
        return self._request_json("POST", "/v1/images/pull", payload=payload)

    def snapshot_sandbox(
        self,
        sandbox_id: str,
        image: str,
        *,
        image_id: str | None = None,
    ) -> JsonObject:
        payload: JsonObject = {"image": image}
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
    ) -> JsonObject:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = dict(self.headers)
        if payload is not None:
            headers["Content-Type"] = "application/json"
        req = request.Request(
            self.base_url + path,
            data=body,
            method=method,
            headers=headers,
        )
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as response:
                raw = response.read().decode("utf-8")
                decoded = json.loads(raw) if raw else {}
        except error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            exc.close()
            decoded = _decode_json_error(raw)
            raise SandboxApiError(
                f"node-agent request failed ({exc.code}): {decoded}",
                status_code=exc.code,
                body=decoded,
            ) from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise SandboxApiError(f"node-agent request failed: {exc}") from exc
        if not isinstance(decoded, dict):
            raise SandboxApiError("node-agent returned a non-object JSON payload", body=decoded)
        return decoded


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

    async def snapshot(self, image: str, *, image_id: str | None = None) -> JsonObject:
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
        session: Any | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._session = session
        self._owned_session: Any | None = None
        self.headers = dict(headers or {})

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
                ttl_seconds=ttl_seconds,
                prepare_id=prepare_id,
            ),
        )

    async def delete_prepared_capacity(self, prepare_id: str) -> JsonObject:
        return await self._request_json(
            "DELETE",
            f"/v1/capacity/prepare/{_quote_segment(prepare_id)}",
        )

    async def get_sandbox(self, sandbox_id: str) -> JsonObject | None:
        for record in await self.list_sandboxes():
            spec = record.get("spec")
            if isinstance(spec, dict) and spec.get("id") == sandbox_id:
                return record
        return None

    async def create_sandbox(
        self,
        spec: SandboxSpec | Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> AsyncSandboxHandle:
        payload = _sandbox_payload(spec, **kwargs)
        response = await self._request_json("POST", "/v1/sandboxes", payload=payload)
        record = response.get("sandbox")
        if not isinstance(record, dict):
            raise SandboxApiError("node-agent returned an invalid sandbox payload", body=response)
        sandbox_spec = record.get("spec")
        sandbox_id = sandbox_spec.get("id") if isinstance(sandbox_spec, dict) else None
        if not isinstance(sandbox_id, str) or not sandbox_id:
            raise SandboxApiError("node-agent sandbox payload is missing spec.id", body=response)
        return AsyncSandboxHandle(self, sandbox_id, record=record, create_response=response)

    async def delete_sandbox(self, sandbox_id: str) -> JsonObject:
        return await self._request_json("DELETE", f"/v1/sandboxes/{_quote_segment(sandbox_id)}")

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

    async def list_images(self) -> list[JsonObject]:
        payload = await self._request_json("GET", "/v1/images")
        images = payload.get("images")
        return [item for item in images if isinstance(item, dict)] if isinstance(images, list) else []

    async def build_image(
        self,
        spec: ImageBuildSpec | Mapping[str, Any] | None = None,
        **kwargs: Any,
    ) -> JsonObject:
        return await self._request_json("POST", "/v1/images/build", payload=_image_build_payload(spec, **kwargs))

    async def pull_image(self, image: str, *, image_id: str | None = None) -> JsonObject:
        payload: JsonObject = {"image": image}
        if image_id is not None:
            payload["id"] = image_id
        return await self._request_json("POST", "/v1/images/pull", payload=payload)

    async def snapshot_sandbox(
        self,
        sandbox_id: str,
        image: str,
        *,
        image_id: str | None = None,
    ) -> JsonObject:
        payload: JsonObject = {"image": image}
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
    ) -> JsonObject:
        headers = dict(self.headers)
        client = await self._client()
        async with client.request(
            method,
            self.base_url + path,
            json=payload,
            headers=headers,
        ) as response:
            raw = await response.text()
            try:
                decoded = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                decoded = {"error": raw}
            if response.status >= 400:
                raise SandboxApiError(
                    f"node-agent request failed ({response.status}): {decoded}",
                    status_code=response.status,
                    body=decoded,
                )
        if not isinstance(decoded, dict):
            raise SandboxApiError("node-agent returned a non-object JSON payload", body=decoded)
        return decoded


def _sandbox_payload(
    spec: SandboxSpec | Mapping[str, Any] | None,
    **kwargs: Any,
) -> JsonObject:
    payload = _object_payload(spec)
    payload.update({key: value for key, value in kwargs.items() if value is not None})
    return payload


def _image_build_payload(
    spec: ImageBuildSpec | Mapping[str, Any] | None,
    **kwargs: Any,
) -> JsonObject:
    upload_context = bool(kwargs.pop("upload_context", True))
    payload = _object_payload(spec)
    payload.update({key: value for key, value in kwargs.items() if value is not None})
    if upload_context:
        _attach_build_context_archive(payload)
    return payload


def _object_payload(spec: object | None) -> JsonObject:
    if spec is None:
        return {}
    if isinstance(spec, Mapping):
        return dict(spec)
    to_dict = getattr(spec, "to_dict", None)
    if callable(to_dict):
        raw = to_dict()
        if isinstance(raw, Mapping):
            return dict(raw)
    raise TypeError("spec must be a mapping or expose to_dict().")


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
    return payload


def _command_list(command: str | Sequence[str]) -> list[str]:
    if isinstance(command, str):
        return [command]
    return [str(item) for item in command]


def _quote_segment(value: str) -> str:
    return parse.quote(value, safe="")


def _text_payload(data: str | bytes) -> str:
    if isinstance(data, bytes):
        return data.decode("utf-8")
    return data


def _decode_json_error(raw: str) -> object:
    try:
        return json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {"error": raw}


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
