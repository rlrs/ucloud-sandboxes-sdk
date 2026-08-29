from __future__ import annotations

import asyncio
import base64
import binascii
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import inspect
import json
import os
from threading import Event, Thread
import time
from typing import Any, Awaitable, Callable, Mapping
from urllib import error, parse, request
from urllib.parse import quote
import uuid
import warnings

from ._http import (
    ResponseTooLargeError,
    open_no_redirect,
    read_async_response,
    read_sync_response,
    response_headers,
)
from ._agent_contract import require_agent_sandbox_record


JsonObject = dict[str, Any]
MAX_RELAY_JSON_BYTES = 32 * 1024 * 1024
MAX_RELAY_HTTP_BODY_BYTES = MAX_RELAY_JSON_BYTES // 2
RELAY_POLL_TIMEOUT_GRACE_SECONDS = 5.0
AGENT_LIFECYCLE_METADATA_KEY = "_ucloud_agent_lifecycle"
MANAGED_AGENT_LIFECYCLE = "managed-process-v1"


class RelayApiError(RuntimeError):
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


def model_relay_env(
    relay_url: str,
    rollout_id: str,
    *,
    api_key: str = "intercepted",
) -> dict[str, str]:
    base = relay_url.rstrip("/")
    return {
        "VF_RELAY_ROLLOUT_ID": rollout_id,
        "OPENAI_BASE_URL": f"{base}/rollouts/{quote(rollout_id, safe='')}/v1",
        "OPENAI_API_KEY": api_key,
    }


def http_tunnel_url(
    relay_url: str,
    rollout_id: str,
    path: str = "/",
    *,
    registration_token: str | None = None,
) -> str:
    suffix = "/" + path.lstrip("/")
    base = f"{relay_url.rstrip('/')}/tunnels/{quote(rollout_id, safe='')}"
    if registration_token is not None:
        _validate_registration_token(registration_token)
        base += f"/_relay/{quote(registration_token, safe='')}"
    return base + suffix


@dataclass(frozen=True)
class RelayRequest:
    request_id: str
    rollout_id: str
    registration_token: str
    endpoint: str
    method: str
    headers: dict[str, str]
    body: object
    body_bytes: bytes
    created_at: float | None = None
    delivered_at: float | None = None
    first_delivered_at: float | None = None
    lease_id: str = ""
    lease_expires_at: float | None = None
    leased_by: str | None = None
    delivery_count: int = 0
    sandbox_id: str | None = None
    sandbox_generation: int | None = None
    expires_at: float | None = None
    idempotency_key: str | None = None
    reattachable: bool = False
    accepted_notified_at: float | None = None
    parked_transport_epoch: str | None = None

    @classmethod
    def from_payload(cls, payload: object) -> "RelayRequest":
        if not isinstance(payload, Mapping):
            raise RelayApiError("relay returned an invalid request", body=payload)
        request_id = _required_string(payload, "request_id")
        rollout_id = _required_string(payload, "rollout_id")
        registration_token = _required_string(payload, "registration_token")
        lease_id = _required_string(payload, "lease_id")
        _validate_registration_token(registration_token)
        headers = payload.get("headers")
        body, body_bytes = _decode_body(payload.get("body"), payload)
        _validate_http_body_size(body_bytes)
        return cls(
            request_id=request_id,
            rollout_id=rollout_id,
            registration_token=registration_token,
            endpoint=str(payload.get("endpoint") or ""),
            method=str(payload.get("method") or "POST"),
            headers=_string_dict(headers),
            body=body,
            body_bytes=body_bytes,
            created_at=_optional_float(payload.get("created_at")),
            delivered_at=_optional_float(payload.get("delivered_at")),
            first_delivered_at=_optional_float(payload.get("first_delivered_at")),
            lease_id=lease_id,
            lease_expires_at=_optional_float(payload.get("lease_expires_at")),
            leased_by=_optional_string(payload.get("leased_by")),
            delivery_count=_int(payload.get("delivery_count"), default=0),
            sandbox_id=_optional_string(payload.get("sandbox_id")),
            sandbox_generation=_optional_int(payload.get("sandbox_generation")),
            expires_at=_optional_float(payload.get("expires_at")),
            idempotency_key=_optional_string(payload.get("idempotency_key")),
            reattachable=_optional_bool(payload.get("reattachable"), default=False),
            accepted_notified_at=_optional_float(payload.get("accepted_notified_at")),
            parked_transport_epoch=_optional_string(
                payload.get("parked_transport_epoch")
            ),
        )


@dataclass(frozen=True)
class RelayPollResult:
    requests: list[RelayRequest]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "RelayPollResult":
        raw_requests = payload.get("requests")
        if not isinstance(raw_requests, list):
            raise RelayApiError("relay returned invalid requests", body=dict(payload))
        return cls(requests=[RelayRequest.from_payload(item) for item in raw_requests])


@dataclass(frozen=True)
class RelayResponse:
    body: object
    status: int = 200
    headers: Mapping[str, str] | None = None


class _RelayWorkerState:
    def __init__(self) -> None:
        self._registration_tokens: dict[str, str] = {}

    def _remember_registration(
        self, rollout_id: str, payload: Mapping[str, Any]
    ) -> None:
        record = payload.get("rollout")
        if not isinstance(record, Mapping):
            raise RelayApiError("relay returned invalid registration", body=payload)
        response_rollout_id = _required_string(record, "rollout_id")
        if response_rollout_id != rollout_id:
            raise RelayApiError(
                "relay registration rollout_id does not match", body=payload
            )
        token = _required_string(record, "registration_token")
        _validate_registration_token(token)
        self._registration_tokens[rollout_id] = token

    def _registration_token(
        self, rollout_id: str, registration_token: str | None = None
    ) -> str:
        token = (
            registration_token
            if registration_token is not None
            else self._registration_tokens.get(rollout_id)
        )
        if token is None:
            raise RelayApiError(
                f"rollout is not registered by this client: {rollout_id}"
            )
        _validate_registration_token(token)
        if registration_token is not None:
            self._registration_tokens[rollout_id] = token
        return token

    def _forget_registration(self, rollout_id: str) -> None:
        self._registration_tokens.pop(rollout_id, None)


class RelayWorkerClient(_RelayWorkerState):
    def __init__(
        self,
        relay_url: str,
        *,
        worker_token: str | None = None,
        timeout_seconds: float = 30.0,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__()
        self.relay_url = relay_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.headers = dict(headers or {})
        if worker_token is not None:
            self.headers["Authorization"] = f"Bearer {worker_token}"

    @classmethod
    def from_env(
        cls,
        *,
        env: Mapping[str, str] | None = None,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> "RelayWorkerClient":
        values = os.environ if env is None else env
        return cls(
            _required_env(values, "UCLOUD_RELAY_URL"),
            worker_token=values.get("UCLOUD_RELAY_WORKER_TOKEN"),
            timeout_seconds=(
                _positive_env_float(
                    values,
                    "UCLOUD_RELAY_TIMEOUT_SECONDS",
                    default=30.0,
                )
                if timeout_seconds is None
                else timeout_seconds
            ),
            headers=headers,
        )

    def rollout_session(
        self,
        rollout_id: str,
        *,
        worker_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        sandbox: object | None = None,
    ) -> "RelaySession":
        return RelaySession(
            self,
            rollout_id,
            worker_id=worker_id,
            metadata=metadata,
            sandbox=sandbox,
        )

    def run_worker(
        self,
        rollout_id: str,
        *,
        handler: Callable[[RelayRequest], object] | None = None,
        upstream_base_url: str | None = None,
        worker_id: str | None = None,
        cancel: Event | None = None,
        max_concurrency: int = 4,
        poll_timeout_seconds: float = 30.0,
        lease_seconds: float = 120.0,
        renewal_interval_seconds: float | None = None,
        max_consecutive_poll_errors: int = 8,
        registration_token: str | None = None,
    ) -> None:
        _run_sync_worker(
            self,
            rollout_id,
            handler=handler,
            upstream_base_url=upstream_base_url,
            worker_id=worker_id,
            cancel=cancel,
            max_concurrency=max_concurrency,
            poll_timeout_seconds=poll_timeout_seconds,
            lease_seconds=lease_seconds,
            renewal_interval_seconds=renewal_interval_seconds,
            max_consecutive_poll_errors=max_consecutive_poll_errors,
            registration_token=registration_token,
        )

    def health(self) -> JsonObject:
        return self._request_json("GET", "/healthz")

    def stats(self) -> JsonObject:
        return self._request_json("GET", "/v1/relay/stats")

    def list_rollouts(self) -> list[JsonObject]:
        return _rollout_records(self._request_json("GET", "/v1/relay/rollouts"))

    def register_rollout(
        self,
        rollout_id: str,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> JsonObject:
        response = self._request_json(
            "POST",
            "/v1/relay/rollouts",
            payload=_registration_payload(rollout_id, metadata),
        )
        self._remember_registration(rollout_id, response)
        return response

    def register_agent_rollout(
        self,
        rollout_id: str,
        sandbox: object,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> JsonObject:
        """Register a rollout with a generation-fenced managed sandbox."""

        return self.register_rollout(
            rollout_id,
            metadata=_agent_rollout_metadata(sandbox, metadata),
        )

    def unregister_rollout(
        self,
        rollout_id: str,
        *,
        registration_token: str | None = None,
    ) -> JsonObject:
        token = self._registration_token(rollout_id, registration_token)
        response = self._request_json(
            "DELETE",
            _unregistration_path(rollout_id),
            payload={"registration_token": token},
        )
        self._forget_registration(rollout_id)
        return response

    def heartbeat(
        self,
        rollout_id: str,
        worker_id: str,
        *,
        metadata: Mapping[str, Any] | None = None,
        registration_token: str | None = None,
    ) -> JsonObject:
        return self._request_json(
            "POST",
            "/worker/heartbeat",
            payload=_heartbeat_payload(
                rollout_id,
                self._registration_token(rollout_id, registration_token),
                worker_id,
                metadata,
            ),
        )

    def poll(
        self,
        rollout_id: str,
        *,
        worker_id: str | None = None,
        timeout_seconds: float | None = None,
        limit: int | None = None,
        lease_seconds: float | None = None,
        registration_token: str | None = None,
    ) -> RelayPollResult:
        token = self._registration_token(rollout_id, registration_token)
        payload = self._request_json(
            "GET",
            _poll_path(
                rollout_id,
                token,
                worker_id=worker_id,
                timeout_seconds=timeout_seconds,
                limit=limit,
                lease_seconds=lease_seconds,
            ),
            timeout_seconds=_poll_client_timeout(self.timeout_seconds, timeout_seconds),
        )
        result = RelayPollResult.from_payload(payload)
        _validate_poll_identity(result, rollout_id, token)
        return result

    def renew_request(
        self,
        relay_request: RelayRequest,
        *,
        worker_id: str | None = None,
        lease_seconds: float | None = None,
    ) -> RelayRequest:
        response = self._request_json(
            "POST",
            "/worker/renew",
            payload=_renew_payload(relay_request, worker_id, lease_seconds),
        )
        return _renewed_request(response, relay_request)

    def respond_to(
        self,
        relay_request: RelayRequest,
        response: object,
        *,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
    ) -> JsonObject:
        return self._request_json(
            "POST",
            "/worker/respond",
            payload=_response_payload(relay_request, response, status, headers),
        )

    def commit_response_bytes_to(
        self,
        relay_request: RelayRequest,
        body: bytes,
        *,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
        attempts: int = 60,
        retry_delay_seconds: float = 1.0,
    ) -> JsonObject:
        """Retry the idempotent commit while a committed result awaits wake."""

        attempts = max(1, attempts)
        for attempt in range(attempts):
            try:
                return self.respond_to(
                    relay_request,
                    body,
                    status=status,
                    headers=headers,
                )
            except RelayApiError as exc:
                if (
                    exc.status_code != 503
                    or exc.retryable is False
                    or attempt + 1 >= attempts
                ):
                    raise
                time.sleep(
                    max(
                        0.0,
                        exc.retry_after_seconds
                        if exc.retry_after_seconds is not None
                        else retry_delay_seconds,
                    )
                )
        raise AssertionError("unreachable")

    def forward_to(
        self,
        relay_request: RelayRequest,
        upstream_base_url: str,
        *,
        timeout_seconds: float | None = None,
    ) -> JsonObject:
        _validate_http_body_size(relay_request.body_bytes)
        upstream_request = request.Request(
            upstream_base_url.rstrip("/") + relay_request.endpoint,
            data=relay_request.body_bytes or None,
            method=relay_request.method,
            headers=_safe_http_headers(relay_request.headers),
        )
        try:
            upstream = open_no_redirect(
                upstream_request,
                timeout=timeout_seconds or self.timeout_seconds,
            )
        except error.HTTPError as exc:
            upstream = exc
        except OSError as exc:
            return self.commit_response_bytes_to(
                relay_request,
                json.dumps({"error": f"upstream request failed: {exc}"}).encode(
                    "utf-8"
                ),
                status=502,
                headers={"Content-Type": "application/json"},
            )
        try:
            body = read_sync_response(upstream, limit=MAX_RELAY_HTTP_BODY_BYTES)
            status = int(upstream.status)
            headers = _safe_http_headers(dict(upstream.headers))
        except ResponseTooLargeError as exc:
            raise RelayApiError(str(exc)) from exc
        finally:
            upstream.close()
        return self.commit_response_bytes_to(
            relay_request,
            body,
            status=status,
            headers=headers,
        )

    def error_request(
        self,
        relay_request: RelayRequest,
        message: str,
        *,
        status: int = 502,
    ) -> JsonObject:
        return self._request_json(
            "POST",
            "/worker/error",
            payload=_error_payload(relay_request, message, status),
        )

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        payload: JsonObject | None = None,
        timeout_seconds: float | None = None,
    ) -> JsonObject:
        raw_body = json.dumps(payload).encode("utf-8") if payload is not None else None
        if raw_body is not None and len(raw_body) > MAX_RELAY_JSON_BYTES:
            raise RelayApiError(
                f"relay request body exceeds the {MAX_RELAY_JSON_BYTES} byte limit"
            )
        headers = dict(self.headers)
        if payload is not None:
            headers["Content-Type"] = "application/json"
        req = request.Request(
            self.relay_url + path,
            data=raw_body,
            method=method,
            headers=headers,
        )
        try:
            with open_no_redirect(
                req,
                timeout=(
                    self.timeout_seconds if timeout_seconds is None else timeout_seconds
                ),
            ) as response:
                response_status = int(getattr(response, "status", 200))
                response_header_values = response_headers(response)
                raw = read_sync_response(response, limit=MAX_RELAY_JSON_BYTES).decode(
                    "utf-8"
                )
                return _decode_relay_json(
                    raw,
                    status=response_status,
                    headers=response_header_values,
                )
        except error.HTTPError as exc:
            header_values = response_headers(exc)
            try:
                raw = read_sync_response(exc, limit=MAX_RELAY_JSON_BYTES).decode(
                    "utf-8", errors="replace"
                )
            except ResponseTooLargeError as size_exc:
                exc.close()
                raise RelayApiError(
                    str(size_exc),
                    status_code=exc.code,
                    headers=header_values,
                ) from size_exc
            exc.close()
            try:
                return _decode_relay_json(
                    raw,
                    status=exc.code,
                    headers=header_values,
                )
            except RelayApiError as api_error:
                raise api_error from exc
        except ResponseTooLargeError as exc:
            raise RelayApiError(
                str(exc),
                status_code=response_status,
                headers=response_header_values,
            ) from exc
        except OSError as exc:
            raise RelayApiError(f"relay request failed: {exc}") from exc
        raise AssertionError("unreachable relay response state")


class AsyncRelayWorkerClient(_RelayWorkerState):
    def __init__(
        self,
        relay_url: str,
        *,
        worker_token: str | None = None,
        timeout_seconds: float = 30.0,
        headers: Mapping[str, str] | None = None,
        session: Any | None = None,
    ) -> None:
        super().__init__()
        self.relay_url = relay_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.headers = dict(headers or {})
        if worker_token is not None:
            self.headers["Authorization"] = f"Bearer {worker_token}"
        self._session = session
        self._owned_session: Any | None = None

    @classmethod
    def from_env(
        cls,
        *,
        env: Mapping[str, str] | None = None,
        timeout_seconds: float | None = None,
        headers: Mapping[str, str] | None = None,
        session: Any | None = None,
    ) -> "AsyncRelayWorkerClient":
        values = os.environ if env is None else env
        return cls(
            _required_env(values, "UCLOUD_RELAY_URL"),
            worker_token=values.get("UCLOUD_RELAY_WORKER_TOKEN"),
            timeout_seconds=(
                _positive_env_float(
                    values,
                    "UCLOUD_RELAY_TIMEOUT_SECONDS",
                    default=30.0,
                )
                if timeout_seconds is None
                else timeout_seconds
            ),
            headers=headers,
            session=session,
        )

    def rollout_session(
        self,
        rollout_id: str,
        *,
        worker_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        sandbox: object | None = None,
    ) -> "AsyncRelaySession":
        return AsyncRelaySession(
            self,
            rollout_id,
            worker_id=worker_id,
            metadata=metadata,
            sandbox=sandbox,
        )

    async def run_worker(
        self,
        rollout_id: str,
        *,
        handler: Callable[[RelayRequest], object | Awaitable[object]] | None = None,
        upstream_base_url: str | None = None,
        worker_id: str | None = None,
        cancel: asyncio.Event | None = None,
        max_concurrency: int = 4,
        poll_timeout_seconds: float = 30.0,
        lease_seconds: float = 120.0,
        renewal_interval_seconds: float | None = None,
        max_consecutive_poll_errors: int = 8,
        registration_token: str | None = None,
    ) -> None:
        await _run_async_worker(
            self,
            rollout_id,
            handler=handler,
            upstream_base_url=upstream_base_url,
            worker_id=worker_id,
            cancel=cancel,
            max_concurrency=max_concurrency,
            poll_timeout_seconds=poll_timeout_seconds,
            lease_seconds=lease_seconds,
            renewal_interval_seconds=renewal_interval_seconds,
            max_consecutive_poll_errors=max_consecutive_poll_errors,
            registration_token=registration_token,
        )

    async def __aenter__(self) -> "AsyncRelayWorkerClient":
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

    async def stats(self) -> JsonObject:
        return await self._request_json("GET", "/v1/relay/stats")

    async def list_rollouts(self) -> list[JsonObject]:
        return _rollout_records(await self._request_json("GET", "/v1/relay/rollouts"))

    async def register_rollout(
        self,
        rollout_id: str,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> JsonObject:
        response = await self._request_json(
            "POST",
            "/v1/relay/rollouts",
            payload=_registration_payload(rollout_id, metadata),
        )
        self._remember_registration(rollout_id, response)
        return response

    async def register_agent_rollout(
        self,
        rollout_id: str,
        sandbox: object,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> JsonObject:
        """Register a rollout with a generation-fenced managed sandbox."""

        return await self.register_rollout(
            rollout_id,
            metadata=_agent_rollout_metadata(sandbox, metadata),
        )

    async def unregister_rollout(
        self,
        rollout_id: str,
        *,
        registration_token: str | None = None,
    ) -> JsonObject:
        token = self._registration_token(rollout_id, registration_token)
        response = await self._request_json(
            "DELETE",
            _unregistration_path(rollout_id),
            payload={"registration_token": token},
        )
        self._forget_registration(rollout_id)
        return response

    async def heartbeat(
        self,
        rollout_id: str,
        worker_id: str,
        *,
        metadata: Mapping[str, Any] | None = None,
        registration_token: str | None = None,
    ) -> JsonObject:
        return await self._request_json(
            "POST",
            "/worker/heartbeat",
            payload=_heartbeat_payload(
                rollout_id,
                self._registration_token(rollout_id, registration_token),
                worker_id,
                metadata,
            ),
        )

    async def poll(
        self,
        rollout_id: str,
        *,
        worker_id: str | None = None,
        timeout_seconds: float | None = None,
        limit: int | None = None,
        lease_seconds: float | None = None,
        registration_token: str | None = None,
    ) -> RelayPollResult:
        token = self._registration_token(rollout_id, registration_token)
        payload = await self._request_json(
            "GET",
            _poll_path(
                rollout_id,
                token,
                worker_id=worker_id,
                timeout_seconds=timeout_seconds,
                limit=limit,
                lease_seconds=lease_seconds,
            ),
            timeout_seconds=_poll_client_timeout(self.timeout_seconds, timeout_seconds),
        )
        result = RelayPollResult.from_payload(payload)
        _validate_poll_identity(result, rollout_id, token)
        return result

    async def renew_request(
        self,
        relay_request: RelayRequest,
        *,
        worker_id: str | None = None,
        lease_seconds: float | None = None,
    ) -> RelayRequest:
        response = await self._request_json(
            "POST",
            "/worker/renew",
            payload=_renew_payload(relay_request, worker_id, lease_seconds),
        )
        return _renewed_request(response, relay_request)

    async def respond_to(
        self,
        relay_request: RelayRequest,
        response: object,
        *,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
    ) -> JsonObject:
        return await self._request_json(
            "POST",
            "/worker/respond",
            payload=_response_payload(relay_request, response, status, headers),
        )

    async def commit_response_bytes_to(
        self,
        relay_request: RelayRequest,
        body: bytes,
        *,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
        attempts: int = 60,
        retry_delay_seconds: float = 1.0,
    ) -> JsonObject:
        """Retry the idempotent commit while a committed result awaits wake."""

        attempts = max(1, attempts)
        for attempt in range(attempts):
            try:
                return await self.respond_to(
                    relay_request,
                    body,
                    status=status,
                    headers=headers,
                )
            except RelayApiError as exc:
                if (
                    exc.status_code != 503
                    or exc.retryable is False
                    or attempt + 1 >= attempts
                ):
                    raise
                await asyncio.sleep(
                    max(
                        0.0,
                        exc.retry_after_seconds
                        if exc.retry_after_seconds is not None
                        else retry_delay_seconds,
                    )
                )
        raise AssertionError("unreachable")

    async def forward_to(
        self,
        relay_request: RelayRequest,
        upstream_base_url: str,
        *,
        timeout_seconds: float | None = None,
    ) -> JsonObject:
        _validate_http_body_size(relay_request.body_bytes)
        client = await self._client()
        request_options: dict[str, Any] = {
            "data": relay_request.body_bytes or None,
            "headers": _safe_http_headers(relay_request.headers),
            "allow_redirects": False,
        }
        if timeout_seconds is not None:
            request_options["timeout"] = timeout_seconds
        try:
            async with client.request(
                relay_request.method,
                upstream_base_url.rstrip("/") + relay_request.endpoint,
                **request_options,
            ) as upstream:
                body = await read_async_response(
                    upstream, limit=MAX_RELAY_HTTP_BODY_BYTES
                )
                status = upstream.status
                headers = _safe_http_headers(dict(upstream.headers))
        except ResponseTooLargeError as exc:
            raise RelayApiError(str(exc)) from exc
        except Exception as exc:
            return await self.commit_response_bytes_to(
                relay_request,
                json.dumps({"error": f"upstream request failed: {exc}"}).encode(
                    "utf-8"
                ),
                status=502,
                headers={"Content-Type": "application/json"},
            )
        return await self.commit_response_bytes_to(
            relay_request,
            body,
            status=status,
            headers=headers,
        )

    async def error_request(
        self,
        relay_request: RelayRequest,
        message: str,
        *,
        status: int = 502,
    ) -> JsonObject:
        return await self._request_json(
            "POST",
            "/worker/error",
            payload=_error_payload(relay_request, message, status),
        )

    async def _client(self) -> Any:
        if self._session is not None:
            return self._session
        if self._owned_session is None:
            try:
                from aiohttp import ClientSession, ClientTimeout
            except ImportError as exc:
                raise RuntimeError(
                    "AsyncRelayWorkerClient requires aiohttp. Install "
                    "ucloud-sandboxes-sdk[async] or ucloud-sandboxes-sdk[inspect]."
                ) from exc
            self._owned_session = ClientSession(
                timeout=ClientTimeout(total=self.timeout_seconds)
            )
        return self._owned_session

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        payload: JsonObject | None = None,
        timeout_seconds: float | None = None,
    ) -> JsonObject:
        if payload is not None:
            encoded = json.dumps(payload).encode("utf-8")
            if len(encoded) > MAX_RELAY_JSON_BYTES:
                raise RelayApiError(
                    f"relay request body exceeds the {MAX_RELAY_JSON_BYTES} byte limit"
                )
        client = await self._client()
        headers = dict(self.headers)
        try:
            async with client.request(
                method,
                self.relay_url + path,
                json=payload,
                headers=headers,
                allow_redirects=False,
                timeout=(
                    self.timeout_seconds
                    if timeout_seconds is None
                    else timeout_seconds
                ),
            ) as response:
                try:
                    raw = (
                        await read_async_response(response, limit=MAX_RELAY_JSON_BYTES)
                    ).decode("utf-8")
                except ResponseTooLargeError as exc:
                    raise RelayApiError(
                        str(exc),
                        status_code=response.status,
                        headers=response_headers(response),
                    ) from exc
                return _decode_relay_json(
                    raw,
                    status=response.status,
                    headers=response_headers(response),
                )
        except asyncio.CancelledError:
            raise
        except RelayApiError:
            raise
        except Exception as exc:
            raise RelayApiError(f"relay request failed: {exc}") from exc


class RelaySession:
    """A registered rollout with deterministic cleanup and a worker loop."""

    def __init__(
        self,
        client: RelayWorkerClient,
        rollout_id: str,
        *,
        worker_id: str | None,
        metadata: Mapping[str, Any] | None,
        sandbox: object | None,
    ) -> None:
        self.client = client
        self.rollout_id = rollout_id
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex}"
        self.metadata = dict(metadata or {})
        self.sandbox = sandbox
        self.registration: JsonObject | None = None
        self.registration_token: str | None = None

    def __enter__(self) -> "RelaySession":
        response = (
            self.client.register_rollout(self.rollout_id, metadata=self.metadata)
            if self.sandbox is None
            else self.client.register_agent_rollout(
                self.rollout_id,
                self.sandbox,
                metadata=self.metadata,
            )
        )
        self.registration = response
        self.registration_token = _registration_token_from_response(
            response,
            self.rollout_id,
        )
        return self

    def __exit__(
        self,
        exc_type: object,
        exc: BaseException | None,
        traceback: object,
    ) -> None:
        del exc_type, traceback
        try:
            self.close()
        except Exception as cleanup_error:
            if exc is None:
                raise
            warnings.warn(
                f"relay rollout cleanup failed after {exc!r}: {cleanup_error}",
                RuntimeWarning,
                stacklevel=2,
            )

    @property
    def base_url(self) -> str:
        token = self._required_registration_token()
        return http_tunnel_url(
            self.client.relay_url,
            self.rollout_id,
            registration_token=token,
        )

    @property
    def openai_base_url(self) -> str:
        return self.base_url.rstrip("/") + "/v1"

    def close(self) -> None:
        token = self.registration_token
        if token is None:
            return
        self.client.unregister_rollout(
            self.rollout_id,
            registration_token=token,
        )
        self.registration_token = None

    def run(
        self,
        *,
        handler: Callable[[RelayRequest], object] | None = None,
        upstream_base_url: str | None = None,
        cancel: Event | None = None,
        max_concurrency: int = 4,
        poll_timeout_seconds: float = 30.0,
        lease_seconds: float = 120.0,
        renewal_interval_seconds: float | None = None,
        max_consecutive_poll_errors: int = 8,
    ) -> None:
        self.client.run_worker(
            self.rollout_id,
            handler=handler,
            upstream_base_url=upstream_base_url,
            worker_id=self.worker_id,
            cancel=cancel,
            max_concurrency=max_concurrency,
            poll_timeout_seconds=poll_timeout_seconds,
            lease_seconds=lease_seconds,
            renewal_interval_seconds=renewal_interval_seconds,
            max_consecutive_poll_errors=max_consecutive_poll_errors,
            registration_token=self._required_registration_token(),
        )

    def _required_registration_token(self) -> str:
        if self.registration_token is None:
            raise RelayApiError("relay session is not registered")
        return self.registration_token


class AsyncRelaySession:
    """Async counterpart to :class:`RelaySession`."""

    def __init__(
        self,
        client: AsyncRelayWorkerClient,
        rollout_id: str,
        *,
        worker_id: str | None,
        metadata: Mapping[str, Any] | None,
        sandbox: object | None,
    ) -> None:
        self.client = client
        self.rollout_id = rollout_id
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex}"
        self.metadata = dict(metadata or {})
        self.sandbox = sandbox
        self.registration: JsonObject | None = None
        self.registration_token: str | None = None

    async def __aenter__(self) -> "AsyncRelaySession":
        response = (
            await self.client.register_rollout(
                self.rollout_id,
                metadata=self.metadata,
            )
            if self.sandbox is None
            else await self.client.register_agent_rollout(
                self.rollout_id,
                self.sandbox,
                metadata=self.metadata,
            )
        )
        self.registration = response
        self.registration_token = _registration_token_from_response(
            response,
            self.rollout_id,
        )
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc: BaseException | None,
        traceback: object,
    ) -> None:
        del exc_type, traceback
        try:
            await self.close()
        except Exception as cleanup_error:
            if exc is None:
                raise
            warnings.warn(
                f"relay rollout cleanup failed after {exc!r}: {cleanup_error}",
                RuntimeWarning,
                stacklevel=2,
            )

    @property
    def base_url(self) -> str:
        token = self._required_registration_token()
        return http_tunnel_url(
            self.client.relay_url,
            self.rollout_id,
            registration_token=token,
        )

    @property
    def openai_base_url(self) -> str:
        return self.base_url.rstrip("/") + "/v1"

    async def close(self) -> None:
        token = self.registration_token
        if token is None:
            return
        await self.client.unregister_rollout(
            self.rollout_id,
            registration_token=token,
        )
        self.registration_token = None

    async def run(
        self,
        *,
        handler: Callable[[RelayRequest], object | Awaitable[object]] | None = None,
        upstream_base_url: str | None = None,
        cancel: asyncio.Event | None = None,
        max_concurrency: int = 4,
        poll_timeout_seconds: float = 30.0,
        lease_seconds: float = 120.0,
        renewal_interval_seconds: float | None = None,
        max_consecutive_poll_errors: int = 8,
    ) -> None:
        await self.client.run_worker(
            self.rollout_id,
            handler=handler,
            upstream_base_url=upstream_base_url,
            worker_id=self.worker_id,
            cancel=cancel,
            max_concurrency=max_concurrency,
            poll_timeout_seconds=poll_timeout_seconds,
            lease_seconds=lease_seconds,
            renewal_interval_seconds=renewal_interval_seconds,
            max_consecutive_poll_errors=max_consecutive_poll_errors,
            registration_token=self._required_registration_token(),
        )

    def _required_registration_token(self) -> str:
        if self.registration_token is None:
            raise RelayApiError("relay session is not registered")
        return self.registration_token


def _run_sync_worker(
    client: RelayWorkerClient,
    rollout_id: str,
    *,
    handler: Callable[[RelayRequest], object] | None,
    upstream_base_url: str | None,
    worker_id: str | None,
    cancel: Event | None,
    max_concurrency: int,
    poll_timeout_seconds: float,
    lease_seconds: float,
    renewal_interval_seconds: float | None,
    max_consecutive_poll_errors: int,
    registration_token: str | None,
) -> None:
    _validate_worker_options(handler, upstream_base_url, max_concurrency)
    stop = cancel or Event()
    worker = worker_id or f"worker-{uuid.uuid4().hex}"
    renewal_interval = _renewal_interval(lease_seconds, renewal_interval_seconds)
    poll_errors = 0
    futures: set[Future[None]] = set()
    with ThreadPoolExecutor(max_workers=max_concurrency) as executor:
        while not stop.is_set():
            completed = {future for future in futures if future.done()}
            futures.difference_update(completed)
            for future in completed:
                future.result()
            available = max_concurrency - len(futures)
            if available <= 0:
                stop.wait(0.05)
                continue
            try:
                result = client.poll(
                    rollout_id,
                    worker_id=worker,
                    timeout_seconds=poll_timeout_seconds,
                    limit=available,
                    lease_seconds=lease_seconds,
                    registration_token=registration_token,
                )
                poll_errors = 0
            except RelayApiError as exc:
                poll_errors += 1
                if (
                    not _relay_error_is_retryable(exc)
                    or poll_errors >= max(1, max_consecutive_poll_errors)
                ):
                    raise
                stop.wait(_relay_retry_delay(exc, poll_errors))
                continue
            for relay_request in result.requests:
                futures.add(
                    executor.submit(
                        _handle_sync_request,
                        client,
                        relay_request,
                        handler=handler,
                        upstream_base_url=upstream_base_url,
                        worker_id=worker,
                        lease_seconds=lease_seconds,
                        renewal_interval_seconds=renewal_interval,
                    )
                )
        for future in futures:
            future.result()


async def _run_async_worker(
    client: AsyncRelayWorkerClient,
    rollout_id: str,
    *,
    handler: Callable[[RelayRequest], object | Awaitable[object]] | None,
    upstream_base_url: str | None,
    worker_id: str | None,
    cancel: asyncio.Event | None,
    max_concurrency: int,
    poll_timeout_seconds: float,
    lease_seconds: float,
    renewal_interval_seconds: float | None,
    max_consecutive_poll_errors: int,
    registration_token: str | None,
) -> None:
    _validate_worker_options(handler, upstream_base_url, max_concurrency)
    stop = cancel or asyncio.Event()
    worker = worker_id or f"worker-{uuid.uuid4().hex}"
    renewal_interval = _renewal_interval(lease_seconds, renewal_interval_seconds)
    poll_errors = 0
    tasks: set[asyncio.Task[None]] = set()
    try:
        while not stop.is_set():
            completed = {task for task in tasks if task.done()}
            tasks.difference_update(completed)
            for task in completed:
                task.result()
            available = max_concurrency - len(tasks)
            if available <= 0:
                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                continue
            try:
                result = await client.poll(
                    rollout_id,
                    worker_id=worker,
                    timeout_seconds=poll_timeout_seconds,
                    limit=available,
                    lease_seconds=lease_seconds,
                    registration_token=registration_token,
                )
                poll_errors = 0
            except RelayApiError as exc:
                poll_errors += 1
                if (
                    not _relay_error_is_retryable(exc)
                    or poll_errors >= max(1, max_consecutive_poll_errors)
                ):
                    raise
                await _wait_async_cancel(stop, _relay_retry_delay(exc, poll_errors))
                continue
            for relay_request in result.requests:
                tasks.add(
                    asyncio.create_task(
                        _handle_async_request(
                            client,
                            relay_request,
                            handler=handler,
                            upstream_base_url=upstream_base_url,
                            worker_id=worker,
                            lease_seconds=lease_seconds,
                            renewal_interval_seconds=renewal_interval,
                        )
                    )
                )
    except asyncio.CancelledError:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
            tasks.clear()
        raise
    finally:
        if tasks:
            await asyncio.gather(*tasks)


def _handle_sync_request(
    client: RelayWorkerClient,
    relay_request: RelayRequest,
    *,
    handler: Callable[[RelayRequest], object] | None,
    upstream_base_url: str | None,
    worker_id: str,
    lease_seconds: float,
    renewal_interval_seconds: float,
) -> None:
    stop = Event()
    renewal_errors: list[RelayApiError] = []
    renewer = Thread(
        target=_renew_sync_lease,
        args=(
            client,
            relay_request,
            worker_id,
            lease_seconds,
            renewal_interval_seconds,
            stop,
            renewal_errors,
        ),
        daemon=True,
    )
    renewer.start()
    try:
        if _is_streaming_model_request(relay_request):
            client.error_request(
                relay_request,
                "streaming model requests are not supported by the relay protocol",
                status=400,
            )
        elif upstream_base_url is not None:
            client.forward_to(relay_request, upstream_base_url)
        else:
            assert handler is not None
            _commit_sync_handler_result(client, relay_request, handler(relay_request))
    except RelayApiError:
        raise
    except Exception as exc:
        client.error_request(relay_request, str(exc))
    finally:
        stop.set()
        renewer.join(timeout=max(1.0, renewal_interval_seconds + 1.0))
    if renewal_errors:
        raise renewal_errors[0]


async def _handle_async_request(
    client: AsyncRelayWorkerClient,
    relay_request: RelayRequest,
    *,
    handler: Callable[[RelayRequest], object | Awaitable[object]] | None,
    upstream_base_url: str | None,
    worker_id: str,
    lease_seconds: float,
    renewal_interval_seconds: float,
) -> None:
    stop = asyncio.Event()
    renewer = asyncio.create_task(
        _renew_async_lease(
            client,
            relay_request,
            worker_id,
            lease_seconds,
            renewal_interval_seconds,
            stop,
        )
    )
    try:
        if _is_streaming_model_request(relay_request):
            await client.error_request(
                relay_request,
                "streaming model requests are not supported by the relay protocol",
                status=400,
            )
        elif upstream_base_url is not None:
            await client.forward_to(relay_request, upstream_base_url)
        else:
            assert handler is not None
            result = handler(relay_request)
            if inspect.isawaitable(result):
                result = await result
            await _commit_async_handler_result(client, relay_request, result)
    except RelayApiError:
        raise
    except Exception as exc:
        await client.error_request(relay_request, str(exc))
    finally:
        stop.set()
        await renewer


def _renew_sync_lease(
    client: RelayWorkerClient,
    relay_request: RelayRequest,
    worker_id: str,
    lease_seconds: float,
    interval: float,
    stop: Event,
    errors: list[RelayApiError],
) -> None:
    while not stop.wait(interval):
        try:
            client.renew_request(
                relay_request,
                worker_id=worker_id,
                lease_seconds=lease_seconds,
            )
        except RelayApiError as exc:
            if not _relay_error_is_retryable(exc):
                errors.append(exc)
                return


async def _renew_async_lease(
    client: AsyncRelayWorkerClient,
    relay_request: RelayRequest,
    worker_id: str,
    lease_seconds: float,
    interval: float,
    stop: asyncio.Event,
) -> None:
    while not await _wait_async_cancel(stop, interval):
        try:
            await client.renew_request(
                relay_request,
                worker_id=worker_id,
                lease_seconds=lease_seconds,
            )
        except RelayApiError as exc:
            if not _relay_error_is_retryable(exc):
                raise


def _rollout_records(payload: Mapping[str, Any]) -> list[JsonObject]:
    rollouts = payload.get("rollouts")
    if not isinstance(rollouts, list):
        return []
    return [dict(item) for item in rollouts if isinstance(item, dict)]


def _registration_token_from_response(
    payload: Mapping[str, Any], rollout_id: str
) -> str:
    record = payload.get("rollout")
    if not isinstance(record, Mapping) or record.get("rollout_id") != rollout_id:
        raise RelayApiError("relay returned invalid registration", body=payload)
    token = _required_string(record, "registration_token")
    _validate_registration_token(token)
    return token


def _validate_worker_options(
    handler: object,
    upstream_base_url: str | None,
    max_concurrency: int,
) -> None:
    if (handler is None) == (upstream_base_url is None):
        raise ValueError("set exactly one of handler or upstream_base_url")
    if max_concurrency < 1:
        raise ValueError("max_concurrency must be positive")
    if upstream_base_url is not None and not upstream_base_url.strip():
        raise ValueError("upstream_base_url cannot be empty")


def _renewal_interval(
    lease_seconds: float,
    renewal_interval_seconds: float | None,
) -> float:
    if lease_seconds <= 0:
        raise ValueError("lease_seconds must be positive")
    interval = (
        min(60.0, lease_seconds / 3.0)
        if renewal_interval_seconds is None
        else renewal_interval_seconds
    )
    if interval <= 0 or interval >= lease_seconds:
        raise ValueError(
            "renewal_interval_seconds must be positive and less than lease_seconds"
        )
    return interval


def _commit_sync_handler_result(
    client: RelayWorkerClient,
    relay_request: RelayRequest,
    result: object,
) -> None:
    if isinstance(result, RelayResponse):
        client.respond_to(
            relay_request,
            result.body,
            status=result.status,
            headers=result.headers,
        )
        return
    client.respond_to(relay_request, result)


async def _commit_async_handler_result(
    client: AsyncRelayWorkerClient,
    relay_request: RelayRequest,
    result: object,
) -> None:
    if isinstance(result, RelayResponse):
        await client.respond_to(
            relay_request,
            result.body,
            status=result.status,
            headers=result.headers,
        )
        return
    await client.respond_to(relay_request, result)


def _is_streaming_model_request(relay_request: RelayRequest) -> bool:
    path = relay_request.endpoint.partition("?")[0].rstrip("/")
    model_endpoint = path.endswith(
        ("/chat/completions", "/completions", "/responses")
    )
    return (
        model_endpoint
        and isinstance(relay_request.body, Mapping)
        and relay_request.body.get("stream") is True
    )


def _relay_error_is_retryable(exc: RelayApiError) -> bool:
    if exc.status_code in {400, 401, 403, 404, 409, 410, 422}:
        return False
    if exc.retryable is not None:
        return exc.retryable
    if exc.status_code is None:
        return True
    return exc.status_code in {408, 425, 429, 500, 502, 503, 504}


def _relay_retry_delay(exc: RelayApiError, consecutive_errors: int) -> float:
    if exc.retry_after_seconds is not None:
        return exc.retry_after_seconds
    return min(30.0, 0.25 * (2 ** max(0, consecutive_errors - 1)))


async def _wait_async_cancel(cancel: asyncio.Event, delay: float) -> bool:
    try:
        await asyncio.wait_for(cancel.wait(), timeout=max(0.0, delay))
    except asyncio.TimeoutError:
        return False
    return True


def _required_env(env: Mapping[str, str], name: str) -> str:
    value = str(env.get(name) or "").strip()
    if not value:
        raise ValueError(f"{name} is required")
    return value


def _positive_env_float(
    env: Mapping[str, str],
    name: str,
    *,
    default: float,
) -> float:
    raw = str(env.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


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
    return max(
        0.0,
        min(60.0, (retry_at - datetime.now(timezone.utc)).total_seconds()),
    )


def _registration_payload(
    rollout_id: str,
    metadata: Mapping[str, Any] | None,
) -> JsonObject:
    if (
        metadata is not None
        and any(field in metadata for field in ("sandbox_id", "sandbox_generation"))
        and metadata.get(AGENT_LIFECYCLE_METADATA_KEY) != MANAGED_AGENT_LIFECYCLE
    ):
        raise RelayApiError(
            "sandbox-bound rollouts must use register_agent_rollout()"
        )
    payload: JsonObject = {"rollout_id": rollout_id}
    if metadata is not None:
        payload["metadata"] = dict(metadata)
    return payload


def _agent_rollout_metadata(
    sandbox: object,
    metadata: Mapping[str, Any] | None,
) -> JsonObject:
    sandbox_id = getattr(sandbox, "id", None)
    record = getattr(sandbox, "record", None)
    if not isinstance(sandbox_id, str) or not sandbox_id:
        raise RelayApiError("agent sandbox handle has no sandbox id")
    if not isinstance(record, Mapping):
        raise RelayApiError("agent sandbox handle has no sandbox record")
    try:
        generation = require_agent_sandbox_record(
            record,
            require_generation=True,
        )
    except ValueError as exc:
        raise RelayApiError(str(exc)) from exc
    assert generation is not None
    result = dict(metadata or {})
    for field, value in (
        (AGENT_LIFECYCLE_METADATA_KEY, MANAGED_AGENT_LIFECYCLE),
        ("sandbox_id", sandbox_id),
        ("sandbox_generation", generation),
    ):
        existing = result.get(field)
        if existing is not None and existing != value:
            raise RelayApiError(
                f"agent rollout metadata {field} conflicts with the sandbox handle"
            )
        result[field] = value
    return result


def _unregistration_path(rollout_id: str) -> str:
    return f"/v1/relay/rollouts/{quote(rollout_id, safe='')}"


def _heartbeat_payload(
    rollout_id: str,
    registration_token: str,
    worker_id: str,
    metadata: Mapping[str, Any] | None,
) -> JsonObject:
    payload: JsonObject = {
        "rollout_id": rollout_id,
        "registration_token": registration_token,
        "worker_id": worker_id,
    }
    if metadata is not None:
        payload["metadata"] = dict(metadata)
    return payload


def _leased_request_payload(relay_request: RelayRequest) -> JsonObject:
    _validate_registration_token(relay_request.registration_token)
    if not relay_request.request_id or not relay_request.lease_id:
        raise RelayApiError("relay request is missing request/lease identity")
    return {
        "request_id": relay_request.request_id,
        "registration_token": relay_request.registration_token,
        "lease_id": relay_request.lease_id,
    }


def _renew_payload(
    relay_request: RelayRequest,
    worker_id: str | None,
    lease_seconds: float | None,
) -> JsonObject:
    payload = _leased_request_payload(relay_request)
    if worker_id is not None:
        payload["worker_id"] = worker_id
    if lease_seconds is not None:
        payload["lease_seconds"] = lease_seconds
    return payload


def _renewed_request(
    response: Mapping[str, Any], relay_request: RelayRequest
) -> RelayRequest:
    request_payload = response.get("request")
    if not isinstance(request_payload, dict):
        raise RelayApiError("relay returned an invalid renew payload", body=response)
    renewed = RelayRequest.from_payload(request_payload)
    if not _valid_transport_state_transition(relay_request, renewed):
        raise RelayApiError(
            "relay returned an inconsistent renewed request", body=response
        )
    expected = replace(
        relay_request,
        lease_expires_at=renewed.lease_expires_at,
        reattachable=renewed.reattachable,
        accepted_notified_at=renewed.accepted_notified_at,
        parked_transport_epoch=renewed.parked_transport_epoch,
    )
    if renewed != expected:
        raise RelayApiError(
            "relay returned an inconsistent renewed request", body=response
        )
    return renewed


def _valid_transport_state_transition(
    previous: RelayRequest, renewed: RelayRequest
) -> bool:
    if previous.reattachable and not renewed.reattachable:
        return False
    if (
        previous.accepted_notified_at is not None
        and renewed.accepted_notified_at != previous.accepted_notified_at
    ):
        return False
    if (
        previous.parked_transport_epoch is not None
        and renewed.parked_transport_epoch != previous.parked_transport_epoch
    ):
        return False
    return not (
        renewed.parked_transport_epoch is not None
        and renewed.accepted_notified_at is None
    )


def _response_payload(
    relay_request: RelayRequest,
    body: object,
    status: int,
    headers: Mapping[str, str] | None,
) -> JsonObject:
    if isinstance(body, bytes):
        _validate_http_body_size(body)
        encoded = {
            "encoding": "base64",
            "value": base64.b64encode(body).decode("ascii"),
        }
    else:
        encoded = {"encoding": "json", "value": body}
    payload = _leased_request_payload(relay_request)
    payload.update({"status": status, "body": encoded})
    if headers is not None:
        payload["headers"] = dict(headers)
    return payload


def _error_payload(
    relay_request: RelayRequest, message: str, status: int
) -> JsonObject:
    payload = _leased_request_payload(relay_request)
    payload.update({"status": status, "error": message})
    return payload


def _poll_path(
    rollout_id: str,
    registration_token: str,
    *,
    worker_id: str | None,
    timeout_seconds: float | None,
    limit: int | None,
    lease_seconds: float | None,
) -> str:
    query = {
        "rollout_id": rollout_id,
        "registration_token": registration_token,
    }
    if worker_id is not None:
        query["worker_id"] = worker_id
    if timeout_seconds is not None:
        query["timeout_seconds"] = _format_number(timeout_seconds)
    if limit is not None:
        query["limit"] = str(limit)
    if lease_seconds is not None:
        query["lease_seconds"] = _format_number(lease_seconds)
    return f"/worker/poll?{parse.urlencode(query)}"


def _poll_client_timeout(
    default_timeout: float, server_timeout: float | None
) -> float | None:
    if server_timeout is None:
        return None
    return max(
        default_timeout,
        server_timeout + RELAY_POLL_TIMEOUT_GRACE_SECONDS,
    )


def _validate_registration_token(value: object) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 32
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RelayApiError(
            "registration_token must be the 32-character lowercase hexadecimal "
            "token returned by register_rollout"
        )


def _validate_http_body_size(body: bytes) -> None:
    if len(body) > MAX_RELAY_HTTP_BODY_BYTES:
        raise RelayApiError(
            f"relay HTTP body exceeds the {MAX_RELAY_HTTP_BODY_BYTES} byte limit"
        )


def _required_string(payload: Mapping[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise RelayApiError(f"relay payload omitted string {field}", body=dict(payload))
    return value


def _validate_poll_identity(
    result: RelayPollResult, rollout_id: str, registration_token: str
) -> None:
    request_ids: set[str] = set()
    for request_item in result.requests:
        if request_item.rollout_id != rollout_id:
            raise RelayApiError(
                "relay poll returned a request for a different rollout",
                body={"request_id": request_item.request_id},
            )
        if request_item.registration_token != registration_token:
            raise RelayApiError(
                "relay poll returned a request for a different registration",
                body={"request_id": request_item.request_id},
            )
        if request_item.request_id in request_ids:
            raise RelayApiError(
                "relay poll returned a duplicate request identity",
                body={"request_id": request_item.request_id},
            )
        request_ids.add(request_item.request_id)


def _decode_relay_json(
    raw: str,
    *,
    status: int,
    headers: Mapping[str, str],
) -> JsonObject:
    try:
        decoded = json.loads(raw) if raw else {}
    except json.JSONDecodeError as exc:
        if 200 <= status < 300:
            raise RelayApiError(
                f"relay returned invalid JSON: {exc}",
                status_code=status,
                body={"error": raw},
                headers=headers,
            ) from exc
        decoded = {"error": raw}
    if not 200 <= status < 300:
        raise RelayApiError(
            f"relay request failed ({status}): {decoded}",
            status_code=status,
            body=decoded,
            headers=headers,
        )
    if not isinstance(decoded, dict):
        raise RelayApiError(
            "relay returned a non-object JSON payload",
            status_code=status,
            body=decoded,
            headers=headers,
        )
    return decoded


def _decode_body(
    body: object,
    payload: Mapping[str, Any],
) -> tuple[object, bytes]:
    if not isinstance(body, Mapping) or set(body) != {"encoding", "value"}:
        raise RelayApiError(
            "relay request body must contain exactly encoding and value", body=payload
        )
    encoding, value = body["encoding"], body["value"]
    if encoding == "json":
        try:
            encoded = json.dumps(
                value, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
            return json.loads(encoded), encoded
        except (TypeError, ValueError) as exc:
            raise RelayApiError(
                "relay request JSON body is invalid", body=payload
            ) from exc
    if encoding != "base64" or not isinstance(value, str):
        raise RelayApiError(
            "relay request body encoding/value is invalid", body=payload
        )
    try:
        return None, base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise RelayApiError(
            "relay request base64 body is invalid", body=payload
        ) from exc


def _safe_http_headers(headers: Mapping[str, Any]) -> dict[str, str]:
    hop_by_hop = {
        "connection",
        "content-length",
        "host",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
    return {
        str(key): str(value)
        for key, value in headers.items()
        if str(key).lower() not in hop_by_hop
    }


def _format_number(value: float) -> str:
    return f"{value:g}"


def _optional_float(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _optional_string(value: object) -> str | None:
    return None if value is None else str(value)


def _optional_int(value: object) -> int | None:
    return None if value is None else _int(value, default=0)


def _optional_bool(value: object, *, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise RelayApiError("relay payload contained an invalid boolean")
    return value


def _int(value: object, *, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _string_dict(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): str(item) for key, item in value.items()}
