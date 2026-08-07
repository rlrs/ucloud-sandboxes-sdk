from __future__ import annotations

import asyncio
import base64
import binascii
from dataclasses import dataclass
import json
import time
from typing import Any, Mapping
from urllib import error, parse, request
from urllib.parse import quote

from ._http import (
    ResponseTooLargeError,
    open_no_redirect,
    read_async_response,
    read_sync_response,
    response_headers,
)


JsonObject = dict[str, Any]
MAX_RELAY_JSON_BYTES = 32 * 1024 * 1024
MAX_RELAY_HTTP_BODY_BYTES = MAX_RELAY_JSON_BYTES // 2
RELAY_POLL_TIMEOUT_GRACE_SECONDS = 5.0


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


@dataclass(frozen=True)
class ModelRelayConfig:
    relay_url: str
    rollout_id: str
    api_key: str = "intercepted"

    @property
    def openai_base_url(self) -> str:
        base = self.relay_url.rstrip("/")
        return f"{base}/rollouts/{quote(self.rollout_id, safe='')}/v1"

    def env(self) -> dict[str, str]:
        return {
            "VF_RELAY_ROLLOUT_ID": self.rollout_id,
            "OPENAI_BASE_URL": self.openai_base_url,
            "OPENAI_API_KEY": self.api_key,
        }


def model_relay_env(
    relay_url: str,
    rollout_id: str,
    *,
    api_key: str = "intercepted",
) -> dict[str, str]:
    return ModelRelayConfig(
        relay_url=relay_url,
        rollout_id=rollout_id,
        api_key=api_key,
    ).env()


@dataclass(frozen=True)
class HttpTunnelConfig:
    relay_url: str
    rollout_id: str
    relay_token: str | None = None
    registration_token: str | None = None

    @property
    def base_url(self) -> str:
        return http_tunnel_url(
            self.relay_url,
            self.rollout_id,
            registration_token=self.registration_token,
        )

    def headers(self) -> dict[str, str]:
        if self.relay_token is None:
            return {}
        return {"X-UCloud-Relay-Token": self.relay_token}


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

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "RelayRequest":
        request_id = _required_string(payload, "request_id")
        rollout_id = _required_string(payload, "rollout_id")
        registration_token = _required_string(payload, "registration_token")
        lease_id = _required_string(payload, "lease_id")
        _validate_registration_token(registration_token)
        headers = payload.get("headers")
        body = payload.get("body")
        body_bytes = _decode_body_bytes(payload, body)
        _validate_http_body_size(body_bytes)
        return cls(
            request_id=request_id,
            rollout_id=rollout_id,
            registration_token=registration_token,
            endpoint=str(payload.get("endpoint") or ""),
            method=str(payload.get("method") or "POST"),
            headers=_string_dict(headers),
            body=_copy_json_value(body),
            body_bytes=body_bytes,
            created_at=_optional_float(payload.get("created_at")),
            delivered_at=_optional_float(payload.get("delivered_at")),
            first_delivered_at=_optional_float(payload.get("first_delivered_at")),
            lease_id=lease_id,
            lease_expires_at=_optional_float(payload.get("lease_expires_at")),
            leased_by=(
                str(payload["leased_by"])
                if payload.get("leased_by") is not None
                else None
            ),
            delivery_count=_int(payload.get("delivery_count"), default=0),
            sandbox_id=(
                str(payload["sandbox_id"])
                if payload.get("sandbox_id") is not None
                else None
            ),
            sandbox_generation=(
                _int(payload.get("sandbox_generation"), default=0)
                if payload.get("sandbox_generation") is not None
                else None
            ),
        )


@dataclass(frozen=True)
class RelayPollResult:
    request: RelayRequest | None
    requests: list[RelayRequest]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "RelayPollResult":
        raw_requests = payload.get("requests")
        if raw_requests is not None and not isinstance(raw_requests, list):
            raise RelayApiError("relay returned invalid requests", body=dict(payload))
        requests: list[RelayRequest] = []
        for item in raw_requests or []:
            if not isinstance(item, Mapping):
                raise RelayApiError("relay returned an invalid request", body=item)
            requests.append(RelayRequest.from_payload(item))
        raw_request = payload.get("request")
        if raw_request is not None and not isinstance(raw_request, Mapping):
            raise RelayApiError("relay returned an invalid request", body=raw_request)
        request_item = (
            RelayRequest.from_payload(raw_request) if raw_request is not None else None
        )
        if request_item is not None and not requests:
            requests = [request_item]
        if (
            request_item is not None
            and requests
            and _request_identity(request_item) != _request_identity(requests[0])
        ):
            raise RelayApiError(
                "relay returned inconsistent request identities", body=dict(payload)
            )
        return cls(
            request=request_item or (requests[0] if requests else None),
            requests=requests,
        )


class _RelayWorkerState:
    def __init__(self) -> None:
        self._registration_tokens: dict[str, str] = {}
        self._request_tokens: dict[str, str] = {}

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

    def _request_token(
        self, request_id: str, registration_token: str | None = None
    ) -> str:
        token = (
            registration_token
            if registration_token is not None
            else self._request_tokens.get(request_id)
        )
        if token is None:
            raise RelayApiError(f"request was not polled by this client: {request_id}")
        _validate_registration_token(token)
        return token

    def _remember_requests(self, result: RelayPollResult) -> None:
        for item in result.requests:
            self._request_tokens[item.request_id] = item.registration_token

    def _forget_registration(self, rollout_id: str, token: str) -> None:
        self._registration_tokens.pop(rollout_id, None)
        self._request_tokens = {
            request_id: request_token
            for request_id, request_token in self._request_tokens.items()
            if request_token != token
        }


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
        self._forget_registration(rollout_id, token)
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
        self._remember_requests(result)
        return result

    def renew(
        self,
        request_id: str,
        lease_id: str,
        *,
        worker_id: str | None = None,
        lease_seconds: float | None = None,
        registration_token: str | None = None,
    ) -> RelayRequest:
        token = self._request_token(request_id, registration_token)
        payload: JsonObject = {
            "request_id": request_id,
            "registration_token": token,
            "lease_id": lease_id,
        }
        if worker_id is not None:
            payload["worker_id"] = worker_id
        if lease_seconds is not None:
            payload["lease_seconds"] = lease_seconds
        response = self._request_json("POST", "/worker/renew", payload=payload)
        request_payload = response.get("request")
        if not isinstance(request_payload, dict):
            raise RelayApiError(
                "relay returned an invalid renew payload", body=response
            )
        renewed = RelayRequest.from_payload(request_payload)
        if renewed.request_id != request_id or renewed.registration_token != token:
            raise RelayApiError(
                "relay returned an inconsistent renewed request", body=response
            )
        self._request_tokens[renewed.request_id] = renewed.registration_token
        return renewed

    def renew_request(
        self,
        relay_request: RelayRequest,
        *,
        worker_id: str | None = None,
        lease_seconds: float | None = None,
    ) -> RelayRequest:
        return self.renew(
            relay_request.request_id,
            relay_request.lease_id,
            worker_id=worker_id,
            lease_seconds=lease_seconds,
            registration_token=relay_request.registration_token,
        )

    def respond(
        self,
        request_id: str,
        lease_id: str,
        response: object,
        *,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
        registration_token: str | None = None,
    ) -> JsonObject:
        token = self._request_token(request_id, registration_token)
        payload: JsonObject = {
            "request_id": request_id,
            "registration_token": token,
            "lease_id": lease_id,
            "status": status,
            "response": response,
        }
        if headers is not None:
            payload["headers"] = dict(headers)
        return self._request_json("POST", "/worker/respond", payload=payload)

    def respond_to(
        self,
        relay_request: RelayRequest,
        response: object,
        *,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
    ) -> JsonObject:
        return self.respond(
            relay_request.request_id,
            relay_request.lease_id,
            response,
            status=status,
            headers=headers,
            registration_token=relay_request.registration_token,
        )

    def respond_bytes(
        self,
        request_id: str,
        lease_id: str,
        body: bytes,
        *,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
        registration_token: str | None = None,
    ) -> JsonObject:
        token = self._request_token(request_id, registration_token)
        _validate_http_body_size(body)
        payload: JsonObject = {
            "request_id": request_id,
            "registration_token": token,
            "lease_id": lease_id,
            "status": status,
            "body_base64": base64.b64encode(body).decode("ascii"),
        }
        if headers is not None:
            payload["headers"] = dict(headers)
        return self._request_json("POST", "/worker/respond", payload=payload)

    def respond_bytes_to(
        self,
        relay_request: RelayRequest,
        body: bytes,
        *,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
    ) -> JsonObject:
        return self.respond_bytes(
            relay_request.request_id,
            relay_request.lease_id,
            body,
            status=status,
            headers=headers,
            registration_token=relay_request.registration_token,
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
                return self.respond_bytes_to(
                    relay_request,
                    body,
                    status=status,
                    headers=headers,
                )
            except RelayApiError as exc:
                if exc.status_code != 503 or attempt + 1 >= attempts:
                    raise
                time.sleep(max(0.0, retry_delay_seconds))
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

    def error(
        self,
        request_id: str,
        lease_id: str,
        message: str,
        *,
        status: int = 502,
        registration_token: str | None = None,
    ) -> JsonObject:
        token = self._request_token(request_id, registration_token)
        return self._request_json(
            "POST",
            "/worker/error",
            payload={
                "request_id": request_id,
                "registration_token": token,
                "lease_id": lease_id,
                "status": status,
                "error": message,
            },
        )

    def error_request(
        self,
        relay_request: RelayRequest,
        message: str,
        *,
        status: int = 502,
    ) -> JsonObject:
        return self.error(
            relay_request.request_id,
            relay_request.lease_id,
            message,
            status=status,
            registration_token=relay_request.registration_token,
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
                try:
                    decoded = json.loads(raw) if raw else {}
                except json.JSONDecodeError as exc:
                    raise RelayApiError(
                        f"relay returned invalid JSON: {exc}",
                        status_code=response_status,
                        body={"error": raw},
                        headers=response_header_values,
                    ) from exc
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
            decoded = _decode_json_error(raw)
            api_error = RelayApiError(
                f"relay request failed ({exc.code}): {decoded}",
                status_code=exc.code,
                body=decoded,
                headers=header_values,
            )
            exc.close()
            raise api_error from exc
        except ResponseTooLargeError as exc:
            raise RelayApiError(
                str(exc),
                status_code=response_status,
                headers=response_header_values,
            ) from exc
        except OSError as exc:
            raise RelayApiError(f"relay request failed: {exc}") from exc
        if not isinstance(decoded, dict):
            raise RelayApiError(
                "relay returned a non-object JSON payload",
                status_code=response_status,
                body=decoded,
                headers=response_header_values,
            )
        return decoded


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
        self._forget_registration(rollout_id, token)
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
        self._remember_requests(result)
        return result

    async def renew(
        self,
        request_id: str,
        lease_id: str,
        *,
        worker_id: str | None = None,
        lease_seconds: float | None = None,
        registration_token: str | None = None,
    ) -> RelayRequest:
        token = self._request_token(request_id, registration_token)
        payload: JsonObject = {
            "request_id": request_id,
            "registration_token": token,
            "lease_id": lease_id,
        }
        if worker_id is not None:
            payload["worker_id"] = worker_id
        if lease_seconds is not None:
            payload["lease_seconds"] = lease_seconds
        response = await self._request_json("POST", "/worker/renew", payload=payload)
        request_payload = response.get("request")
        if not isinstance(request_payload, dict):
            raise RelayApiError(
                "relay returned an invalid renew payload", body=response
            )
        renewed = RelayRequest.from_payload(request_payload)
        if renewed.request_id != request_id or renewed.registration_token != token:
            raise RelayApiError(
                "relay returned an inconsistent renewed request", body=response
            )
        self._request_tokens[renewed.request_id] = renewed.registration_token
        return renewed

    async def renew_request(
        self,
        relay_request: RelayRequest,
        *,
        worker_id: str | None = None,
        lease_seconds: float | None = None,
    ) -> RelayRequest:
        return await self.renew(
            relay_request.request_id,
            relay_request.lease_id,
            worker_id=worker_id,
            lease_seconds=lease_seconds,
            registration_token=relay_request.registration_token,
        )

    async def respond(
        self,
        request_id: str,
        lease_id: str,
        response: object,
        *,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
        registration_token: str | None = None,
    ) -> JsonObject:
        token = self._request_token(request_id, registration_token)
        payload: JsonObject = {
            "request_id": request_id,
            "registration_token": token,
            "lease_id": lease_id,
            "status": status,
            "response": response,
        }
        if headers is not None:
            payload["headers"] = dict(headers)
        return await self._request_json("POST", "/worker/respond", payload=payload)

    async def respond_to(
        self,
        relay_request: RelayRequest,
        response: object,
        *,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
    ) -> JsonObject:
        return await self.respond(
            relay_request.request_id,
            relay_request.lease_id,
            response,
            status=status,
            headers=headers,
            registration_token=relay_request.registration_token,
        )

    async def respond_bytes(
        self,
        request_id: str,
        lease_id: str,
        body: bytes,
        *,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
        registration_token: str | None = None,
    ) -> JsonObject:
        token = self._request_token(request_id, registration_token)
        _validate_http_body_size(body)
        payload: JsonObject = {
            "request_id": request_id,
            "registration_token": token,
            "lease_id": lease_id,
            "status": status,
            "body_base64": base64.b64encode(body).decode("ascii"),
        }
        if headers is not None:
            payload["headers"] = dict(headers)
        return await self._request_json("POST", "/worker/respond", payload=payload)

    async def respond_bytes_to(
        self,
        relay_request: RelayRequest,
        body: bytes,
        *,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
    ) -> JsonObject:
        return await self.respond_bytes(
            relay_request.request_id,
            relay_request.lease_id,
            body,
            status=status,
            headers=headers,
            registration_token=relay_request.registration_token,
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
                return await self.respond_bytes_to(
                    relay_request,
                    body,
                    status=status,
                    headers=headers,
                )
            except RelayApiError as exc:
                if exc.status_code != 503 or attempt + 1 >= attempts:
                    raise
                await asyncio.sleep(max(0.0, retry_delay_seconds))
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

    async def error(
        self,
        request_id: str,
        lease_id: str,
        message: str,
        *,
        status: int = 502,
        registration_token: str | None = None,
    ) -> JsonObject:
        token = self._request_token(request_id, registration_token)
        return await self._request_json(
            "POST",
            "/worker/error",
            payload={
                "request_id": request_id,
                "registration_token": token,
                "lease_id": lease_id,
                "status": status,
                "error": message,
            },
        )

    async def error_request(
        self,
        relay_request: RelayRequest,
        message: str,
        *,
        status: int = 502,
    ) -> JsonObject:
        return await self.error(
            relay_request.request_id,
            relay_request.lease_id,
            message,
            status=status,
            registration_token=relay_request.registration_token,
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
        async with client.request(
            method,
            self.relay_url + path,
            json=payload,
            headers=headers,
            allow_redirects=False,
            timeout=(
                self.timeout_seconds if timeout_seconds is None else timeout_seconds
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
            try:
                decoded = json.loads(raw) if raw else {}
            except json.JSONDecodeError as exc:
                if 200 <= response.status < 300:
                    raise RelayApiError(
                        f"relay returned invalid JSON: {exc}",
                        status_code=response.status,
                        body={"error": raw},
                        headers=response_headers(response),
                    ) from exc
                decoded = {"error": raw}
            if not 200 <= response.status < 300:
                raise RelayApiError(
                    f"relay request failed ({response.status}): {decoded}",
                    status_code=response.status,
                    body=decoded,
                    headers=response_headers(response),
                )
        if not isinstance(decoded, dict):
            raise RelayApiError(
                "relay returned a non-object JSON payload",
                status_code=response.status,
                body=decoded,
                headers=response_headers(response),
            )
        return decoded


def _rollout_records(payload: Mapping[str, Any]) -> list[JsonObject]:
    rollouts = payload.get("rollouts")
    if not isinstance(rollouts, list):
        return []
    return [dict(item) for item in rollouts if isinstance(item, dict)]


def _registration_payload(
    rollout_id: str,
    metadata: Mapping[str, Any] | None,
) -> JsonObject:
    payload: JsonObject = {"rollout_id": rollout_id}
    if metadata is not None:
        payload["metadata"] = dict(metadata)
    return payload


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


def _request_identity(request_item: RelayRequest) -> tuple[str, str, str, str]:
    return (
        request_item.request_id,
        request_item.rollout_id,
        request_item.registration_token,
        request_item.lease_id,
    )


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


def _decode_json_error(raw: str) -> object:
    try:
        decoded = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {"error": raw}
    return decoded


def _decode_body_bytes(payload: Mapping[str, Any], body: object) -> bytes:
    encoded = payload.get("body_base64")
    if encoded is None:
        return json.dumps(
            body,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    if not isinstance(encoded, str):
        raise RelayApiError("relay request body_base64 is not a string", body=payload)
    try:
        return base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise RelayApiError(
            "relay request body_base64 is invalid", body=payload
        ) from exc


def _copy_json_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _copy_json_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_copy_json_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return None


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


def _int(value: object, *, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _string_dict(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): str(item) for key, item in value.items()}
