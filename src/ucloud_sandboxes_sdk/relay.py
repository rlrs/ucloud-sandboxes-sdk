from __future__ import annotations

from dataclasses import dataclass
import json
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
    path_scoped_base_url: bool = True

    @property
    def openai_base_url(self) -> str:
        base = self.relay_url.rstrip("/")
        if self.path_scoped_base_url:
            return f"{base}/rollouts/{quote(self.rollout_id, safe='')}/v1"
        return f"{base}/v1"

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
    path_scoped_base_url: bool = True,
) -> dict[str, str]:
    return ModelRelayConfig(
        relay_url=relay_url,
        rollout_id=rollout_id,
        api_key=api_key,
        path_scoped_base_url=path_scoped_base_url,
    ).env()


@dataclass(frozen=True)
class RelayRequest:
    request_id: str
    rollout_id: str
    registration_token: str
    endpoint: str
    method: str
    headers: dict[str, str]
    body: JsonObject
    created_at: float | None = None
    delivered_at: float | None = None
    first_delivered_at: float | None = None
    lease_id: str = ""
    lease_expires_at: float | None = None
    leased_by: str | None = None
    delivery_count: int = 0

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "RelayRequest":
        headers = payload.get("headers")
        body = payload.get("body")
        relay_request = cls(
            request_id=str(payload.get("request_id") or ""),
            rollout_id=str(payload.get("rollout_id") or ""),
            registration_token=str(payload.get("registration_token") or ""),
            endpoint=str(payload.get("endpoint") or ""),
            method=str(payload.get("method") or "POST"),
            headers=_string_dict(headers),
            body=dict(body) if isinstance(body, dict) else {},
            created_at=_optional_float(payload.get("created_at")),
            delivered_at=_optional_float(payload.get("delivered_at")),
            first_delivered_at=_optional_float(payload.get("first_delivered_at")),
            lease_id=str(payload.get("lease_id") or ""),
            lease_expires_at=_optional_float(payload.get("lease_expires_at")),
            leased_by=(
                str(payload["leased_by"])
                if payload.get("leased_by") is not None
                else None
            ),
            delivery_count=_int(payload.get("delivery_count"), default=0),
        )
        _validate_registration_token(relay_request.registration_token)
        if (
            not relay_request.request_id
            or not relay_request.rollout_id
            or not relay_request.lease_id
        ):
            raise RelayApiError(
                "relay returned a request without request, rollout, or lease identity",
                body=dict(payload),
            )
        return relay_request


@dataclass(frozen=True)
class RelayPollResult:
    request: RelayRequest | None
    requests: list[RelayRequest]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "RelayPollResult":
        raw_requests = payload.get("requests")
        requests = (
            [
                RelayRequest.from_payload(item)
                for item in raw_requests
                if isinstance(item, dict)
            ]
            if isinstance(raw_requests, list)
            else []
        )
        raw_request = payload.get("request")
        request_item = (
            RelayRequest.from_payload(raw_request)
            if isinstance(raw_request, dict)
            else None
        )
        if request_item is not None and not requests:
            requests = [request_item]
        return cls(request=request_item or (requests[0] if requests else None), requests=requests)


class _RelayRegistrationCache:
    def __init__(self) -> None:
        self._registration_tokens: dict[str, str] = {}

    def _remember_registration(self, rollout_id: str, response: JsonObject) -> None:
        rollout = response.get("rollout")
        if not isinstance(rollout, Mapping):
            raise RelayApiError("relay returned an invalid registration payload", body=response)
        token = str(rollout.get("registration_token") or "")
        _validate_registration_token(token)
        response_rollout_id = str(rollout.get("rollout_id") or rollout_id)
        if response_rollout_id != rollout_id:
            raise RelayApiError("relay registration rollout_id does not match", body=response)
        self._registration_tokens[rollout_id] = token

    def _registration_token(
        self,
        rollout_id: str,
        registration_token: str | None,
    ) -> str:
        token = registration_token or self._registration_tokens.get(rollout_id, "")
        _validate_registration_token(token)
        if registration_token is not None:
            self._registration_tokens[rollout_id] = token
        return token


class RelayWorkerClient(_RelayRegistrationCache):
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
        payload = self._request_json("GET", "/v1/relay/rollouts")
        rollouts = payload.get("rollouts")
        return [
            dict(item)
            for item in rollouts
            if isinstance(item, dict)
        ] if isinstance(rollouts, list) else []

    def register_rollout(
        self,
        rollout_id: str,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> JsonObject:
        payload: JsonObject = {"rollout_id": rollout_id}
        if metadata is not None:
            payload["metadata"] = dict(metadata)
        response = self._request_json("POST", "/register_rollout", payload=payload)
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
            "POST",
            "/unregister_rollout",
            payload={"rollout_id": rollout_id, "registration_token": token},
        )
        if self._registration_tokens.get(rollout_id) == token:
            self._registration_tokens.pop(rollout_id, None)
        return response

    def heartbeat(
        self,
        rollout_id: str,
        worker_id: str,
        *,
        registration_token: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> JsonObject:
        payload: JsonObject = {
            "rollout_id": rollout_id,
            "registration_token": self._registration_token(
                rollout_id,
                registration_token,
            ),
            "worker_id": worker_id,
        }
        if metadata is not None:
            payload["metadata"] = dict(metadata)
        return self._request_json("POST", "/worker/heartbeat", payload=payload)

    def poll(
        self,
        rollout_id: str,
        *,
        registration_token: str | None = None,
        worker_id: str | None = None,
        timeout_seconds: float | None = None,
        limit: int | None = None,
        lease_seconds: float | None = None,
    ) -> RelayPollResult:
        query: dict[str, str] = {
            "rollout_id": rollout_id,
            "registration_token": self._registration_token(
                rollout_id,
                registration_token,
            ),
        }
        if worker_id is not None:
            query["worker_id"] = worker_id
        if timeout_seconds is not None:
            query["timeout_seconds"] = _format_number(timeout_seconds)
        if limit is not None:
            query["limit"] = str(limit)
        if lease_seconds is not None:
            query["lease_seconds"] = _format_number(lease_seconds)
        payload = self._request_json(
            "GET",
            f"/worker/poll?{parse.urlencode(query)}",
            timeout_seconds=(
                max(
                    self.timeout_seconds,
                    timeout_seconds + RELAY_POLL_TIMEOUT_GRACE_SECONDS,
                )
                if timeout_seconds is not None
                else None
            ),
        )
        return RelayPollResult.from_payload(payload)

    def renew(
        self,
        request_id: str,
        lease_id: str,
        *,
        registration_token: str,
        worker_id: str | None = None,
        lease_seconds: float | None = None,
    ) -> RelayRequest:
        _validate_registration_token(registration_token)
        payload: JsonObject = {
            "registration_token": registration_token,
            "request_id": request_id,
            "lease_id": lease_id,
        }
        if worker_id is not None:
            payload["worker_id"] = worker_id
        if lease_seconds is not None:
            payload["lease_seconds"] = lease_seconds
        response = self._request_json("POST", "/worker/renew", payload=payload)
        request_payload = response.get("request")
        if not isinstance(request_payload, dict):
            raise RelayApiError("relay returned an invalid renew payload", body=response)
        return RelayRequest.from_payload(request_payload)

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
            registration_token=relay_request.registration_token,
            worker_id=worker_id,
            lease_seconds=lease_seconds,
        )

    def respond(
        self,
        request_id: str,
        lease_id: str,
        response: object,
        *,
        registration_token: str,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
    ) -> JsonObject:
        _validate_registration_token(registration_token)
        payload: JsonObject = {
            "registration_token": registration_token,
            "request_id": request_id,
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
            registration_token=relay_request.registration_token,
            status=status,
            headers=headers,
        )

    def error(
        self,
        request_id: str,
        lease_id: str,
        message: str,
        *,
        registration_token: str,
        status: int = 502,
    ) -> JsonObject:
        _validate_registration_token(registration_token)
        return self._request_json(
            "POST",
            "/worker/error",
            payload={
                "registration_token": registration_token,
                "request_id": request_id,
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
            registration_token=relay_request.registration_token,
            status=status,
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
                    self.timeout_seconds
                    if timeout_seconds is None
                    else timeout_seconds
                ),
            ) as response:
                raw = read_sync_response(
                    response,
                    limit=MAX_RELAY_JSON_BYTES,
                ).decode("utf-8")
                try:
                    decoded = json.loads(raw) if raw else {}
                except json.JSONDecodeError as exc:
                    raise RelayApiError(
                        f"relay returned invalid JSON: {exc}",
                        status_code=int(getattr(response, "status", 200)),
                        body={"error": raw},
                        headers=response_headers(response),
                    ) from exc
        except error.HTTPError as exc:
            try:
                raw = read_sync_response(
                    exc,
                    limit=MAX_RELAY_JSON_BYTES,
                ).decode("utf-8", errors="replace")
            except ResponseTooLargeError as size_exc:
                api_error = RelayApiError(
                    str(size_exc),
                    status_code=exc.code,
                    headers=response_headers(exc),
                )
                exc.close()
                raise api_error from size_exc
            decoded = _decode_json_error(raw)
            api_error = RelayApiError(
                f"relay request failed ({exc.code}): {decoded}",
                status_code=exc.code,
                body=decoded,
                headers=response_headers(exc),
            )
            exc.close()
            raise api_error from exc
        except (OSError, ResponseTooLargeError) as exc:
            raise RelayApiError(f"relay request failed: {exc}") from exc
        if not isinstance(decoded, dict):
            raise RelayApiError("relay returned a non-object JSON payload", body=decoded)
        return decoded


class AsyncRelayWorkerClient(_RelayRegistrationCache):
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
        payload = await self._request_json("GET", "/v1/relay/rollouts")
        rollouts = payload.get("rollouts")
        return [
            dict(item)
            for item in rollouts
            if isinstance(item, dict)
        ] if isinstance(rollouts, list) else []

    async def register_rollout(
        self,
        rollout_id: str,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> JsonObject:
        payload: JsonObject = {"rollout_id": rollout_id}
        if metadata is not None:
            payload["metadata"] = dict(metadata)
        response = await self._request_json("POST", "/register_rollout", payload=payload)
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
            "POST",
            "/unregister_rollout",
            payload={"rollout_id": rollout_id, "registration_token": token},
        )
        if self._registration_tokens.get(rollout_id) == token:
            self._registration_tokens.pop(rollout_id, None)
        return response

    async def heartbeat(
        self,
        rollout_id: str,
        worker_id: str,
        *,
        registration_token: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> JsonObject:
        payload: JsonObject = {
            "rollout_id": rollout_id,
            "registration_token": self._registration_token(
                rollout_id,
                registration_token,
            ),
            "worker_id": worker_id,
        }
        if metadata is not None:
            payload["metadata"] = dict(metadata)
        return await self._request_json("POST", "/worker/heartbeat", payload=payload)

    async def poll(
        self,
        rollout_id: str,
        *,
        registration_token: str | None = None,
        worker_id: str | None = None,
        timeout_seconds: float | None = None,
        limit: int | None = None,
        lease_seconds: float | None = None,
    ) -> RelayPollResult:
        query: dict[str, str] = {
            "rollout_id": rollout_id,
            "registration_token": self._registration_token(
                rollout_id,
                registration_token,
            ),
        }
        if worker_id is not None:
            query["worker_id"] = worker_id
        if timeout_seconds is not None:
            query["timeout_seconds"] = _format_number(timeout_seconds)
        if limit is not None:
            query["limit"] = str(limit)
        if lease_seconds is not None:
            query["lease_seconds"] = _format_number(lease_seconds)
        payload = await self._request_json(
            "GET",
            f"/worker/poll?{parse.urlencode(query)}",
            timeout_seconds=(
                max(
                    self.timeout_seconds,
                    timeout_seconds + RELAY_POLL_TIMEOUT_GRACE_SECONDS,
                )
                if timeout_seconds is not None
                else None
            ),
        )
        return RelayPollResult.from_payload(payload)

    async def renew(
        self,
        request_id: str,
        lease_id: str,
        *,
        registration_token: str,
        worker_id: str | None = None,
        lease_seconds: float | None = None,
    ) -> RelayRequest:
        _validate_registration_token(registration_token)
        payload: JsonObject = {
            "registration_token": registration_token,
            "request_id": request_id,
            "lease_id": lease_id,
        }
        if worker_id is not None:
            payload["worker_id"] = worker_id
        if lease_seconds is not None:
            payload["lease_seconds"] = lease_seconds
        response = await self._request_json("POST", "/worker/renew", payload=payload)
        request_payload = response.get("request")
        if not isinstance(request_payload, dict):
            raise RelayApiError("relay returned an invalid renew payload", body=response)
        return RelayRequest.from_payload(request_payload)

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
            registration_token=relay_request.registration_token,
            worker_id=worker_id,
            lease_seconds=lease_seconds,
        )

    async def respond(
        self,
        request_id: str,
        lease_id: str,
        response: object,
        *,
        registration_token: str,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
    ) -> JsonObject:
        _validate_registration_token(registration_token)
        payload: JsonObject = {
            "registration_token": registration_token,
            "request_id": request_id,
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
            registration_token=relay_request.registration_token,
            status=status,
            headers=headers,
        )

    async def error(
        self,
        request_id: str,
        lease_id: str,
        message: str,
        *,
        registration_token: str,
        status: int = 502,
    ) -> JsonObject:
        _validate_registration_token(registration_token)
        return await self._request_json(
            "POST",
            "/worker/error",
            payload={
                "registration_token": registration_token,
                "request_id": request_id,
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
            registration_token=relay_request.registration_token,
            status=status,
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
                    await read_async_response(
                        response,
                        limit=MAX_RELAY_JSON_BYTES,
                    )
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
            raise RelayApiError("relay returned a non-object JSON payload", body=decoded)
        return decoded


def _validate_registration_token(value: object) -> None:
    token = value if isinstance(value, str) else ""
    if len(token) != 32 or any(character not in "0123456789abcdef" for character in token):
        raise RelayApiError(
            "registration_token must be the 32-character token returned by "
            "register_rollout"
        )


def _decode_json_error(raw: str) -> object:
    try:
        decoded = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        return {"error": raw}
    return decoded


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
