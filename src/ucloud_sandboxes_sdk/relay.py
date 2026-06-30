from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping
from urllib import error, parse, request
from urllib.parse import quote


JsonObject = dict[str, Any]


class RelayApiError(RuntimeError):
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
        return cls(
            request_id=str(payload.get("request_id") or ""),
            rollout_id=str(payload.get("rollout_id") or ""),
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


class RelayWorkerClient:
    def __init__(
        self,
        relay_url: str,
        *,
        worker_token: str | None = None,
        timeout_seconds: float = 30.0,
        headers: Mapping[str, str] | None = None,
    ) -> None:
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
        return self._request_json("POST", "/register_rollout", payload=payload)

    def unregister_rollout(self, rollout_id: str) -> JsonObject:
        return self._request_json(
            "POST",
            "/unregister_rollout",
            payload={"rollout_id": rollout_id},
        )

    def heartbeat(
        self,
        rollout_id: str,
        worker_id: str,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> JsonObject:
        payload: JsonObject = {"rollout_id": rollout_id, "worker_id": worker_id}
        if metadata is not None:
            payload["metadata"] = dict(metadata)
        return self._request_json("POST", "/worker/heartbeat", payload=payload)

    def poll(
        self,
        rollout_id: str,
        *,
        worker_id: str | None = None,
        timeout_seconds: float | None = None,
        limit: int | None = None,
        lease_seconds: float | None = None,
    ) -> RelayPollResult:
        query: dict[str, str] = {"rollout_id": rollout_id}
        if worker_id is not None:
            query["worker_id"] = worker_id
        if timeout_seconds is not None:
            query["timeout_seconds"] = _format_number(timeout_seconds)
        if limit is not None:
            query["limit"] = str(limit)
        if lease_seconds is not None:
            query["lease_seconds"] = _format_number(lease_seconds)
        payload = self._request_json("GET", f"/worker/poll?{parse.urlencode(query)}")
        return RelayPollResult.from_payload(payload)

    def renew(
        self,
        request_id: str,
        lease_id: str,
        *,
        worker_id: str | None = None,
        lease_seconds: float | None = None,
    ) -> RelayRequest:
        payload: JsonObject = {"request_id": request_id, "lease_id": lease_id}
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
            worker_id=worker_id,
            lease_seconds=lease_seconds,
        )

    def respond(
        self,
        request_id: str,
        lease_id: str,
        response: object,
        *,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
    ) -> JsonObject:
        payload: JsonObject = {
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
    ) -> JsonObject:
        return self._request_json(
            "POST",
            "/worker/error",
            payload={
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
            status=status,
        )

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        payload: JsonObject | None = None,
    ) -> JsonObject:
        raw_body = json.dumps(payload).encode("utf-8") if payload is not None else None
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
            with request.urlopen(req, timeout=self.timeout_seconds) as response:
                raw = response.read().decode("utf-8")
                decoded = json.loads(raw) if raw else {}
        except error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            exc.close()
            decoded = _decode_json_error(raw)
            raise RelayApiError(
                f"relay request failed ({exc.code}): {decoded}",
                status_code=exc.code,
                body=decoded,
            ) from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise RelayApiError(f"relay request failed: {exc}") from exc
        if not isinstance(decoded, dict):
            raise RelayApiError("relay returned a non-object JSON payload", body=decoded)
        return decoded


class AsyncRelayWorkerClient:
    def __init__(
        self,
        relay_url: str,
        *,
        worker_token: str | None = None,
        timeout_seconds: float = 30.0,
        headers: Mapping[str, str] | None = None,
        session: Any | None = None,
    ) -> None:
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
        return await self._request_json("POST", "/register_rollout", payload=payload)

    async def unregister_rollout(self, rollout_id: str) -> JsonObject:
        return await self._request_json(
            "POST",
            "/unregister_rollout",
            payload={"rollout_id": rollout_id},
        )

    async def heartbeat(
        self,
        rollout_id: str,
        worker_id: str,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> JsonObject:
        payload: JsonObject = {"rollout_id": rollout_id, "worker_id": worker_id}
        if metadata is not None:
            payload["metadata"] = dict(metadata)
        return await self._request_json("POST", "/worker/heartbeat", payload=payload)

    async def poll(
        self,
        rollout_id: str,
        *,
        worker_id: str | None = None,
        timeout_seconds: float | None = None,
        limit: int | None = None,
        lease_seconds: float | None = None,
    ) -> RelayPollResult:
        query: dict[str, str] = {"rollout_id": rollout_id}
        if worker_id is not None:
            query["worker_id"] = worker_id
        if timeout_seconds is not None:
            query["timeout_seconds"] = _format_number(timeout_seconds)
        if limit is not None:
            query["limit"] = str(limit)
        if lease_seconds is not None:
            query["lease_seconds"] = _format_number(lease_seconds)
        payload = await self._request_json("GET", f"/worker/poll?{parse.urlencode(query)}")
        return RelayPollResult.from_payload(payload)

    async def renew(
        self,
        request_id: str,
        lease_id: str,
        *,
        worker_id: str | None = None,
        lease_seconds: float | None = None,
    ) -> RelayRequest:
        payload: JsonObject = {"request_id": request_id, "lease_id": lease_id}
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
            worker_id=worker_id,
            lease_seconds=lease_seconds,
        )

    async def respond(
        self,
        request_id: str,
        lease_id: str,
        response: object,
        *,
        status: int = 200,
        headers: Mapping[str, str] | None = None,
    ) -> JsonObject:
        payload: JsonObject = {
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
    ) -> JsonObject:
        return await self._request_json(
            "POST",
            "/worker/error",
            payload={
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
    ) -> JsonObject:
        client = await self._client()
        headers = dict(self.headers)
        async with client.request(
            method,
            self.relay_url + path,
            json=payload,
            headers=headers,
        ) as response:
            raw = await response.text()
            try:
                decoded = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                decoded = {"error": raw}
            if response.status >= 400:
                raise RelayApiError(
                    f"relay request failed ({response.status}): {decoded}",
                    status_code=response.status,
                    body=decoded,
                )
        if not isinstance(decoded, dict):
            raise RelayApiError("relay returned a non-object JSON payload", body=decoded)
        return decoded


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
