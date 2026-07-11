from __future__ import annotations

import base64
import binascii
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
class HttpTunnelConfig:
    relay_url: str
    tunnel_id: str
    relay_token: str | None = None

    @property
    def base_url(self) -> str:
        return http_tunnel_url(self.relay_url, self.tunnel_id)

    def headers(self) -> dict[str, str]:
        if self.relay_token is None:
            return {}
        return {"X-UCloud-Relay-Token": self.relay_token}


def http_tunnel_url(relay_url: str, tunnel_id: str, path: str = "/") -> str:
    suffix = "/" + path.lstrip("/")
    return f"{relay_url.rstrip('/')}/tunnels/{quote(tunnel_id, safe='')}{suffix}"


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

    @property
    def tunnel_id(self) -> str:
        return self.rollout_id

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "RelayRequest":
        headers = payload.get("headers")
        body = payload.get("body")
        body_bytes = _decode_body_bytes(payload, body)
        return cls(
            request_id=str(payload.get("request_id") or ""),
            rollout_id=str(payload.get("rollout_id") or payload.get("tunnel_id") or ""),
            registration_token=str(payload.get("registration_token") or ""),
            endpoint=str(payload.get("endpoint") or ""),
            method=str(payload.get("method") or "POST"),
            headers=_string_dict(headers),
            body=_copy_json_value(body),
            body_bytes=body_bytes,
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
        return cls(
            request=request_item or (requests[0] if requests else None),
            requests=requests,
        )


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
        self._registration_tokens: dict[str, str] = {}
        self._request_tokens: dict[str, str] = {}

    def health(self) -> JsonObject:
        return self._request_json("GET", "/healthz")

    def stats(self) -> JsonObject:
        return self._request_json("GET", "/v1/relay/stats")

    def list_rollouts(self) -> list[JsonObject]:
        payload = self._request_json("GET", "/v1/relay/rollouts")
        rollouts = payload.get("rollouts")
        return (
            [dict(item) for item in rollouts if isinstance(item, dict)]
            if isinstance(rollouts, list)
            else []
        )

    def list_tunnels(self) -> list[JsonObject]:
        payload = self._request_json("GET", "/v1/tunnels")
        tunnels = payload.get("rollouts")
        return (
            [dict(item) for item in tunnels if isinstance(item, dict)]
            if isinstance(tunnels, list)
            else []
        )

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

    def register_tunnel(
        self,
        tunnel_id: str,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> JsonObject:
        payload: JsonObject = {"tunnel_id": tunnel_id}
        if metadata is not None:
            payload["metadata"] = dict(metadata)
        response = self._request_json("POST", "/v1/tunnels/register", payload=payload)
        self._remember_registration(tunnel_id, response)
        return response

    def unregister_rollout(
        self,
        rollout_id: str,
        *,
        registration_token: str | None = None,
    ) -> JsonObject:
        token = registration_token or self._registration_token(rollout_id)
        response = self._request_json(
            "POST",
            "/unregister_rollout",
            payload={"rollout_id": rollout_id, "registration_token": token},
        )
        self._forget_registration(rollout_id, token)
        return response

    def unregister_tunnel(
        self,
        tunnel_id: str,
        *,
        registration_token: str | None = None,
    ) -> JsonObject:
        token = registration_token or self._registration_token(tunnel_id)
        response = self._request_json(
            "POST",
            "/v1/tunnels/unregister",
            payload={"tunnel_id": tunnel_id, "registration_token": token},
        )
        self._forget_registration(tunnel_id, token)
        return response

    def heartbeat(
        self,
        rollout_id: str,
        worker_id: str,
        *,
        metadata: Mapping[str, Any] | None = None,
        registration_token: str | None = None,
    ) -> JsonObject:
        payload: JsonObject = {
            "rollout_id": rollout_id,
            "registration_token": registration_token
            or self._registration_token(rollout_id),
            "worker_id": worker_id,
        }
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
        registration_token: str | None = None,
    ) -> RelayPollResult:
        query: dict[str, str] = {
            "rollout_id": rollout_id,
            "registration_token": registration_token
            or self._registration_token(rollout_id),
        }
        if worker_id is not None:
            query["worker_id"] = worker_id
        if timeout_seconds is not None:
            query["timeout_seconds"] = _format_number(timeout_seconds)
        if limit is not None:
            query["limit"] = str(limit)
        if lease_seconds is not None:
            query["lease_seconds"] = _format_number(lease_seconds)
        payload = self._request_json("GET", f"/worker/poll?{parse.urlencode(query)}")
        result = RelayPollResult.from_payload(payload)
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
        payload: JsonObject = {
            "request_id": request_id,
            "registration_token": registration_token or self._request_token(request_id),
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
        self._request_tokens[renewed.request_id] = renewed.registration_token or str(
            payload["registration_token"]
        )
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
        payload: JsonObject = {
            "request_id": request_id,
            "registration_token": registration_token or self._request_token(request_id),
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
        payload: JsonObject = {
            "request_id": request_id,
            "registration_token": registration_token or self._request_token(request_id),
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

    def forward_to(
        self,
        relay_request: RelayRequest,
        upstream_base_url: str,
        *,
        timeout_seconds: float | None = None,
    ) -> JsonObject:
        upstream_request = request.Request(
            upstream_base_url.rstrip("/") + relay_request.endpoint,
            data=relay_request.body_bytes or None,
            method=relay_request.method,
            headers=_safe_http_headers(relay_request.headers),
        )
        try:
            upstream = request.urlopen(
                upstream_request,
                timeout=timeout_seconds or self.timeout_seconds,
            )
        except error.HTTPError as exc:
            upstream = exc
        except OSError as exc:
            return self.respond_bytes_to(
                relay_request,
                json.dumps({"error": f"upstream request failed: {exc}"}).encode(
                    "utf-8"
                ),
                status=502,
                headers={"Content-Type": "application/json"},
            )
        try:
            body = upstream.read()
            status = int(upstream.status)
            headers = _safe_http_headers(dict(upstream.headers))
        finally:
            upstream.close()
        return self.respond_bytes_to(
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
        return self._request_json(
            "POST",
            "/worker/error",
            payload={
                "request_id": request_id,
                "registration_token": registration_token
                or self._request_token(request_id),
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

    def _remember_registration(
        self, rollout_id: str, payload: Mapping[str, Any]
    ) -> None:
        record = payload.get("rollout")
        token = (
            record.get("registration_token") if isinstance(record, Mapping) else None
        )
        if not isinstance(token, str) or not token:
            raise RelayApiError(
                "relay registration omitted registration_token", body=payload
            )
        self._registration_tokens[rollout_id] = token

    def _registration_token(self, rollout_id: str) -> str:
        token = self._registration_tokens.get(rollout_id)
        if token is None:
            raise RelayApiError(
                f"rollout is not registered by this client: {rollout_id}"
            )
        return token

    def _request_token(self, request_id: str) -> str:
        token = self._request_tokens.get(request_id)
        if token is None:
            raise RelayApiError(f"request was not polled by this client: {request_id}")
        return token

    def _remember_requests(self, result: RelayPollResult) -> None:
        for item in result.requests:
            token = item.registration_token or self._registration_tokens.get(
                item.rollout_id
            )
            if token:
                self._request_tokens[item.request_id] = token

    def _forget_registration(self, rollout_id: str, token: str) -> None:
        self._registration_tokens.pop(rollout_id, None)
        self._request_tokens = {
            request_id: request_token
            for request_id, request_token in self._request_tokens.items()
            if request_token != token
        }

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
            raise RelayApiError(
                "relay returned a non-object JSON payload", body=decoded
            )
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
        self._registration_tokens: dict[str, str] = {}
        self._request_tokens: dict[str, str] = {}

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
        return (
            [dict(item) for item in rollouts if isinstance(item, dict)]
            if isinstance(rollouts, list)
            else []
        )

    async def list_tunnels(self) -> list[JsonObject]:
        payload = await self._request_json("GET", "/v1/tunnels")
        tunnels = payload.get("rollouts")
        return (
            [dict(item) for item in tunnels if isinstance(item, dict)]
            if isinstance(tunnels, list)
            else []
        )

    async def register_rollout(
        self,
        rollout_id: str,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> JsonObject:
        payload: JsonObject = {"rollout_id": rollout_id}
        if metadata is not None:
            payload["metadata"] = dict(metadata)
        response = await self._request_json(
            "POST", "/register_rollout", payload=payload
        )
        self._remember_registration(rollout_id, response)
        return response

    async def register_tunnel(
        self,
        tunnel_id: str,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> JsonObject:
        payload: JsonObject = {"tunnel_id": tunnel_id}
        if metadata is not None:
            payload["metadata"] = dict(metadata)
        response = await self._request_json(
            "POST", "/v1/tunnels/register", payload=payload
        )
        self._remember_registration(tunnel_id, response)
        return response

    async def unregister_rollout(
        self,
        rollout_id: str,
        *,
        registration_token: str | None = None,
    ) -> JsonObject:
        token = registration_token or self._registration_token(rollout_id)
        response = await self._request_json(
            "POST",
            "/unregister_rollout",
            payload={"rollout_id": rollout_id, "registration_token": token},
        )
        self._forget_registration(rollout_id, token)
        return response

    async def unregister_tunnel(
        self,
        tunnel_id: str,
        *,
        registration_token: str | None = None,
    ) -> JsonObject:
        token = registration_token or self._registration_token(tunnel_id)
        response = await self._request_json(
            "POST",
            "/v1/tunnels/unregister",
            payload={"tunnel_id": tunnel_id, "registration_token": token},
        )
        self._forget_registration(tunnel_id, token)
        return response

    async def heartbeat(
        self,
        rollout_id: str,
        worker_id: str,
        *,
        metadata: Mapping[str, Any] | None = None,
        registration_token: str | None = None,
    ) -> JsonObject:
        payload: JsonObject = {
            "rollout_id": rollout_id,
            "registration_token": registration_token
            or self._registration_token(rollout_id),
            "worker_id": worker_id,
        }
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
        registration_token: str | None = None,
    ) -> RelayPollResult:
        query: dict[str, str] = {
            "rollout_id": rollout_id,
            "registration_token": registration_token
            or self._registration_token(rollout_id),
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
            "GET", f"/worker/poll?{parse.urlencode(query)}"
        )
        result = RelayPollResult.from_payload(payload)
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
        payload: JsonObject = {
            "request_id": request_id,
            "registration_token": registration_token or self._request_token(request_id),
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
        self._request_tokens[renewed.request_id] = renewed.registration_token or str(
            payload["registration_token"]
        )
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
        payload: JsonObject = {
            "request_id": request_id,
            "registration_token": registration_token or self._request_token(request_id),
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
        payload: JsonObject = {
            "request_id": request_id,
            "registration_token": registration_token or self._request_token(request_id),
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

    async def forward_to(
        self,
        relay_request: RelayRequest,
        upstream_base_url: str,
        *,
        timeout_seconds: float | None = None,
    ) -> JsonObject:
        client = await self._client()
        request_options: dict[str, Any] = {
            "data": relay_request.body_bytes or None,
            "headers": _safe_http_headers(relay_request.headers),
        }
        if timeout_seconds is not None:
            request_options["timeout"] = timeout_seconds
        try:
            async with client.request(
                relay_request.method,
                upstream_base_url.rstrip("/") + relay_request.endpoint,
                **request_options,
            ) as upstream:
                body = await upstream.read()
                status = upstream.status
                headers = _safe_http_headers(dict(upstream.headers))
        except Exception as exc:
            return await self.respond_bytes_to(
                relay_request,
                json.dumps({"error": f"upstream request failed: {exc}"}).encode(
                    "utf-8"
                ),
                status=502,
                headers={"Content-Type": "application/json"},
            )
        return await self.respond_bytes_to(
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
        return await self._request_json(
            "POST",
            "/worker/error",
            payload={
                "request_id": request_id,
                "registration_token": registration_token
                or self._request_token(request_id),
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

    def _remember_registration(
        self, rollout_id: str, payload: Mapping[str, Any]
    ) -> None:
        record = payload.get("rollout")
        token = (
            record.get("registration_token") if isinstance(record, Mapping) else None
        )
        if not isinstance(token, str) or not token:
            raise RelayApiError(
                "relay registration omitted registration_token", body=payload
            )
        self._registration_tokens[rollout_id] = token

    def _registration_token(self, rollout_id: str) -> str:
        token = self._registration_tokens.get(rollout_id)
        if token is None:
            raise RelayApiError(
                f"rollout is not registered by this client: {rollout_id}"
            )
        return token

    def _request_token(self, request_id: str) -> str:
        token = self._request_tokens.get(request_id)
        if token is None:
            raise RelayApiError(f"request was not polled by this client: {request_id}")
        return token

    def _remember_requests(self, result: RelayPollResult) -> None:
        for item in result.requests:
            token = item.registration_token or self._registration_tokens.get(
                item.rollout_id
            )
            if token:
                self._request_tokens[item.request_id] = token

    def _forget_registration(self, rollout_id: str, token: str) -> None:
        self._registration_tokens.pop(rollout_id, None)
        self._request_tokens = {
            request_id: request_token
            for request_id, request_token in self._request_tokens.items()
            if request_token != token
        }

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
            raise RelayApiError(
                "relay returned a non-object JSON payload", body=decoded
            )
        return decoded


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
