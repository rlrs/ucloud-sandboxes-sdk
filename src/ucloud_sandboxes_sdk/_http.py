from __future__ import annotations

import http.client
import select
import ssl
import sys
import threading
import time
from typing import Any
from urllib import error, request
from urllib.parse import urlsplit

# Retire idle pooled connections before the public proxy's 10-second timeout.
# A stale connection can lose a POST before its response is available, and
# ambiguous sandbox mutations cannot safely be retried.
ASYNC_KEEPALIVE_TIMEOUT_SECONDS = 5.0


class _RejectRedirects(request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


_NO_REDIRECT_OPENER = request.build_opener(_RejectRedirects())


class ResponseTooLargeError(RuntimeError):
    pass


def open_no_redirect(req: request.Request, *, timeout: float) -> Any:
    return _NO_REDIRECT_OPENER.open(req, timeout=timeout)


_DEFAULT_USER_AGENT = f"Python-urllib/{sys.version_info[0]}.{sys.version_info[1]}"
_MAX_IDLE_PER_ORIGIN = 16


class _ConnectionPool:
    """Idle HTTP/1.1 connections per origin, retired before the proxy's timeout."""

    def __init__(self, idle_seconds: float, max_idle: int) -> None:
        self.idle_seconds = idle_seconds
        self.max_idle = max_idle
        self._idle: dict[tuple[str, str, int], list[tuple[http.client.HTTPConnection, float]]] = {}
        self._guard = threading.Lock()
        self._context: ssl.SSLContext | None = None

    def https_context(self) -> ssl.SSLContext:
        # Loading the trust store costs milliseconds; build it once. This is
        # the context urllib would create for each request.
        with self._guard:
            if self._context is None:
                self._context = ssl._create_default_https_context()
            return self._context

    def take(self, key: tuple[str, str, int]) -> http.client.HTTPConnection | None:
        now = time.monotonic()
        while True:
            with self._guard:
                idle = self._idle.get(key)
                if not idle:
                    return None
                conn, returned_at = idle.pop()
            if now - returned_at < self.idle_seconds and not _dropped(conn):
                return conn
            conn.close()

    def give(self, key: tuple[str, str, int], conn: http.client.HTTPConnection) -> None:
        with self._guard:
            idle = self._idle.setdefault(key, [])
            if len(idle) < self.max_idle:
                idle.append((conn, time.monotonic()))
                return
        conn.close()


def _dropped(conn: http.client.HTTPConnection) -> bool:
    """An idle connection is unusable once the peer closed or wrote to it."""
    sock = conn.sock
    if sock is None:
        return True
    try:
        readable, _, _ = select.select([sock], [], [], 0)
    except (OSError, ValueError):
        return True
    return bool(readable)


_POOL = _ConnectionPool(ASYNC_KEEPALIVE_TIMEOUT_SECONDS, _MAX_IDLE_PER_ORIGIN)


class _PooledResponse:
    """A urllib-shaped response that returns its connection once fully read."""

    def __init__(
        self,
        key: tuple[str, str, int],
        conn: http.client.HTTPConnection,
        response: http.client.HTTPResponse,
        url: str,
    ) -> None:
        self._key = key
        self._conn: http.client.HTTPConnection | None = conn
        self._response = response
        self.status = self.code = response.status
        self.reason = response.reason
        self.headers = self.msg = response.headers
        self.url = url

    def read(self, amt: int | None = None) -> bytes:
        return self._response.read() if amt is None else self._response.read(amt)

    def getcode(self) -> int:
        return self.status

    def geturl(self) -> str:
        return self.url

    def info(self) -> Any:
        return self.headers

    def __getattr__(self, name: str) -> Any:
        return getattr(self._response, name)

    def close(self) -> None:
        conn, self._conn = self._conn, None
        if conn is None:
            return
        response = self._response
        if response.isclosed() and not response.will_close:
            _POOL.give(self._key, conn)
            return
        response.close()
        conn.close()

    def __enter__(self) -> "_PooledResponse":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def open_reusing(req: request.Request, *, timeout: float) -> Any:
    """Like ``open_no_redirect``, but keeps the connection for the next request.

    A new TCP and TLS handshake per request costs several round trips and
    milliseconds of client CPU. A response returns its connection to the pool
    only after its body is fully read. Proxied requests use urllib.
    """
    parts = urlsplit(req.full_url)
    scheme = parts.scheme.lower()
    host = parts.hostname
    if scheme not in {"http", "https"} or not host or _proxied(scheme, host):
        return open_no_redirect(req, timeout=timeout)
    port = parts.port or (443 if scheme == "https" else 80)
    key = (scheme, host, port)
    selector = parts.path or "/"
    if parts.query:
        selector += "?" + parts.query
    headers = {name.title(): value for name, value in req.header_items()}
    headers.setdefault("User-Agent", _DEFAULT_USER_AGENT)
    method = req.get_method()
    conn = _POOL.take(key)
    reused = conn is not None
    if conn is None:
        conn = (
            http.client.HTTPSConnection(host, port, timeout=timeout, context=_POOL.https_context())
            if scheme == "https"
            else http.client.HTTPConnection(host, port, timeout=timeout)
        )
        try:
            conn.connect()
        except OSError as exc:
            conn.close()
            raise error.URLError(exc) from exc
    else:
        conn.timeout = timeout
        if conn.sock is not None:
            conn.sock.settimeout(timeout)
    try:
        try:
            conn.request(method, selector, body=req.data, headers=headers)
        except OSError as exc:
            raise error.URLError(exc) from exc
        response = conn.getresponse()
    except (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError, error.URLError):
        conn.close()
        # A reused connection the peer closed before reading this request.
        # Only a read-only request may safely be sent again.
        if reused and method in {"GET", "HEAD"}:
            return open_reusing(req, timeout=timeout)
        raise
    except BaseException:
        conn.close()
        raise
    wrapped = _PooledResponse(key, conn, response, req.full_url)
    if not 200 <= response.status < 300:
        raise error.HTTPError(req.full_url, response.status, response.reason, response.headers, wrapped)
    return wrapped


def _proxied(scheme: str, host: str) -> bool:
    proxies = request.getproxies()
    return scheme in proxies and not request.proxy_bypass(host)


def response_headers(value: object) -> dict[str, str]:
    headers = getattr(value, "headers", None)
    items = getattr(headers, "items", None)
    if not callable(items):
        return {}
    return {str(key): str(item) for key, item in items()}


def read_sync_response(response: object, *, limit: int) -> bytes:
    _check_content_length(response, limit)
    read = getattr(response, "read")
    try:
        body = read(limit + 1)
    except TypeError:
        body = read()
    if len(body) > limit:
        raise ResponseTooLargeError(f"response exceeds the {limit} byte limit")
    return body


async def read_async_response(response: object, *, limit: int) -> bytes:
    _check_content_length(response, limit)
    content = getattr(response, "content", None)
    read = getattr(content, "read", None)
    if callable(read):
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = await read(min(64 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise ResponseTooLargeError(f"response exceeds the {limit} byte limit")
        return b"".join(chunks)

    response_read = getattr(response, "read", None)
    if callable(response_read):
        body = await response_read()
    else:
        body = (await getattr(response, "text")()).encode("utf-8")
    if len(body) > limit:
        raise ResponseTooLargeError(f"response exceeds the {limit} byte limit")
    return body


def _check_content_length(response: object, limit: int) -> None:
    raw_length = next(
        (
            value
            for key, value in response_headers(response).items()
            if key.lower() == "content-length"
        ),
        None,
    )
    if raw_length is None:
        return
    try:
        length = int(raw_length)
    except ValueError:
        return
    if length > limit:
        raise ResponseTooLargeError(f"response exceeds the {limit} byte limit")
