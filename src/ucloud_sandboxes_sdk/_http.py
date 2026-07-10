from __future__ import annotations

from typing import Any
from urllib import request


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
    """Open one request without forwarding credentials to redirect targets."""

    return _NO_REDIRECT_OPENER.open(req, timeout=timeout)


def response_headers(value: object) -> dict[str, str]:
    headers = getattr(value, "headers", None)
    if headers is None:
        return {}
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
                raise ResponseTooLargeError(
                    f"response exceeds the {limit} byte limit"
                )
        body = b"".join(chunks)
    else:
        response_read = getattr(response, "read", None)
        if callable(response_read):
            body = await response_read()
        else:
            body = (await getattr(response, "text")()).encode("utf-8")
    if len(body) > limit:
        raise ResponseTooLargeError(f"response exceeds the {limit} byte limit")
    return body


def _check_content_length(response: object, limit: int) -> None:
    length = next(
        (
            value
            for key, value in response_headers(response).items()
            if key.lower() == "content-length"
        ),
        None,
    )
    if length is None:
        return
    try:
        parsed = int(length)
    except ValueError:
        return
    if parsed > limit:
        raise ResponseTooLargeError(f"response exceeds the {limit} byte limit")
