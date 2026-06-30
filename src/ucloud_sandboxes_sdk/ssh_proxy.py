from __future__ import annotations

import argparse
import asyncio
import os
import sys
from urllib.parse import quote, urlsplit, urlunsplit


def websocket_url(gateway_url: str, sandbox_id: str) -> str:
    parsed = urlsplit(gateway_url.rstrip("/"))
    if parsed.scheme not in {"http", "https", "ws", "wss"}:
        raise ValueError("gateway_url must use http, https, ws, or wss")
    scheme = {
        "http": "ws",
        "https": "wss",
        "ws": "ws",
        "wss": "wss",
    }[parsed.scheme]
    path = (
        parsed.path.rstrip("/")
        + f"/v1/sandboxes/{quote(sandbox_id, safe='')}/ssh/ws"
    )
    return urlunsplit((scheme, parsed.netloc, path, "", ""))


async def run_proxy(
    *,
    gateway_url: str,
    sandbox_id: str,
    token: str | None = None,
    token_env: str | None = "UCLOUD_SANDBOX_API_TOKEN",
) -> int:
    try:
        from aiohttp import ClientSession, WSMsgType
    except ImportError as exc:
        raise RuntimeError(
            "SSH proxy requires aiohttp. Install ucloud-sandboxes-sdk[async]."
        ) from exc

    effective_token = token
    if effective_token is None and token_env:
        effective_token = os.environ.get(token_env)
    headers = {}
    if effective_token:
        headers["Authorization"] = f"Bearer {effective_token}"

    async with ClientSession(headers=headers) as session:
        async with session.ws_connect(
            websocket_url(gateway_url, sandbox_id),
            heartbeat=30.0,
            max_msg_size=16 * 1024 * 1024,
        ) as ws:
            stdout_task = asyncio.create_task(_websocket_to_stdout(ws, WSMsgType))
            stdin_task = asyncio.create_task(_stdin_to_websocket(ws))
            done, pending = await asyncio.wait(
                {stdout_task, stdin_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            for task in done:
                if not task.cancelled():
                    task.result()
    return 0


async def _stdin_to_websocket(ws: object) -> None:
    while True:
        data = await asyncio.to_thread(sys.stdin.buffer.read, 16 * 1024)
        if not data:
            await ws.send_str("close")
            return
        await ws.send_bytes(data)


async def _websocket_to_stdout(ws: object, ws_msg_type: object) -> None:
    async for message in ws:
        if message.type == ws_msg_type.BINARY:
            sys.stdout.buffer.write(message.data)
            sys.stdout.buffer.flush()
        elif message.type == ws_msg_type.TEXT:
            sys.stderr.write(message.data + "\n")
            sys.stderr.flush()
        elif message.type in {ws_msg_type.CLOSE, ws_msg_type.CLOSED}:
            return
        elif message.type == ws_msg_type.ERROR:
            raise RuntimeError(f"SSH websocket failed: {ws.exception()}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Bridge OpenSSH ProxyCommand traffic to a UCloud sandbox SSH websocket.",
    )
    parser.add_argument("--gateway-url", required=True)
    parser.add_argument("--sandbox-id", required=True)
    parser.add_argument("--token")
    parser.add_argument("--token-env", default="UCLOUD_SANDBOX_API_TOKEN")
    args = parser.parse_args(argv)
    return asyncio.run(
        run_proxy(
            gateway_url=args.gateway_url,
            sandbox_id=args.sandbox_id,
            token=args.token,
            token_env=args.token_env,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
