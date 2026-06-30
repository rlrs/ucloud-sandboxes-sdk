from __future__ import annotations

import unittest

from ucloud_sandboxes_sdk.ssh_proxy import websocket_url


class SshProxyTests(unittest.TestCase):
    def test_builds_websocket_url_from_gateway_url(self) -> None:
        self.assertEqual(
            websocket_url("https://gateway.example.org/base/", "sandbox:one"),
            "wss://gateway.example.org/base/v1/sandboxes/sandbox%3Aone/ssh/ws",
        )

    def test_rejects_non_http_gateway_url(self) -> None:
        with self.assertRaises(ValueError):
            websocket_url("file:///tmp/socket", "sandbox-one")


if __name__ == "__main__":
    unittest.main()
