import asyncio
import importlib.util
import json
import os
import unittest
from unittest.mock import patch

from ucloud_sandboxes_sdk import (
    AsyncSandboxClient,
    Image,
    SandboxClient,
    SandboxNetworkPolicy,
    SandboxSpec,
    SandboxSshSpec,
)
from tests.test_client import _SyncResponse, _AsyncResponse, _ScriptedAsyncSession


class NetworkPolicyTests(unittest.TestCase):
    def spec(self, **kwargs):
        return SandboxSpec(
            id="restricted", image=Image.from_registry("busybox"), **kwargs
        )

    def test_explicit_policy_and_default_backward_compatibility(self):
        self.assertNotIn("network_policy", self.spec().to_dict())
        policy = SandboxNetworkPolicy.relay_only()
        self.assertEqual(
            self.spec(network_policy=policy).to_dict()["network_policy"],
            {"egress": "relay", "relay": "default"},
        )
        self.assertEqual(
            SandboxSpec.benchmark(
                id="test", image=Image.from_registry("ubuntu"), network_policy=policy
            ).network_policy,
            policy,
        )
        for kwargs in ({"network": "none"}, {"ssh": SandboxSshSpec(enabled=True)}):
            with self.assertRaises(ValueError):
                self.spec(network_policy=policy, **kwargs)
        with self.assertRaises(TypeError):
            self.spec(network_policy={"egress": "relay"})
        for raw in (
            None,
            [],
            {"egress": "all"},
            {"egress": "relay"},
            {"egress": "relay", "relay": "default", "allow": "*"},
        ):
            with self.assertRaises(ValueError):
                SandboxNetworkPolicy.from_dict(raw)

    def test_sync_and_async_send_identical_policy(self):
        spec = self.spec(network_policy=SandboxNetworkPolicy.relay_only("filtered"))
        sync_requests = []
        response = {"sandbox": {"spec": spec.to_dict()}}

        def open_request(req, **kwargs):
            sync_requests.append(json.loads(req.data))
            return _SyncResponse(json.dumps(response).encode())

        with patch("ucloud_sandboxes_sdk.client.open_no_redirect", open_request):
            SandboxClient("http://gateway.invalid").create_sandbox(spec)
        session = _ScriptedAsyncSession(
            lambda *_: _AsyncResponse(json.dumps(response), status=201)
        )

        async def create():
            await AsyncSandboxClient(
                "http://gateway.invalid", session=session
            ).create_sandbox(spec)

        asyncio.run(create())
        self.assertEqual(sync_requests[0], session.requests[0][2]["json"])
        self.assertEqual(
            sync_requests[0]["network_policy"], {"egress": "relay", "relay": "filtered"}
        )

    @unittest.skipUnless(importlib.util.find_spec("inspect_ai"), "requires inspect-ai")
    def test_inspect_can_select_named_relay(self):
        from ucloud_sandboxes_sdk.integrations.inspect import _settings_from_env

        with patch.dict(
            os.environ,
            {
                "UCLOUD_SANDBOX_URL": "http://gateway.invalid",
                "UCLOUD_SANDBOX_RELAY": "filtered",
            },
            clear=True,
        ):
            self.assertEqual(
                _settings_from_env().network_policy,
                SandboxNetworkPolicy.relay_only("filtered"),
            )
