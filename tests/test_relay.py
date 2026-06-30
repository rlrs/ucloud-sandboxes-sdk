from __future__ import annotations

import unittest

from ucloud_sandboxes_sdk import ModelRelayConfig, model_relay_env


class ModelRelayConfigTests(unittest.TestCase):
    def test_builds_path_scoped_openai_environment(self) -> None:
        env = model_relay_env(
            "https://relay.example.org/",
            "run:001",
            api_key="sandbox-token",
        )

        self.assertEqual(env["VF_RELAY_ROLLOUT_ID"], "run:001")
        self.assertEqual(
            env["OPENAI_BASE_URL"],
            "https://relay.example.org/rollouts/run%3A001/v1",
        )
        self.assertEqual(env["OPENAI_API_KEY"], "sandbox-token")

    def test_can_build_plain_v1_environment_for_custom_header_transport(self) -> None:
        config = ModelRelayConfig(
            "https://relay.example.org",
            "run-001",
            path_scoped_base_url=False,
        )

        self.assertEqual(config.openai_base_url, "https://relay.example.org/v1")


if __name__ == "__main__":
    unittest.main()
