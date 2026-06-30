from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote


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
