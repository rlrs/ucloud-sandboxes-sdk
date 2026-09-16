from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any


RELAY_NAME = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")


@dataclass(frozen=True)
class SandboxNetworkPolicy:
    """Host-enforced egress selection, independent of network transport.

    Relay names refer to trusted deployment configuration, never guest URLs.
    Additional transports/proxy protocols can extend this contract explicitly.
    """

    egress: str = "direct"
    relay: str | None = None

    def __post_init__(self) -> None:
        if self.egress not in ("direct", "relay"):
            raise ValueError("network_policy.egress must be 'direct' or 'relay'")
        if self.egress == "relay":
            if not isinstance(self.relay, str) or not RELAY_NAME.fullmatch(self.relay):
                raise ValueError("network_policy.relay must be a valid relay name")
        elif self.relay is not None:
            raise ValueError("network_policy.relay requires egress='relay'")

    @classmethod
    def relay_only(cls, relay: str = "default") -> SandboxNetworkPolicy:
        return cls(egress="relay", relay=relay)

    @classmethod
    def from_dict(cls, raw: Any) -> SandboxNetworkPolicy:
        if not isinstance(raw, dict) or set(raw) - {"egress", "relay"}:
            raise ValueError(
                "network_policy must be an object with egress and relay fields"
            )
        return cls(egress=raw.get("egress", "direct"), relay=raw.get("relay"))

    def to_dict(self) -> dict[str, Any]:
        return {"egress": self.egress, **({"relay": self.relay} if self.relay else {})}

    @property
    def capability(self) -> str:
        return f"network-policy-relay-v1:{self.relay}"
