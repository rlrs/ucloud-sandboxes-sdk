"""Behavior smoke test for an installed SDK wheel with no optional extras."""

from importlib.metadata import version

from ucloud_sandboxes_sdk import (
    Image,
    SandboxClient,
    SandboxSpec,
    __version__,
    http_tunnel_url,
    model_relay_env,
    sandbox_auth_headers,
)


def main() -> None:
    assert __version__ == version("ucloud-sandboxes-sdk")
    spec = SandboxSpec(
        id="wheel-smoke",
        image=Image.from_registry("registry.example/image:latest"),
        command=("true",),
        memory_mb=128,
        cpus=1,
        disk_mb=256,
    )
    payload = spec.to_dict()
    assert payload["id"] == "wheel-smoke"
    assert payload["image"] == "registry.example/image:latest"
    assert SandboxClient("https://gateway.example", api_token="token")
    assert sandbox_auth_headers("token") == {"X-UCloud-Sandbox-Token": "token"}
    assert model_relay_env("https://relay.example", "rollout-one")[
        "OPENAI_BASE_URL"
    ].endswith("/rollouts/rollout-one/v1")
    assert http_tunnel_url(
        "https://relay.example",
        "rollout-one",
        "/health",
    ).endswith("/tunnels/rollout-one/health")

    class StatusClient(SandboxClient):
        def _request_json(self, method, path, **kwargs):
            assert (method, path) == (
                "GET", "/v1/sandboxes?view=status&id=wheel-smoke",
            )
            return {"view": "status", "sandboxes": [{
                "id": "wheel-smoke", "spec": {"id": "wheel-smoke"},
                "generation": 1, "state": "unknown", "cached_state": "running",
                "node": {"fresh": False},
            }]}

    status_client = StatusClient("https://gateway.example")
    assert status_client.list_sandbox_statuses(sandbox_ids=[]) == []
    status = status_client.get_sandbox_status("wheel-smoke")
    assert status["state"] == "unknown" and status["node"]["fresh"] is False

    class GroupClient(SandboxClient):
        def _request_json(self, method, path, **kwargs):
            assert (method, path) == ("POST", "/v1/sandboxes:batch")
            assert "id" not in kwargs["payload"]["spec"]
            return {"group": {"id": "wheel", "count": 1, "state": "active"},
                    "sandboxes": [{"id": "wheel-0000", "status": "running"}]}

    (member,) = GroupClient("https://gateway.example").create_sandbox_group(
        "wheel", spec, count=1,
    )
    assert member.id == "wheel-0000"


if __name__ == "__main__":
    main()
