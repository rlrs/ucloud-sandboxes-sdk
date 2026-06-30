# UCloud Sandboxes SDK Agent Notes

This repository is the client-facing Python package for UCloud sandbox gateways.
Keep it focused on gateway protocol clients, Inspect AI integration, and
developer-facing examples.

## Scope

- Package name: `ucloud-sandboxes-sdk`
- Import name: `ucloud_sandboxes_sdk`
- Public API lives in `src/ucloud_sandboxes_sdk/client.py`.
- Inspect AI integration lives in `src/ucloud_sandboxes_sdk/integrations/inspect.py`.
- Tests use local fake HTTP servers or mocked clients for protocol coverage.

## Design Constraints

- Treat the gateway/node-agent API as an HTTP protocol boundary.
- Keep VM lifecycle, node initialization, autoscaling policy, and runtime setup
  in the service repository.
- Keep sync and async clients behaviorally aligned when adding endpoints.
- Preserve simple JSON-compatible request/response shapes. Put scheduling
  behavior in the gateway API first, then expose that protocol here.
- Public SDK sandbox/image methods use the `Image` helper. Do not add raw
  string or arbitrary mapping image shortcuts.
- Prepared capacity is an expiring gateway demand signal. Future sandbox
  creation still uses the normal gateway placement path.
- Prepared builder capacity is a separate expiring gateway demand signal for
  build-capable VMs. Future image builds still use `POST /v1/images/build`.
- Treat registry tags as the durable builder-to-sandbox handoff. Builders push
  tags, and sandbox nodes pull/cache tags before creating containers.
- Do not treat image ids as transferred images. A pushed image id may resolve to
  a recorded registry tag; an unpushed image id is builder-local only.

## Verification

Run from this repository root:

```bash
uv run python -m unittest
uv build
```

Inspect tests are skipped unless `inspect-ai` is installed:

```bash
uv run --extra inspect python -m unittest
```

Use the local fake gateway for normal unit tests. Keep live gateway smoke tests
in separate operational docs.
