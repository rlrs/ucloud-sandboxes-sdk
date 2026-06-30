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
- Prepared capacity is an expiring gateway demand signal. Future sandbox
  creation still uses the normal gateway placement path.

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
