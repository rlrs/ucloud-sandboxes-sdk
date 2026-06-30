# UCloud Sandboxes SDK Agent Notes

This repository is the client-facing Python package for UCloud sandbox gateways.
It must stay independent from the autoscaler/control-plane implementation.

## Scope

- Package name: `ucloud-sandboxes-sdk`
- Import name: `ucloud_sandboxes_sdk`
- Public API lives in `src/ucloud_sandboxes_sdk/client.py`.
- Inspect AI integration lives in `src/ucloud_sandboxes_sdk/integrations/inspect.py`.
- Tests must not import the autoscaler package (`ucloud_sandboxes`). Use local
  fake HTTP servers or mocked clients for protocol coverage.

## Design Constraints

- Treat the gateway/node-agent API as an HTTP protocol boundary.
- Do not add UCloud credentials, VM lifecycle logic, node initialization,
  autoscaling policy, or gVisor runtime code here.
- Keep sync and async clients behaviorally aligned when adding endpoints.
- Preserve simple JSON-compatible request/response shapes. The SDK should not
  invent scheduling abstractions that the gateway does not expose.
- Prepared capacity is only an expiring demand signal. It is not a reservation,
  lease, or placeholder sandbox.

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

Do not rely on a live gateway for normal unit tests. Live smoke tests should be
documented separately and must not require secrets checked into the repo.
