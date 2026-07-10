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

## Consumer Workflow Invariants

When writing examples, integrations, or generated code, follow
`docs/agent-guide.md`. In particular:

- Point clients at the public gateway and give every retryable sandbox create a
  stable id. Retrying that id with a changed spec is a conflict, not an update.
- For a cold custom-image burst, prepare builder capacity and generic sandbox
  capacity before starting the build. After the build, update the same sandbox
  prepare id with the pushed registry tag. A new prepare id adds demand rather
  than replacing it.
- Prepared sandbox units survive autoscaler reconciliation until matching
  allocations claim them or their TTL expires. Prepared builder signals are
  one-shot and are consumed after an executing autoscaler cycle reacts.
- SDK Dockerfile builds always push to their required registry tag. Do not add
  an unpushed or remote-builder-context mode. Do not add an SDK image-delete
  operation; registry retention and garbage collection own image storage
  lifecycle.
- Use total cold-start/build budgets measured in minutes. Bound concurrent
  creates and execs; an exec is a remote process lifecycle, not a cheap local
  function call.
- Never blindly repeat a side-effecting command after
  `ExecEventHistoryLostError`: the command may have completed even though its
  retained event history is incomplete.
- In `finally`, delete every attempted deterministic sandbox id (including
  creates with ambiguous responses) and any remaining prepared capacity.
  Suspended UCloud nodes are still billed, so do not recommend suspended pools
  as a cold-start strategy.

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
