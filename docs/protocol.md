# Gateway Protocol Notes

The SDK wraps the public gateway/node-agent HTTP API. Keep this document aligned
with `src/ucloud_sandboxes_sdk/client.py` when endpoints are added.

## Core Endpoints

- `GET /healthz`
- `GET /v1/sandboxes`
- `POST /v1/sandboxes`
- `DELETE /v1/sandboxes/<sandbox-id>`
- `GET /v1/sandboxes/<sandbox-id>/ssh`
- `POST /v1/sandboxes/<sandbox-id>/exec`
- `GET /v1/exec/<session-id>`
- `GET /v1/exec/<session-id>/events?after=<n>&limit=<n>&wait_seconds=<s>`
- `POST /v1/exec/<session-id>/stdin`
- `POST /v1/exec/<session-id>/close-stdin`
- `GET /v1/images`
- `POST /v1/images/build`
- `POST /v1/images/pull`
- `POST /v1/sandboxes/<sandbox-id>/snapshot`
- `GET /v1/capacity/prepare`
- `POST /v1/capacity/prepare`
- `DELETE /v1/capacity/prepare/<prepare-id>`

## Sandbox Resources

Sandbox create requests are individually resource-shaped:

```json
{
  "id": "sample-1",
  "image": "python:3.12-slim",
  "cpus": 1,
  "memory_mb": 2048,
  "disk_mb": 10240
}
```

The SDK should pass through resource fields as requested by the caller. It
should not enforce local scheduling policy; the gateway decides placement and
may return `503` while nodes are scaling up.

## Exec Events

Exec is session based. `POST /v1/sandboxes/<id>/exec` starts a session and
returns a session object. The SDK then polls `GET /v1/exec/<session>/events`.
Events are ordered by integer `sequence`; clients pass `after` to avoid
re-reading events.

Terminal statuses are:

- `exited`
- `failed`

`SandboxExecResult.stdout` and `.stderr` are assembled from events whose
`stream` fields are `stdout` and `stderr`.

## Prepared Capacity

`POST /v1/capacity/prepare` accepts:

```json
{
  "id": "run-id",
  "count": 16,
  "cpus": 1,
  "memory_mb": 2048,
  "disk_mb": 10240,
  "ttl_seconds": 900
}
```

Semantics:

- The signal contributes `count * resources` to autoscaler demand.
- It expires automatically at `ttl_seconds`.
- Deleting it removes the demand signal.
- It does not reserve capacity for a user, node, or future sandbox id.
- It does not create sandboxes.

SDK changes in this area should stay thin: expose the gateway operation, return
the gateway JSON, and avoid adding local reservation state.

## Error Handling

Sync and async clients raise `SandboxApiError` for non-2xx HTTP responses and
malformed JSON/object payloads. `status_code` is set for HTTP errors, and
`body` contains the decoded JSON error body when possible.

Inspect integration retries transient scale-up and gateway errors, but normal
SDK methods should not retry by default unless the public API explicitly grows a
retry policy.
