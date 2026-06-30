# Gateway Protocol Notes

The SDK wraps the public gateway/node-agent HTTP API. Keep this document aligned
with `src/ucloud_sandboxes_sdk/client.py` when endpoints are added.

## Core Endpoints

- `GET /healthz`
- `GET /v1/sandboxes`
- `POST /v1/sandboxes`
- `DELETE /v1/sandboxes/<sandbox-id>`
- `PUT /v1/sandboxes/<sandbox-id>/files?path=<absolute-container-path>`
- `GET /v1/sandboxes/<sandbox-id>/files?path=<absolute-container-path>`
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

The SDK passes these resource fields through to the gateway. The gateway owns
placement and may return `503` while nodes are scaling up.

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

## File Transfer

`PUT /v1/sandboxes/<sandbox-id>/files?path=/absolute/container/path` uploads the
raw request body to a file in the sandbox.

`GET /v1/sandboxes/<sandbox-id>/files?path=/absolute/container/path` downloads
the raw file bytes.

The SDK exposes these as:

- `upload_file(...)`
- `upload_file_from_path(...)`
- `download_file(...)`
- `download_file_to_path(...)`

The sandbox handle methods use the same operations with the handle's sandbox id.
Inspect `read_file()` and `write_file()` call these endpoints.

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
- Future sandbox creation still uses the normal gateway placement path.

SDK changes in this area should expose the gateway operation, return the
gateway JSON, and keep scheduler state in the gateway.

## Error Handling

Sync and async clients raise `SandboxApiError` for non-2xx HTTP responses and
malformed JSON/object payloads. `status_code` is set for HTTP errors, and
`body` contains the decoded JSON error body when possible.

Inspect integration retries transient scale-up and gateway errors. Normal SDK
methods make one gateway request per method call.
