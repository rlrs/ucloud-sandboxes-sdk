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
- `GET /v1/builders/prepare`
- `POST /v1/builders/prepare`
- `DELETE /v1/builders/prepare/<prepare-id>`

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

The SDK requires `image` to be an `Image` helper. `Image.from_registry(...)`
sends a registry tag, `Image.from_name(...)` sends a gateway image id, and
`Image.from_dockerfile(...)` carries build metadata for `build_image()`.
The gateway owns placement and may return `503` while nodes are scaling up.

## Images

`POST /v1/images/build` accepts:

```json
{
  "id": "python-base",
  "tag": "ucloud-sandbox-registry:5000/ucloud/python-base:latest",
  "context_path": ".",
  "context_archive_base64": "<tar.gz bytes encoded as base64>",
  "context_archive_format": "tar.gz",
  "dockerfile": "Dockerfile",
  "push": true,
  "build_args": {},
  "labels": {}
}
```

The SDK attaches `context_archive_base64` by default when
`Image.from_dockerfile(...).build_spec.context_path` points at a local
directory. Pass `upload_context=False` to `build_image()` when `context_path`
already exists on the gateway or builder VM.
`build_image()` submits with `wait: false`, then polls
`GET /v1/images/builds/{build_id_or_image_id}` until the tracked build reaches
`succeeded` or `failed`. SDK callers can use `on_status` to receive each status
change and rolling `log_tail`. Large builds should pass `timeout_seconds` as
the overall wait deadline and context-upload request timeout.

Tracked build status is exposed through:

```text
POST /v1/images/build       # body includes wait: false
GET  /v1/images/builds
GET  /v1/images/builds/{build_id_or_image_id}
```

Builds intended for sandbox nodes should set `push: true` and use a registry
tag. The gateway records the pushed tag under the image id, so a later sandbox
create can use either `Image.from_registry("host:5000/repo/name:tag")` or
`Image.from_name("python-base")`. Unpushed builds are local to the
builder/control-plane Docker daemon and should not be treated as portable.

`POST /v1/images/pull` accepts:

```json
{
  "image": "ucloud-sandbox-registry:5000/ucloud/python-base:latest",
  "id": "python-base"
}
```

`POST /v1/sandboxes/<sandbox-id>/snapshot` accepts:

```json
{
  "image": "ucloud-sandbox-registry:5000/ucloud/snapshot:latest",
  "id": "snapshot"
}
```

Snapshots that must survive node scale-down should use a registry tag and be
pushed by the gateway service.

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
- The executing autoscaler consumes the signal after reacting to it.
- It expires automatically at `ttl_seconds` if no cycle consumes it.
- Deleting it removes the demand signal.
- Future sandbox creation still uses the normal gateway placement path.

SDK changes in this area should expose the gateway operation, return the
gateway JSON, and keep scheduler state in the gateway.

## Prepared Builder Capacity

`POST /v1/builders/prepare` accepts:

```json
{
  "id": "build-run-id",
  "count": 1,
  "ttl_seconds": 900
}
```

Semantics:

- The signal asks the autoscaler to bring `count` builder-only VMs online.
- The executing autoscaler consumes the signal after reacting to it.
- It expires automatically at `ttl_seconds` if no cycle consumes it.
- Deleting it removes the demand signal.
- Future image builds still use `POST /v1/images/build` and normal gateway
  routing.

Builder nodes are for Docker build and registry push work. They should
advertise `image-build` and should not advertise `sandbox`. The durable handoff
from builders to sandbox nodes is a registry tag: build requests that should be
used by sandboxes should set `push: true` and use a registry tag. Sandbox nodes
pull and cache registry tags before starting containers; the gateway does not
copy builder-local Docker images between VMs.

When the gateway records a pushed image, sandbox creation may use either the
registry tag or the image id. In the SDK that means
`Image.from_registry("host:5000/repo/name:tag")` or
`Image.from_name("name")`. Image-id creation resolves to the recorded tag.
Unpushed image ids must be rejected or surfaced as unavailable because the image
only exists on the builder/control-plane Docker daemon that built it.

## Error Handling

Sync and async clients raise `SandboxApiError` for non-2xx HTTP responses and
malformed JSON/object payloads. `status_code` is set for HTTP errors, and
`body` contains the decoded JSON error body when possible.

Inspect integration retries transient scale-up and gateway errors. Normal SDK
methods make one gateway request per method call.
