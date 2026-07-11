# Gateway Protocol Notes

The SDK wraps the public gateway/node-agent HTTP API. Keep this document aligned
with `src/ucloud_sandboxes_sdk/client.py` when endpoints are added.

## Core Endpoints

- `GET /healthz`
- `GET /v1/sandboxes`
- `POST /v1/sandboxes`
- `POST /v1/sandboxes/<source-id>/forks`
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

Protected sandbox gateways expect the token in `X-UCloud-Sandbox-Token`.
The Python clients set this when constructed with `api_token=...`. Avoid
standard `Authorization` for UCloud public-link sandbox gateway calls because
that header can be consumed before the request reaches the gateway service.

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

## Live Sandbox Fork

Fork support is opt-in on the source sandbox:

```json
{
  "id": "agent-source",
  "image": "registry.example.org/agent:latest",
  "memory_mb": 2048,
  "disk_mb": 10240,
  "forkable": true,
  "fork_protocol": {
    "version": "agent-v1",
    "prepare_command": ["/usr/local/bin/fork-agent", "prepare"],
    "ready_command": ["/usr/local/bin/fork-agent", "ready"],
    "timeout_seconds": 30
  }
}
```

Single-child fork requests use:

```json
{
  "sandbox": {
    "id": "agent-child",
    "env": {"AGENT_BRANCH": "child"},
    "ttl_seconds": 900
  }
}
```

Batch requests replace `sandbox` with `sandboxes` and accept 1-64 ordered child
overlays. One immutable checkpoint is shared by the batch. Child overlays may
change only id, environment, labels, TTL, memory, and CPU; image, command,
working directory, user/security profile, mounts, network, and disk layout stay
restore-compatible with the source.

The node appends checkpoint id, nonce, and role to the configured hook command.
The prepare command acknowledges with `UCLOUD_FORK_PREPARED=<nonce>`. Source
and child ready commands acknowledge with
`UCLOUD_FORK_READY=<nonce>:<resume|restore>` after their initial process tree
has handled the transition. A cancel callback uses the `cancel` role. The
application must use `/proc/gvisor/checkpoint` to distinguish resume from
restore and `/proc/gvisor/spec_environ` to read the child's restore-time
identity.

Successful responses set `intent_persisted: true`, return restored sandbox
records plus per-child fork metadata, and preserve request order. The SDK
validates child identity, `restored: true`, and common checkpoint identity
before returning handles. New operations return HTTP 201 and exact replays may
return HTTP 200.

Error responses can include top-level `intent_persisted`, `retryable`, and an
ordered `intents` list. `SandboxApiError` exposes those fields as properties.
Callers must replay the identical request for durable or ambiguous intents and
keep the source alive until the fork response is acknowledged.

The Inspect AI provider reads sandbox security settings from environment
variables and passes them as `security` on `POST /v1/sandboxes`. Use
`UCLOUD_SANDBOX_SECURITY` for a JSON object, or set individual fields with
`UCLOUD_SANDBOX_SECURITY_USER`, `UCLOUD_SANDBOX_SECURITY_CAP_DROP`,
`UCLOUD_SANDBOX_SECURITY_CAP_ADD`,
`UCLOUD_SANDBOX_SECURITY_NO_NEW_PRIVILEGES`,
`UCLOUD_SANDBOX_SECURITY_PIDS_LIMIT`,
`UCLOUD_SANDBOX_SECURITY_READ_ONLY_ROOTFS`, and
`UCLOUD_SANDBOX_SECURITY_INIT`. Empty `USER`, empty `CAP_DROP`, and
`PIDS_LIMIT=none` are accepted when compatibility with root-oriented benchmark
images is required.

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

The Inspect integration generates deterministic image ids for Dockerfile and
single-service Compose builds. The id is derived from the Dockerfile, build
context contents, build args, explicit Compose image tag if any, and the SDK's
build compatibility version. Before uploading a local context, the provider
checks `GET /v1/images` for a matching pushed image and `GET /v1/images/builds`
for a matching active build. This keeps repeated Harbor/Inspect samples from
rebuilding the same environment after a previous pushed build is available or
while another client is already building it.

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
  "image": "ucloud-sandbox-registry:5000/ucloud/python-base:latest",
  "ttl_seconds": 900
}
```

Semantics:

- The signal contributes `count * resources` to autoscaler demand.
- The executing autoscaler consumes the signal after reacting to it.
- It expires automatically at `ttl_seconds` if no cycle consumes it.
- Deleting it removes the demand signal.
- If `image` is set, the gateway opportunistically pulls that image onto
  already-ready sandbox nodes that can fit the requested resources.
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
