# Gateway Protocol Notes

The SDK wraps the public gateway HTTP API. Keep this document aligned with
`src/ucloud_sandboxes_sdk/client.py` when endpoints are added. Direct node-agent
lifecycle calls are intentionally outside the public SDK: the gateway owns
placement, durable generations, operation identity, and node authentication.

## Core Endpoints

- `GET /healthz`
- `GET /v1/nodes`
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

Protected sandbox gateways expect the token in `X-UCloud-Sandbox-Token`.
The Python clients set this when constructed with `api_token=...`. Avoid
standard `Authorization` for UCloud public-link sandbox gateway calls because
that header can be consumed before the request reaches the gateway service.
Credentialed SDK requests do not follow redirects, because forwarding either
the gateway token or relay worker token to a different origin would disclose
it. Configure the final HTTPS gateway/relay URL directly.

`GET /v1/heartbeat` is an internal node-agent endpoint. The deprecated
`heartbeat()` client method remains temporarily for compatibility, but new code
should use the gateway's `GET /v1/nodes` through `list_nodes()`.

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
Repeating a sandbox create with the same id and exact specification is the
supported recovery operation after a timeout or disconnect. The gateway keeps
the same durable generation, operation id, and target node. The SDK must not
invent or send node generation headers itself.

## Model Relay Worker Fencing

`POST /register_rollout` returns a random, 32-character `registration_token`.
Every rollout-scoped worker operation must echo it:

- `POST /unregister_rollout`
- `POST /worker/heartbeat`
- `GET /worker/poll`
- `POST /worker/renew`
- `POST /worker/respond`
- `POST /worker/error`

Worker clients remember the latest token per rollout. `RelayRequest` also
carries the token so `renew_request()`, `respond_to()`, and `error_request()`
remain fenced. A new client process must be given the persisted token
explicitly. Re-registering a rollout invalidates delayed traffic carrying the
old token.

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

For a local build context, the SDK first probes the deterministic compressed
archive by digest:

```http
GET /v1/image-contexts/sha256:<hex>
```

An exact `digest` and `size` response reuses the stored archive. A missing
archive is sent as a raw request body:

```http
PUT /v1/image-contexts/sha256:<hex>
Content-Type: application/gzip
Content-Length: <compressed size>
```

The upload endpoint may return either a newly stored or deduplicated context.
The SDK then sends `POST /v1/images/build` with a compact reference:

```json
{
  "id": "python-base",
  "tag": "ucloud-sandbox-registry:5000/ucloud/python-base:latest",
  "context_path": ".",
  "context_archive_digest": "sha256:<hex>",
  "context_archive_format": "tar.gz",
  "context_archive_size": 12345,
  "dockerfile": "Dockerfile",
  "push": true,
  "build_args": {},
  "labels": {}
}
```

If the upload endpoint returns `404` or `405`, the SDK treats the gateway as an
older deployment and retries the build using the former
`context_archive_base64` JSON field. Pass `upload_context=False` to
`build_image()` when `context_path` already exists on the gateway or builder VM.
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

The service bounds retained event history. If the first returned sequence is
not exactly the next expected sequence, the SDK raises
`ExecEventHistoryLostError`; it never returns a partial stdout/stderr tail as a
complete command result.

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
- Each matching sandbox allocation atomically claims one prepared unit.
- Provider VM acceptance and autoscaler reconciliation do not consume it.
- Unclaimed units remain through slow VM boots until `ttl_seconds` expires.
- Matching uses the requested resource shape and, when present, image.
- Posting the same prepare id replaces the stored hint with the supplied count;
  a different id adds another demand signal.
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

This one-shot behavior is intentionally different from prepared sandbox
capacity, whose individual units remain until matching sandbox allocations
claim them or the hint expires.

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
malformed JSON/object payloads. `status_code` is set for HTTP errors, `body`
contains the decoded JSON error body when possible, and `headers` retains
response headers such as `Retry-After`.

`create_sandbox()` and `build_image()` retry explicit cold-capacity responses
within their total start/build budgets. They preserve the same sandbox id or
prepared build payload across attempts. Inspect additionally checks for an
accepted image build before resubmitting an ambiguous build request and retries
safe sandbox deletion during cleanup. Other structured gateway errors surface
to callers. The generic request transport only retries the UCloud public-link
pre-dispatch `Job is unavailable` response, bounded by the method's timeout
budget.
