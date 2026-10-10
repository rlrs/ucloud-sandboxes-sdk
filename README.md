# ucloud-sandboxes-sdk

Python SDK and Inspect AI sandbox provider for UCloud-compatible sandbox
gateways, including UCloud and Hetzner deployments.

Use this package from benchmark runners, evaluations, and user code that needs
to create sandboxes, execute commands, stream results, manage images, and signal
near-term capacity needs through a deployed UCloud sandbox gateway.

> **Training with verifiers?** Install
> [`verifiers-ucloud`](https://github.com/rlrs/verifiers-ucloud) at a tag instead
> (`uv add "verifiers-ucloud @ git+https://github.com/rlrs/verifiers-ucloud@v0.3.5"`).
> It pins a tested release of this SDK; do not install the SDK separately next
> to it. Use the SDK directly only for code that drives sandboxes without
> verifiers, and then always from a release wheel, never from a branch.

## Install

Install the versioned wheel from the GitHub release (the SDK is not currently
published on PyPI):

```bash
uv add "ucloud-sandboxes-sdk @ https://github.com/rlrs/ucloud-sandboxes-sdk/releases/download/v0.4.33/ucloud_sandboxes_sdk-0.4.33-py3-none-any.whl"
uv add "ucloud-sandboxes-sdk[async] @ https://github.com/rlrs/ucloud-sandboxes-sdk/releases/download/v0.4.33/ucloud_sandboxes_sdk-0.4.33-py3-none-any.whl"
uv add "ucloud-sandboxes-sdk[inspect] @ https://github.com/rlrs/ucloud-sandboxes-sdk/releases/download/v0.4.33/ucloud_sandboxes_sdk-0.4.33-py3-none-any.whl"
```

Use the base package for the synchronous client, the `async` extra for
`AsyncSandboxClient`, and the `inspect` extra for `inspect eval --sandbox
ucloud`.

## Authentication

Pass the deployment's sandbox API key with `api_token`. The SDK sends it as
`X-UCloud-Sandbox-Token`, which avoids UCloud public-link handling of standard
`Authorization` headers:

```python
from ucloud_sandboxes_sdk import Image, SandboxClient

client = SandboxClient(
    "https://app-sandboxes.cloud.sdu.dk",
    api_token="<token>",
)
```

The same configuration can be loaded directly from
`UCLOUD_SANDBOX_URL`, `UCLOUD_SANDBOX_API_TOKEN`, and optional
`UCLOUD_SANDBOX_TIMEOUT_SECONDS`:

```python
client = SandboxClient.from_env()
```

Raw HTTP callers should send the same token as
`X-UCloud-Sandbox-Token: <token>`.

For Hetzner, use the gateway's public HTTPS IPv4 URL in exactly the same
constructor; no domain is required. SDK users need neither the Hetzner API
token nor the separate gateway operator token:

```python
client = SandboxClient(
    "https://203.0.113.10",
    api_token="<sandbox-api-key>",
)
```

## Sandboxes

For status polling, SDK 0.4.33 adds compact inventory methods in both clients:

```python
from ucloud_sandboxes_sdk import SandboxClient

client = SandboxClient.from_env()
statuses = client.list_sandbox_statuses()  # All sandbox statuses.
statuses = client.list_sandbox_statuses(sandbox_ids=["agent-1", "agent-2"])
status = client.get_sandbox_status("agent-1")  # None if absent.
if status is not None:
    print(status["id"], status["state"])
```

```python
from ucloud_sandboxes_sdk import AsyncSandboxClient

async with AsyncSandboxClient.from_env() as client:
    statuses = await client.list_sandbox_statuses(sandbox_ids=["agent-1", "agent-2"])
    status = await client.get_sandbox_status("agent-1")
```

These methods opt in to `GET /v1/sandboxes?view=status`, with repeated `id`
parameters for exact ID filtering. Each record contains `id`, `spec` with only
the ID, `state`, `cached_state`, `node`, `created_at`, `updated_at`, and
`generation`. Omitting full specifications, images, resource requirements, and
snapshot descriptors reduces response size and gateway read/render work for
status-only callers. The view uses the same route and heartbeat observations
and freshness rules as the default inventory; it does not refresh workers.

Omit `sandbox_ids` or pass `None` for the whole fleet. An explicit empty list
returns `[]` without an HTTP request. A filter accepts at most 256 IDs, each a
nonempty string of at most 512 characters without a NUL character.

The gateway must support the compact status view and identify its response with
`view: "status"`; unsupported or malformed responses raise `SandboxApiError`.
Installing this SDK alone does not change existing `list_sandboxes()` or
`get_sandbox()` calls: they continue returning full records. Keep using those
methods when you need specifications or labels, including Inspect CLI cleanup.

```python
from ucloud_sandboxes_sdk import Image, SandboxClient, SandboxSpec

client = SandboxClient(
    "https://app-sandboxes.cloud.sdu.dk",
    api_token="<token>",
)

sandbox = client.create_sandbox(
    SandboxSpec(
        id="example",
        image=Image.from_registry("python:3.12-slim"),
        command=["sleep", "300"],
        cpus=1,
        memory_mb=2048,
        disk_mb=10240,
        ttl_seconds=600,
        parkable=True,
    )
)
try:
    result = sandbox.exec(
        ["python", "-c", "print('ok')"],
        timeout_seconds=30,
    )
    assert result.success
    print(result.stdout)
finally:
    sandbox.delete()
```

`exec()` returns stdout, stderr, exit status, and the ordered event stream.
The client feeds stdin and drains output concurrently. For long-lived or
interactive commands, call `start_exec()`, then use the returned exec handle
to write stdin, read events, close stdin, or wait for completion. Feed input and
drain output concurrently: the server applies output backpressure to slow readers.
Keep the event cursor when reconnecting; already acknowledged history is not a
durable replay log.

When `parkable=True`, a direct-runtime node may checkpoint an idle sandbox and
release its live runsc backend. Exec and file operations transparently wake it;
its filesystem and process state remain intact. Parking is opt-in because its
disk admission includes the complete memory backing required by the sandbox's
hard limit.

Publication of a parked checkpoint can briefly outlive the park response. If
an operation reaches the gateway during that exact pre-dispatch window, the
gateway returns `snapshot_publication_pending`; synchronous and asynchronous
SDK clients retry that fence automatically. They also retry
`node_active_exec_deferred`, which is emitted before an exec is dispatched when
measured node pressure is temporarily high, and
`http_request_capacity_exhausted`, which guarantees that HTTP admission rejected
the request before its handler ran. Other non-idempotent exec errors are surfaced
without replay, so an ambiguous command is never run twice.

During sandbox creation, a retryable capacity response's `Retry-After` value is
the authoritative polling cadence. The SDK adds bounded jitter to spread
concurrent clients, but does not compound that server-directed delay with
exponential transport backoff. This lets a cold create use newly ready worker
capacity promptly while its overall create timeout remains the hard bound.

For a long-lived agent that must survive relay-driven park/wake and migration,
create a managed-process sandbox without an initial command and use
`start_agent()`:

```python
agent_sandbox = client.create_sandbox(
    SandboxSpec(
        id="agent-run-001",
        image=Image.from_registry("python:3.12-slim"),
        cpus=1,
        memory_mb=2048,
        disk_mb=10240,
        ttl_seconds=3600,
        parkable=True,
        managed_process=True,
    )
)
agent = agent_sandbox.start_agent(
    ["python", "-m", "my_agent"],
)
result = agent.wait()
```

The sandbox must be created with both `parkable=True` and
`managed_process=True`. The primary process and its bounded log ledger then
live inside the checkpoint. Attached `start_exec()` sessions remain for tools
and short commands; they deliberately block parking because gVisor cannot
reattach their host-side transport after restore.

Managed agents are not parked merely because the node has seen no HTTP request
for a while. The SDK/relay protocol chooses the safe point after model-request
acceptance and coordinates that transition with the gateway. This distinction
is why a primary agent must use `start_agent()` rather than an attached exec.

`AsyncSandboxHandle.start_agent()` provides the same contract with `await`.
Use the returned job handle to wait, inspect status, or read the bounded stdout
and stderr ledger after a wake or migration.

Bind the rollout with `register_agent_rollout(rollout_id, agent_sandbox)`.
Generic `register_rollout()` deliberately rejects sandbox identity metadata;
the managed helper is the one supported path for lifecycle-aware parking.

Benchmark images that expect a VM-like writable Linux layout can use the typed
host profile directly, or the higher-level factory:

```python
from ucloud_sandboxes_sdk import SandboxLinuxHostSpec

spec = SandboxSpec.benchmark(
    id="swebench-001",
    image=Image.from_registry("ubuntu:24.04"),
    cpus=2,
    memory_mb=4096,
    disk_mb=20480,
    linux_host=SandboxLinuxHostSpec(enable_cron=True),
)
```

For ACP and persistent harnesses, the async client also exposes a subprocess-like
process handle. Its stdin accepts UTF-8 bytes, stdout and stderr are independent
`asyncio.StreamReader` instances, and signals are routed to the exec session:

```python
process = await async_sandbox.open_process(["python", "harness.py"])
process.stdin.write(b"request\n")
await process.stdin.drain()
line = await process.stdout.readline()
process.terminate()
returncode = await process.wait()
```

### Toolkits

`SandboxSpec(toolkits=["vf-harness:latest"])` asks the gateway to stack up to
four read-only toolkits on the image, each under `/opt/ucloud/toolkits/<name>`.
A toolkit is named `name:tag` (pinned to a root when the sandbox is created) or
`name@sha256:<root>`. The sandbox's environment is otherwise unchanged.

### Sandbox groups

SDK 0.4.35 adds group create to both clients. One request creates `count`
sandboxes of one spec, `<group_id>-0000` onward, packed onto few workers so each
attaches the image once:

```python
from dataclasses import replace

from ucloud_sandboxes_sdk import SandboxGroupUnavailableError

spec = SandboxSpec.benchmark(id="unused", image=Image.from_registry("ubuntu:24.04"))
try:
    members = client.create_sandbox_group("rollouts-7", spec, count=8)
except SandboxGroupUnavailableError:
    members = [
        client.create_sandbox(replace(spec, id=f"rollouts-7-{index:04d}"))
        for index in range(8)
    ]
for sandbox in members:
    sandbox.exec(["true"])
    sandbox.delete()
```

The spec's `id` is not sent. Members are ordinary sandboxes, deleted one by one
or together with `delete_sandbox_group(group_id)`; `get_sandbox_group(group_id)`
reports each member's state (`None` for an unknown group). While some members
wait for capacity the call repeats the identical request, as the gateway asks,
until the deadline (`request_timeout_seconds`, 10 minutes by default).
`on_progress` receives each answer as a `SandboxGroupStatus`, so members already
placed can be used before the rest. A gateway in ranked placement does not
create groups: the call raises `SandboxGroupUnavailableError` and creates
nothing. Other failures raise `SandboxGroupError`, whose `group` lists the
members the gateway placed.

## Files

Upload and download files as raw bytes through the gateway:

```python
sandbox.upload_file("/workspace/input.txt", b"hello\n")
data = sandbox.download_file("/workspace/output.txt")

sandbox.upload_file_from_path("local-input.txt", "/workspace/input.txt")
```

An upload creates missing parent directories and writes a private (0600) file.

To write many files, such as an agent harness, send them in one request with
`upload_files`. The sandbox extracts them with one exec instead of one per file:

```python
sandbox.upload_files(
    {
        "harness/run.py": run_py,                # relative to base_dir
        "/workspace/harness/lib/util.py": util,  # absolute, under base_dir
    },
    base_dir="/workspace",
    mode=0o644,
)
# {"ok": True, "sandbox_id": ..., "path": "/workspace", "files": 2,
#  "directories": 0, "bytes": ..., "size": ...}
```

Every file is created or replaced with `mode` (default `0o600`, as `upload_file`
writes); missing parent directories are created and existing directories are
left unchanged. Paths are checked before anything is sent: `base_dir` must be
absolute, no path may contain `..` or control characters, name `base_dir` itself,
repeat another path, or be the parent of another file. At most 10,000 files and
256 MiB, both of file content and of the compressed archive, go in one call. An
empty mapping sends nothing and returns `files` and `bytes` of 0. The upload is
not atomic: a failure can leave some files written, and repeating the call is
safe.

A gateway, worker or sandbox that cannot extract archives (an older release, or
an image without `tar`) answers 403, 404, 405 or 501; `upload_files` then
uploads each file with `upload_file`, in path order, and returns the same
`ok`, `sandbox_id`, `path`, `files` and `bytes` with `"fallback": "per_file"`.
Those files are 0600 whatever `mode` is. Each call tries the archive first.

The same methods are available on `SandboxClient` and `AsyncSandboxClient` when
you already have a sandbox id.

## Model Relay

When the sandbox needs to call a model endpoint that is only reachable from a
separate worker environment, point OpenAI-compatible clients at a public relay:

```python
from ucloud_sandboxes_sdk import Image, SandboxClient, SandboxSpec, model_relay_env

relay_env = model_relay_env(
    "https://relay.example.org",
    "run-001",
    api_key="<sandbox-relay-token>",
)

sandbox = client.create_sandbox(
    SandboxSpec(
        id="run-001",
        image=Image.from_registry("registry.example.org/swebench/task:latest"),
        cpus=1,
        memory_mb=2048,
        disk_mb=10240,
        network="bridge",
        parkable=True,
        managed_process=True,
        env=relay_env,
        labels={"rollout": "run-001"},
    )
)
```

The helper sets `OPENAI_BASE_URL` to
`https://relay.example.org/rollouts/run-001/v1`, plus `OPENAI_API_KEY` and
`VF_RELAY_ROLLOUT_ID`.

### Relay-only networking

Requires SDK **0.4.18+** and server **0.5.33+**. Select the policy explicitly when
creating a sandbox; direct networking remains the default:

```python
from ucloud_sandboxes_sdk import Image, SandboxNetworkPolicy, SandboxSpec, model_relay_env

restricted = client.create_sandbox(
    SandboxSpec(
        id="restricted-run",
        image=Image.from_registry("registry.example.org/swebench/task:latest"),
        network="bridge",
        network_policy=SandboxNetworkPolicy.relay_only("default"),
        parkable=True,
        managed_process=True,
        env=model_relay_env(
            "https://relay.example.org",  # Must match the configured relay endpoint.
            "restricted-run",
            api_key="<sandbox-relay-token>",
        ),
    )
)
```

The async client and benchmark factory support the same policy. The relay name
is an administrator-configured policy identity, not a URL. The administrator
configures `sandbox.network_relays`, for example
`{"default":"relay.example.org:443"}`, and supplies the corresponding URL to
sandbox clients. A dedicated private relay address is also supported; use its
actual protocol, hostname and port in `model_relay_env()`.

Use a dedicated endpoint. The host firewall restricts destination IPs and TCP
ports; it does not distinguish virtual hosts on a shared HTTPS ingress. Relay
environment variables alone do not restrict networking, and selecting a policy
does not automatically proxy arbitrary application traffic through the relay.
The endpoint can later be a filtering proxy, with the same host rules preventing
direct bypass.

The gateway and worker must support `network-policy-relay-v1:default`; older
nodes cannot silently run this as unrestricted networking. This mode blocks
all other destinations, guest DNS, UDP, IPv6, and inbound SSH. Bake dependencies
into the image first. Host-side DNS and a stable guest hostname mapping preserve
TLS names across relay address changes. Clients must honour `/etc/hosts`.
The policy is preserved through park/wake and migration.

For Inspect AI, select the same named policy before running an evaluation:

```bash
export UCLOUD_SANDBOX_RELAY=default
```

Configure the sandbox application's relay URL and token as above. Unset
`UCLOUD_SANDBOX_RELAY` to use the provider's normal network settings for new
sandboxes.

### Relay workers

Launch the sandbox-side agent with `start_agent()` as shown above. The managed
process ledger, relay acceptance, gateway program transition, and checkpoint
form one fenced protocol. Normal exec and file activity is never implicitly
treated as safe to checkpoint.

Run a worker near the model endpoint with a managed rollout session. It
registers the rollout, exposes a registration-authenticated tunnel URL, bounds
concurrency, renews request leases during long calls, classifies polling
failures, and unregisters on exit:

```python
from ucloud_sandboxes_sdk import RelayResponse, RelayWorkerClient

relay = RelayWorkerClient.from_env()
with relay.rollout_session(
    "run-001",
    worker_id="lumi-worker-1",
    sandbox=sandbox,
) as session:
    session.run(
        handler=lambda request: RelayResponse(
            call_local_openai_compatible_model(request.body)
        ),
        max_concurrency=8,
        lease_seconds=600,
    )
```

`respond_to()` and `commit_response_bytes_to()` acknowledge **durable acceptance**,
not sandbox wake or receipt. New servers return `committed: true` and
`delivery_status: "pending"` or `"released"`; released means the caller may receive
the result, not that it has consumed it. The server retries pending delivery
independently. A lost acknowledgement retries the identical result and never
requires a second model invocation. Older servers omit these fields and may
still wait for wake before acknowledging. Both clients validate the new receipt
contract when present. Wait for application continuation separately when needed.

`update_resource_phase()` reports optional scheduling advice for a registered
rollout. Supply a strictly increasing `sequence`, a `phase` (`model_wait`, `tool`,
`rollout_complete`, `training_pause`, or `training_resume`), and a bounded
`ttl_seconds`. A model wait may include `expected_remaining_wait_seconds`.
Identical retries preserve their sequence and payload. The registration token
fences the rollout incarnation; expired or stale advice cannot authorize parking,
cancel execution, or delete a sandbox. This optional endpoint requires server
0.5.114 or newer. Missing hints preserve normal scheduling behavior.

Use `AsyncRelayWorkerClient` for async workers; it exposes the same methods with
`await`. `from_env()` reads `UCLOUD_RELAY_URL`,
`UCLOUD_RELAY_WORKER_TOKEN`, and optional `UCLOUD_RELAY_TIMEOUT_SECONDS`.
Owned async relay sessions use separate bounded connection pools: 512 upstream
requests, 128 polls and 128 control requests per shared client. Configure
`max_forward_connections` and `max_poll_connections` on
`AsyncRelayWorkerClient`, or set `UCLOUD_RELAY_MAX_FORWARD_CONNECTIONS` and
`UCLOUD_RELAY_MAX_POLL_CONNECTIONS` when using `from_env()`. Values must be
positive integers; set a lower forwarding limit if your upstream requires it.
Caller-supplied sessions retain their own connection policy and ownership.
These transport limits apply across rollouts, separately from each worker's
`max_concurrency`. Shared `run_worker` loops shorten idle polls as worker count
grows, aiming to rotate all workers through the bounded pool in four seconds.
This avoids holding one public relay connection per idle rollout. Direct `poll()`
calls retain their requested timeout.

Upstream forwarding has its own `forward_timeout_seconds` budget (default
7,200 seconds), also configurable with `UCLOUD_RELAY_FORWARD_TIMEOUT_SECONDS`.
Gateway control calls retain their separate 30-second default. For example,
`AsyncRelayWorkerClient.from_env(forward_timeout_seconds=1800)` allows long
model generations without lengthening control-call timeouts. A per-call
`forward_to(..., timeout_seconds=...)` overrides the forwarding budget, including
when using an injected HTTP session. Async forwarding applies a total request
deadline; synchronous forwarding uses the underlying socket timeout.

Choose a budget that covers queueing, prefill and generation: 8,192 output tokens
at 26 tokens/second already require about 315 seconds. The gateway request
lifetime and the outer rollout deadline must also accommodate that work.
Upstream timeouts are returned as HTTP 504 with the configured budget in the
error message. This setting controls `forward_to` and `run_worker` with
`upstream_base_url`; custom handlers must configure their own model client.

Streaming model requests (`stream: true`) are rejected with a clear client
error because the current relay protocol buffers one complete response.

When supervising a rollout and a background relay worker, await the worker's
result before reporting cancellation of the rollout. A callback that only
cancels the rollout can hide the worker's original error. This pattern retains
the primary error while draining both tasks:

```python
rollout_task = asyncio.create_task(run_rollout())
worker_task = asyncio.create_task(relay.run_worker(
    rollout_id, upstream_base_url=model_url,
))
try:
    done, _ = await asyncio.wait(
        {rollout_task, worker_task}, return_when=asyncio.FIRST_COMPLETED,
    )
    if worker_task in done:
        await worker_task  # Propagate the actual worker failure.
        if not rollout_task.done():
            raise RuntimeError("relay worker stopped before rollout completed")
    result = await rollout_task
finally:
    for task in (rollout_task, worker_task):
        if not task.done():
            task.cancel()
    await asyncio.gather(rollout_task, worker_task, return_exceptions=True)
```

### General HTTP tunnel

The same relay can expose any buffered HTTP service, not only OpenAI endpoints.
Register a tunnel and forward each leased request to the worker-local service:

```python
from ucloud_sandboxes_sdk import RelayWorkerClient

relay = RelayWorkerClient.from_env()
with relay.rollout_session("dev-api") as session:
    print(session.base_url)  # registration-authenticated caller URL
    session.run(upstream_base_url="http://127.0.0.1:8080")
```

Callers use the tunnel URL and a dedicated relay-auth header. Keeping relay
authentication separate means an upstream `Authorization` header can pass
through unchanged:

```python
tunnel_url = http_tunnel_url(
    "https://relay.example.org",
    "dev-api",
)
tunnel_headers = {"X-UCloud-Relay-Token": "<sandbox-relay-token>"}

# requests.get(tunnel_url + "v1/data", headers=tunnel_headers)
```

The tunnel preserves methods, percent-encoded paths, query strings, headers,
status codes, and binary request/response bodies. This first implementation is
buffered HTTP with a 16 MiB raw body limit; WebSockets, streaming responses, and
raw TCP tunnels are not included.

## Prepared Capacity

If a runner knows it will soon need a burst of sandboxes, it can send a
capacity hint before the first sandbox request:

```python
client.prepare_capacity(
    prepare_id="mbpp-run",
    count=16,
    cpus=1,
    memory_mb=2048,
    disk_mb=10240,
    image=Image.from_name("python-base"),
    parkable=True,
    ttl_seconds=900,
)
```

The signal contributes `count * resources` to gateway demand until the
future sandbox claims it. Set `parkable=True` when the matching sandboxes are
parkable; the gateway expands writable `disk_mb` into the same hard checkpoint
reservation used by sandbox admission. The TTL is a cleanup bound for abandoned
runs. If `image` is set, the gateway also tries to prewarm that image on
already-ready sandbox nodes that can fit the requested resources. Cancel it
early when a run is abandoned:

```python
client.delete_prepared_capacity("mbpp-run")
```

If the same run will need Docker builds before sandbox creation, request builder
capacity separately:

```python
client.prepare_builder(
    prepare_id="mbpp-builds",
    count=1,
    ttl_seconds=900,
)
```

Builder prepare signals prewarm build-capable VM capacity only. They do not
reserve a builder, upload a context, or transfer images to sandbox nodes.

## Images

Build images through the gateway using a stable image id. The gateway owns the
private registry name, assigns the internal tag, pushes the build durably, and
later resolves the id for sandbox nodes. Clients do not configure the managed
registry hostname or port.

```python
image = Image.from_dockerfile(
    name="python-base",
    context_path="./docker/python-base",
)
client.build_image(
    image,
    on_status=lambda build: print(
        build["status"],
        build.get("updated_at"),
        (build.get("log_tail") or "")[-500:],
    ),
)

sandbox = client.create_sandbox(
    SandboxSpec(
        id="python-version",
        image=Image.from_name("python-base"),
        command=["python", "--version"],
        cpus=1,
        memory_mb=2048,
        disk_mb=10240,
    )
)
```

`Image.from_dockerfile(...)` describes a Docker build. `client.build_image(...)`
archives `context_path` deterministically, probes the SHA-256 digest, streams an
upload only when the exact archive is absent, submits a tracked build that
references the immutable archive, and polls until it succeeds or fails.
The same lower-level flow is available as `submit_image_build(...)`,
`get_image_build(...)`, `list_image_builds()`, and `wait_for_image_build(...)`.

The async client packages contexts in two shared worker threads, with at most
two submitted preparations per event loop. Waiting for a packaging slot counts
against the submission deadline; it does not block other async SDK operations.
Each submission creates one archive and reuses it across admission retries.
Keep the source directory unchanged until submission finishes: packaging is a
file-by-file snapshot, not an atomic filesystem snapshot. Separate submissions
read the directory again; the SDK does not cache archives by path.

Cancellation prevents queued packaging from starting. Running packaging cannot
be interrupted safely, so it finishes in its worker and closes its temporary
archive without submitting a build. Cancellation during an HTTP request remains
ambiguous if the gateway already accepted it; use the same stable image identity
to inspect or retry that build. Canceling the client does not cancel an accepted
server build.

Managed builds are always pushed by the gateway because the builder and sandbox
node Docker daemons are different machines. `tag` remains optional for explicit
external or advanced registry workflows, but normal SDK and integration code
should omit it.

For large Docker builds, pass `timeout_seconds` to `build_image()` as the
overall wait deadline and context-upload request timeout. Status polls use the
client's normal request timeout and return build state, command, node metadata,
error text, and a rolling log tail.

After a managed build, create sandboxes with the recorded image id:

```python
client.create_sandbox(
    SandboxSpec(
        id="python-base-example",
        image=Image.from_name("python-base"),
        cpus=1,
        memory_mb=2048,
        disk_mb=10240,
    )
)
```

You can also explicitly pull/cache a shared registry image under a gateway image
id:

```python
client.pull_image(
    Image.from_registry("registry.example.org/ucloud/python-base:latest"),
    image_id="python-base",
    count=4,
    cpus=1,
    memory_mb=2048,
)

```

### Image recipes

A trainer names task images it may never have built. Register each name with
the Dockerfile build that makes it; the gateway builds missing images on demand
or ahead of time:

```python
from ucloud_sandboxes_sdk import ImageRecipe

client.register_image_recipes([
    ImageRecipe("tmax:task_000001", "./tasks/000001", retention="pinned"),
])
client.ensure_images(["tmax:task_000001"])   # {name: {"state": "building", ...}}
client.wait_for_images(["tmax:task_000001"]) # until ready, failed or unknown
```

`ensure_images` is cheap and idempotent: call it with the next step's names so
their builds overlap the current step. A sandbox created with
`Image.from_name(name)` before its build finishes waits for it (the SDK retries
the gateway's `503 image_building`); a recipe that cannot build fails the
create with `409 image_build_failed`. `pinned` keeps the built image;
`cached` lets it age out and be rebuilt when asked for again.

### Image index

The gateway's image index holds the training image names it serves, each with
its environment, the dataset tasks that use it and its state. A trainer samples
only the tasks whose names are in it:

```python
client.image_index_summary()                     # names and tasks per environment
answer = client.image_index_task_ids("tmax")     # {"task_ids": [...], "excluded": {...}}
json.dump(answer["task_ids"], open("tmax.task-ids.json", "w"))  # a task_ids_file
for row in client.image_index_names(environment="tmax", state="failed"):
    print(row["name"], client.image_index_name(row["name"])["error"])
```

## Async Client

```python
from ucloud_sandboxes_sdk import AsyncSandboxClient, Image, SandboxSpec

async with AsyncSandboxClient(
    "https://app-sandboxes.cloud.sdu.dk",
    api_token="<token>",
) as client:
    sandbox = await client.create_sandbox(
        SandboxSpec(
            id="async-example",
            image=Image.from_registry("busybox:latest"),
            cpus=0.5,
            memory_mb=256,
            disk_mb=1024,
        )
    )
    try:
        result = await sandbox.exec(["true"], timeout_seconds=30)
    finally:
        await sandbox.delete()
```

The async client mirrors the synchronous gateway operations.

## Inspect AI

Install:

```bash
uv add "ucloud-sandboxes-sdk[inspect]"
```

Set runtime configuration:

```bash
export UCLOUD_SANDBOX_URL="https://app-sandboxes.cloud.sdu.dk"
export UCLOUD_SANDBOX_API_TOKEN="<token>"
export UCLOUD_SANDBOX_IMAGE="python:3.12-slim"
export UCLOUD_SANDBOX_CPUS="1"
export UCLOUD_SANDBOX_MEMORY_MB="2048"
export UCLOUD_SANDBOX_DISK_MB="10240"
export UCLOUD_SANDBOX_START_TIMEOUT_SECONDS="1800"
export UCLOUD_SANDBOX_BUILD_TIMEOUT_SECONDS="1800"
export UCLOUD_SANDBOX_RETRY_INTERVAL_SECONDS="10"
```

For a Hetzner deployment, replace `UCLOUD_SANDBOX_URL` with its public HTTPS
IPv4 URL. `UCLOUD_SANDBOX_API_TOKEN` remains the sandbox API key.

Run:

```bash
inspect eval task.py --sandbox ucloud
```

The provider accepts `None`, a single-service Compose config, a Compose YAML
file, or a Dockerfile. Compose `image`, `build.context`, `build.dockerfile`,
`command`, `environment`, `cpus`, `mem_limit`, `working_dir`, and
`network_mode` are mapped into a sandbox spec. `UCLOUD_SANDBOX_NETWORK`
overrides Compose networking when set. Dockerfile configs and single-service
Compose builds call `build_image`; local build contexts are uploaded to the
gateway. Generated build image ids are deterministic over the Dockerfile,
build context, build args, explicit Compose image value, and build-cache schema.
Registry coordinates are assigned by the gateway and never enter the
Inspect request. Reusing an unchanged context across samples or runs reuses a
pushed gateway image record; if another client already has the same build
running, the provider waits for that build instead of submitting another copy
of the context.
Multi-service Compose is rejected until the UCloud node agent has
project-level Compose support. Inspect `read_file()` and `write_file()` use the
gateway file endpoints. The SDK owns idempotent sandbox-create retries and
`Retry-After` handling; the provider separately recovers ambiguous image-build
submissions. Start and build timeouts
are treated as total budgets; individual scale-up attempts and build-status
polls are bounded by the remaining budget. After a builder accepts an image
build, the provider waits by build ID instead of re-submitting the build.

The Inspect provider passes a sandbox security profile into sandbox creation.
By default it uses `SandboxSecuritySpec()`, which runs as `1000:1000`, drops all
capabilities, enables `no-new-privileges`, uses `--init`, and sets a PID limit.
Set `UCLOUD_SANDBOX_SECURITY` to a JSON object to override the profile:

```bash
export UCLOUD_SANDBOX_SECURITY='{"user":null,"cap_drop":[],"no_new_privileges":false,"pids_limit":null}'
```

Set `UCLOUD_SANDBOX_SSH=1` only for debug sandboxes whose images explicitly
support an SSH server. Normal benchmark control uses exec and file APIs; model
connectivity should use a relay environment as shown above.

## Development

```bash
uv run python -m unittest
uv build
```

Run Inspect integration tests with the optional dependency installed:

```bash
uv run --extra inspect python -m unittest
```

The unit tests use a local fake gateway. Keep live gateway smoke tests in
separate operational docs.

### Cold builder admission

Build submission waits for explicit gateway `builder_not_ready`, `builder_busy`,
or `node_admission_closed` responses within its timeout, retaining the same
image identity and uploaded context. The default submission budget is ten
minutes, including context upload; `timeout_seconds` overrides it. Ambiguous
POST failures and build execution failures are not automatically resubmitted.
This requires gateway 0.5.46 or newer to advertise the admission fence.

Relay worker sessions sharing one client also share `max_inflight_requests`
(default 512; `UCLOUD_RELAY_MAX_INFLIGHT_REQUESTS` for `from_env`). Admission is
FIFO and reserves one request before each poll, so idle sessions do not hoard
their per-session concurrency allowance. Empty polls return capacity immediately. A request holds capacity through durable response
acceptance, independently of sandbox wake. Per-session `max_concurrency` remains
its local share. This budget queues work instead of rejecting it, and is distinct
from the async forwarding connection pool. Reply and renewal connections remain
reserved separately. Share one client across an experiment; different processes
need a supervisor to divide their total budget. Direct `poll()` callers retain
responsibility for admitting work before leasing it.
