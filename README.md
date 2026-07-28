# ucloud-sandboxes-sdk

Python SDK and Inspect AI sandbox provider for UCloud sandbox gateways.

Use this package from benchmark runners, evaluations, and user code that needs
to create sandboxes, execute commands, stream results, manage images, and signal
near-term capacity needs through a deployed UCloud sandbox gateway.

## Install

```bash
uv add ucloud-sandboxes-sdk
uv add "ucloud-sandboxes-sdk[async]"
uv add "ucloud-sandboxes-sdk[inspect]"
```

Use the base package for the synchronous client, the `async` extra for
`AsyncSandboxClient`, and the `inspect` extra for `inspect eval --sandbox
ucloud`.

## Authentication

Pass the gateway token with `api_token`. The SDK sends it as
`X-UCloud-Sandbox-Token`, which avoids UCloud public-link handling of standard
`Authorization` headers:

```python
from ucloud_sandboxes_sdk import Image, SandboxClient

client = SandboxClient(
    "https://app-sandboxes.cloud.sdu.dk",
    api_token="<token>",
)
```

Raw HTTP callers should send the same token as
`X-UCloud-Sandbox-Token: <token>`.

## Sandboxes

```python
from ucloud_sandboxes_sdk import Image, SandboxClient

client = SandboxClient(
    "https://app-sandboxes.cloud.sdu.dk",
    api_token="<token>",
)

sandbox = client.create_sandbox(
    id="example",
    image=Image.from_registry("python:3.12-slim"),
    command=["sleep", "300"],
    cpus=1,
    memory_mb=2048,
    disk_mb=10240,
    ttl_seconds=600,
    parkable=True,
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

`exec()` returns stdout, stderr, exit status, and the ordered event stream. For
long-lived or interactive commands, call `start_exec()`, then use the returned
exec handle to write stdin, read events, close stdin, or wait for completion.
When `parkable=True`, a direct-runtime node may checkpoint an idle sandbox and
release its live runsc backend. Exec and file operations transparently wake it;
its filesystem and process state remain intact. Parking is opt-in because its
disk admission includes the complete memory backing required by the sandbox's
hard limit.

## Live Forking

Forkable workloads must implement the gateway's `agent-v1` quiesce/readiness
protocol in their initial process tree. The SDK describes the hook commands;
the commands themselves must be present in the image and coordinate with the
long-running agent process:

```python
from ucloud_sandboxes_sdk import (
    Image,
    SandboxClient,
    SandboxForkProtocolSpec,
    SandboxForkSpec,
    SandboxSpec,
)

client = SandboxClient(
    "https://app-sandboxes.cloud.sdu.dk",
    api_token="<token>",
)
source = client.create_sandbox(
    SandboxSpec(
        id="agent-source",
        image=Image.from_registry("registry.example.org/agent:latest"),
        command=["/usr/local/bin/agent"],
        memory_mb=2048,
        cpus=1,
        disk_mb=10240,
        network="bridge",
        forkable=True,
        fork_protocol=SandboxForkProtocolSpec(
            prepare_command=("/usr/local/bin/fork-agent", "prepare"),
            ready_command=("/usr/local/bin/fork-agent", "ready"),
            timeout_seconds=30,
        ),
    )
)

child = source.fork(
    id="agent-child",
    env={"AGENT_BRANCH": "child"},
    ttl_seconds=900,
)
assert child.fork_metadata["restored"] is True

children = source.fork_many(
    (
        SandboxForkSpec(id="agent-child-a", env={"AGENT_BRANCH": "a"}),
        SandboxForkSpec(id="agent-child-b", env={"AGENT_BRANCH": "b"}),
    )
)
```

The gateway appends `<checkpoint-id> <nonce> <role>` to each hook command. The
prepare hook must print `UCLOUD_FORK_PREPARED=<nonce>` after the initial process
has quiesced and opened `/proc/gvisor/checkpoint`. Ready hooks must print
`UCLOUD_FORK_READY=<nonce>:<role>` only after the source resumed or the child
read its new identity from `/proc/gvisor/spec_environ` and rekeyed inherited
state. Forkable sources require explicit memory and disk limits and cannot use
the direct SSH option.

The corresponding client methods are `fork_sandbox()` and
`fork_sandboxes()`; async clients and handles expose the same operations. A
returned child handle keeps the normal sandbox record in `record`, its
per-child checkpoint result in `fork_metadata`, and the complete gateway
response in `create_response`.

Fork calls use a one-hour request timeout by default so the maximum 64-child
fan-out can complete within the gateway's bounded restore window. Override it
with `timeout_seconds`. If a fork raises `SandboxApiError`, inspect
`intent_persisted`, `intents`, and `retryable`. Replay the exact same request
when intent state is `True` or unknown; do not submit a different child id while
the original outcome is ambiguous.

## Files

Upload and download files as raw bytes through the gateway:

```python
sandbox.upload_file("/workspace/input.txt", b"hello\n")
data = sandbox.download_file("/workspace/output.txt")

sandbox.upload_file_from_path("local-input.txt", "/workspace/input.txt")
sandbox.download_file_to_path("/workspace/output.txt", "local-output.txt")
```

The same methods are available on `SandboxClient` and `AsyncSandboxClient` when
you already have a sandbox id.

## Model Relay

When the sandbox needs to call a model endpoint that is only reachable from a
separate worker environment, point OpenAI-compatible clients at a public relay:

```python
from ucloud_sandboxes_sdk import Image, SandboxClient, model_relay_env

relay_env = model_relay_env(
    "https://relay.example.org",
    "run-001",
    api_key="<sandbox-relay-token>",
)

sandbox = client.create_sandbox(
    image=Image.from_registry("registry.example.org/swebench/task:latest"),
    cpus=1,
    memory_mb=2048,
    disk_mb=10240,
    network="bridge",
    env=relay_env,
    labels={"rollout": "run-001"},
)
```

The helper sets `OPENAI_BASE_URL` to
`https://relay.example.org/rollouts/run-001/v1`, plus `OPENAI_API_KEY` and
`VF_RELAY_ROLLOUT_ID`.

Run a worker near the model endpoint with `RelayWorkerClient`. Polling leases a
request to one worker; renew the lease while a long local inference call is
running, then respond with the OpenAI-compatible JSON body:

```python
import threading
from ucloud_sandboxes_sdk import RelayWorkerClient

relay = RelayWorkerClient(
    "https://relay.example.org",
    worker_token="<worker-relay-token>",
)

relay.register_rollout("run-001")
poll = relay.poll(
    "run-001",
    worker_id="lumi-worker-1",
    timeout_seconds=30,
    limit=8,
    lease_seconds=600,
)

for request in poll.requests:
    stop = threading.Event()

    def renew_loop() -> None:
        while not stop.wait(60):
            relay.renew_request(
                request,
                worker_id="lumi-worker-1",
                lease_seconds=600,
            )

    renewer = threading.Thread(target=renew_loop, daemon=True)
    renewer.start()
    try:
        response = call_local_openai_compatible_model(request.body)
        relay.respond_to(request, response)
    except Exception as exc:
        relay.error_request(request, str(exc))
    finally:
        stop.set()
        renewer.join(timeout=1)
```

Use `AsyncRelayWorkerClient` for async workers; it exposes the same methods with
`await`.

### General HTTP tunnel

The same relay can expose any buffered HTTP service, not only OpenAI endpoints.
Register a tunnel and forward each leased request to the worker-local service:

```python
from ucloud_sandboxes_sdk import HttpTunnelConfig, RelayWorkerClient

relay = RelayWorkerClient(
    "https://relay.example.org",
    worker_token="<worker-relay-token>",
)
relay.register_tunnel("dev-api")

while True:
    for request in relay.poll("dev-api", timeout_seconds=30).requests:
        relay.forward_to(request, "http://127.0.0.1:8080")
```

Callers use the tunnel URL and a dedicated relay-auth header. Keeping relay
authentication separate means an upstream `Authorization` header can pass
through unchanged:

```python
tunnel = HttpTunnelConfig(
    "https://relay.example.org",
    "dev-api",
    relay_token="<sandbox-relay-token>",
)

# requests.get(tunnel.base_url + "v1/data", headers=tunnel.headers())
```

The tunnel preserves methods, percent-encoded paths, query strings, headers,
status codes, and binary request/response bodies. This first implementation is
buffered HTTP with a 32 MiB body limit; WebSockets, streaming responses, and raw
TCP tunnels are not included.

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
    image=Image.from_registry("ucloud-sandbox-registry:5000/ucloud/python-base:latest"),
    ttl_seconds=900,
)
```

The signal contributes `count * resources` to gateway demand until the
executing autoscaler reacts and consumes it. The TTL is a cleanup bound for
missed cycles or a stopped autoscaler. If `image` is set, the gateway also tries
to prewarm that image on already-ready sandbox nodes that can fit the requested
resources. Cancel it early when a run is abandoned:

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

Build images through the gateway and use registry tags as the durable cache
between build-capable machines and sandbox nodes. With a control-plane-managed
registry, use the registry's private-network host in the tag and set
`push=True`.

```python
image = Image.from_dockerfile(
    name="python-base",
    tag="ucloud-sandbox-registry:5000/ucloud/python-base:latest",
    context_path="./docker/python-base",
    push=True,
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
    image=Image.from_name("python-base"),
    command=["python", "--version"],
    cpus=1,
    memory_mb=2048,
    disk_mb=10240,
)
```

`Image.from_dockerfile(...)` describes a Docker build. `client.build_image(...)`
uploads `context_path` as a compressed tarball by default, submits a tracked
build to the gateway, and polls build status until it succeeds or fails. The
same lower-level flow is available as `submit_image_build(...)`,
`get_image_build(...)`, `list_image_builds()`, and
`wait_for_image_build(...)`. If the build context already exists on the gateway
or builder VM, pass `upload_context=False`:

```python
client.build_image(
    Image.from_dockerfile(
        name="preloaded-context",
        tag="ucloud-sandbox-registry:5000/ucloud/preloaded-context:latest",
        context_path="/work/ucloud-sandboxes/build-contexts/preloaded-context",
        push=True,
    ),
    upload_context=False,
    timeout_seconds=3000,
)
```

Use `push=True` with a registry tag for any image that sandbox nodes should run.
The builder/control-plane Docker daemon and sandbox-node Docker daemons are
different machines. The registry tag is the durable handoff.
For large Docker builds, pass `timeout_seconds` to `build_image()` as the
overall wait deadline and context-upload request timeout. Status polls use the
client's normal request timeout and return build state, command, node metadata,
error text, and a rolling log tail.

After a pushed build, sandbox creation can use either the registry tag or the
recorded image id:

```python
client.create_sandbox(
    image=Image.from_registry("ucloud-sandbox-registry:5000/ucloud/python-base:latest"),
    cpus=1,
    memory_mb=2048,
    disk_mb=10240,
)

client.create_sandbox(
    image=Image.from_name("python-base"),
    cpus=1,
    memory_mb=2048,
    disk_mb=10240,
)
```

You can also explicitly pull/cache a shared registry image under a gateway image
id:

```python
client.pull_image(
    Image.from_registry("ucloud-sandbox-registry:5000/ucloud/python-base:latest"),
    image_id="python-base",
    count=4,
    cpus=1,
    memory_mb=2048,
)

client.snapshot_sandbox(
    "example",
    Image.from_registry("registry.example.org/ucloud/example-snapshot:latest"),
)
```

Snapshots should also target a registry tag if another node will need to run the
image later. Images built or snapshotted without `push=True` are local to the
builder/control-plane Docker daemon and are not available after a builder VM
scales down.

## Async Client

```python
from ucloud_sandboxes_sdk import AsyncSandboxClient, Image

async with AsyncSandboxClient(
    "https://app-sandboxes.cloud.sdu.dk",
    api_token="<token>",
) as client:
    sandbox = await client.create_sandbox(
        id="async-example",
        image=Image.from_registry("busybox:latest"),
        cpus=0.5,
        memory_mb=256,
        disk_mb=1024,
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
export UCLOUD_SANDBOX_BUILD_IMAGE_PREFIX="ucloud-sandbox-registry:5000/ucloud-inspect"
export UCLOUD_SANDBOX_START_TIMEOUT_SECONDS="1800"
export UCLOUD_SANDBOX_BUILD_TIMEOUT_SECONDS="1800"
export UCLOUD_SANDBOX_RETRY_INTERVAL_SECONDS="10"
```

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
gateway. Generated build tags use `UCLOUD_SANDBOX_BUILD_IMAGE_PREFIX`, falling back to
`UCLOUD_SANDBOX_REGISTRY_PREFIX`, then
`ucloud-sandbox-registry:5000/ucloud-inspect`. Explicit Compose `image:` values
are preserved. Generated build image ids and tags are deterministic over the
Dockerfile, build context, build args, explicit tag, and SDK compatibility
version. Reusing an unchanged context across samples or runs reuses a pushed
gateway image record; if another client already has the same build running, the
provider waits for that build instead of submitting another copy of the context.
For Dockerfile and Compose builds, the provider adds empty
writable Harbor harness directories (`/tests`, `/logs/agent`, `/logs/verifier`,
`/task`, and `/oracle`) in the built image without copying test files into the
image. Multi-service Compose is rejected until the UCloud node agent has
project-level Compose support. Inspect `read_file()` and `write_file()` use the
gateway file endpoints. When the gateway reports that a sandbox or builder node
is scaling up, or the gateway connection briefly drops during scale-up, the
provider retries until the configured timeout expires. Start and build timeouts
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

The same fields can be set individually:

```bash
export UCLOUD_SANDBOX_SECURITY_USER=""                 # unset Docker --user
export UCLOUD_SANDBOX_SECURITY_CAP_DROP=""             # comma-separated, empty means none
export UCLOUD_SANDBOX_SECURITY_CAP_ADD="SYS_PTRACE"
export UCLOUD_SANDBOX_SECURITY_NO_NEW_PRIVILEGES="0"
export UCLOUD_SANDBOX_SECURITY_PIDS_LIMIT="none"
export UCLOUD_SANDBOX_SECURITY_READ_ONLY_ROOTFS="false"
export UCLOUD_SANDBOX_SECURITY_INIT="true"
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
