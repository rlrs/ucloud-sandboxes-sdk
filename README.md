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

Pass the gateway bearer token as an HTTP `Authorization` header:

```python
from ucloud_sandboxes_sdk import SandboxClient

client = SandboxClient(
    "https://app-sandboxes.cloud.sdu.dk",
    headers={"Authorization": "Bearer <token>"},
)
```

## Sandboxes

```python
from ucloud_sandboxes_sdk import SandboxClient

client = SandboxClient(
    "https://app-sandboxes.cloud.sdu.dk",
    headers={"Authorization": "Bearer <token>"},
)

sandbox = client.create_sandbox(
    id="example",
    image="python:3.12-slim",
    command=["sleep", "300"],
    cpus=1,
    memory_mb=2048,
    disk_mb=10240,
    ttl_seconds=600,
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
from ucloud_sandboxes_sdk import SandboxClient, model_relay_env

relay_env = model_relay_env(
    "https://relay.example.org",
    "run-001",
    api_key="<sandbox-relay-token>",
)

sandbox = client.create_sandbox(
    image="registry.example.org/swebench/task:latest",
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
    ttl_seconds=900,
)
```

The signal contributes `count * resources` to gateway demand until its TTL
expires. Cancel it early when a run is abandoned:

```python
client.delete_prepared_capacity("mbpp-run")
```

## Images

Build images through the gateway and use registry tags as the durable cache
between build-capable machines and sandbox nodes.

```python
client.build_image(
    id="python-base",
    tag="registry.example.org/ucloud/python-base:latest",
    context_path="./docker/python-base",
    push=True,
)

client.pull_image(
    "registry.example.org/ucloud/python-base:latest",
    image_id="python-base",
)

client.snapshot_sandbox(
    "example",
    "registry.example.org/ucloud/example-snapshot:latest",
)
```

When `context_path` points to a local directory, the SDK sends a compressed
build context in the JSON request. Pass `upload_context=False` when the path
already exists on the gateway machine.

## Async Client

```python
from ucloud_sandboxes_sdk import AsyncSandboxClient

async with AsyncSandboxClient(
    "https://app-sandboxes.cloud.sdu.dk",
    headers={"Authorization": "Bearer <token>"},
) as client:
    sandbox = await client.create_sandbox(
        id="async-example",
        image="busybox:latest",
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
export UCLOUD_SANDBOX_START_TIMEOUT_SECONDS="1800"
export UCLOUD_SANDBOX_BUILD_TIMEOUT_SECONDS="1800"
export UCLOUD_SANDBOX_RETRY_INTERVAL_SECONDS="10"
```

Run:

```bash
inspect eval task.py --sandbox ucloud
```

The provider accepts `None`, a single-service Compose config, a Compose YAML
file, or a Dockerfile. Compose `image`, `command`, and `environment` are mapped
into a sandbox spec. Dockerfile configs call `build_image`; local build contexts
are uploaded to the gateway. Inspect `read_file()` and `write_file()` use the
gateway file endpoints. When the gateway reports that a sandbox or builder node
is scaling up, the provider retries until the configured timeout expires.

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
