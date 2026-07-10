# Agent and Workload Guide

This is the default operating guide for AI coding agents, evaluation runners,
and batch systems using `ucloud-sandboxes-sdk`. Treat the rules below as API
invariants. The public gateway owns placement, VM lifecycle, durable operation
identity, and node credentials; clients should not reproduce those mechanisms.

## Choose the Smallest Surface

- Use `SandboxClient` for a few synchronous operations.
- Use `AsyncSandboxClient` for bounded concurrent batches.
- Use the Inspect AI provider for `inspect eval`. It maps the supported
  single-service configuration, generates deterministic build identities,
  joins matching in-progress builds, and performs retry-safe cleanup. Do not
  recreate that adapter in an evaluation script.
- Use `RelayWorkerClient` or `AsyncRelayWorkerClient` when sandbox model calls
  must reach a worker near a private model endpoint. Persist rollout
  registration tokens across worker process restarts.

## The Golden Path

For a burst that needs a custom image:

1. Choose a unique run id and deterministic sandbox ids.
2. Request builder capacity and sandbox capacity immediately. Leave the image
   off the first sandbox hint so VM boot overlaps the image build.
3. Build and push the image to the private registry. The SDK packages the
   context deterministically and avoids uploading an identical context twice.
4. Update the **same** sandbox prepare id with the returned registry tag. This
   replaces the generic hint and starts image prewarming without adding demand.
5. Create sandboxes with bounded concurrency and a cold-start timeout measured
   in minutes.
6. Reuse each sandbox for related steps and use bounded concurrency for exec.
7. Delete sandboxes and remaining prepare signals in `finally`.

Start steps 2 and 3 before doing unrelated setup. A capacity request made only
when the first sandbox is created cannot hide any VM boot time.

## Reference Async Workflow

The async client is the simplest choice for a batch. This skeleton deliberately
uses separate limits for creation and exec, preserves successful handles when
one create fails, and cleans up partial runs:

```python
import asyncio
import logging
import os
from uuid import uuid4

from ucloud_sandboxes_sdk import AsyncSandboxClient, Image


async def main() -> None:
    run_id = f"eval-{uuid4().hex}"
    capacity_id = f"{run_id}-sandboxes"
    builder_id = f"{run_id}-builder"
    count = 100
    resources = {"cpus": 1, "memory_mb": 2048, "disk_mb": 10240}
    sandbox_ids = [f"{run_id}-{index:04d}" for index in range(count)]
    sandboxes = []

    image = Image.from_dockerfile(
        name=f"agent-image-{run_id}",
        tag=f"ucloud-sandbox-registry:5000/agents/{run_id}:v1",
        context_path="./image",
        push=True,
    )

    async with AsyncSandboxClient(
        os.environ["UCLOUD_SANDBOX_URL"],
        api_token=os.environ["UCLOUD_SANDBOX_API_TOKEN"],
        timeout_seconds=120,
    ) as client:
        try:
            await client.prepare_builder(
                prepare_id=builder_id,
                count=1,
                ttl_seconds=900,
            )
            await client.prepare_capacity(
                prepare_id=capacity_id,
                count=count,
                ttl_seconds=900,
                **resources,
            )

            built = await client.build_image(image, timeout_seconds=1800)
            runtime_image = Image.from_registry(built["image"]["tag"])

            # Reuse the id: this updates the hint instead of doubling demand.
            await client.prepare_capacity(
                prepare_id=capacity_id,
                count=count,
                image=runtime_image,
                ttl_seconds=900,
                **resources,
            )

            create_limit = asyncio.Semaphore(16)

            async def create_one(sandbox_id: str):
                async with create_limit:
                    return await client.create_sandbox(
                        id=sandbox_id,
                        image=runtime_image,
                        command=["sleep", "1800"],
                        ttl_seconds=1800,
                        start_timeout_seconds=1800,
                        request_timeout_seconds=120,
                        **resources,
                    )

            outcomes = await asyncio.gather(
                *(create_one(sandbox_id) for sandbox_id in sandbox_ids),
                return_exceptions=True,
            )
            failures = []
            for outcome in outcomes:
                if isinstance(outcome, BaseException):
                    failures.append(outcome)
                else:
                    sandboxes.append(outcome)
            if failures:
                raise failures[0]

            exec_limit = asyncio.Semaphore(16)

            async def run_one(sandbox):
                async with exec_limit:
                    result = await sandbox.exec(
                        ["python", "-c", "print('ready')"],
                        timeout_seconds=180,
                    )
                    if not result.success:
                        raise RuntimeError(
                            f"exec failed ({result.exit_code}): {result.stderr}"
                        )
                    return result.stdout

            exec_outcomes = await asyncio.gather(
                *(run_one(sandbox) for sandbox in sandboxes),
                return_exceptions=True,
            )
            exec_failures = [
                outcome
                for outcome in exec_outcomes
                if isinstance(outcome, BaseException)
            ]
            if exec_failures:
                raise exec_failures[0]
        finally:
            prepare_cleanup = await asyncio.gather(
                client.delete_prepared_capacity(capacity_id),
                client.delete_prepared_builder(builder_id),
                return_exceptions=True,
            )

            # Delete every attempted id: a lost create response is ambiguous.
            cleanup_limit = asyncio.Semaphore(16)

            async def delete_one(sandbox_id: str):
                async with cleanup_limit:
                    return await client.delete_sandbox(sandbox_id)

            sandbox_cleanup = await asyncio.gather(
                *(delete_one(sandbox_id) for sandbox_id in sandbox_ids),
                return_exceptions=True,
            )
            for failure in (*prepare_cleanup, *sandbox_cleanup):
                if isinstance(failure, BaseException):
                    # Production runners should retry with a bound and alert.
                    logging.error("sandbox cleanup failed: %r", failure)


asyncio.run(main())
```

Use a lower concurrency limit when the caller, gateway, workload image, or
remote command is heavy. Increase it only from measurements. One hundred
simultaneous exec starts optimize neither latency nor reliability.

## Identity, Retries, and Ambiguous Outcomes

- Give each logical sandbox a stable id. Repeating the same id and exact spec
  is the recovery operation after a timeout or disconnect. Reusing the id with
  a changed spec is a conflict.
- Let `create_sandbox()` and `build_image()` wait through retryable cold
  capacity within their total timeout. Do not wrap them in an unbounded retry
  loop or generate a new id on every attempt.
- A custom image build uses a stable logical image name and an immutable,
  versioned tag. `push=True` is required when another VM will run it.
- `ExecEventHistoryLostError` means the command's retained event stream has a
  gap. The command may already have performed side effects. Reconcile state or
  use an application-level idempotency key before deciding to run it again.
- Public-link transient responses and `Retry-After` are already handled within
  caller timeouts. SDK credentials are never forwarded across redirects; use
  the final gateway URL rather than adding custom redirect logic.

## Capacity Semantics

Prepared sandbox capacity is demand, not a reservation or availability
guarantee. Each unit remains until a matching sandbox allocation claims it or
the TTL expires. Matching includes resource shape and, if present, image.
Provider acceptance of a VM does not consume these units.

A prepare id identifies one replaceable hint. Updating the same id replaces its
stored count; using another id adds demand. The golden-path update happens
before sandbox creation. If allocations have already started, send the desired
**unclaimed** count rather than resetting the original total. For several
images, split the expected sandbox count accurately across one id per image.
Submit generic hints first, build the images concurrently, then update each same
id with its image. Do not issue the full workload count once per image.

Prepared builder capacity is different: it is a one-shot signal consumed after
an executing autoscaler cycle reacts. It does not reserve a particular builder.

Keep TTLs long enough to cover cloud boot variance but delete signals as soon
as a run is canceled or finishes. Suspended nodes are billed like running nodes,
so suspended pools are not an acceptable substitute for early capacity hints.

## Image Rules

- `Image.from_registry(...)` refers to an existing portable image.
- `Image.from_dockerfile(...)` plus `build_image()` builds a context. Keep that
  context small and use a stable `.dockerignore`; content-addressed upload
  deduplication saves transfer, not Docker build work.
- Use the successful build's returned registry tag for sandbox creation and
  prewarming. The service resolves it to an immutable digest for distribution.
- An unpushed build or snapshot is local to one builder/control-plane Docker
  daemon and can disappear when that VM scales down.
- Registry retention and garbage collection own deletion. There is no public
  SDK image-delete operation because deleting distributed image metadata safely
  requires stronger lifecycle semantics than removing one local record.

## Exec Rules

Use `sandbox.exec()` for ordinary one-shot commands. Use `start_exec()` only
when stdin, streaming, or explicit lifecycle control is required. Session ids
are opaque; the SDK and gateway route them to the origin node.

Exec is a remote process start followed by event delivery, not a cheap RPC.
Prefer one command that performs a coherent step over many tiny commands, reuse
an existing sandbox where isolation permits, set an explicit timeout, inspect
`result.success`, and limit concurrent starts. Never infer success from stdout
alone.

## Cleanup Contract

Every owner of a sandbox must have a `finally` path that deletes it. Track and
delete every attempted deterministic id, not only successful handles: a create
response can be lost after the gateway committed the sandbox. Also delete
capacity and builder prepare ids; deletion is still appropriate when an
allocation or autoscaler cycle may already have consumed the signal.

Cleanup failure is an operational error, not harmless logging noise. Record it,
retry it with a bound, and expose it to the run controller so leaked billable
resources can be reconciled.

## Avoid These Patterns

- Calling node-agent URLs directly or constructing generation headers.
- Waiting for an image build to finish before requesting sandbox capacity.
- Creating a new capacity id when adding the built image to an existing hint.
- Treating prepared capacity as a reservation or a suspended warm pool.
- Using builder-local image ids as if they were distributed images.
- Retrying side-effecting exec commands after losing their result history.
- Launching unbounded create/exec fan-out.
- Relying only on sandbox TTL instead of explicit cleanup.
