# Changelog

## 0.4.15 - 2026-08-29

- Added typed `container`/`linux_host` profiles, `SandboxLinuxHostSpec`, and a
  `SandboxSpec.benchmark()` factory.
- Added sync and async `from_env()` constructors for sandbox and relay clients.
- Added managed relay rollout sessions and worker loops with bounded
  concurrency, cancellation, lease renewal, retry classification, deterministic
  unregistration, and explicit rejection of unsupported streaming model calls.
- Added `RelayApiError.retryable` and `retry_after_seconds`.
- Added an asyncio subprocess-like sandbox process handle with stdin, separate
  stdout/stderr streams, wait, terminate, and kill.
- Removed the Inspect integration's outer create retry loop so the canonical
  SDK retry and `Retry-After` policy remains authoritative.

## 0.4.14 - 2026-08-28

- Required sandbox-bound relay registrations to use the managed-agent contract
  emitted by `register_agent_rollout()`, so a generic attached-exec rollout
  fails during setup instead of failing its first park attempt.
- Retry the exact `node_active_exec_deferred` pre-dispatch fence for sync and
  async exec starts. Generic or post-dispatch failures remain non-retryable.

## 0.4.13 - 2026-08-28

- Keep stable sandbox creation requests retrying through the extended cold-node
  scale-up window instead of applying the shorter generic transient-error cap.

## 0.4.12 - 2026-08-28

- Validate successful file-upload acknowledgements against the requested
  sandbox, path, and exact byte count for both synchronous and asynchronous
  clients, preventing an empty or misrouted upload from failing later at exec.

## 0.4.11 - 2026-08-27

- Unified synchronous and asynchronous managed-agent validation behind one
  shared lifecycle contract used by both sandbox and relay clients.
- Removed the unsupported public snapshot-publication method, whose server
  endpoint never existed, so the SDK exposes only end-to-end capabilities.
- Clarified that the SDK and relay coordinate managed-agent parking while
  attached exec sessions deliberately remain non-parkable.

## 0.4.10 - 2026-08-27

- Transparently retry the exact `snapshot_publication_pending` pre-dispatch
  fence for synchronous and asynchronous sandbox operations.
- Preserve at-most-once behavior for non-idempotent operations by refusing to
  replay generic structured-capacity or UCloud ingress HTML failures.
- Document the brief asynchronous publication window for parkable sandboxes
  and the SDK/backend retry contract.

## 0.4.9 - 2026-08-27

- Added synchronous and asynchronous `start_agent()` APIs for launching a
  checkpoint-owned primary process in sandboxes created with both
  `parkable=True` and `managed_process=True`.
- Added `register_agent_rollout()` to bind relay registrations to the sandbox
  ID and positive generation from a managed sandbox handle, rejecting missing
  or conflicting lifecycle metadata before making the relay request.
- Exposed relay expiry, idempotency, acceptance, reattachment, and parked
  transport-epoch state, and strictly validated those fields across lease
  renewal.
- Documented that managed agent processes and their bounded logs survive
  park/wake and migration, while attached exec sessions are for tools and short
  commands and intentionally block parking.
- Hardened the minimal installation and release checks with deterministic
  request construction, bounded transport behavior, property coverage,
  linting, and wheel smoke tests on Python 3.10 and 3.13.

The release also includes the previously accumulated unreleased changes:

- Defaulted SDK-created sandboxes to the production isolated bridge network;
  no-network execution remains available as an explicit opt-in.
- Defined one strict SDK contract for sandbox lifecycle, capacity, image builds,
  relay registration, HTTP tunnels, and SSH access.
- Made local image contexts deterministic and content-addressed.
- Unified sync and async request construction, response decoding, and relay
  token state.
- Made rollout the sole relay-registration vocabulary while retaining arbitrary
  HTTP tunnels as a separate transport.
- Removed fork APIs, constructor and payload aliases, inline build contexts,
  resource mapping alternatives, and response-key fallbacks.
- Made interrupted Inspect cleanup close the original async client while
  preserving the inspected sandbox.
- Bounded request and response bodies, disabled redirects, enforced contiguous
  exec event sequences, and carried one deadline across retries.
- Streamed and deduplicated deterministic build contexts, fenced relay response
  identities, and made Inspect cleanup and ambiguous build recovery explicit.
