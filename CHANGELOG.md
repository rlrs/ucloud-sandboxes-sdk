# Changelog

## 0.4.28 - 2026-09-24

- Retry transient image-build status polling failures in both clients without
  resubmitting the build. Read timeouts, disconnects, and transient HTTP errors
  use jittered backoff within the original build deadline. Authentication,
  missing-build, protocol errors, and cancellation still propagate. Waiting
  without a deadline permits six consecutive poll retries.

## 0.4.27

Sync and async exec(input=...) send stdin and consume output concurrently, avoiding deadlocks with bounded server output. Failures and cancellation stop the command and clean up peer I/O while preserving the original error.

## 0.4.25 - 2026-09-23

Short noninteractive execs request up to 50 ms of initial output in their start response. Completed output avoids a follow-up HTTP poll; partial output retains sequence and final-watermark checks. Older servers continue through the existing event endpoint.

## 0.4.24 - 2026-09-23

- Finish exec waits and event iteration at the server-proven final output
  sequence, avoiding an extra confirmation request while preserving paginated
  stdout/stderr. Older servers retain the existing polling behavior.

## 0.4.21 - 2026-09-19

- Let explicit exec-event admission rejections retry within the caller deadline,
  matching sandbox operations instead of stopping after sixteen attempts.
- Keep relay workers running when lease renewal races with a successfully
  committed reply; only the specific already-completed renewal response is
  ignored after a successful commit, preserving other lease failures.
- Give async relay polling, upstream forwarding, and control requests separate
  bounded connection pools so many long polls cannot starve reply commits or
  lease renewals. The polling pool supports 512 concurrent polls.
- Retire async clients' idle HTTP connections after five seconds, before the
  public proxy's ten-second idle close, to avoid stale-connection POST failures.
  Caller-supplied sessions retain their own connection settings.
- Retry idempotent relay response commits after transport failures and transient
  HTTP errors, retaining the same request/lease identity and response bytes.
- Preserve attempt bounds, Retry-After, explicit non-retryable responses, and
  terminal registration/lease/caller failures. Ordinary ambiguous upload or
  execution failures are still not automatically replayed.

## 0.4.20 - 2026-09-18

- Retry explicit gateway/node startup and restore admission rejections for
  sync and async operations, including file uploads, with jitter and Retry-After.
- Let safe pre-dispatch retries use the caller deadline instead of a separate
  sixteen-attempt cutoff; retain conservative handling of ambiguous timeouts.
- Bound backoff exponent computation for long-lived startup queues.

## 0.4.17 - 2026-09-11

- Separate upstream forwarding timeouts from gateway control-call timeouts in
  sync and async relay clients. Forwarding defaults to 7,200 seconds and accepts
  `forward_timeout_seconds` or `UCLOUD_RELAY_FORWARD_TIMEOUT_SECONDS`; explicit
  per-request deadlines override injected HTTP session defaults.
- Report upstream timeouts as HTTP 504 with a descriptive error and the
  configured forwarding budget, including synchronous response-body timeouts.
- Preserve the original async worker or forwarding exception while cancelling
  and draining sibling requests and lease-renewal tasks.
- Document client-side rollout supervision that surfaces worker failures before
  cancellation cleanup.

## 0.4.16 - 2026-09-03

- Retry the service's explicit `http_request_capacity_exhausted` pre-dispatch
  fence for synchronous and asynchronous requests, including exec starts and
  cleanup. Generic retryable 503 responses remain non-replayable for mutating
  methods because they do not prove the request was rejected before dispatch.

- Preserved explicit gateway image-name versus registry-reference intent across
  sandbox creation, capacity preparation, and image pulls in both sync and
  async clients, including safe retries for transient pre-dispatch image
  resolution fences.
- Made exec event polling adapt to the client's HTTP timeout and use bounded
  long polls, reducing quiet polling load without delaying output or process
  completion notifications.

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
