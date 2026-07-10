# Changelog

This project uses semantic versioning.

## Unreleased

- Prepared the breaking `0.3.0` SDK surface: removed the internal-node
  `heartbeat()` method, replaced ambiguous image-name aliases with
  `Image.from_gateway_id()`, made Dockerfile image ids explicit, and required
  stable caller-supplied sandbox and capacity ids.
- Removed the raw/typed duplicate SSH accessors and the image-dependent
  `create_ssh_sandbox()` shortcut; `ssh_target()` now returns the typed target.
- Made sandbox handles clear their cached record after deletion and raise on a
  refresh miss instead of silently returning stale state.
- Made list methods reject malformed gateway arrays instead of silently
  dropping invalid entries or treating a malformed response as an empty list.
- Removed relay response-shape fallbacks that hid malformed request envelopes,
  poll batches, rollout registrations, and rollout lists.
- Tightened SSH target and Inspect image/build parsing to the current gateway
  schema instead of fabricating defaults from incomplete responses.
- Made `build_image()` return the canonical tracked build record and reject a
  nominal success that does not contain a pushed image id and registry tag.
- Required local, content-addressed build-context uploads and always-pushed
  registry builds; removed the legacy base64 JSON fallback, remote-context
  escape hatch, and synthetic camelCase build result wrapper.
- Removed the unsupported unscoped model-relay URL mode and placeholder API-key
  default, and standardized Inspect configuration on `UCLOUD_SANDBOX_URL` and
  `UCLOUD_SANDBOX_BUILD_IMAGE_PREFIX`.
- Added an opinionated agent/workload guide covering cold build/boot overlap,
  stable operation identity, bounded concurrency, exec ambiguity, and cleanup.
- Corrected the protocol documentation to distinguish allocation-claimed
  sandbox capacity from one-shot prepared builder signals.
- Streamed deterministic build contexts to a content-addressed binary upload
  endpoint before submitting compact build JSON.
- Probed content-addressed build contexts before upload so repeated identical
  builds reuse the gateway copy without retransmitting it.
- Added rollout registration-token fencing to sync and async relay worker
  clients and carried the token on leased requests.
- Rejected credentialed HTTP and SSH-websocket redirects instead of forwarding
  gateway or worker credentials to redirect targets.
- Detected gaps in bounded exec event history and raised
  `ExecEventHistoryLostError` instead of returning incomplete output as final.
- Preserved response headers on API errors, honored explicit gateway
  `retryable` responses and `Retry-After`, and kept transparent public-link
  retries within the caller's timeout budget.
- Recovered ambiguous HTTP image-build submissions before resubmitting and
  made Inspect sandbox cleanup retry-safe without leaking interrupted clients
  or silently forgetting failed deletions.
- Aligned successful-response validation across sync and async clients and
  documented the public gateway as the SDK lifecycle boundary.
- Set package metadata and `__version__` to the next breaking version, `0.3.0`.

## 0.2.8 - 2026-07-06

- Retried transient UCloud public-link `503` responses that return the
  UCloud `Job is unavailable` HTML page during normal SDK API calls.
- Kept ordinary structured gateway `503` responses non-retryable in the
  generic request layer so scale-up and capacity errors still surface cleanly.

## 0.2.7 - 2026-07-05

- Mapped single-service Compose `network_mode` into sandbox networking.
- Kept `UCLOUD_SANDBOX_NETWORK` as an explicit override over Compose
  networking when it is set.

## 0.2.6 - 2026-07-04

- Added `api_token` to sync and async sandbox clients, sent as
  `X-UCloud-Sandbox-Token` for UCloud public-link compatibility.
- Switched the Inspect provider and SSH proxy helper to the public-link-safe
  sandbox token header.
- Let the Inspect provider read `UCLOUD_SANDBOX_API_URL` in addition to the
  existing sandbox URL environment variables.

## 0.2.5 - 2026-07-04

- Generated Inspect Dockerfile and Compose build image ids from a deterministic
  build-context fingerprint instead of the random sandbox id.
- Reused pushed gateway image records for matching deterministic Inspect build
  ids and tags instead of submitting duplicate builds.
- Joined matching active Inspect image builds instead of submitting and
  uploading duplicate contexts.
- Kept generated Inspect registry tags stable across samples and runs when the
  Dockerfile, build context, build args, and SDK build compatibility version do
  not change.
- Added optional image prewarm parameters to capacity prepare and multi-node
  image pull calls.

## 0.2.4 - 2026-07-04

- Recovered Inspect image builds after transient disconnects during build
  submission by looking up the deterministic image id before resubmitting.
- Kept accepted image builds from being duplicated when the submit response is
  lost before reaching the SDK.

## 0.2.3 - 2026-07-04

- Added Inspect AI environment configuration for sandbox security profiles.
- Passed the configured Inspect security profile through to sandbox creation.

## 0.2.2 - 2026-07-04

- Treated SDK image build timeouts as total build deadlines during polling.
- Bounded image build polling requests by the remaining timeout budget.
- Added `request_timeout_seconds` for per-call sandbox creation request timeouts.
- Passed remaining Inspect scale-up budget into sandbox and builder attempts.
- Avoided re-submitting Inspect image builds after the builder has accepted them.
- Added empty writable Harbor harness directories to images built by the Inspect
  Dockerfile and Compose adapters.

## 0.2.1 - 2026-07-04

- Fixed generated Inspect build tags to default to the UCloud private registry.
- Added `UCLOUD_SANDBOX_BUILD_IMAGE_PREFIX` for generated Inspect build tags.
- Retried transient aiohttp client disconnects during sandbox and builder scale-up waits.

## 0.2.0 - 2026-07-04

- Added Inspect AI support for Harbor-style single-service Compose builds.
- Mapped single-service Compose `cpus`, `mem_limit`, and `working_dir` into sandbox creation.
- Added explicit rejection for multi-service Compose until node-agent Compose project support exists.
