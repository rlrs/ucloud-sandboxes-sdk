# Changelog

This project uses semantic versioning.

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
