# Changelog

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
