# Changelog

## Unreleased

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
