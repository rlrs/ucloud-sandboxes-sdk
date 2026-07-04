# Changelog

This project uses semantic versioning.

## 0.2.0 - 2026-07-04

- Added Inspect AI support for Harbor-style single-service Compose builds.
- Mapped single-service Compose `cpus`, `mem_limit`, and `working_dir` into sandbox creation.
- Added explicit rejection for multi-service Compose until node-agent Compose project support exists.
