# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows semantic versioning.

## [Unreleased]

### Added

- Packaging metadata and installable `subrecon` CLI entry point for `uv tool install` and `pipx install`.
- `--version` CLI flag and centralized version source-of-truth via `subrecon_version.py`.
- Non-blocking scheduled/manual live-smoke GitHub Actions workflow (`.github/workflows/live-smoke.yml`).
- Release governance docs: `SECURITY.md` and `docs/RELEASE.md`.

### Changed

- Default search provider set to `commoncrawl`; `bing` remains optional/best-effort via `--search-providers`.
- Testing docs updated to command-first usage (`uv run subrecon`) and refreshed baseline/snapshot notes.
- Degraded `source_health` states (`partial`/`error`) now add deterministic `operator_action` notes and emit a concise terminal reliability warning block.
- Added deterministic run-scan report fixture coverage to catch schema/output drift in CI.
- Hardened CT/search collectors against upstream schema/parser drift by handling malformed JSON shapes and provider helper exceptions without crashing.

## [0.1.0] - 2026-03-22

### Added

- Initial public MVP:
  - Passive subdomain discovery (`crt.sh`, optional `subfinder`, optional `amass`)
  - Indexed leak signal collection (`bing`, `commoncrawl`)
  - Cloud storage signal checks (AWS S3, Google Cloud Storage, Azure Blob)
  - Passive subdomain takeover fingerprint checks
  - Structured `source_health` reliability telemetry in report output
- Deterministic unit test suite with CI quality gates (lint/format/compile/tests).
- Reliability improvements including HTTP retries/backoff and amass compatibility fallback modes.
