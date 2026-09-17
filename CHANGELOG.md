# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows semantic versioning.

## [Unreleased]

### Added

- Packaging metadata and installable `volt` CLI entry point for `uv tool install` and `pipx install`.
- `--version` CLI flag and centralized version source-of-truth via `volt_version.py`.
- Offline installed-CLI smoke gate: CI builds a wheel, installs it non-editably, and validates the installed `volt` against the offline report contract (`scripts/validation_smoke.py`).
- Public release governance docs: `SECURITY.md` and `docs/RELEASE.md`.
- Contributor workflow doc: `CONTRIBUTING.md`.
- Public onboarding docs: `docs/QUICKSTART.md` and `docs/TRIAGE.md`.
- Project support policy: `SUPPORT.md`.
- Pilot execution/launch decision template: `docs/PILOT_RUNBOOK.md`.
- Pilot metrics capture template: `docs/PILOT_LOG_TEMPLATE.md`.
- One-command local pilot test harness: `scripts/run_pilot_test.sh`.
- Pilot execution record example: `docs/PILOT_LOG_2026-03-22.md`.

### Changed

- Default search provider set to `commoncrawl`.
- Search reliability hardened: when Common Crawl index discovery fails, search now auto-runs Bing fallback queries and reports degraded coverage as `partial` (instead of a hard `error` when fallback coverage succeeds).
- Common Crawl hardening: index endpoint selection now prefers newest `CC-MAIN` collection ID, and query path now attempts `status=200` filtering with compatibility fallback for servers that reject filter syntax.
- CT reliability hardened: when `crt.sh` is unavailable or returns invalid responses, CT collection now falls back to Cert Spotter API while preserving degraded source-health telemetry.
- S3 live-testing reliability hardened with dynamic canary selection (`scripts/select_s3_canary.py`) and negative-control fallback when known public targets are stale/unavailable.
- Passive S3 reliability hardened for modern cloaked responses: anonymous `NoSuchBucket` object/website results are treated as ambiguous, and optional website probing now supports unknown-region fallback scanning for stronger passive confirmation.
- S3 canary selection now includes passive website-probe-aware viability checks (for example `toolbox2`) and pilot harness S3 cases now run with `--s3-website-probe`.
- Testing docs updated for command-first usage and refreshed baseline/snapshot notes.
- Public documentation refreshed with the current deterministic baseline (`115` tests), `volt` branding, and clearer release/support guidance.
- Degraded `source_health` states (`partial`/`error`) now add deterministic `operator_action` notes and emit a concise terminal reliability warning block.
- Added deterministic run-scan report fixture coverage to catch schema/output drift in CI.
- Hardened CT/search collectors against upstream schema/parser drift by handling malformed JSON shapes and provider helper exceptions without crashing.
- Compile coverage now runs through `scripts/check_compile.py`, which fails explicitly on missing compile targets (replacing stale `subrecon*` filenames that `compileall` silently passed).
- Removed the uncontrolled scheduled/manual live-smoke workflow (`.github/workflows/live-smoke.yml`); automated live checks are suspended pending explicitly controlled fixtures and a reviewed contact boundary.

## [0.1.0] - 2026-03-22

### Added

- Initial public MVP:
  - Passive subdomain discovery (`crt.sh`, optional `subfinder`, optional `amass`)
  - Indexed leak signal collection (`commoncrawl`)
  - Cloud storage signal checks (AWS S3, Google Cloud Storage, Azure Blob)
  - Passive subdomain takeover fingerprint checks
  - Structured `source_health` reliability telemetry in report output
- Deterministic unit test suite with CI quality gates (lint/format/compile/tests).
- Reliability improvements including HTTP retries/backoff and amass compatibility fallback modes.
