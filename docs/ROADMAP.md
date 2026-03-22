# Subrecon Roadmap

Guiding principle: keep the tool small, transparent, and predictable. Prefer simple and elegant improvements over feature bloat.

## Phase 1: Foundation (Now)

- Adopt `uv` as the default workflow.
- Keep dependencies minimal (stdlib-first).
- Add a small automated test baseline for core logic.
- Keep CLI behavior stable while improving reliability.
- Status: complete.

## Phase 2: Structure

- Split `subrecon.py` into focused modules:
  - `cli`
  - `models`
  - `sources` (ct/search/s3/tools)
  - `reporting`
- Avoid introducing abstractions until they reduce code complexity.
- Status: complete.
  - Extracted `models` and `reporting` with no behavior change.
  - Extracted `sources/ct.py`, `sources/search.py`, `sources/storage.py`, `sources/takeover.py`, and `sources/tools.py`.
  - Extracted `cli.py` (`build_parser` and `main`) while keeping compatibility wrappers in `subrecon.py`.
  - Extracted `run_scan` orchestration into `cli.py` while keeping `subrecon.run_scan` as a compatibility wrapper.
  - Extracted CLI/input helpers (`load_domains`, `parse_keywords`, `parse_search_providers`, `positive_int`) into `cli.py` with compatibility wrappers.
  - Extracted generic runtime helpers (`log`, `init_source_health`, `normalize_domain`, `check_tool`, `run_command`) into `core.py` with compatibility wrappers.
  - Extracted HTTP transport helper (`fetch_url`) into `networking.py` with wrapper injection preserving patched-test behavior.
  - Extracted takeover helper primitives into `sources/takeover.py` (`fetch_doh_cname_records`, signature/fingerprint matching, endpoint probe) with compatibility wrappers.
  - Extracted Azure Blob parsing/classification helpers into `sources/storage.py` with compatibility wrappers.
  - Extracted structured-output parsing/provenance helpers into `parsing.py` with compatibility wrappers.
  - Extracted search helper primitives into `sources/search.py` (dork/commoncrawl query builders, index discovery, result normalization, leak classification) with compatibility wrappers.
  - Extracted storage naming/wordlist helpers into `sources/storage.py` (S3 candidate extraction + Azure account/container helpers) with compatibility wrappers.
  - Extracted static configuration constants into `constants.py` while preserving `subrecon` constant exports.
  - Added canonical `models.py` and `reporting.py` modules; retained `subrecon_models.py`/`subrecon_reporting.py` as compatibility shims.

## Phase 3: Reliability

- Improve source-level error reporting in output JSON.
- Add conservative retries/backoff for transient HTTP failures.
- Keep output deterministic and easy to diff.
- Status: complete.
  - Added run-level `source_health` to reports.
  - Added structured per-source `error_types` and capped `error_samples` in `source_health`.
  - Added automatic S3 list-probe fallback for ambiguous HEAD responses.
  - Added GCP bucket existence/listability checks.
  - Added Azure Blob CNAME-derived container listability checks.
  - Added lightweight HTTP retries/backoff for transient fetch failures.
  - Added amass compatibility fallback (`-src` and `-json`) with plain-output fallback.
  - Added pluggable search providers (`bing`, `commoncrawl`).
  - Added passive subdomain takeover detection via CNAME + fingerprint matching.
  - Added curated takeover signatures with edge-case handling.
  - Tuned HTTP retry budgets by source class (CT/search/takeover) while keeping cloud probe retries at `0`.
  - Added deterministic normalization for `source_health` notes/error maps/samples before JSON output.

## Phase 4: Quality Gates

- Expand test coverage for source parsing and edge cases.
- Add linting/formatting checks via `uv run`.
- Optionally add a lightweight CI workflow once local test/lint steps are stable.
- Status: complete.
  - Added CI workflow at `.github/workflows/ci.yml` running Ruff lint/format checks, static compile checks, and `uv run python -m unittest discover`.
  - Added `ruff` dev dependency group and standardized local/CI lint+format checks on `uv run ruff ...`.
  - Expanded automated tests for edge-case parsing and partial-failure source-health transitions.
  - Added parser edge-case tests for S3/Azure error-code extraction fallbacks.
  - Added deterministic partial-failure simulation commands to `docs/TESTING.md`.

## Immediate Next Actions

1. Periodically refresh the live-smoke snapshot in `docs/TESTING.md` as upstream sources evolve.
2. Evaluate when to deprecate compatibility shims (`subrecon_models.py`, `subrecon_reporting.py`) after downstream consumers migrate.
3. Keep CI runtime bounded while adding new targeted tests.
