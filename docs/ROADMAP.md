# Subrecon Roadmap

Guiding principle: keep the tool small, transparent, and predictable. Prefer simple and elegant improvements over feature bloat.

## Phase 1: Foundation (Now)

- Adopt `uv` as the default workflow.
- Keep dependencies minimal (stdlib-first).
- Add a small automated test baseline for core logic.
- Keep CLI behavior stable while improving reliability.

## Phase 2: Structure

- Split `subrecon.py` into focused modules:
  - `cli`
  - `models`
  - `sources` (ct/search/s3/tools)
  - `reporting`
- Avoid introducing abstractions until they reduce code complexity.
- Status: started. `models` and `reporting` were extracted first with no CLI behavior change.

## Phase 3: Reliability

- Improve source-level error reporting in output JSON.
- Add conservative retries/backoff for transient HTTP failures.
- Keep output deterministic and easy to diff.
- Status: in progress.
  - Added run-level `source_health` to reports.
  - Added automatic S3 list-probe fallback for ambiguous HEAD responses.
  - Added pluggable search providers (`bing`, `commoncrawl`).

## Phase 4: Quality Gates

- Expand test coverage for source parsing and edge cases.
- Add linting/formatting checks via `uv run`.
- Optionally add a lightweight CI workflow once local test/lint steps are stable.

## Immediate Next Actions

1. Add lightweight retries/backoff for HTTP requests to reduce transient source failures.
2. Refactor collectors into a `sources/` module package without changing report schema.
3. Add one CI job for `uv run python -m unittest discover`.
