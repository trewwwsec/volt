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

## MVP Positioning Insight (March 22, 2026)

- Current position: strong technical CLI MVP for security engineers.
- Estimated readiness:
  - MVP (engineer-facing CLI): `~8/10`
  - Polished MVP (customer-facing): `~5.5/10`
- Interpretation:
  - Core detection/reporting pipeline is in good shape.
  - Reliability and test gates are strong.
  - Main remaining gap is productization and operator UX, not core scan logic.

## Phase 5: Productization (Next)

- Make distribution first-class:
  - Ship an installable package with a `subrecon` CLI entry point.
  - Move from script-first usage to command-first usage.
- Stabilize default operator experience:
  - Default search provider to `commoncrawl`; keep `bing` opt-in.
  - Continue surfacing source reliability clearly via `source_health`.
- Add release/governance basics:
  - Introduce release notes/changelog and versioned release process.
  - Add `SECURITY.md` and contribution guidance for external users.
- Improve operational readiness:
  - Add bounded live smoke validation as scheduled/manual CI (separate from unit gate).
  - Keep deterministic tests as the required merge gate.
- Status: in progress.

### Phase 5 Exit Criteria

- Install + run path is one command (`uv tool`/`pipx`) with `subrecon --help`.
- First tagged release with versioned notes and upgrade guidance.
- Operator docs include triage workflow for indexed-leak/cloud/takeover findings.
- CI includes a non-blocking bounded live smoke job for upstream-source drift detection.

### Phase 5: 8-Week Delivery Checkpoints

- Week 1: Product lock and acceptance criteria
  - Freeze customer-facing MVP scope and non-goals.
  - Define launch gates and map each gate to measurable checks.
  - Deliverable: `docs/ROADMAP.md` + release checklist updated with final gates.
- Week 2: Distribution and install UX
  - Ship installable package with `subrecon` console entrypoint.
  - Add `--version` and version source-of-truth.
  - Deliverable: install docs validated on clean environment (`pipx` and `uv tool`).
- Week 3: Safe defaults and operator UX
  - Default search providers to `commoncrawl` and document `bing` as opt-in.
  - Improve degraded-mode messaging and operator guidance in `source_health` notes.
  - Deliverable: updated defaults + docs + regression tests.
- Week 4: Reliability hardening
  - Expand edge-case handling for upstream parsing/drift and provider outages.
  - Add deterministic report fixture tests for schema/output stability.
  - Deliverable: green test suite with new reliability-focused coverage.
- Week 5: CI operational readiness
  - Add scheduled/manual bounded live-smoke CI job (non-blocking).
  - Keep deterministic unit/lint/compile checks as blocking merge gates.
  - Deliverable: CI workflow(s) merged with clear pass/fail semantics.
- Week 6: Security and release governance
  - Add/validate `SECURITY.md`, disclosure flow, and release-note standards.
  - Add contributor and support-path documentation.
  - Deliverable: governance docs merged and linked from README.
- Week 7: Customer documentation and pilot prep
  - Publish quickstart, finding-interpretation, and triage playbooks.
  - Prepare pilot runbook and issue-triage process.
  - Deliverable: customer docs set complete and review-ready.
- Week 8: Pilot execution and launch decision
  - Run pilot with authorized design partners and collect run quality metrics.
  - Triage blockers, cut release candidate, and make go/no-go decision.
  - Deliverable: `v1.0.0` tag if launch gates pass.

### Milestone Issues (Ready To File)

- Milestone `M5-A` (Weeks 1-2): Distribution Foundation
  - Issue: Add installable package metadata and `subrecon` console entrypoint.
    - Acceptance: `pipx install .` and `uv tool install .` both expose `subrecon --help`.
  - Issue: Add `--version` and centralized version management.
    - Acceptance: CLI reports project version and release process updates version in one place.
  - Issue: Add release checklist and first tagged release workflow.
    - Acceptance: documented checklist used to cut a reproducible release candidate.

- Milestone `M5-B` (Weeks 3-5): Reliability and Operator UX
  - Issue: Default search provider configuration to `commoncrawl` and document `bing` opt-in.
    - Acceptance: CLI defaults changed, docs updated, and parser/provider tests pass.
  - Issue: Improve degraded-mode guidance in `source_health` and terminal output.
    - Acceptance: partial/error runs include actionable operator notes with deterministic formatting.
  - Issue: Add report fixture tests and upstream-drift reliability tests.
    - Acceptance: new tests validate stable schema ordering and common source-failure scenarios.
  - Issue: Add non-blocking bounded live-smoke CI workflow.
    - Acceptance: workflow runs on schedule/manual trigger and publishes artifacts/results.

- Milestone `M5-C` (Weeks 6-8): Customer Readiness and Launch
  - Issue: Finalize governance docs (`SECURITY.md`, `CONTRIBUTING.md`, support policy links).
    - Acceptance: docs merged, linked from README, and tested for clarity in onboarding.
  - Issue: Publish customer docs (quickstart + finding triage playbooks).
    - Acceptance: new user can complete first successful scan and triage sample findings in under 10 minutes.
  - Issue: Run pilot and track launch gates.
    - Acceptance: pilot metrics recorded; go/no-go decision logged; `v1.0.0` tagged on pass.

## Immediate Next Actions

1. Completed: Packaging + entrypoint + centralized `--version` workflow (Week 2).
2. Completed: Week 3 operator UX hardening (deterministic degraded-source guidance + notes).
3. Completed: Week 4 reliability hardening (report fixture regression + upstream drift tests).
4. Completed: Week 6/7 docs foundations (`CONTRIBUTING.md`, `SUPPORT.md`, quickstart, triage playbook).
5. Next: Execute pilot runbook on authorized targets and capture launch-gate metrics.
6. Next: Prepare release candidate cut checklist and finalize go/no-go decision log.

### S3: High-Impact Improvements To Prioritize Next

1. Add strict AWS-valid bucket-name filtering before probe execution.
   - Why: reduces wasted probes and increases useful signal density.
2. Add region-aware second-phase probes using `x-amz-bucket-region` from initial `HEAD` responses.
   - Why: improves existence classification when global endpoint responses are ambiguous.
3. Add optional S3 website-endpoint probing (`s3-website-<region>`) for static-site exposure.
   - Why: catches website-hosted buckets that REST endpoint-only probing can miss.
4. Add endpoint-family awareness in classification (bucket vs access-point/MRAP alias patterns).
   - Why: reduces false attribution and keeps findings scoped to true bucket ownership signals.
5. Add optional low cloud-probe retry budget (`0 -> 1`) with jittered backoff.
   - Why: improves resilience against transient network/edge failures while preserving conservative defaults.

### GCS: High-Impact Enumeration + Detection Plan (Research-Based)

1. Add strict GCS bucket-name validation before probing.
   - Include GCS-specific rules: `3-63` chars (or dotful names up to `222`), no IP-style names, no `goog*` prefix, and no `google`/close misspellings.
   - Why: removes invalid probes early and prevents wasted budget on impossible candidates.

2. Add dedicated GCS name-generation tracks for domain-style buckets.
   - Keep current hyphenated candidates, and add high-signal dotful candidates from owned domains/hostnames (for example `assets.example.com`), because dotful bucket names are first-class in GCS.
   - Why: materially improves discovery for static-site and domain-aligned bucket naming.

3. Add XML error-code parsing for GCS responses and classify by error code, not status alone.
   - Parse `<Code>` from XML responses (`AccessDenied`, `NoSuchBucket`, etc.) for list/object probes.
   - Why: `403` and `404` are much more actionable when paired with XML code, reducing ambiguous outcomes.

4. Add second-phase object probe (`GET /<random-probe-key>`) to disambiguate existence.
   - Keep `HEAD` + list probe as primary path, then run object probe only when still ambiguous.
   - Why: improves true/false existence classification while preserving low-touch behavior.

5. Add optional dual-endpoint probing (path-style + virtual-hosted style) with conservative default.
   - Probe `https://storage.googleapis.com/<bucket>/...` first; optionally fall back to `https://<bucket>.storage.googleapis.com/...` on ambiguous responses.
   - Why: increases resilience across endpoint behaviors and catches edge cases without changing default operator UX.

6. Add confidence guardrails for globally common bucket names.
   - Down-rank or suppress weak `likely_exists` hits when candidate origin is generic (for example single common noun) and target affinity is low.
   - Why: global bucket namespace creates many unrelated `403 AccessDenied` collisions; this improves signal precision.

7. Expand GCS source-health telemetry.
   - Track `raw_candidates`, `filtered_invalid_candidates`, `filtered_reasons`, `error_code_counts`, `ambiguous`, and `suppressed_weak_likely`.
   - Why: gives operators transparent diagnostics and supports reliable tuning.

8. Add optional low retry budget for GCS cloud probes (`0 -> 1`) with existing jitter/backoff path.
   - Why: hardens live reliability under transient network/CDN failures while preserving current defaults.

### GCS Implementation Order (Small PR-Style Sequence)

1. PR1: GCS name validator + candidate filtering + telemetry fields.
2. PR2: Dotful/domain-style candidate generation path (behind conservative defaults if needed).
3. PR3: XML error-code parser + classification matrix updates (`NoSuchBucket` vs `AccessDenied`).
4. PR4: Second-phase random object probe for ambiguous candidates.
5. PR5: Optional dual-endpoint fallback behavior + tests.
6. PR6: Confidence guardrails for generic-name collisions + report note updates.
7. PR7: Optional GCS probe retry budget + reliability tests + live-smoke refresh.

### Azure Blob: High-Impact Enumeration + Detection Plan (Research-Based)

1. Expand endpoint/suffix coverage beyond `blob.core.windows.net`.
   - Add support for sovereign suffixes (for example `core.usgovcloudapi.net`, `core.chinacloudapi.cn`) and new DNS-zone endpoint patterns (`<account>.z[00-99].blob.storage.azure.net`).
   - Why: account discovery and validation currently miss real-world non-default endpoint shapes.

2. Strengthen CNAME-driven account discovery from discovered hostnames.
   - Detect blob-service endpoints, static website endpoints (`*.web.core.windows.net`), and map custom-domain CNAMEs back to storage accounts.
   - Why: enterprise targets frequently expose storage through custom domains, not raw account hostnames.

3. Add system-container coverage for high-signal exposure paths.
   - Probe reserved/system containers with encoded names where applicable (`$web`, `$root`, `$logs`) in addition to generated names.
   - Why: static website hosting auto-creates `$web`, and these containers are high-value exposure surfaces.

4. Improve Azure probe pipeline to be endpoint-aware and deterministic.
   - Keep current anonymous list probe, but add/standardize container `HEAD` checks (`restype=container`) with explicit API version handling before/alongside list probes.
   - Why: live behavior differs materially by endpoint and API version, affecting reliability and false negatives.

5. Use error-code-driven classification (not status-only).
   - Prioritize `x-ms-error-code` + XML `<Code>` semantics in classification (`NoAuthenticationInformation`, `AuthenticationFailed`, `ContainerNotFound`, `ResourceNotFound`, `FeatureVersionMismatch`).
   - Why: same HTTP status can map to very different meanings for account/container existence and publicability.

6. Add optional blob-level anonymous-read checks when list is denied.
   - For containers likely configured as blob-public (not container-public), add lightweight object probes (HEAD-first) for common static paths.
   - Why: list-denied does not always mean blob reads are denied; current list-only logic can miss real exposures.

7. Add account-first probe caching and scheduling.
   - Resolve/account-check once, then fan out container probes only when account reachability is confirmed/likely.
   - Why: reduces wasted probes, improves runtime, and increases confidence consistency per account.

8. Expand Azure source-health telemetry for operator triage.
   - Add counters for `account_resolved`, `account_unresolved`, `error_code_counts`, `system_container_hits`, `blob_only_hits`, and `ambiguous`.
   - Why: clear diagnostics make degraded-mode and confidence decisions actionable.

### Azure Blob Implementation Order (Small PR-Style Sequence)

1. PR1: Endpoint suffix expansion + DNS-zone endpoint parsing + account inference upgrades.
2. PR2: System-container coverage (`$web/$root/$logs`) + validator updates/tests.
3. PR3: Error-code classification matrix + normalized Azure error telemetry.
4. PR4: Endpoint-aware probe orchestration (HEAD/list ordering + account-first caching).
5. PR5: Optional blob-only anonymous-read probes for list-denied cases.
6. PR6: Optional Azure probe retry budget + reliability/live-smoke refresh.
