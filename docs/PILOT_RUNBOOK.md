# Pilot Runbook

Use this runbook to execute a bounded customer pilot and make a launch go/no-go decision.

Use [docs/PILOT_LOG_TEMPLATE.md](PILOT_LOG_TEMPLATE.md) to capture metrics consistently.

Fast path (from repo root):

```bash
scripts/run_pilot_test.sh --mode quick
```

For broader coverage:

```bash
scripts/run_pilot_test.sh --mode full
```

## 1. Preconditions

- Authorized target list approved.
- Operator has legal approval for passive OSINT collection.
- Current release candidate is tagged and reproducible.
- Deterministic quality gates are green.

## 2. Pilot Scope

For each pilot target:

1. Core run:
   - `subrecon -d <target> -o <target>_core.json`
2. Bounded cloud signal checks:
   - S3-only
   - GCS-only
   - Azure probe checks (as applicable)
3. Optional source-specific runs:
   - CT only
   - Search only (`commoncrawl` baseline)

Reference commands: [docs/TESTING.md](TESTING.md)

## 3. Data To Capture

For each run capture:

- Command executed
- Tool version (`subrecon --version`)
- Runtime duration
- `summary.total_findings`
- `source_health` statuses (`ok`, `ok_no_results`, `partial`, `error`)
- Any `operator_action` notes from degraded sources

## 4. Launch Gates

Record pass/fail for each gate:

1. Installability:
   - `uv tool install --from . subrecon` works
   - `pipx install .` works
2. Deterministic quality:
   - lint + format + compile + unit tests all pass
3. Reliability:
   - no critical regression in source-health behavior
   - degraded paths emit actionable guidance
4. Documentation:
   - quickstart and triage docs are sufficient for first-run success
5. Pilot outcomes:
   - pilot operators can run and interpret reports without maintainer intervention

## 5. Decision Template

Go:
- All launch gates pass.
- No unresolved high-severity defects.

No-go:
- Reproducible reliability regressions in core flows.
- Insufficient onboarding/triage clarity for pilot operators.
- Blocking defects without mitigations.

## 6. Post-Pilot Actions

1. Convert defects and enhancements into tracked issues.
2. Update `CHANGELOG.md` and release notes.
3. Re-run deterministic + bounded live-smoke checks before final tag.
