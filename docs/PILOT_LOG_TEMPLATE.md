# Pilot Metrics Log Template

Use this template with [docs/PILOT_RUNBOOK.md](PILOT_RUNBOOK.md) during pilot execution.

## Session Metadata

- Date:
- Operator:
- Subrecon version (`subrecon --version`):
- Git commit:

## Target Run Records

| Target | Run Type | Command Ref | Duration (s) | Total Findings | Degraded Sources (`partial/error`) | Notes |
| --- | --- | --- | ---: | ---: | --- | --- |
| example.com | core | `core run` | 0 | 0 | none |  |

## Launch Gate Checklist

| Gate | Pass/Fail | Evidence |
| --- | --- | --- |
| Installability (`uv tool` + `pipx`) |  |  |
| Deterministic quality gates |  |  |
| Reliability guidance behavior |  |  |
| Onboarding docs clarity |  |  |
| Pilot operator self-sufficiency |  |  |

## Decision Record

- Decision: `GO` / `NO-GO`
- Rationale:
- Blocking Issues:
- Follow-up Actions:

