# Pilot Metrics Log Template

Use this template with [docs/PILOT_RUNBOOK.md](PILOT_RUNBOOK.md) during pilot execution.

## Session Metadata

- Date:
- Operator:
- Volt version (`volt --version`):
- Git commit:

## Target Run Records

| Target | Run Type | Command Ref | Duration (s) | Total Findings | Degraded Sources (`partial/error`) | Notes |
| --- | --- | --- | ---: | ---: | --- | --- |
| example.com | core | `core_run` | 0 | 0 | none | Replace with the relevant report key or command label. |

## Launch Gate Checklist

| Gate | Pass/Fail | Evidence |
| --- | --- | --- |
| Installability (`uv tool` + `pipx`) |  |  |
| Deterministic quality gates |  |  |
| Reliability guidance behavior |  |  |
| Onboarding docs clarity |  |  |
| Pilot operator self-sufficiency |  | Must be an unqualified pass. Any caveat, workaround, or maintainer-only interpretation requirement counts as fail. |

## Decision Record

- Decision: `GO` / `NO-GO`
- Rationale:
- Blocking Issues:
- Follow-up Actions:
