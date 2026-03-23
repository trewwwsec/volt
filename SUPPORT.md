# Support Policy

## Scope

This repository supports passive OSINT perimeter intelligence workflows.

Supported:
- Installation and usage issues.
- Reproducible bugs in deterministic scan/report behavior.
- Documentation gaps and incorrect guidance.

Out of scope:
- Requests for active exploitation/scanning features.
- Unauthorized target assessment guidance.

## How To Get Help

1. Open a GitHub issue with:
   - exact command used
   - sanitized target or context
   - expected behavior
   - actual behavior
   - relevant `source_health` block from the output report
2. Include environment details:
   - OS
   - Python version
   - `volt --version`

For sensitive security reports, follow [SECURITY.md](SECURITY.md) instead of public issues.

## Response Expectations

- Best-effort triage for new issues.
- Reproducible defects are prioritized over feature requests.
- High-impact reliability regressions are prioritized for patch releases.
- Issues with minimal reproduction detail may be closed until enough context is available to reproduce them.
