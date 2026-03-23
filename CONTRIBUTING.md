# Contributing

Thanks for contributing to `subrecon`.

## Scope and Safety

- Keep changes aligned with passive OSINT-only behavior.
- Do not add active scanning, exploitation, authentication attempts, or destructive actions.
- Prefer secure-by-default behavior and explicit operator guidance.

## Development Setup

Requirements:

- Python 3.10+
- `uv`

Setup:

```bash
uv sync --group dev
```

## Local Quality Gates

Run before opening a PR:

```bash
uv run ruff check .
uv run ruff format --check .
uv run python -m compileall -q subrecon.py cli.py constants.py core.py models.py networking.py parsing.py reporting.py subrecon_models.py subrecon_reporting.py sources tests
uv run python -m unittest discover -s tests -p "test_*.py"
```

Optional live checks are documented in [docs/TESTING.md](docs/TESTING.md).

## Pull Request Guidelines

- Keep PRs small and focused.
- Preserve existing defaults unless explicitly changing them is the goal.
- Add or update tests for behavior changes.
- Update docs/changelog when user-facing behavior changes.
- Include a short validation summary (commands run + key outcomes).

## Reporting Security Issues

Do not open public issues for sensitive vulnerabilities.

- Follow [SECURITY.md](SECURITY.md) for disclosure guidance.

