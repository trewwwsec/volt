# Release Checklist

This checklist defines the minimum release process for the first tagged public release and subsequent tags.

## 1. Pre-Release Validation

Run deterministic gates:

```bash
uv run ruff check .
uv run ruff format --check .
uv run python -m compileall -q subrecon.py cli.py constants.py core.py models.py networking.py parsing.py reporting.py subrecon_models.py subrecon_reporting.py sources tests
uv run python -m unittest discover -s tests -p "test_*.py"
```

Run bounded live smoke (non-blocking quality signal):

- Trigger `.github/workflows/live-smoke.yml` manually, or
- Run the matrix in `docs/TESTING.md` locally with bounded targets.

## 2. Package Installability Checks

Validate command-first install flows:

```bash
uv tool install --from . subrecon
subrecon --help
subrecon --version

pipx install .
subrecon --help
subrecon --version
```

## 3. Docs and Baseline Refresh

Before tagging:

1. Update `CHANGELOG.md` with the release version/date and highlights.
2. Refresh `docs/TESTING.md` baseline test count and latest smoke snapshot data.
3. Verify README CLI/default-provider docs match current behavior.

## 4. Tagging and Notes

Tag sequence:

1. Bump `__version__` in `subrecon_version.py`.
2. Commit release prep changes.
3. Create annotated tag (example: `v0.1.0`).
4. Push commit + tag.
5. Publish GitHub release notes from `CHANGELOG.md`.

## 5. Post-Release

1. Add next-cycle `Unreleased` section in `CHANGELOG.md`.
2. Track any live-smoke drift findings as follow-up issues.
