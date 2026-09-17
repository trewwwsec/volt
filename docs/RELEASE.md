# Release Checklist

This checklist defines the minimum release process for public tags.

## 1. Pre-Release Validation

Run deterministic gates:

```bash
uv run ruff check .
uv run ruff format --check .
python scripts/check_compile.py
python -m unittest discover -s tests -p "test_*.py"
```

If `uv run` is not usable in the local environment, direct `python -m ...` validation is acceptable for release preparation as long as the results are captured.

Offline validation is required (the deterministic gates above plus the offline
installed-CLI smoke in `docs/TESTING.md`). Automated live smoke is suspended;
do not run live matrix commands as part of release validation until controlled
fixtures and a reviewed contact boundary are defined.

## 2. Package Installability Checks

Validate command-first install flows:

```bash
uv tool install --from . volt
volt --help
volt --version

pipx install .
volt --help
volt --version
```

## 3. Docs and Baseline Refresh

Before tagging:

1. Update `CHANGELOG.md` with the release version/date and highlights.
2. Refresh `docs/TESTING.md` baseline test count and latest smoke snapshot data.
3. Verify README CLI/default-provider docs match current behavior.
4. Confirm support, security, and contributing docs still reflect the intended public support posture.

## 4. Tagging and Notes

Tag sequence:

1. Bump `__version__` in `volt_version.py`.
2. Commit release prep changes.
3. Create annotated tag (example: `v0.1.0`).
4. Push commit + tag.
5. Publish GitHub release notes from `CHANGELOG.md`.

## 5. Post-Release

1. Add next-cycle `Unreleased` section in `CHANGELOG.md`.
2. Track offline-gate failures and any controlled-fixture design work as follow-up issues.
3. Capture any public launch feedback as issues or roadmap updates.
