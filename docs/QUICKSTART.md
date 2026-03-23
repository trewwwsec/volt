# Quickstart

This guide gets a first successful `subrecon` run with deterministic validation steps.

## 1. Install

Using `uv tool`:

```bash
uv tool install --from . subrecon
subrecon --version
subrecon --help
```

Using `pipx`:

```bash
pipx install .
subrecon --version
subrecon --help
```

## 2. Run a First Scan

```bash
subrecon -d example.com -o perimeter_report.json
```

## 3. Validate Output Quickly

Check top-level summary and source reliability:

```bash
uv run python - <<'PY'
import json
from pathlib import Path

data = json.loads(Path("perimeter_report.json").read_text())
print("total_findings:", data.get("summary", {}).get("total_findings"))
for source, stats in sorted(data.get("source_health", {}).items()):
    print(f"{source}: status={stats.get('status')} errors={stats.get('errors')} timeouts={stats.get('timeouts')}")
PY
```

## 4. Run a Bounded High-Signal Cloud Check

S3 signal check:

```bash
S3_CANARY="$(uv run python scripts/select_s3_canary.py || true)"
S3_TARGET="${S3_CANARY:-subrecon-negative-s3-$(date +%s)}"
subrecon -d "${S3_TARGET}.test" --keywords "$S3_TARGET" --s3-website-probe --no-ct --no-subfinder --no-amass --no-search --no-gcp --no-azure --no-takeover -o s3_report.json
```

GCS signal check:

```bash
subrecon -d gcp-public-data.test --keywords gcp-public-data-landsat --no-ct --no-subfinder --no-amass --no-search --no-s3 --no-azure --no-takeover -o gcs_report.json
```

Azure direct probe check:

```bash
uv run python -c "import subrecon; print(subrecon.check_single_azure_blob_container('azureopendatastorage','nyctlc',10))"
```

## 5. Interpret Reliability

- `source_health.<module>.status=ok`: source path succeeded.
- `ok_no_results`: source worked but found nothing.
- `partial` or `error`: reliability degraded; treat negative results as inconclusive for that source and rerun after reviewing `error_types`, `error_samples`, and `notes`.

## 6. Next

- Use [docs/TRIAGE.md](TRIAGE.md) to triage findings by type.
- Use [docs/TESTING.md](TESTING.md) for deterministic and live validation commands.
