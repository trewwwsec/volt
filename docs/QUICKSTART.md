# Quickstart

This guide gets a first successful `volt` run with a minimal, repeatable workflow.

## 1. Install

Using `uv tool`:

```bash
uv tool install --from . volt
volt --version
volt --help
```

Using `pipx`:

```bash
pipx install .
volt --version
volt --help
```

## 2. Run a First Scan

```bash
volt -d example.com -o perimeter_report.json
```

## 3. Review the Result

Check the summary and source reliability:

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

## 4. Run a Focused Validation Pass

S3:

```bash
S3_CANARY="$(uv run python scripts/select_s3_canary.py || true)"
S3_TARGET="${S3_CANARY:-volt-negative-s3-$(date +%s)}"
volt -d "${S3_TARGET}.test" --keywords "$S3_TARGET" --s3-website-probe --no-ct --no-subfinder --no-amass --no-search --no-gcp --no-azure --no-takeover -o s3_report.json
```

GCS:

```bash
volt -d gcp-public-data.test --keywords gcp-public-data-landsat --no-ct --no-subfinder --no-amass --no-search --no-s3 --no-azure --no-takeover -o gcs_report.json
```

Azure Blob:

```bash
uv run python -c "import volt; print(volt.check_single_azure_blob_container('azureopendatastorage','nyctlc',10))"
```

## 5. Interpret Reliability

- `source_health.<module>.status=ok`: source path succeeded.
- `ok_no_results`: source worked but found nothing.
- `partial` or `error`: coverage degraded. Review `error_types`, `error_samples`, and `notes` before treating a negative result as meaningful.

## 6. Next

- Use [docs/TRIAGE.md](TRIAGE.md) to triage findings by type.
- Use [docs/TESTING.md](TESTING.md) for deterministic and live validation commands.
