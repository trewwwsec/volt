# volt

`volt` is a lightweight Attack Surface Management (ASM) CLI for passive perimeter intelligence.

It helps security teams discover internet-facing assets and exposure signals from public data sources without crossing into active scanning or intrusive validation. `volt` is designed for authorized monitoring workflows where low-touch collection, transparent evidence, and predictable output matter more than raw breadth.

Documentation:

- Quickstart: [docs/QUICKSTART.md](docs/QUICKSTART.md)
- Testing: [docs/TESTING.md](docs/TESTING.md)
- Triage playbook: [docs/TRIAGE.md](docs/TRIAGE.md)
- Release process: [docs/RELEASE.md](docs/RELEASE.md)
- Roadmap: [docs/ROADMAP.md](docs/ROADMAP.md)
- Security policy: [SECURITY.md](SECURITY.md)
- Support policy: [SUPPORT.md](SUPPORT.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)

## What Volt Does

- Discovers subdomains from Certificate Transparency data, with optional passive enrichment from `subfinder` and `amass`.
- Searches public indexes for high-signal leak indicators such as `.env`, SQL dumps, backups, and exposed `.git` metadata.
- Generates and probes likely AWS S3, Google Cloud Storage, and Azure Blob names using anonymous, passive-safe checks.
- Flags potential subdomain takeover conditions using CNAME/provider correlation and response fingerprinting.
- Produces structured JSON output with findings, severity, confidence, evidence, and per-source reliability telemetry.

## What Volt Does Not Do

- No active port scanning.
- No exploitation or payload delivery.
- No login attempts.
- No authenticated cloud access.
- No object download from S3, GCS, or Azure Blob.
- No deep crawling or recursive web scraping.

## Install

Requirements:

- Python 3.10+
- `uv` recommended, or `pipx`
- Optional for broader passive subdomain coverage: `subfinder`, `amass`

Install with `uv tool`:

```bash
uv tool install --from . volt
volt --version
volt --help
```

Install with `pipx`:

```bash
pipx install .
volt --version
volt --help
```

For local development, `uv run python volt.py ...` remains supported, but `volt ...` is the primary operator path.

## Quick Start

Run a first scan:

```bash
volt -d example.com -o perimeter_report.json
```

Run a focused S3 validation:

```bash
S3_CANARY="$(uv run python scripts/select_s3_canary.py || true)"
S3_TARGET="${S3_CANARY:-volt-negative-s3-$(date +%s)}"
volt -d "${S3_TARGET}.test" --keywords "$S3_TARGET" --s3-website-probe --no-ct --no-search --no-subfinder --no-amass --no-gcp --no-azure -o s3_report.json
```

Run a search-only pass with the default provider:

```bash
volt -d example.com --search-providers commoncrawl --no-ct --no-subfinder --no-amass --no-s3 --no-gcp --no-azure -o search_report.json
```

## Core CLI Options

```text
-d, --domain             Single root domain
-dL, --domain-list       File with root domains
-o, --output             Output JSON file (default: perimeter_report.json)
--version                Show installed volt version and exit
--organization           Organization name for candidate generation
--keywords               Comma-separated org or brand keywords
--search-providers       Search providers (default: commoncrawl; optional: bing)
--timeout                HTTP timeout in seconds (default: 10)
--tool-timeout           Timeout for subfinder/amass in seconds (default: 120)
-t, --threads            Concurrent worker threads (default: 20)
--max-bucket-candidates  Max cloud storage names to test per module (default: 300)
--s3-website-probe       Enable optional S3 website endpoint probing
--gcp-dual-endpoint-probe Enable optional GCS virtual-hosted fallback probing
--azure-object-probe     Enable optional Azure blob-object probes
--no-ct                  Disable CT collection
--no-subfinder           Disable subfinder
--no-amass               Disable amass
--no-search              Disable search-index checks
--no-s3                  Disable S3 checks
--no-gcp                 Disable GCS checks
--no-azure               Disable Azure Blob checks
--no-takeover            Disable takeover checks
```

## Output Shape

Top-level report fields:

- `generated_at`
- `mode` (`passive_osint`)
- `targets`
- `organization`
- `legal`
- `inventory`
- `source_health`
- `summary`
- `findings`

`source_health` tracks module reliability for the run (status, queries, errors, timeouts, and counts). Use this to distinguish "no findings" from "source unavailable/partial".

When any source finishes in `partial` or `error`, `volt` now prints a deterministic end-of-run reliability warning block and includes `operator_action:` guidance notes in that source's `source_health.notes` field.

Common status values:

- `ok`
- `ok_no_results`
- `ok_no_candidates`
- `partial`
- `error`
- `disabled`
- `skipped_tool_missing`

A finding includes:

- `asset_type` (`subdomain`, `indexed_leak`, `s3_bucket`, `gcp_bucket`, `azure_blob_container`, `subdomain_takeover`)
- `asset`
- `severity`
- `confidence`
- `title`
- `description`
- `source`
- `tags`
- `evidence`

## Reliability and Triage

`volt` reports per-source reliability in `source_health`. Use it to distinguish a clean negative result from a degraded run caused by upstream outages, timeouts, or parsing drift.

Interpretation:

- `ok`: source completed successfully
- `ok_no_results`: source ran successfully and found nothing
- `partial`: source produced some value but coverage was degraded
- `error`: source failed for this run, including deterministic local tool startup failures detected during preflight

Search-index results, bucket existence signals, and takeover fingerprints should be treated as triage leads until verified in an authorized workflow.

## Development

Common local commands:

```bash
uv run ruff check .
uv run ruff format --check .
python -m compileall -q volt.py cli.py constants.py core.py models.py networking.py parsing.py reporting.py volt_models.py volt_reporting.py sources tests
python -m unittest discover -s tests -p "test_*.py"
```
