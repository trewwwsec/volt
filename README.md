# subrecon

`subrecon` is a low-touch perimeter intelligence scanner for domains/organizations.

It is designed for legal-safe OSINT workflows: no port scanning, no exploitation, and no authenticated access attempts.

## What It Does

- Discovers subdomains from public Certificate Transparency records (`crt.sh`)
- Optionally enriches passive subdomain coverage with:
  - `subfinder` (passive sources)
  - `amass enum -passive`
- Uses source provenance from `subfinder`/`amass` structured output to score confidence on discovered subdomains
- Runs search-index dorks via pluggable providers (`bing`, `commoncrawl`) for indexed leak indicators such as:
  - `.env`
  - SQL dumps
  - backup/archive artifacts
  - `.git/config`
- Generates likely cloud storage names from organization/domain signals and checks:
  - AWS S3 bucket endpoints with strict AWS name validation, `HEAD` plus automatic region-aware list-probe fallback (`ListObjectsV2` with `max-keys=0`) for ambiguous responses, and optional website-endpoint probes
  - Google Cloud Storage (GCS) bucket endpoints with `HEAD` plus list probe fallback
  - Azure Blob containers inferred from discovered-host CNAMEs (`*.blob.core.windows.net`) with anonymous list probes
- Checks discovered subdomains for takeover signals using CNAME provider matching plus landing-page fingerprint validation
- Produces a product-style JSON report with:
  - finding severity
  - confidence
  - evidence
  - summary counts by severity and type

## What It Does Not Do

- No active port scanning (`nmap`, `naabu`, etc.)
- No exploit attempts
- No login attempts
- No S3 object download
- No Google Cloud Storage (GCS) object download
- No Azure Blob object download
- No deep content crawling

## Requirements

- Python 3.10+
- `uv` (recommended)
- Optional (for broader passive subdomain coverage):
  - `subfinder`
  - `amass`

## Install (CLI)

Install from this repository with `uv tool`:

```bash
uv tool install --from . subrecon
subrecon --help
subrecon --version
```

Install with `pipx`:

```bash
pipx install .
subrecon --help
subrecon --version
```

Script-first usage (`uv run python subrecon.py ...`) remains supported for compatibility, but command-first usage is now the default operator path.

## Development (uv)

- Run the CLI:
  - `uv run subrecon -d example.com -o perimeter_report.json`
- Run tests:
  - `uv run python -m unittest discover -s tests -p "test_*.py"`
- Run lint:
  - `uv run ruff check .`
- Check formatting:
  - `uv run ruff format --check .`

Roadmap: [docs/ROADMAP.md](docs/ROADMAP.md)
Quickstart: [docs/QUICKSTART.md](docs/QUICKSTART.md)
Triage playbook: [docs/TRIAGE.md](docs/TRIAGE.md)
Pilot runbook: [docs/PILOT_RUNBOOK.md](docs/PILOT_RUNBOOK.md)
Pilot log template: [docs/PILOT_LOG_TEMPLATE.md](docs/PILOT_LOG_TEMPLATE.md)
Latest pilot log sample: [docs/PILOT_LOG_2026-03-22.md](docs/PILOT_LOG_2026-03-22.md)
Pilot test script: `scripts/run_pilot_test.sh`
Testing: [docs/TESTING.md](docs/TESTING.md)
Release process: [docs/RELEASE.md](docs/RELEASE.md)
Changelog: [CHANGELOG.md](CHANGELOG.md)
Security policy: [SECURITY.md](SECURITY.md)
Support policy: [SUPPORT.md](SUPPORT.md)
Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
CI: `.github/workflows/ci.yml` (`push`/`pull_request`)
Live smoke CI: `.github/workflows/live-smoke.yml` (`schedule`/`workflow_dispatch`, non-blocking)

## Usage

### Quick start (recommended defaults)

```bash
uv run subrecon -d example.com -o perimeter_report.json
```

### S3-focused check (high signal)

```bash
S3_CANARY="$(uv run python scripts/select_s3_canary.py || true)"
S3_TARGET="${S3_CANARY:-subrecon-negative-s3-$(date +%s)}"
uv run subrecon -d "${S3_TARGET}.test" --keywords "$S3_TARGET" --s3-website-probe --no-ct --no-search --no-subfinder --no-amass --no-gcp --no-azure -o s3_report.json
```

### Takeover-focused check

```bash
uv run subrecon -d example.com --no-search --no-s3 --no-gcp --no-azure -o takeover_report.json
```

### Search-only check using Common Crawl

```bash
uv run subrecon -d example.com --search-providers commoncrawl --no-ct --no-subfinder --no-amass --no-s3 --no-gcp --no-azure -o search_report.json
```

### Single domain

```bash
uv run subrecon -d example.com -o perimeter_report.json
```

### Domain list

```bash
uv run subrecon -dL domains.txt -o perimeter_report.json
```

### Add org context for better bucket-name intelligence

```bash
uv run subrecon -d example.com --organization "Acme Corp" --keywords acme,acmepay,acme-dev
```

### Disable modules

```bash
uv run subrecon -d example.com --no-search --no-s3
```

## CLI

```text
-d, --domain           Single root domain
-dL, --domain-list     File with root domains
-o, --output           Output JSON file (default: perimeter_report.json)
--version              Show installed subrecon version and exit
--organization         Organization name for better bucket candidate generation
--keywords             Comma-separated org/brand keywords
--search-providers     Comma-separated search providers (default: commoncrawl; optional: bing)
--timeout              HTTP timeout seconds (default: 10)
--tool-timeout         Timeout for subfinder/amass runs (default: 120)
-t, --threads          Concurrent worker threads (default: 20)
-v, --verbose          Verbose mode
--max-bucket-candidates Max cloud storage names to check per module (default: 300)
--s3-list-probe        Enable anonymous ListObjectsV2 fallback probes (default: enabled)
--no-s3-list-probe     Disable anonymous ListObjectsV2 fallback probes
--s3-website-probe     Enable optional S3 static website endpoint probe (default: disabled)
--s3-probe-retries     Extra retry budget for S3 probes (choices: 0 or 1, default: 0)
--gcp-dual-endpoint-probe Enable optional GCS virtual-hosted endpoint fallback probe
--gcp-probe-retries    Extra retry budget for GCS probes (choices: 0 or 1, default: 0)
--no-ct                Disable CT log collection
--no-subfinder         Disable passive subdomain collection via subfinder
--no-amass             Disable passive subdomain collection via amass
--no-search            Disable search-index dorking
--no-s3                Disable S3 bucket checks
--no-gcp               Disable GCP bucket checks
--no-azure             Disable Azure Blob container checks
--azure-object-probe   Enable optional Azure blob-object probes when list access is denied
--azure-probe-retries  Extra retry budget for Azure probes (choices: 0 or 1, default: 0)
--no-takeover          Disable passive subdomain takeover fingerprint checks
```

## Search Providers

- `commoncrawl` (default): Common Crawl index queries with deterministic parsing behavior.
- `bing` (optional / best-effort): HTML search parsing for dork-like queries that can drift with markup/rate limits.
- To opt into both providers: `--search-providers commoncrawl,bing`

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

When any source finishes in `partial` or `error`, `subrecon` now prints a deterministic end-of-run reliability warning block and includes `operator_action:` guidance notes in that source's `source_health.notes` field.

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

## Legal + Operational Notes

- Run only against domains/orgs you are authorized to monitor.
- Search-index findings are indicators, not proof of current exposure.
- Validate critical findings inside an approved internal security workflow.

## Troubleshooting

- If `subfinder`/`amass` return `0` hosts, increase `--tool-timeout` (for example `--tool-timeout 600`).
- If `amass` reports `flag provided but not defined: -src` or `-json`, subrecon now retries in compatibility mode (without `-src`, then plain passive output parsing as needed); source-level provenance confidence may be reduced until amass is upgraded.
- Passive-source tools depend on network reachability and source/provider availability.
- HTTP retry behavior is conservative and source-specific (CT/search retry, takeover lighter retry, cloud probe checks remain no-retry by default).
- If S3 checks return `0` with an "ambiguous responses" note, AWS `HeadBucket` responses were inconclusive (generic `400/403/404` without enough signal). The tool automatically attempts an anonymous `ListObjectsV2` fallback probe (`max-keys=0`).
- Use `--no-s3-list-probe` only if you need strict HEAD-only behavior.
- Use `--s3-website-probe` if you want additional static-site exposure signal (`s3-website-<region>` endpoints).
- Use `--s3-probe-retries 1` in unstable environments; default remains `0` for low-noise behavior.
- Use `--gcp-dual-endpoint-probe` for optional fallback probing on `<bucket>.storage.googleapis.com` when path-style responses are ambiguous.
- Use `--gcp-probe-retries 1` in unstable environments; default remains `0` for conservative behavior.
- If search findings are unexpectedly empty, run with `--search-providers commoncrawl` and check `source_health.search` in the report.
- GCP bucket findings are heuristic (`200` strong signal, `403` likely-exists signal); treat low-severity bucket existence as triage leads.
- Azure Blob findings currently report high-signal anonymous listability only (`HTTP 200` on list probes); `source_health.azure` still tracks inferred accounts/probe counts when no findings are returned.
- Takeover findings are signal-based; treat edge-case fingerprints as triage leads and verify ownership/claimability in an authorized workflow.
