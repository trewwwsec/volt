# subrecon

`subrecon` is a passive perimeter intelligence scanner for domains/organizations.

It is designed for legal-safe OSINT workflows: no port scanning, no exploitation, no object retrieval.

## What It Does (Passive Only)

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
- Generates likely S3 bucket names from organization/domain signals and checks bucket endpoints with `HEAD` plus automatic list-probe fallback (`ListObjectsV2` with `max-keys=0`) for ambiguous responses
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

## Requirements

- Python 3.10+
- Optional (for broader passive subdomain coverage):
  - `subfinder`
  - `amass`

## Development (uv)

- Run the CLI:
  - `uv run python subrecon.py -d example.com -o perimeter_report.json`
- Run tests:
  - `uv run python -m unittest discover -s tests -p "test_*.py"`

## Codex Setup

This repo includes a Codex conversion workflow inspired by `everything-claude-code`.

- Shell command:
  - `./codex-setup --dry-run`
  - `./codex-setup`
- Python entrypoint:
  - `uv run python codex_setup.py --dry-run`
  - `uv run python codex_setup.py`

What it writes:
- `.codex/config.toml` (Codex baseline config, no MCP server blocks by default)
- `.codex/AGENTS.md` (Codex-specific instructions)
- `.codex/prompts/*.md` (converted command prompts, including `/codex-setup`)
- `.codex/conversion-manifest.json` (conversion summary)

Slash command source:
- `commands/codex-setup.md`

Roadmap: [docs/ROADMAP.md](docs/ROADMAP.md)
Testing: [docs/TESTING.md](docs/TESTING.md)

## Usage

### Quick start (recommended defaults)

```bash
uv run python subrecon.py -d example.com -o perimeter_report.json
```

### S3-focused check (high signal)

```bash
uv run python subrecon.py -d example.com --keywords noaa-goes19 --no-ct --no-search --no-subfinder --no-amass -o s3_report.json
```

### Search-only check using Common Crawl

```bash
uv run python subrecon.py -d example.com --search-providers commoncrawl --no-ct --no-subfinder --no-amass --no-s3 -o search_report.json
```

### Single domain

```bash
uv run python subrecon.py -d example.com -o perimeter_report.json
```

### Domain list

```bash
uv run python subrecon.py -dL domains.txt -o perimeter_report.json
```

### Add org context for better bucket-name intelligence

```bash
uv run python subrecon.py -d example.com --organization "Acme Corp" --keywords acme,acmepay,acme-dev
```

### Disable modules

```bash
uv run python subrecon.py -d example.com --no-search --no-s3
```

## CLI

```text
-d, --domain           Single root domain
-dL, --domain-list     File with root domains
-o, --output           Output JSON file (default: perimeter_report.json)
--organization         Organization name for better bucket candidate generation
--keywords             Comma-separated org/brand keywords
--search-providers     Comma-separated search providers (default: bing,commoncrawl)
--timeout              HTTP timeout seconds (default: 10)
--tool-timeout         Timeout for subfinder/amass runs (default: 300)
-t, --threads          Concurrent worker threads (default: 20)
-v, --verbose          Verbose mode
--max-bucket-candidates Max S3 names to check (default: 800)
--s3-list-probe        Enable anonymous ListObjectsV2 fallback probes (default: enabled)
--no-s3-list-probe     Disable anonymous ListObjectsV2 fallback probes
--no-ct                Disable CT log collection
--no-subfinder         Disable passive subdomain collection via subfinder
--no-amass             Disable passive subdomain collection via amass
--no-search            Disable search-index dorking
--no-s3                Disable S3 bucket checks
```

## Search Providers

- `bing`: HTML search parsing for dork-like queries.
- `commoncrawl`: Common Crawl index queries.
- Recommended stable setting for MVP use: `--search-providers commoncrawl`

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

Common status values:

- `ok`
- `ok_no_results`
- `partial`
- `error`
- `disabled`
- `skipped_tool_missing`

A finding includes:

- `asset_type` (`subdomain`, `indexed_leak`, `s3_bucket`)
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
- Passive-source tools depend on network reachability and source/provider availability.
- If S3 checks return `0` with an "ambiguous responses" note, AWS `HeadBucket` responses were inconclusive (generic `400/403/404` without enough signal). The tool automatically attempts an anonymous `ListObjectsV2` fallback probe (`max-keys=0`).
- Use `--no-s3-list-probe` only if you need strict HEAD-only behavior.
- If search findings are unexpectedly empty, run with `--search-providers commoncrawl` and check `source_health.search` in the report.
