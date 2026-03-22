# subrecon

`subrecon` is now a passive perimeter intelligence scanner for domains/organizations.

It is designed for legal-safe OSINT workflows: no port scanning, no exploitation, no object retrieval.

## What It Does (Passive Only)

- Discovers subdomains from public Certificate Transparency records (`crt.sh`)
- Optionally enriches passive subdomain coverage with:
  - `subfinder` (passive sources)
  - `amass enum -passive`
- Runs search-index dorks (Bing) for indexed leak indicators such as:
  - `.env`
  - SQL dumps
  - backup/archive artifacts
  - `.git/config`
- Generates likely S3 bucket names from organization/domain signals and checks bucket endpoint status with `HEAD` requests only
- Produces a product-style JSON report with:
  - finding severity
  - confidence
  - evidence
  - summary counts by severity and type

## What It Does Not Do

- No active port scanning (`nmap`, `naabu`, etc.)
- No exploit attempts
- No login attempts
- No S3 object download/listing

## Requirements

- Python 3.10+
- Optional (for broader passive subdomain coverage):
  - `subfinder`
  - `amass`

## Usage

### Single domain

```bash
python3 subrecon.py -d example.com -o perimeter_report.json
```

### Domain list

```bash
python3 subrecon.py -dL domains.txt -o perimeter_report.json
```

### Add org context for better bucket-name intelligence

```bash
python3 subrecon.py -d example.com --organization "Acme Corp" --keywords acme,acmepay,acme-dev
```

### Disable modules

```bash
python3 subrecon.py -d example.com --no-search --no-s3
```

## CLI

```text
-d, --domain           Single root domain
-dL, --domain-list     File with root domains
-o, --output           Output JSON file (default: perimeter_report.json)
--organization         Organization name for better bucket candidate generation
--keywords             Comma-separated org/brand keywords
--timeout              HTTP timeout seconds (default: 10)
-t, --threads          Concurrent worker threads (default: 20)
-v, --verbose          Verbose mode
--max-bucket-candidates Max S3 names to check (default: 800)
--no-ct                Disable CT log collection
--no-subfinder         Disable passive subdomain collection via subfinder
--no-amass             Disable passive subdomain collection via amass
--no-search            Disable search-index dorking
--no-s3                Disable S3 bucket checks
```

## Output Shape

Top-level report fields:

- `generated_at`
- `mode` (`passive_osint`)
- `targets`
- `organization`
- `legal`
- `inventory`
- `summary`
- `findings`

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
