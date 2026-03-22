# Testing

This project uses deterministic tests first, then optional live smoke checks.

## Automated Gate

Run all tests:

```bash
uv run python -m unittest discover -s tests -p "test_*.py"
```

Current baseline (March 22, 2026): `37` tests passing.

Current suite covers:

- Domain parsing and normalization
- Keyword parsing
- Search provider parsing/validation (`bing`, `commoncrawl`)
- Finding deduplication and severity ordering
- Subfinder/amass structured provenance parsing and confidence scoring
- Bing and Common Crawl search parsing paths and leak classification
- CT JSON parsing path
- S3 `HEAD` + fallback `ListObjectsV2` classification path
- Subdomain takeover CNAME/fingerprint detection path
- Source-health report block generation
- `run_scan` orchestration with mocked source modules
- Command runner success/timeout behavior

## Live Smoke Checks (Optional)

These rely on network and external source availability:

```bash
# CT only
uv run python subrecon.py -d example.com --no-search --no-s3 --no-subfinder --no-amass -o /tmp/subrecon_ct_smoke.json

# Search only (stable MVP provider)
uv run python subrecon.py -d example.com --search-providers commoncrawl --no-ct --no-subfinder --no-amass --no-s3 --no-takeover -o /tmp/subrecon_search_smoke.json

# S3 only (known public bucket signal)
uv run python subrecon.py -d noaa-goes19.test --keywords noaa-goes19 --no-ct --no-subfinder --no-amass --no-search --no-takeover -o /tmp/subrecon_s3_smoke.json

# Takeover path (inventory + takeover only)
uv run python subrecon.py -d example.com --no-search --no-s3 --no-ct -o /tmp/subrecon_takeover_smoke.json

# Subfinder only
uv run python subrecon.py -d example.com --no-ct --no-amass --no-search --no-s3 --no-takeover -o /tmp/subrecon_subfinder_smoke.json

# Amass only
uv run python subrecon.py -d example.com --no-ct --no-subfinder --no-search --no-s3 --no-takeover -o /tmp/subrecon_amass_smoke.json
```

## Notes

- External tools (`subfinder`, `amass`) and live data sources can be flaky.
- Some amass versions fail with `flag provided but not defined: -src`; if so, skip amass smoke (`--no-amass`) until compatibility fallback is added.
- A passing automated gate means core logic is stable; live source behavior still depends on upstream services.
