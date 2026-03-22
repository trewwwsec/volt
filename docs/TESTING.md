# Testing

This project uses deterministic tests first, then optional live smoke checks.

## Automated Gate

Run all tests:

```bash
uv run python -m unittest discover -s tests -p "test_*.py"
```

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
uv run python subrecon.py -d example.com --no-search --no-s3 --no-subfinder --no-amass -o /tmp/subrecon_ct_smoke.json
uv run python subrecon.py -d example.com --no-ct --no-search --no-subfinder --no-amass -o /tmp/subrecon_s3_smoke.json
uv run python subrecon.py -d example.com --no-search --no-s3 --no-ct -o /tmp/subrecon_takeover_smoke.json
```

## Notes

- External tools (`subfinder`, `amass`) and live data sources can be flaky.
- A passing automated gate means core logic is stable; live source behavior still depends on upstream services.
