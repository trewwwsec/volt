# Testing

This project uses deterministic tests first, then optional live smoke checks.

## Automated Gate

Run all tests:

```bash
uv run python -m unittest discover -s tests -p "test_*.py"
```

Current baseline (March 22, 2026): `70` tests passing.

CI gate:

- GitHub Actions workflow: `.github/workflows/ci.yml`
- Trigger: `push` and `pull_request`
- Lint: `uv run ruff check .`
- Format check: `uv run ruff format --check .`
- Static check: `uv run python -m compileall -q subrecon.py cli.py constants.py core.py models.py networking.py parsing.py reporting.py subrecon_models.py subrecon_reporting.py sources tests`
- Test command: `uv run python -m unittest discover -s tests -p "test_*.py"`

Current suite covers:

- Domain parsing and normalization
- Keyword parsing
- Search provider parsing/validation (`bing`, `commoncrawl`)
- Finding deduplication and severity ordering
- Subfinder/amass structured provenance parsing and confidence scoring
- Amass compatibility fallback paths (`-src` -> no-`-src`, `-json` -> plain-output parsing)
- Bing and Common Crawl search parsing paths and leak classification
- CT JSON parsing path
- S3 `HEAD` + fallback `ListObjectsV2` classification path
- Azure Blob CNAME/account inference + anonymous list-probe classification path
- Subdomain takeover CNAME/fingerprint detection path
- HTTP retry/backoff behavior for transient fetch failures
- Source-specific retry policy wiring (CT/search/takeover vs cloud probes)
- Edge-case parsing behavior (Common Crawl index/id fallback, S3/Azure error-code extraction fallback, and URL de-duplication)
- Partial-failure source health transitions (`partial`/`error`) for CT, takeover, S3, and Azure paths
- Source-health report block generation
- Structured source-health error telemetry (`error_types`, `error_samples`) and normalization
- `run_scan` orchestration with mocked source modules
- Command runner success/timeout behavior

## Partial-Failure Simulation (Deterministic)

Use targeted tests to validate reliability state transitions without external dependencies:

```bash
uv run python -m unittest tests.test_subrecon_pipeline.SubreconPipelineTest.test_collect_ct_subdomains_partial_when_some_domains_fail
uv run python -m unittest tests.test_subrecon_pipeline.SubreconPipelineTest.test_collect_search_index_findings_commoncrawl_index_failure_sets_error
uv run python -m unittest tests.test_subrecon_pipeline.SubreconPipelineTest.test_collect_s3_bucket_findings_error_when_all_checks_fail
uv run python -m unittest tests.test_subrecon_pipeline.SubreconPipelineTest.test_collect_azure_blob_findings_partial_when_doh_errors
uv run python -m unittest tests.test_subrecon_pipeline.SubreconPipelineTest.test_collect_subdomain_takeover_findings_partial_on_probe_error
```

## Live Smoke Checks (Optional)

These rely on network and external source availability:

```bash
# CT only
uv run python subrecon.py -d example.com --no-search --no-s3 --no-gcp --no-azure --no-subfinder --no-amass -o /tmp/subrecon_ct_smoke.json

# Search only (stable MVP provider)
uv run python subrecon.py -d example.com --search-providers commoncrawl --no-ct --no-subfinder --no-amass --no-s3 --no-gcp --no-azure --no-takeover -o /tmp/subrecon_search_smoke.json

# S3 only (known public bucket signal)
uv run python subrecon.py -d noaa-goes19.test --keywords noaa-goes19 --no-ct --no-subfinder --no-amass --no-search --no-gcp --no-azure --no-takeover -o /tmp/subrecon_s3_smoke.json

# GCP bucket only (existence/listability signal)
uv run python subrecon.py -d gcp-public-data.test --keywords gcp-public-data-landsat --no-ct --no-subfinder --no-amass --no-search --no-s3 --no-azure --no-takeover -o /tmp/subrecon_gcp_smoke.json

# Azure Blob probe check (public container target)
uv run python -c "import subrecon; print(subrecon.check_single_azure_blob_container('azureopendatastorage','nyctlc',10))"

# Takeover path (inventory + takeover only)
uv run python subrecon.py -d example.com --no-search --no-s3 --no-gcp --no-azure --no-ct -o /tmp/subrecon_takeover_smoke.json

# Subfinder only
uv run python subrecon.py -d example.com --no-ct --no-amass --no-search --no-s3 --no-gcp --no-azure --no-takeover -o /tmp/subrecon_subfinder_smoke.json

# Amass only
uv run python subrecon.py -d example.com --no-ct --no-subfinder --no-search --no-s3 --no-gcp --no-azure --no-takeover -o /tmp/subrecon_amass_smoke.json
```

### Latest Smoke Snapshot (March 22, 2026)

Environment: local macOS runner, passive internet-reachable execution.

- CT-only (`/tmp/subrecon_ct_smoke.json`): `source_health.ct.status=ok`, `summary.total_findings=6`
- Search-only Common Crawl (`/tmp/subrecon_search_smoke.json`): `source_health.search.status=partial`, `summary.total_findings=4`
- S3-only (`/tmp/subrecon_s3_smoke.json`): `source_health.s3.status=ok`, `s3.ambiguous=0`, `summary.total_findings=1` (`noaa-goes19`)
- GCP-only (`/tmp/subrecon_gcp_smoke.json`): `source_health.gcp.status=ok`, `summary.total_findings=2`
- Azure direct probe (`check_single_azure_blob_container`): `status=200`, `existence=confirmed_public` on `azureopendatastorage/nyctlc`
- Takeover-focused (`/tmp/subrecon_takeover_smoke.json`): run as CT+takeover (`--no-subfinder --no-amass`) to keep runtime bounded; `source_health.takeover.status=ok_no_results`, `summary.total_findings=6` (CT inventory findings)

## Rigorous Live Matrix (Bounded E2E)

Use this matrix for a higher-confidence live validation while keeping runtime bounded.

```bash
# Core end-to-end path (all passive HTTP sources + takeover, no external tools)
uv run python subrecon.py -d iana.org --no-subfinder --no-amass -o /tmp/subrecon_live3_core_e2e_iana.json

# CT only
uv run python subrecon.py -d iana.org --no-search --no-s3 --no-gcp --no-azure --no-subfinder --no-amass --no-takeover -o /tmp/subrecon_live3_ct_only_iana.json

# Search only (Common Crawl)
uv run python subrecon.py -d iana.org --search-providers commoncrawl --no-ct --no-subfinder --no-amass --no-s3 --no-gcp --no-azure --no-takeover -o /tmp/subrecon_live3_search_only_iana.json

# S3 only
uv run python subrecon.py -d noaa-goes19.test --keywords noaa-goes19 --no-ct --no-subfinder --no-amass --no-search --no-gcp --no-azure --no-takeover -o /tmp/subrecon_live3_s3_only.json

# GCP only
uv run python subrecon.py -d gcp-public-data.test --keywords gcp-public-data-landsat --no-ct --no-subfinder --no-amass --no-search --no-s3 --no-azure --no-takeover -o /tmp/subrecon_live3_gcp_only.json

# Takeover + CT inventory
uv run python subrecon.py -d iana.org --no-search --no-s3 --no-gcp --no-azure --no-subfinder --no-amass -o /tmp/subrecon_live3_takeover_ct_iana.json

# Subfinder only
uv run python subrecon.py -d iana.org --no-ct --no-amass --no-search --no-s3 --no-gcp --no-azure --no-takeover -o /tmp/subrecon_live3_subfinder_only_iana.json

# Amass only
uv run python subrecon.py -d iana.org --no-ct --no-subfinder --no-search --no-s3 --no-gcp --no-azure --no-takeover -o /tmp/subrecon_live3_amass_only_iana.json

# Azure direct probe
uv run python -c "import subrecon; print(subrecon.check_single_azure_blob_container('azureopendatastorage','nyctlc',10))"
```

### Latest Rigorous Matrix Snapshot (March 22, 2026)

Environment: local macOS runner, passive internet-reachable execution.

- Core E2E (`/tmp/subrecon_live3_core_e2e_iana.json`): `source_health.ct=ok`, `search=partial`, `s3=ok`, `gcp=ok`, `azure=ok_no_results`, `takeover=ok_no_results`, `summary.total_findings=78`
- CT-only (`/tmp/subrecon_live3_ct_only_iana.json`): `source_health.ct=error`, `error_types.http_0=1`, `summary.total_findings=0` (transient upstream/network failure)
- Search-only Common Crawl (`/tmp/subrecon_live3_search_only_iana.json`): `source_health.search=partial`, `error_types.commoncrawl_http_404=3`, `summary.total_findings=16`
- S3-only (`/tmp/subrecon_live3_s3_only.json`): `source_health.s3=ok`, `summary.total_findings=1`
- GCP-only (`/tmp/subrecon_live3_gcp_only.json`): `source_health.gcp=ok`, `summary.total_findings=2`
- Takeover+CT (`/tmp/subrecon_live3_takeover_ct_iana.json`): `ct=ok`, `takeover=ok_no_results`, `summary.total_findings=21`
- Subfinder-only (`/tmp/subrecon_live3_subfinder_only_iana.json`): `source_health.subfinder=ok`, `summary.total_findings=65`
- Amass-only (`/tmp/subrecon_live3_amass_only_iana.json`): `source_health.amass=error`, `timeouts=1`, `error_types.amass_timeout=1`, `summary.total_findings=0`
- Azure direct probe: `status=200`, `existence=confirmed_public` on `azureopendatastorage/nyctlc`

## Notes

- External tools (`subfinder`, `amass`) and live data sources can be flaky.
- Some amass versions do not support `-src`/`-json`; subrecon now auto-falls back to compatible amass modes, but source provenance detail may be reduced.
- A passing automated gate means core logic is stable; live source behavior still depends on upstream services.
