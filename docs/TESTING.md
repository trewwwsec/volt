# Testing

This project uses deterministic tests first, then optional live smoke checks.

## Deterministic Gate

Primary commands:

```bash
uv run ruff check .
uv run ruff format --check .
python -m compileall -q volt.py cli.py constants.py core.py models.py networking.py parsing.py reporting.py volt_models.py volt_reporting.py sources tests
python -m unittest discover -s tests -p "test_*.py"
```

Current baseline: `115` tests passing.

If `uv run` is unavailable in a local environment, use direct `python -m ...` commands for deterministic verification.

CI gate:

- GitHub Actions workflow: `.github/workflows/ci.yml`
- Trigger: `push` and `pull_request`
- Lint: `uv run ruff check .`
- Format check: `uv run ruff format --check .`
- Static check: `python -m compileall -q volt.py cli.py constants.py core.py models.py networking.py parsing.py reporting.py volt_models.py volt_reporting.py sources tests`
- Test command: `python -m unittest discover -s tests -p "test_*.py"`
- Separate non-blocking live smoke workflow: `.github/workflows/live-smoke.yml` (`schedule` + `workflow_dispatch`)

Current suite covers:

- Domain parsing and normalization
- Keyword parsing
- Search provider parsing/validation (`bing`, `commoncrawl`)
- Finding deduplication and severity ordering
- Subfinder/amass structured provenance parsing and confidence scoring
- Amass compatibility fallback paths (`-src` -> no-`-src`, `-json` -> plain-output parsing)
- Amass startup-failure preflight (`amass_tool_unhealthy`) for deterministic local execution failures
- Bing and Common Crawl search parsing paths and leak classification
- Common Crawl index-failure fallback to Bing with degraded (`partial`) source-health semantics
- Common Crawl endpoint selection and filter-compatibility fallback behavior (`filter==status:200` with retry fallback)
- CT JSON parsing path
- CT fallback path (`crt.sh` -> Cert Spotter) with degraded (`partial`) source-health semantics
- S3 `HEAD` + fallback `ListObjectsV2` classification path
- S3 candidate validation filtering (reserved/invalid names), region-aware probe wiring, optional website probe path, and probe-retry override
- S3 cloaked-`NoSuchBucket` ambiguity handling + unknown-region website endpoint fallback probing
- GCS candidate validation filtering, domain-style candidate generation, XML error-code classification, second-phase object probe, optional dual-endpoint fallback, and probe-retry override
- Azure Blob CNAME/account inference + endpoint-aware HEAD/list classification path
- Azure Blob optional blob-object probe path and optional probe-retry override
- Subdomain takeover CNAME/fingerprint detection path
- HTTP retry/backoff behavior for transient fetch failures
- Source-specific retry policy wiring (CT/search/takeover vs cloud probes)
- Edge-case parsing behavior (Common Crawl index/id fallback, S3/Azure error-code extraction fallback, and URL de-duplication)
- Partial-failure source health transitions (`partial`/`error`) for CT, takeover, S3, and Azure paths
- Source-health report block generation
- Structured source-health error telemetry (`error_types`, `error_samples`) and normalization
- Deterministic run-scan report fixture regression (`tests/fixtures/run_scan_reference_fixture.json`)
- Upstream drift reliability guards for CT/search parsing and provider exception paths
- `run_scan` orchestration with mocked source modules
- Command runner success/timeout behavior
- Amass timeout retry/fallback reliability transitions (`ok_no_results` and timeout-only `partial`)

## Targeted Reliability Tests

Use targeted tests to validate degraded-state handling without external dependencies:

```bash
python -m unittest tests.test_volt_pipeline.VoltPipelineTest.test_collect_ct_subdomains_partial_when_some_domains_fail
python -m unittest tests.test_volt_pipeline.VoltPipelineTest.test_collect_search_index_findings_commoncrawl_index_failure_sets_error
python -m unittest tests.test_volt_pipeline.VoltPipelineTest.test_collect_s3_bucket_findings_error_when_all_checks_fail
python -m unittest tests.test_volt_pipeline.VoltPipelineTest.test_collect_s3_bucket_findings_partial_when_some_checks_succeed
python -m unittest tests.test_volt_pipeline.VoltPipelineTest.test_collect_azure_blob_findings_partial_when_doh_errors
python -m unittest tests.test_volt_pipeline.VoltPipelineTest.test_collect_subdomain_takeover_findings_partial_on_probe_error
python -m unittest tests.test_volt_pipeline.VoltPipelineTest.test_collect_amass_subdomains_marks_error_when_tool_unhealthy
```

## Live Smoke Checks (Optional)

These rely on network and external source availability. Treat them as smoke validation, not merge gates.

One-command harness:

```bash
scripts/run_pilot_test.sh --mode quick
```

```bash
# CT only
uv run volt -d example.com --no-search --no-s3 --no-gcp --no-azure --no-subfinder --no-amass -o /tmp/volt_ct_smoke.json

# Search only (stable MVP provider)
uv run volt -d example.com --search-providers commoncrawl --no-ct --no-subfinder --no-amass --no-s3 --no-gcp --no-azure --no-takeover -o /tmp/volt_search_smoke.json

# S3 only (auto-select live canary; fallback to deterministic negative control)
S3_CANARY="$(uv run python scripts/select_s3_canary.py || true)"
S3_TARGET="${S3_CANARY:-volt-negative-s3-$(date +%s)}"
uv run volt -d "${S3_TARGET}.test" --keywords "$S3_TARGET" --s3-website-probe --no-ct --no-subfinder --no-amass --no-search --no-gcp --no-azure --no-takeover -o /tmp/volt_s3_smoke.json

# GCS bucket only (existence/listability signal)
uv run volt -d gcp-public-data.test --keywords gcp-public-data-landsat --no-ct --no-subfinder --no-amass --no-search --no-s3 --no-azure --no-takeover -o /tmp/volt_gcp_smoke.json

# Azure Blob probe check (public container target)
uv run python -c "import volt; print(volt.check_single_azure_blob_container('azureopendatastorage','nyctlc',10))"

# Azure Blob probe check with retry override
uv run python -c "import volt; print(volt.check_single_azure_blob_container('azureopendatastorage','nyctlc',10, azure_probe_retries=1))"

# Takeover path (inventory + takeover only)
uv run volt -d example.com --no-search --no-s3 --no-gcp --no-azure --no-ct -o /tmp/volt_takeover_smoke.json

# Subfinder only
uv run volt -d example.com --no-ct --no-amass --no-search --no-s3 --no-gcp --no-azure --no-takeover -o /tmp/volt_subfinder_smoke.json

# Amass only
uv run volt -d example.com --no-ct --no-subfinder --no-search --no-s3 --no-gcp --no-azure --no-takeover -o /tmp/volt_amass_smoke.json
```

### Historical Smoke Snapshot

Environment: local macOS runner, passive internet-reachable execution.
Reference bundle: `/tmp/volt-pilot-20260322-225939` (quick mode).

- Core E2E (`core_e2e_iana.json`): `source_health.ct=ok`, `search=partial`, `s3=ok_no_results`, `gcp=ok`, `azure=ok_no_results`, `takeover=ok_no_results`, `summary.total_findings=56`
- S3-only canary (`s3_only_canary.json`): `source_health.s3=ok`, `summary.total_findings=1`
- GCS-only (`gcs_only_landsat.json`): `source_health.gcp=ok`, `summary.total_findings=2`
- Azure direct probe (`azure_probe_default.txt` + `azure_probe_retry1.txt`): `status=200`, `existence=confirmed_public` on `azureopendatastorage/nyctlc`

## Rigorous Live Matrix (Bounded E2E)

Use this matrix for a higher-confidence live validation while keeping runtime bounded.

```bash
# Core end-to-end path (all passive HTTP sources + takeover, no external tools)
uv run volt -d iana.org --no-subfinder --no-amass -o /tmp/volt_live3_core_e2e_iana.json

# CT only
uv run volt -d iana.org --no-search --no-s3 --no-gcp --no-azure --no-subfinder --no-amass --no-takeover -o /tmp/volt_live3_ct_only_iana.json

# Search only (Common Crawl)
uv run volt -d iana.org --search-providers commoncrawl --no-ct --no-subfinder --no-amass --no-s3 --no-gcp --no-azure --no-takeover -o /tmp/volt_live3_search_only_iana.json

# S3 only (auto-select live canary; fallback to deterministic negative control)
S3_CANARY="$(uv run python scripts/select_s3_canary.py || true)"
S3_TARGET="${S3_CANARY:-volt-negative-s3-$(date +%s)}"
uv run volt -d "${S3_TARGET}.test" --keywords "$S3_TARGET" --s3-website-probe --no-ct --no-subfinder --no-amass --no-search --no-gcp --no-azure --no-takeover -o /tmp/volt_live3_s3_only.json

# GCS only
uv run volt -d gcp-public-data.test --keywords gcp-public-data-landsat --no-ct --no-subfinder --no-amass --no-search --no-s3 --no-azure --no-takeover -o /tmp/volt_live3_gcp_only.json

# Takeover + CT inventory
uv run volt -d iana.org --no-search --no-s3 --no-gcp --no-azure --no-subfinder --no-amass -o /tmp/volt_live3_takeover_ct_iana.json

# Subfinder only
uv run volt -d iana.org --no-ct --no-amass --no-search --no-s3 --no-gcp --no-azure --no-takeover -o /tmp/volt_live3_subfinder_only_iana.json

# Amass only
uv run volt -d iana.org --no-ct --no-subfinder --no-search --no-s3 --no-gcp --no-azure --no-takeover -o /tmp/volt_live3_amass_only_iana.json

# Azure direct probe
uv run python -c "import volt; print(volt.check_single_azure_blob_container('azureopendatastorage','nyctlc',10))"

# Azure direct probe (retry override)
uv run python -c "import volt; print(volt.check_single_azure_blob_container('azureopendatastorage','nyctlc',10, azure_probe_retries=1))"
```

### Historical Rigorous Matrix Snapshot

Environment: local macOS runner, passive internet-reachable execution.
Reference bundle: `/tmp/volt-pilot-20260322-231020` (full mode).

- Core E2E (`core_e2e_iana.json`): `source_health.ct=ok`, `search=error`, `s3=ok_no_results`, `gcp=ok`, `azure=ok_no_results`, `takeover=ok_no_results`, `summary.total_findings=37`
- CT-only (`ct_only_iana.json`): `source_health.ct=ok`, `summary.total_findings=21`
- Search-only Common Crawl (`search_only_iana.json`): `source_health.search=error`, `error_types={bing_challenge_page:5, commoncrawl_index_unavailable:1}`, `summary.total_findings=0`
- S3-only canary (`s3_only_canary.json`): `source_health.s3=ok`, `summary.total_findings=1`
- GCS-only (`gcs_only_landsat.json`): `source_health.gcp=ok`, `summary.total_findings=2`
- Takeover+CT (`takeover_ct_iana.json`): `ct=ok`, `takeover=ok_no_results`, `summary.total_findings=21`
- Subfinder-only (`subfinder_only_iana.json`): `source_health.subfinder=ok`, `summary.total_findings=65`
- Amass-only (`amass_only_iana.json`): `source_health.amass=partial`, `summary.total_findings=0` (`-src`/`-json` unsupported fallback active; plain-output compatibility mode returned no hosts)
- Azure direct probe (`azure_probe_default.txt`, `azure_probe_retry1.txt`): `status=200`, `existence=confirmed_public` on `azureopendatastorage/nyctlc`

Current builds also perform a narrow amass startup preflight. Deterministic local execution failures can report `error` with `error_types.amass_tool_unhealthy`, while timeout-only probe failures are treated as inconclusive and fall back to the normal amass execution path.

### Historical Exegol Validation Snapshot

Environment: Exegol `htb` container with `uv` in-container.

- Amass-only default timeout (`/workspace/tools/volt/tmp_amass_exegol_default.json`): `source_health.amass.status=ok`, `hosts=74`, `timeouts=0`, `errors=0`
- Amass-only forced timeout (`/workspace/tools/volt/tmp_amass_exegol_t1.json`, `--tool-timeout 1`): `source_health.amass.status=partial`, `timeouts=1`, `errors=0`

## Release Baseline Refresh

For each release tag:

1. Run deterministic gate (`unittest`, lint, format, compile checks).
2. Run bounded live smoke matrix (local or CI workflow dispatch).
3. Update baseline test count and latest smoke snapshots in this document.
4. Update `CHANGELOG.md` release entry with notable reliability/source-health changes.

## Notes

- External tools (`subfinder`, `amass`) and live data sources can be flaky.
- Some amass versions do not support `-src`/`-json`; volt now auto-falls back to compatible amass modes, but source provenance detail may be reduced.
- If amass fails deterministically before enumeration can begin, volt marks the source `error` with `error_types.amass_tool_unhealthy` and skips amass execution.
- Timeout-only health probe failures are treated as inconclusive and do not, by themselves, mark amass unhealthy.
- A passing automated gate means core logic is stable; live source behavior still depends on upstream services.
