#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SEARCH_DIR="$SCRIPT_DIR"
REPO_ROOT=""
while [[ "$SEARCH_DIR" != "/" ]]; do
  if [[ -f "$SEARCH_DIR/pyproject.toml" && -f "$SEARCH_DIR/subrecon.py" ]]; then
    REPO_ROOT="$SEARCH_DIR"
    break
  fi
  SEARCH_DIR="$(dirname "$SEARCH_DIR")"
done
if [[ -z "$REPO_ROOT" ]]; then
  echo "[!] could not locate repository root from script path: $SCRIPT_DIR" >&2
  exit 1
fi
cd "$REPO_ROOT"

MODE="quick"
OUT_DIR=""
SKIP_GATES=0
SKIP_LIVE=0

usage() {
  cat <<'EOF'
Usage: scripts/run_pilot_test.sh [options]

Options:
  --mode quick|full      Matrix scope (default: quick)
  --out-dir PATH         Output directory (default: /tmp/subrecon-pilot-<timestamp>)
  --skip-gates           Skip deterministic quality gates
  --skip-live            Skip live matrix execution
  -h, --help             Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="${2:-}"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    --skip-gates)
      SKIP_GATES=1
      shift
      ;;
    --skip-live)
      SKIP_LIVE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[!] unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ "$MODE" != "quick" && "$MODE" != "full" ]]; then
  echo "[!] --mode must be quick or full" >&2
  exit 1
fi

if [[ -z "$OUT_DIR" ]]; then
  OUT_DIR="/tmp/subrecon-pilot-$(date +%Y%m%d-%H%M%S)"
fi
mkdir -p "$OUT_DIR"
export UV_CACHE_DIR="${UV_CACHE_DIR:-$OUT_DIR/.uv-cache}"

echo "[*] pilot test output dir: $OUT_DIR"
echo "[*] mode: $MODE"
echo "[*] uv cache dir: $UV_CACHE_DIR"
echo "[*] repo root: $REPO_ROOT"

if [[ $SKIP_GATES -eq 0 ]]; then
  echo "[*] running deterministic quality gates..."
  uv run ruff check .
  uv run ruff format --check .
  uv run python -m compileall -q \
    subrecon.py cli.py constants.py core.py models.py networking.py parsing.py \
    reporting.py subrecon_models.py subrecon_reporting.py sources tests
  uv run python -m unittest discover -s tests -p "test_*.py"
else
  echo "[*] skipping deterministic quality gates"
fi

echo "[*] collecting version metadata..."
{
  echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "git_commit=$(git rev-parse HEAD)"
  echo "uv_version=$(uv --version)"
  subrecon_version="$(uv run subrecon --version 2>/dev/null || true)"
  if [[ -z "$subrecon_version" ]]; then
    subrecon_version="$(python3 -c 'import subrecon_version; print(subrecon_version.__version__)' 2>/dev/null || echo unavailable)"
  fi
  echo "subrecon_version=$subrecon_version"
} > "$OUT_DIR/metadata.txt"

if [[ $SKIP_LIVE -eq 1 ]]; then
  echo "[*] skipping live matrix"
  exit 0
fi

run_case() {
  local name="$1"
  shift
  local outfile="$OUT_DIR/${name}.json"
  local logfile="$OUT_DIR/${name}.log"
  echo "[*] running case: $name"
  set +e
  "$@" -o "$outfile" > "$logfile" 2>&1
  local rc=$?
  set -e
  echo "$rc" > "$OUT_DIR/${name}.rc"
  if [[ $rc -ne 0 ]]; then
    echo "[!] case failed: $name (rc=$rc). see $logfile"
  else
    echo "[+] case completed: $name -> $outfile"
  fi
}

echo "[*] running bounded live matrix..."

run_case core_e2e_iana \
  uv run subrecon -d iana.org --no-subfinder --no-amass

run_case s3_only_noaa_goes19 \
  uv run subrecon -d noaa-goes19.test --keywords noaa-goes19 \
  --no-ct --no-subfinder --no-amass --no-search --no-gcp --no-azure --no-takeover

run_case gcs_only_landsat \
  uv run subrecon -d gcp-public-data.test --keywords gcp-public-data-landsat \
  --no-ct --no-subfinder --no-amass --no-search --no-s3 --no-azure --no-takeover

echo "[*] running Azure direct probes..."
uv run python -c "import subrecon; print(subrecon.check_single_azure_blob_container('azureopendatastorage','nyctlc',10))" \
  > "$OUT_DIR/azure_probe_default.txt" 2>&1 || true
uv run python -c "import subrecon; print(subrecon.check_single_azure_blob_container('azureopendatastorage','nyctlc',10, azure_probe_retries=1))" \
  > "$OUT_DIR/azure_probe_retry1.txt" 2>&1 || true

if [[ "$MODE" == "full" ]]; then
  run_case ct_only_iana \
    uv run subrecon -d iana.org --no-search --no-s3 --no-gcp --no-azure --no-subfinder --no-amass --no-takeover

  run_case search_only_iana \
    uv run subrecon -d iana.org --search-providers commoncrawl --no-ct --no-subfinder --no-amass --no-s3 --no-gcp --no-azure --no-takeover

  run_case takeover_ct_iana \
    uv run subrecon -d iana.org --no-search --no-s3 --no-gcp --no-azure --no-subfinder --no-amass

  run_case subfinder_only_iana \
    uv run subrecon -d iana.org --no-ct --no-amass --no-search --no-s3 --no-gcp --no-azure --no-takeover

  run_case amass_only_iana \
    uv run subrecon -d iana.org --no-ct --no-subfinder --no-search --no-s3 --no-gcp --no-azure --no-takeover
fi

echo "[*] building summary..."
uv run python - <<'PY' "$OUT_DIR"
import json
from pathlib import Path
import sys

out_dir = Path(sys.argv[1])
summary = {}
for report in sorted(out_dir.glob("*.json")):
    try:
        data = json.loads(report.read_text(encoding="utf-8"))
    except Exception as exc:
        summary[report.name] = {"status": "unreadable", "error": str(exc)}
        continue
    src = data.get("source_health", {})
    status_map = {k: v.get("status", "unknown") for k, v in sorted(src.items())}
    summary[report.name] = {
        "total_findings": data.get("summary", {}).get("total_findings", 0),
        "source_status": status_map,
    }

summary_path = out_dir / "summary.json"
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
print(json.dumps(summary, indent=2, sort_keys=True))
PY

echo "[+] pilot test bundle ready: $OUT_DIR"
echo "[+] next: copy metrics into docs/PILOT_LOG_TEMPLATE.md"
