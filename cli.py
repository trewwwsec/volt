from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable, Optional


def parse_keywords(value: Optional[str]) -> list[str]:
    if not value:
        return []
    return [x.strip().lower() for x in value.split(",") if x.strip()]


def parse_search_providers(
    value: Optional[str], *, supported_search_providers: set[str]
) -> list[str]:
    if not value:
        return ["commoncrawl"]
    ordered: list[str] = []
    for item in value.split(","):
        provider = item.strip().lower()
        if not provider:
            continue
        if provider not in supported_search_providers:
            supported = ", ".join(sorted(supported_search_providers))
            raise ValueError(
                f"Unsupported search provider '{provider}'. Supported values: {supported}"
            )
        if provider not in ordered:
            ordered.append(provider)
    if not ordered:
        raise ValueError("No valid search providers configured")
    return ordered


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"Invalid integer value: {value}") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("Value must be a positive integer")
    return parsed


def load_domains(
    single: Optional[str],
    domain_list: Optional[str],
    *,
    normalize_domain: Callable[[str], str],
) -> list[str]:
    domains: list[str] = []

    if single:
        domains.append(normalize_domain(single))

    if domain_list:
        path = Path(domain_list)
        try:
            with path.open() as handle:
                for line in handle:
                    raw = line.strip()
                    if not raw or raw.startswith("#"):
                        continue
                    domains.append(normalize_domain(raw))
        except OSError as exc:
            raise ValueError(
                f"Could not read domain list file '{domain_list}': {exc}"
            ) from exc

    return sorted(set(domains))


def build_parser(*, positive_int: Callable[[str], int]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Passive perimeter discovery tool for domains/orgs using public OSINT "
            "signals (CT logs, indexed exposure dorks, S3/GCP/Azure storage checks, "
            "and subdomain takeover fingerprints)."
        )
    )

    parser.add_argument("-d", "--domain", help="Single root domain")
    parser.add_argument("-dL", "--domain-list", help="File with root domains")
    parser.add_argument("-o", "--output", default="perimeter_report.json")
    parser.add_argument(
        "--organization",
        help="Organization/company name to improve bucket candidate generation",
    )
    parser.add_argument(
        "--keywords",
        help="Comma-separated keywords/brands for passive bucket guessing",
    )
    parser.add_argument(
        "--search-providers",
        default="commoncrawl",
        help="Comma-separated search providers (default: commoncrawl; optional: bing)",
    )
    parser.add_argument(
        "--timeout", type=positive_int, default=10, help="HTTP timeout seconds"
    )
    parser.add_argument(
        "--tool-timeout",
        type=positive_int,
        default=120,
        help="Timeout seconds for passive external tools (subfinder/amass)",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=positive_int,
        default=20,
        help="Worker threads for concurrent passive checks",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument(
        "--max-bucket-candidates",
        type=positive_int,
        default=300,
        help="Maximum candidate cloud storage names to check per module",
    )
    parser.add_argument(
        "--s3-list-probe",
        action="store_true",
        dest="s3_list_probe",
        help=(
            "Enable anonymous ListObjectsV2 probes (max-keys=0) when S3 HEAD responses "
            "are ambiguous (enabled by default)"
        ),
    )
    parser.add_argument(
        "--no-s3-list-probe",
        action="store_false",
        dest="s3_list_probe",
        help="Disable anonymous ListObjectsV2 fallback probes for ambiguous S3 responses",
    )
    parser.set_defaults(s3_list_probe=True)
    parser.add_argument(
        "--s3-website-probe",
        action="store_true",
        help=(
            "Enable optional S3 website-endpoint probes "
            "(s3-website-<region>) for additional existence signals"
        ),
    )
    parser.add_argument(
        "--s3-probe-retries",
        type=int,
        choices=[0, 1],
        default=0,
        help=(
            "S3 probe retry budget for transient failures "
            "(0=default conservative, 1=single retry with backoff)"
        ),
    )
    parser.add_argument(
        "--gcp-dual-endpoint-probe",
        action="store_true",
        help=(
            "Enable optional GCS fallback probing on virtual-hosted XML endpoint "
            "(<bucket>.storage.googleapis.com) when path-style probing is ambiguous"
        ),
    )

    parser.add_argument(
        "--no-ct", action="store_true", help="Disable CT log collection"
    )
    parser.add_argument(
        "--no-subfinder",
        action="store_true",
        help="Disable passive subdomain collection via subfinder",
    )
    parser.add_argument(
        "--no-amass",
        action="store_true",
        help="Disable passive subdomain collection via amass",
    )
    parser.add_argument(
        "--no-search", action="store_true", help="Disable search-index exposure dorks"
    )
    parser.add_argument("--no-s3", action="store_true", help="Disable S3 bucket checks")
    parser.add_argument(
        "--no-gcp", action="store_true", help="Disable GCP bucket checks"
    )
    parser.add_argument(
        "--no-azure", action="store_true", help="Disable Azure Blob container checks"
    )
    parser.add_argument(
        "--no-takeover",
        action="store_true",
        help="Disable passive subdomain takeover fingerprint checks",
    )

    return parser


def run_scan(
    args: argparse.Namespace,
    *,
    load_domains: Callable[[Optional[str], Optional[str]], list[str]],
    parse_search_providers: Callable[[Optional[str]], list[str]],
    parse_keywords: Callable[[Optional[str]], list[str]],
    scan_context_cls: Callable[..., Any],
    init_source_health: Callable[[str, bool], dict[str, Any]],
    collect_subfinder_subdomains: Callable[
        [Any, dict[str, Any]], tuple[set[str], list[Any]]
    ],
    collect_amass_subdomains: Callable[
        [Any, dict[str, Any]], tuple[set[str], list[Any]]
    ],
    collect_ct_subdomains: Callable[[Any, dict[str, Any]], tuple[set[str], list[Any]]],
    collect_search_index_findings: Callable[
        [Any, dict[str, Any]], tuple[set[str], list[Any]]
    ],
    collect_s3_bucket_findings: Callable[[Any, set[str], dict[str, Any]], list[Any]],
    collect_gcp_bucket_findings: Callable[[Any, set[str], dict[str, Any]], list[Any]],
    collect_azure_blob_findings: Callable[[Any, set[str], dict[str, Any]], list[Any]],
    collect_subdomain_takeover_findings: Callable[
        [Any, set[str], dict[str, Any]], list[Any]
    ],
    dedupe_findings: Callable[[list[Any]], list[Any]],
    make_summary: Callable[[list[Any]], dict[str, Any]],
    finding_sort_key: Callable[[Any], Any],
    asdict_fn: Callable[[Any], dict[str, Any]],
    normalize_source_health: Callable[[dict[str, dict[str, Any]]], None],
    now_utc_iso: Callable[[], str],
) -> dict[str, Any]:
    domains = load_domains(args.domain, args.domain_list)
    if not domains:
        raise ValueError("No valid domains provided. Use -d or -dL.")
    search_providers = parse_search_providers(args.search_providers)

    context = scan_context_cls(
        domains=domains,
        organization=args.organization,
        keywords=parse_keywords(args.keywords),
        search_providers=search_providers,
        timeout=args.timeout,
        tool_timeout=args.tool_timeout,
        threads=args.threads,
        max_bucket_candidates=args.max_bucket_candidates,
        verbose=args.verbose,
        s3_list_probe=args.s3_list_probe,
        s3_website_probe=getattr(args, "s3_website_probe", False),
        s3_probe_retries=getattr(args, "s3_probe_retries", 0),
        gcp_dual_endpoint_probe=getattr(args, "gcp_dual_endpoint_probe", False),
    )

    print(f"[*] Passive scan started for {len(domains)} domain(s)")
    print("[*] Mode: passive OSINT only (no direct target exploitation/scanning)")

    findings: list[Any] = []
    discovered_hosts: set[str] = set()
    source_health: dict[str, dict[str, Any]] = {
        "subfinder": init_source_health("subfinder", not args.no_subfinder),
        "amass": init_source_health("amass", not args.no_amass),
        "ct": init_source_health("crt.sh", not args.no_ct),
        "search": init_source_health("search", not args.no_search),
        "s3": init_source_health("s3", not args.no_s3),
        "gcp": init_source_health("gcp", not args.no_gcp),
        "azure": init_source_health("azure", not args.no_azure),
        "takeover": init_source_health("takeover", not args.no_takeover),
    }
    if not args.no_search:
        source_health["search"]["providers"] = {
            provider: {"status": "pending", "queries": 0, "errors": 0, "results": 0}
            for provider in search_providers
        }

    if not args.no_subfinder:
        print("[*] Collecting passive subdomains (subfinder)...")
        sf_hosts, sf_findings = collect_subfinder_subdomains(
            context, source_health["subfinder"]
        )
        discovered_hosts.update(sf_hosts)
        findings.extend(sf_findings)
        print(f"    [subfinder] hosts discovered: {len(sf_hosts)}")

    if not args.no_amass:
        print("[*] Collecting passive subdomains (amass)...")
        am_hosts, am_findings = collect_amass_subdomains(
            context, source_health["amass"]
        )
        discovered_hosts.update(am_hosts)
        findings.extend(am_findings)
        print(f"    [amass] hosts discovered: {len(am_hosts)}")

    if not args.no_ct:
        print("[*] Collecting subdomains from CT logs (crt.sh)...")
        ct_hosts, ct_findings = collect_ct_subdomains(context, source_health["ct"])
        discovered_hosts.update(ct_hosts)
        findings.extend(ct_findings)
        print(f"    [ct] hosts discovered: {len(ct_hosts)}")

    if not args.no_search:
        provider_list = ", ".join(search_providers)
        print(f"[*] Collecting indexed exposure signals ({provider_list})...")
        search_hosts, search_findings = collect_search_index_findings(
            context,
            source_health["search"],
        )
        discovered_hosts.update(search_hosts)
        findings.extend(search_findings)
        print(f"    [search] indexed findings: {len(search_findings)}")

    if not args.no_s3:
        if args.s3_list_probe:
            if getattr(args, "s3_website_probe", False):
                print(
                    "[*] Checking candidate S3 bucket names "
                    "(HEAD + optional list probe + website probe)..."
                )
            else:
                print(
                    "[*] Checking candidate S3 bucket names "
                    "(HEAD + optional list probe)..."
                )
        else:
            if getattr(args, "s3_website_probe", False):
                print(
                    "[*] Checking candidate S3 bucket names "
                    "(HEAD only + optional website probe)..."
                )
            else:
                print("[*] Checking candidate S3 bucket names (HEAD only)...")
        s3_findings = collect_s3_bucket_findings(
            context, discovered_hosts, source_health["s3"]
        )
        findings.extend(s3_findings)
        print(f"    [s3] matching bucket names: {len(s3_findings)}")

    if not args.no_gcp:
        if getattr(args, "gcp_dual_endpoint_probe", False):
            print(
                "[*] Checking candidate GCP bucket names "
                "(HEAD + list probe + optional dual endpoint)..."
            )
        else:
            print("[*] Checking candidate GCP bucket names (HEAD + list probe)...")
        gcp_findings = collect_gcp_bucket_findings(
            context, discovered_hosts, source_health["gcp"]
        )
        findings.extend(gcp_findings)
        print(f"    [gcp] matching bucket names: {len(gcp_findings)}")

    if not args.no_azure:
        print("[*] Checking inferred Azure Blob containers (CNAME + list probe)...")
        azure_findings = collect_azure_blob_findings(
            context, discovered_hosts, source_health["azure"]
        )
        findings.extend(azure_findings)
        print(f"    [azure] matching blob containers: {len(azure_findings)}")

    if not args.no_takeover:
        print("[*] Checking discovered subdomains for takeover fingerprints...")
        takeover_findings = collect_subdomain_takeover_findings(
            context,
            discovered_hosts,
            source_health["takeover"],
        )
        findings.extend(takeover_findings)
        print(f"    [takeover] potential takeover findings: {len(takeover_findings)}")

    findings = dedupe_findings(findings)
    normalize_source_health(source_health)

    legal_notes = [
        "No direct port scanning or exploitation performed.",
        "Search/index signals require validation in an authorized workflow.",
        "Takeover checks use DNS-over-HTTPS CNAME resolution and passive HTTP fingerprinting.",
        "GCP checks use bucket endpoint HEAD/GET requests only (no object retrieval).",
        "Azure Blob checks use anonymous list probes only (no blob/object retrieval).",
    ]
    if args.s3_list_probe:
        legal_notes.append(
            "S3 checks use HEAD requests and optional anonymous ListObjectsV2 probes "
            "with max-keys=0 (no object retrieval)."
        )
    else:
        legal_notes.append(
            "S3 checks use bucket endpoint HEAD requests only (no object retrieval)."
        )
    if getattr(args, "s3_website_probe", False):
        legal_notes.append(
            "S3 website probing uses anonymous HTTP requests against "
            "region-scoped website endpoints (no object retrieval)."
        )
    if getattr(args, "gcp_dual_endpoint_probe", False):
        legal_notes.append(
            "GCP dual-endpoint probing may add optional virtual-hosted XML endpoint "
            "checks when path-style responses are ambiguous."
        )

    return {
        "generated_at": now_utc_iso(),
        "mode": "passive_osint",
        "targets": domains,
        "organization": args.organization,
        "legal": {
            "active_scanning_performed": False,
            "notes": legal_notes,
        },
        "inventory": {
            "discovered_hosts": sorted(discovered_hosts),
        },
        "source_health": source_health,
        "summary": make_summary(findings),
        "findings": [
            {
                **asdict_fn(f),
                "evidence": [asdict_fn(e) for e in f.evidence],
            }
            for f in sorted(findings, key=finding_sort_key)
        ],
    }


def main(
    *,
    build_parser: Callable[[], argparse.ArgumentParser],
    run_scan: Callable[[argparse.Namespace], dict[str, Any]],
) -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        report = run_scan(args)
    except ValueError as exc:
        print(f"[!] {exc}")
        sys.exit(1)

    try:
        with open(args.output, "w") as out:
            json.dump(report, out, indent=2)
    except OSError as exc:
        print(f"[!] Could not write output file '{args.output}': {exc}")
        sys.exit(1)

    print(f"[+] Report written: {args.output}")
    print(f"[+] Total findings: {report['summary']['total_findings']}")
