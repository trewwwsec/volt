#!/usr/bin/env python3

import argparse
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from html import unescape
from pathlib import Path
from typing import Optional
from urllib import error, parse, request

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (compatible; subrecon-passive/1.0; +https://github.com/)"
)


@dataclass
class Evidence:
    source_url: str
    note: str


@dataclass
class Finding:
    asset_type: str
    asset: str
    severity: str
    confidence: str
    title: str
    description: str
    source: str
    tags: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)


@dataclass
class ScanContext:
    domains: list[str]
    organization: Optional[str]
    keywords: list[str]
    timeout: int
    threads: int
    max_bucket_candidates: int
    verbose: bool


def log(msg: str, verbose: bool = False, force: bool = False) -> None:
    if force or verbose:
        print(msg)


def normalize_domain(value: str) -> str:
    return value.strip().lower().lstrip(".")


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    out: list[Finding] = []
    for finding in findings:
        if finding.asset_type in {"subdomain", "s3_bucket"}:
            key = (finding.asset_type, finding.asset.lower(), "")
        else:
            key = (finding.asset_type, finding.asset.lower(), finding.title.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def check_tool(name: str) -> bool:
    return shutil.which(name) is not None


def run_command(cmd: list[str], timeout: int) -> tuple[bool, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception:
        return False, ""

    if proc.returncode != 0:
        return False, ""
    return True, proc.stdout


def parse_hosts_from_output(raw: str, domain: str) -> set[str]:
    out: set[str] = set()
    for line in raw.splitlines():
        host = normalize_domain(line.replace("*.", ""))
        if not host:
            continue
        if host == domain or host.endswith(f".{domain}"):
            out.add(host)
    return out


def collect_subfinder_subdomains(context: ScanContext) -> tuple[set[str], list[Finding]]:
    if not check_tool("subfinder"):
        log("[subfinder] tool not found; skipping", context.verbose)
        return set(), []

    hosts: set[str] = set()
    for domain in context.domains:
        ok, output = run_command(
            ["subfinder", "-d", domain, "-silent", "-o", "/dev/stdout"],
            timeout=max(60, context.timeout * 8),
        )
        if not ok:
            continue
        hosts.update(parse_hosts_from_output(output, domain))

    findings = [
        Finding(
            asset_type="subdomain",
            asset=host,
            severity="info",
            confidence="medium",
            title="Subdomain discovered by passive source aggregator",
            description="Discovered by subfinder in passive mode.",
            source="subfinder",
            tags=["inventory", "passive"],
            evidence=[
                Evidence(
                    source_url="https://github.com/projectdiscovery/subfinder",
                    note="Passive source correlation.",
                )
            ],
        )
        for host in sorted(hosts)
    ]
    return hosts, findings


def collect_amass_subdomains(context: ScanContext) -> tuple[set[str], list[Finding]]:
    if not check_tool("amass"):
        log("[amass] tool not found; skipping", context.verbose)
        return set(), []

    hosts: set[str] = set()
    for domain in context.domains:
        ok, output = run_command(
            ["amass", "enum", "-passive", "-d", domain],
            timeout=max(90, context.timeout * 12),
        )
        if not ok:
            continue
        hosts.update(parse_hosts_from_output(output, domain))

    findings = [
        Finding(
            asset_type="subdomain",
            asset=host,
            severity="info",
            confidence="medium",
            title="Subdomain discovered by passive DNS intelligence",
            description="Discovered by amass passive mode.",
            source="amass",
            tags=["inventory", "passive"],
            evidence=[
                Evidence(
                    source_url="https://github.com/owasp-amass/amass",
                    note="Passive DNS/OSINT enumeration.",
                )
            ],
        )
        for host in sorted(hosts)
    ]
    return hosts, findings


def fetch_url(
    url: str,
    timeout: int,
    method: str = "GET",
    headers: Optional[dict[str, str]] = None,
) -> tuple[int, str, dict[str, str]]:
    req_headers = {"User-Agent": DEFAULT_USER_AGENT}
    if headers:
        req_headers.update(headers)

    req = request.Request(url, headers=req_headers, method=method)

    try:
        with request.urlopen(req, timeout=timeout) as resp:
            body = ""
            if method != "HEAD":
                body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body, dict(resp.headers.items())
    except error.HTTPError as exc:
        body = ""
        if method != "HEAD":
            try:
                body = exc.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
        return exc.code, body, dict(exc.headers.items()) if exc.headers else {}
    except error.URLError:
        return 0, "", {}
    except Exception:
        return 0, "", {}


def collect_ct_subdomains(context: ScanContext) -> tuple[set[str], list[Finding]]:
    findings: list[Finding] = []
    discovered: set[str] = set()

    for domain in context.domains:
        query = parse.quote(f"%.{domain}")
        url = f"https://crt.sh/?q={query}&output=json"

        status, body, _ = fetch_url(url, timeout=context.timeout)
        if status != 200 or not body.strip():
            log(f"[ct] {domain}: no data (status={status})", context.verbose)
            continue

        try:
            rows = json.loads(body)
        except json.JSONDecodeError:
            log(f"[ct] {domain}: failed to parse ct json", context.verbose)
            continue

        for row in rows:
            names = str(row.get("name_value", "")).splitlines()
            for name in names:
                host = normalize_domain(name.replace("*.", ""))
                if not host:
                    continue
                if host == domain or host.endswith(f".{domain}"):
                    discovered.add(host)

        log(f"[ct] {domain}: {len(discovered)} cumulative hosts", context.verbose)

    for host in sorted(discovered):
        findings.append(
            Finding(
                asset_type="subdomain",
                asset=host,
                severity="info",
                confidence="high",
                title="Subdomain discovered in CT logs",
                description="Found in public certificate transparency records.",
                source="crt.sh",
                tags=["inventory", "ct-log", "passive"],
                evidence=[
                    Evidence(
                        source_url="https://crt.sh/",
                        note="Observed in certificate transparency dataset.",
                    )
                ],
            )
        )

    return discovered, findings


def build_dork_queries(domain: str) -> list[tuple[str, str]]:
    return [
        (f"site:{domain} ext:env", "dotenv"),
        (f"site:{domain} ext:sql", "sql-dump"),
        (f"site:{domain} (ext:bak OR ext:backup OR ext:old)", "backup-file"),
        (f"site:{domain} inurl:.git/config", "git-config"),
        (f"site:{domain} (ext:zip OR ext:tar OR ext:gz)", "archive"),
    ]


def parse_bing_results(html: str) -> list[dict[str, str]]:
    blocks = re.findall(r'<li class="b_algo".*?</li>', html, flags=re.S)
    results: list[dict[str, str]] = []

    for block in blocks:
        href_match = re.search(r'<h2><a href="(https?://[^"]+)"', block)
        if not href_match:
            continue

        title_match = re.search(r"<h2><a[^>]*>(.*?)</a></h2>", block, flags=re.S)
        snippet_match = re.search(r'<p>(.*?)</p>', block, flags=re.S)

        title = ""
        snippet = ""
        if title_match:
            title = re.sub(r"<.*?>", "", title_match.group(1))
        if snippet_match:
            snippet = re.sub(r"<.*?>", "", snippet_match.group(1))

        results.append(
            {
                "url": unescape(href_match.group(1)),
                "title": unescape(title.strip()),
                "snippet": unescape(snippet.strip()),
            }
        )

    return results


def classify_leak(url: str, snippet: str) -> tuple[str, str, str, list[str]]:
    lower = f"{url} {snippet}".lower()

    rules: list[tuple[list[str], str, str, str, list[str]]] = [
        (
            [".env", "dotenv"],
            "Potential .env exposure indexed",
            "high",
            "Indexed result suggests a dotenv file might be exposed.",
            ["credentials", "env-file", "indexed"],
        ),
        (
            [".git/config", "/.git/"],
            "Potential Git metadata exposure indexed",
            "high",
            "Indexed result suggests repository metadata may be exposed.",
            ["source-code", "git", "indexed"],
        ),
        (
            ["backup", ".bak", ".old", "backup.sql"],
            "Potential backup file indexed",
            "medium",
            "Indexed result suggests backup artifacts may be exposed.",
            ["backup", "indexed"],
        ),
        (
            [".sql"],
            "Potential SQL dump indexed",
            "high",
            "Indexed result suggests SQL dump data may be publicly reachable.",
            ["database", "indexed"],
        ),
        (
            [".zip", ".tar", ".gz"],
            "Potential archive exposure indexed",
            "medium",
            "Indexed result suggests downloadable archives may be exposed.",
            ["archive", "indexed"],
        ),
    ]

    for needles, title, sev, desc, tags in rules:
        if any(n in lower for n in needles):
            return title, sev, desc, tags

    return (
        "Potential sensitive file indexed",
        "low",
        "Search result matched a sensitive-file dork pattern.",
        ["indexed"],
    )


def collect_search_index_findings(context: ScanContext) -> tuple[set[str], list[Finding]]:
    findings: list[Finding] = []
    discovered_hosts: set[str] = set()

    for domain in context.domains:
        for query, category in build_dork_queries(domain):
            url = f"https://www.bing.com/search?q={parse.quote_plus(query)}&count=30"
            status, body, _ = fetch_url(url, timeout=context.timeout)
            if status != 200 or not body:
                log(
                    f"[search] {domain} query='{query}' failed status={status}",
                    context.verbose,
                )
                continue

            results = parse_bing_results(body)
            log(
                f"[search] {domain} query='{category}' results={len(results)}",
                context.verbose,
            )

            for item in results:
                target = item["url"]
                parsed = parse.urlparse(target)
                host = (parsed.hostname or "").lower()
                if not host:
                    continue

                if not (host == domain or host.endswith(f".{domain}")):
                    continue

                discovered_hosts.add(host)
                title, severity, description, tags = classify_leak(
                    target, item.get("snippet", "")
                )
                findings.append(
                    Finding(
                        asset_type="indexed_leak",
                        asset=target,
                        severity=severity,
                        confidence="medium",
                        title=title,
                        description=description,
                        source="bing",
                        tags=["passive", category, *tags],
                        evidence=[
                            Evidence(
                                source_url=url,
                                note=f"Search hit title: {item.get('title', '')[:120]}",
                            )
                        ],
                    )
                )

    return discovered_hosts, findings


def sanitize_bucket_label(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9.-]", "-", value.lower())
    cleaned = cleaned.strip("-.")
    cleaned = re.sub(r"\.{2,}", ".", cleaned)
    cleaned = re.sub(r"-{2,}", "-", cleaned)
    return cleaned


def extract_bucket_candidates_from_hosts(hosts: set[str]) -> set[str]:
    candidates: set[str] = set()

    for host in hosts:
        parts = host.split(".")
        if not parts:
            continue

        candidates.add(sanitize_bucket_label(host.replace(".", "-")))

        if len(parts) > 2:
            left = "-".join(parts[:-2])
            candidates.add(sanitize_bucket_label(left))

        if "s3" in parts:
            idx = parts.index("s3")
            if idx > 0:
                candidates.add(sanitize_bucket_label(parts[idx - 1]))

    return {c for c in candidates if 3 <= len(c) <= 63}


def build_bucket_wordlist(context: ScanContext, discovered_hosts: set[str]) -> set[str]:
    words: set[str] = set()

    for domain in context.domains:
        base = domain.split(".")[0]
        words.add(sanitize_bucket_label(base))
        words.add(sanitize_bucket_label(domain.replace(".", "-")))

    if context.organization:
        words.add(sanitize_bucket_label(context.organization.replace(" ", "-")))

    for kw in context.keywords:
        words.add(sanitize_bucket_label(kw))

    words.update(extract_bucket_candidates_from_hosts(discovered_hosts))

    patterns = [
        "{w}",
        "{w}-assets",
        "{w}-static",
        "{w}-media",
        "{w}-uploads",
        "{w}-backup",
        "{w}-backups",
        "{w}-dev",
        "{w}-prod",
        "{w}-logs",
    ]

    candidates: set[str] = set()
    for word in words:
        if not word:
            continue
        for pat in patterns:
            candidate = sanitize_bucket_label(pat.format(w=word))
            if 3 <= len(candidate) <= 63:
                candidates.add(candidate)

    return candidates


def check_single_bucket_exists(bucket: str, timeout: int) -> tuple[str, Optional[int], bool, str]:
    url = f"https://{bucket}.s3.amazonaws.com/"
    status, _, headers = fetch_url(url, timeout=timeout, method="HEAD")

    exists_codes = {200, 301, 302, 307, 403}
    exists = status in exists_codes

    region = headers.get("x-amz-bucket-region") or headers.get("X-Amz-Bucket-Region")
    return bucket, status, exists, region or ""


def collect_s3_bucket_findings(context: ScanContext, hosts: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    candidates = sorted(build_bucket_wordlist(context, hosts))
    if not candidates:
        return findings

    if len(candidates) > context.max_bucket_candidates:
        log(
            "[s3] candidate list capped at "
            f"{context.max_bucket_candidates} (from {len(candidates)})",
            context.verbose,
            force=True,
        )
        candidates = candidates[: context.max_bucket_candidates]

    log(f"[s3] checking {len(candidates)} bucket candidates", context.verbose)

    checked = 0
    with ThreadPoolExecutor(max_workers=context.threads) as pool:
        futures = {
            pool.submit(check_single_bucket_exists, bucket, context.timeout): bucket
            for bucket in candidates
        }
        for fut in as_completed(futures):
            checked += 1
            bucket = futures[fut]
            try:
                _, status, exists, region = fut.result()
            except Exception:
                continue

            if context.verbose and checked % 50 == 0:
                log(
                    f"[s3] progress {checked}/{len(candidates)}",
                    context.verbose,
                )

            if not exists:
                continue

            severity = "low"
            confidence = "medium"
            title = "S3 bucket name exists"
            description = "Bucket endpoint responded, indicating the bucket name exists."

            if status == 200:
                severity = "medium"
                confidence = "high"
                title = "Potentially public S3 bucket"
                description = (
                    "Bucket endpoint returned HTTP 200. Validate access control in a "
                    "permitted environment."
                )
            elif status == 403:
                description = (
                    "Bucket exists but denied anonymous access (HTTP 403). "
                    "Still useful for exposed naming/asset inventory."
                )

            region_note = f" region={region}" if region else ""
            findings.append(
                Finding(
                    asset_type="s3_bucket",
                    asset=bucket,
                    severity=severity,
                    confidence=confidence,
                    title=title,
                    description=description,
                    source="aws-s3-head",
                    tags=["cloud", "s3", "passive"],
                    evidence=[
                        Evidence(
                            source_url=f"https://{bucket}.s3.amazonaws.com/",
                            note=f"HEAD status={status}.{region_note}",
                        )
                    ],
                )
            )

    return findings


def make_summary(findings: list[Finding]) -> dict:
    by_type = Counter(f.asset_type for f in findings)
    by_severity = Counter(f.severity for f in findings)

    return {
        "total_findings": len(findings),
        "by_type": dict(sorted(by_type.items())),
        "by_severity": dict(sorted(by_severity.items())),
    }


def parse_keywords(value: Optional[str]) -> list[str]:
    if not value:
        return []
    return [x.strip().lower() for x in value.split(",") if x.strip()]


def load_domains(single: Optional[str], domain_list: Optional[str]) -> list[str]:
    domains: list[str] = []

    if single:
        domains.append(normalize_domain(single))

    if domain_list:
        path = Path(domain_list)
        with path.open() as handle:
            for line in handle:
                raw = line.strip()
                if not raw or raw.startswith("#"):
                    continue
                domains.append(normalize_domain(raw))

    return sorted(set(domains))


def run_scan(args: argparse.Namespace) -> dict:
    domains = load_domains(args.domain, args.domain_list)
    if not domains:
        raise ValueError("No valid domains provided. Use -d or -dL.")

    context = ScanContext(
        domains=domains,
        organization=args.organization,
        keywords=parse_keywords(args.keywords),
        timeout=args.timeout,
        threads=args.threads,
        max_bucket_candidates=args.max_bucket_candidates,
        verbose=args.verbose,
    )

    print(f"[*] Passive scan started for {len(domains)} domain(s)")
    print("[*] Mode: passive OSINT only (no direct target exploitation/scanning)")

    findings: list[Finding] = []
    discovered_hosts: set[str] = set()

    if not args.no_subfinder:
        print("[*] Collecting passive subdomains (subfinder)...")
        sf_hosts, sf_findings = collect_subfinder_subdomains(context)
        discovered_hosts.update(sf_hosts)
        findings.extend(sf_findings)
        print(f"    [subfinder] hosts discovered: {len(sf_hosts)}")

    if not args.no_amass:
        print("[*] Collecting passive subdomains (amass)...")
        am_hosts, am_findings = collect_amass_subdomains(context)
        discovered_hosts.update(am_hosts)
        findings.extend(am_findings)
        print(f"    [amass] hosts discovered: {len(am_hosts)}")

    if not args.no_ct:
        print("[*] Collecting subdomains from CT logs (crt.sh)...")
        ct_hosts, ct_findings = collect_ct_subdomains(context)
        discovered_hosts.update(ct_hosts)
        findings.extend(ct_findings)
        print(f"    [ct] hosts discovered: {len(ct_hosts)}")

    if not args.no_search:
        print("[*] Collecting indexed exposure signals (Bing dorks)...")
        search_hosts, search_findings = collect_search_index_findings(context)
        discovered_hosts.update(search_hosts)
        findings.extend(search_findings)
        print(f"    [search] indexed findings: {len(search_findings)}")

    if not args.no_s3:
        print("[*] Checking candidate S3 bucket names (HEAD only)...")
        s3_findings = collect_s3_bucket_findings(context, discovered_hosts)
        findings.extend(s3_findings)
        print(f"    [s3] matching bucket names: {len(s3_findings)}")

    findings = dedupe_findings(findings)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "passive_osint",
        "targets": domains,
        "organization": args.organization,
        "legal": {
            "active_scanning_performed": False,
            "notes": [
                "No direct port scanning or exploitation performed.",
                "Search/index signals require validation in an authorized workflow.",
                "S3 checks use bucket endpoint HEAD requests only (no object retrieval).",
            ],
        },
        "inventory": {
            "discovered_hosts": sorted(discovered_hosts),
        },
        "summary": make_summary(findings),
        "findings": [
            {
                **asdict(f),
                "evidence": [asdict(e) for e in f.evidence],
            }
            for f in sorted(findings, key=lambda x: (x.severity, x.asset_type, x.asset))
        ],
    }

    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Passive perimeter discovery tool for domains/orgs using public OSINT "
            "signals (CT logs, indexed exposure dorks, S3 bucket name checks)."
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
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout seconds")
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=20,
        help="Worker threads for concurrent passive checks",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument(
        "--max-bucket-candidates",
        type=int,
        default=800,
        help="Maximum candidate S3 bucket names to check",
    )

    parser.add_argument("--no-ct", action="store_true", help="Disable CT log collection")
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

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        report = run_scan(args)
    except ValueError as exc:
        print(f"[!] {exc}")
        sys.exit(1)

    with open(args.output, "w") as out:
        json.dump(report, out, indent=2)

    print(f"[+] Report written: {args.output}")
    print(f"[+] Total findings: {report['summary']['total_findings']}")


if __name__ == "__main__":
    main()
