#!/usr/bin/env python3

import argparse
import json
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import datetime, timezone
from html import unescape
from pathlib import Path
from typing import Any, Optional
from urllib import error, parse, request

from subrecon_models import Evidence, Finding, ScanContext
from subrecon_reporting import dedupe_findings, finding_sort_key, make_summary

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (compatible; subrecon-passive/1.0; +https://github.com/)"
)
SUPPORTED_SEARCH_PROVIDERS = {"bing", "commoncrawl"}


def log(msg: str, verbose: bool = False, force: bool = False) -> None:
    if force or verbose:
        print(msg)


def init_source_health(name: str, enabled: bool = True) -> dict[str, Any]:
    return {
        "name": name,
        "enabled": enabled,
        "status": "disabled" if not enabled else "ok",
        "queried": 0,
        "hosts": 0,
        "findings": 0,
        "errors": 0,
        "timeouts": 0,
        "notes": [],
    }


def normalize_domain(value: str) -> str:
    return value.strip().lower().lstrip(".")


def check_tool(name: str) -> bool:
    return shutil.which(name) is not None


def run_command(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return 124, stdout, stderr
    except Exception as exc:
        return 1, "", str(exc)

    return proc.returncode, proc.stdout, proc.stderr


def parse_hosts_from_output(raw: str, domain: str) -> set[str]:
    out: set[str] = set()
    for line in raw.splitlines():
        host = normalize_domain(line.replace("*.", ""))
        if not host:
            continue
        if host == domain or host.endswith(f".{domain}"):
            out.add(host)
    return out


def extract_host_from_value(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    candidate = value.strip()
    if not candidate:
        return ""
    if "://" in candidate:
        parsed = parse.urlparse(candidate)
        if parsed.hostname:
            return normalize_domain(parsed.hostname)
    candidate = candidate.split("/", 1)[0]
    return normalize_domain(candidate.replace("*.", ""))


def extract_source_names(record: dict[str, Any]) -> set[str]:
    out: set[str] = set()

    def add_source(value: Any) -> None:
        if not isinstance(value, str):
            return
        normalized = re.sub(r"\s+", " ", value.strip().lower())
        if normalized:
            out.add(normalized)

    for key in ("source", "src"):
        add_source(record.get(key))

    for key in ("sources",):
        value = record.get(key)
        if isinstance(value, str):
            add_source(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    add_source(item)
                elif isinstance(item, dict):
                    for nested_key in ("name", "source", "id"):
                        if nested_key in item:
                            add_source(item.get(nested_key))
                            break

    tag = record.get("tag")
    if isinstance(tag, str) and tag.strip():
        out.add(f"tag:{tag.strip().lower()}")

    return out


def iter_json_records(raw: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    text = raw.strip()
    if not text:
        return records

    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, dict):
                        records.append(item)
            return records
        except json.JSONDecodeError:
            pass

    for line in raw.splitlines():
        candidate = line.strip()
        if not candidate or not candidate.startswith("{"):
            continue
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            records.append(parsed)

    return records


def parse_structured_hosts_with_sources(
    raw: str, domain: str, host_keys: tuple[str, ...]
) -> dict[str, set[str]]:
    host_sources: dict[str, set[str]] = {}
    for record in iter_json_records(raw):
        host = ""
        for key in host_keys:
            host = extract_host_from_value(record.get(key))
            if host:
                break
        if not host:
            continue
        if not (host == domain or host.endswith(f".{domain}")):
            continue
        host_sources.setdefault(host, set()).update(extract_source_names(record))
    return host_sources


def parse_subfinder_structured_output(raw: str, domain: str) -> dict[str, set[str]]:
    return parse_structured_hosts_with_sources(raw, domain, ("host", "url", "input", "name"))


def parse_amass_structured_output(raw: str, domain: str) -> dict[str, set[str]]:
    return parse_structured_hosts_with_sources(raw, domain, ("name", "host", "hostname", "domain"))


def score_provenance_confidence(sources: set[str]) -> str:
    source_count = len([src for src in sources if not src.startswith("tag:")])
    if source_count >= 3:
        return "high"
    if source_count >= 1:
        return "medium"
    return "low"


def collect_subfinder_subdomains(
    context: ScanContext, health: Optional[dict[str, Any]] = None
) -> tuple[set[str], list[Finding]]:
    stats = health if health is not None else init_source_health("subfinder")
    if not check_tool("subfinder"):
        log("[subfinder] tool not found; skipping", context.verbose)
        stats["status"] = "skipped_tool_missing"
        stats["notes"].append("subfinder not installed")
        return set(), []

    hosts: set[str] = set()
    host_sources: dict[str, set[str]] = {}
    structured_domains = 0
    fallback_domains = 0
    for domain in context.domains:
        stats["queried"] += 1
        rc, stdout, stderr = run_command(
            ["subfinder", "-d", domain, "-silent", "-oJ", "-cs"],
            timeout=context.tool_timeout,
        )
        structured = parse_subfinder_structured_output(stdout, domain)
        if structured:
            structured_domains += 1
            parsed = set(structured.keys())
            for host, sources in structured.items():
                host_sources.setdefault(host, set()).update(sources)
        else:
            fallback_domains += 1
            parsed = parse_hosts_from_output(stdout, domain)
            for host in parsed:
                host_sources.setdefault(host, set())
        hosts.update(parsed)

        if rc == 124 and not parsed:
            stats["timeouts"] += 1
            print(
                f"    [subfinder] {domain}: timed out after {context.tool_timeout}s "
                "(try increasing --tool-timeout)"
            )
            continue
        if rc != 0 and not parsed:
            stats["errors"] += 1
            err = (stderr or "").strip().splitlines()
            detail = err[-1] if err else "unknown error"
            print(f"    [subfinder] {domain}: command failed (rc={rc}) - {detail}")
        elif rc != 0 and parsed:
            log(
                f"[subfinder] {domain}: rc={rc}, parsed {len(parsed)} hosts from partial output",
                context.verbose,
            )

        if rc == 0 and context.verbose:
            log(f"[subfinder] {domain}: parsed {len(parsed)} hosts", context.verbose)


    findings: list[Finding] = []
    for host in sorted(hosts):
        sources = sorted(host_sources.get(host, set()))
        confidence = score_provenance_confidence(set(sources))
        source_note = "No upstream source metadata returned."
        if sources:
            source_note = f"{len(sources)} passive sources: {', '.join(sources[:8])}"
        findings.append(
            Finding(
                asset_type="subdomain",
                asset=host,
                severity="info",
                confidence=confidence,
                title="Subdomain discovered by passive source aggregator",
                description="Discovered by subfinder in passive mode with source provenance.",
                source="subfinder",
                tags=["inventory", "passive", "provenance"],
                evidence=[
                    Evidence(
                        source_url="https://github.com/projectdiscovery/subfinder",
                        note=source_note,
                    )
                ],
            )
        )
    stats["hosts"] = len(hosts)
    stats["findings"] = len(findings)
    stats["structured_domains"] = structured_domains
    stats["fallback_domains"] = fallback_domains
    if stats["timeouts"] or stats["errors"]:
        stats["status"] = "partial" if hosts else "error"
    return hosts, findings


def collect_amass_subdomains(
    context: ScanContext, health: Optional[dict[str, Any]] = None
) -> tuple[set[str], list[Finding]]:
    stats = health if health is not None else init_source_health("amass")
    if not check_tool("amass"):
        log("[amass] tool not found; skipping", context.verbose)
        stats["status"] = "skipped_tool_missing"
        stats["notes"].append("amass not installed")
        return set(), []

    hosts: set[str] = set()
    host_sources: dict[str, set[str]] = {}
    structured_domains = 0
    fallback_domains = 0
    for domain in context.domains:
        stats["queried"] += 1
        rc, stdout, stderr = run_command(
            ["amass", "enum", "-passive", "-d", domain, "-src", "-json", "/dev/stdout"],
            timeout=context.tool_timeout,
        )
        structured = parse_amass_structured_output(stdout, domain)
        if structured:
            structured_domains += 1
            parsed = set(structured.keys())
            for host, sources in structured.items():
                host_sources.setdefault(host, set()).update(sources)
        else:
            fallback_domains += 1
            parsed = parse_hosts_from_output(stdout, domain)
            for host in parsed:
                host_sources.setdefault(host, set())
        hosts.update(parsed)

        if rc == 124 and not parsed:
            stats["timeouts"] += 1
            print(
                f"    [amass] {domain}: timed out after {context.tool_timeout}s "
                "(try increasing --tool-timeout)"
            )
            continue
        if rc != 0 and not parsed:
            stats["errors"] += 1
            err = (stderr or "").strip().splitlines()
            detail = err[-1] if err else "unknown error"
            print(f"    [amass] {domain}: command failed (rc={rc}) - {detail}")
        elif rc != 0 and parsed:
            log(
                f"[amass] {domain}: rc={rc}, parsed {len(parsed)} hosts from partial output",
                context.verbose,
            )

        if rc == 0 and context.verbose:
            log(f"[amass] {domain}: parsed {len(parsed)} hosts", context.verbose)


    findings: list[Finding] = []
    for host in sorted(hosts):
        sources = sorted(host_sources.get(host, set()))
        confidence = score_provenance_confidence(set(sources))
        source_note = "No upstream source metadata returned."
        if sources:
            source_note = f"{len(sources)} passive sources: {', '.join(sources[:8])}"
        findings.append(
            Finding(
                asset_type="subdomain",
                asset=host,
                severity="info",
                confidence=confidence,
                title="Subdomain discovered by passive DNS intelligence",
                description="Discovered by amass passive mode with source provenance.",
                source="amass",
                tags=["inventory", "passive", "provenance"],
                evidence=[
                    Evidence(
                        source_url="https://github.com/owasp-amass/amass",
                        note=source_note,
                    )
                ],
            )
        )
    stats["hosts"] = len(hosts)
    stats["findings"] = len(findings)
    stats["structured_domains"] = structured_domains
    stats["fallback_domains"] = fallback_domains
    if stats["timeouts"] or stats["errors"]:
        stats["status"] = "partial" if hosts else "error"
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


def collect_ct_subdomains(
    context: ScanContext, health: Optional[dict[str, Any]] = None
) -> tuple[set[str], list[Finding]]:
    stats = health if health is not None else init_source_health("crt.sh")
    findings: list[Finding] = []
    discovered: set[str] = set()

    for domain in context.domains:
        stats["queried"] += 1
        query = parse.quote(f"%.{domain}")
        url = f"https://crt.sh/?q={query}&output=json"

        status, body, _ = fetch_url(url, timeout=context.timeout)
        if status != 200 or not body.strip():
            stats["errors"] += 1
            log(f"[ct] {domain}: no data (status={status})", context.verbose)
            continue

        try:
            rows = json.loads(body)
        except json.JSONDecodeError:
            stats["errors"] += 1
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

    stats["hosts"] = len(discovered)
    stats["findings"] = len(findings)
    if stats["errors"]:
        stats["status"] = "partial" if discovered else "error"
    return discovered, findings


def build_dork_queries(domain: str) -> list[tuple[str, str]]:
    return [
        (f"site:{domain} ext:env", "dotenv"),
        (f"site:{domain} ext:sql", "sql-dump"),
        (f"site:{domain} (ext:bak OR ext:backup OR ext:old)", "backup-file"),
        (f"site:{domain} inurl:.git/config", "git-config"),
        (f"site:{domain} (ext:zip OR ext:tar OR ext:gz)", "archive"),
    ]


def build_commoncrawl_patterns(domain: str) -> list[tuple[str, str]]:
    return [
        (f"*.{domain}/*.env", "dotenv"),
        (f"{domain}/*.env", "dotenv"),
        (f"*.{domain}/*.sql", "sql-dump"),
        (f"{domain}/*.sql", "sql-dump"),
        (f"*.{domain}/*.bak", "backup-file"),
        (f"*.{domain}/*.backup", "backup-file"),
        (f"*.{domain}/*.old", "backup-file"),
        (f"*.{domain}/.git/config", "git-config"),
        (f"{domain}/.git/config", "git-config"),
        (f"*.{domain}/*.zip", "archive"),
        (f"*.{domain}/*.tar", "archive"),
        (f"*.{domain}/*.gz", "archive"),
    ]


def fetch_commoncrawl_index_endpoint(timeout: int) -> Optional[str]:
    status, body, _ = fetch_url("https://index.commoncrawl.org/collinfo.json", timeout=timeout)
    if status != 200 or not body:
        return None
    try:
        rows = json.loads(body)
    except json.JSONDecodeError:
        return None
    if not isinstance(rows, list):
        return None
    for row in rows:
        if not isinstance(row, dict):
            continue
        endpoint = row.get("cdx-api")
        if isinstance(endpoint, str) and endpoint.startswith("http"):
            return endpoint.rstrip("/")
        identifier = row.get("id")
        if isinstance(identifier, str) and identifier.strip():
            suffix = identifier if identifier.endswith("-index") else f"{identifier}-index"
            return f"https://index.commoncrawl.org/{suffix}"
    return None


def fetch_commoncrawl_results(
    index_endpoint: str, pattern: str, timeout: int, limit: int = 25
) -> tuple[int, list[dict[str, str]], str]:
    url = (
        f"{index_endpoint}?url={parse.quote_plus(pattern)}&output=json&fl=url&limit={limit}"
    )
    status, body, _ = fetch_url(url, timeout=timeout)
    if status != 200 or not body:
        return status, [], url
    results: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in iter_json_records(body):
        target = row.get("url")
        if not isinstance(target, str) or not target:
            continue
        if target in seen:
            continue
        seen.add(target)
        results.append({"url": target, "title": "", "snippet": ""})
    return status, results, url


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


def collect_search_index_findings(
    context: ScanContext, health: Optional[dict[str, Any]] = None
) -> tuple[set[str], list[Finding]]:
    stats = health if health is not None else init_source_health("search")
    findings: list[Finding] = []
    discovered_hosts: set[str] = set()
    provider_stats: dict[str, dict[str, Any]] = {
        provider: {"queries": 0, "errors": 0, "results": 0, "status": "ok"}
        for provider in context.search_providers
    }

    commoncrawl_index = None
    if "commoncrawl" in context.search_providers:
        commoncrawl_index = fetch_commoncrawl_index_endpoint(context.timeout)
        if not commoncrawl_index:
            provider_stats["commoncrawl"]["status"] = "error"
            provider_stats["commoncrawl"]["errors"] += 1
            provider_stats["commoncrawl"]["queries"] += 1
            stats["errors"] += 1
            stats["notes"].append("failed to resolve Common Crawl index endpoint")

    for domain in context.domains:
        if "bing" in context.search_providers:
            for query, category in build_dork_queries(domain):
                provider_stats["bing"]["queries"] += 1
                stats["queried"] += 1
                url = f"https://www.bing.com/search?q={parse.quote_plus(query)}&count=30"
                status, body, _ = fetch_url(url, timeout=context.timeout)
                if status != 200 or not body:
                    provider_stats["bing"]["errors"] += 1
                    stats["errors"] += 1
                    log(
                        f"[search] provider=bing {domain} query='{query}' failed status={status}",
                        context.verbose,
                    )
                    continue

                results = parse_bing_results(body)
                provider_stats["bing"]["results"] += len(results)
                log(
                    f"[search] provider=bing {domain} query='{category}' results={len(results)}",
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

        if "commoncrawl" in context.search_providers and commoncrawl_index:
            for pattern, category in build_commoncrawl_patterns(domain):
                provider_stats["commoncrawl"]["queries"] += 1
                stats["queried"] += 1
                status, results, query_url = fetch_commoncrawl_results(
                    commoncrawl_index, pattern, context.timeout
                )
                if status != 200:
                    provider_stats["commoncrawl"]["errors"] += 1
                    stats["errors"] += 1
                    log(
                        f"[search] provider=commoncrawl {domain} pattern='{pattern}' "
                        f"failed status={status}",
                        context.verbose,
                    )
                    continue

                provider_stats["commoncrawl"]["results"] += len(results)
                log(
                    f"[search] provider=commoncrawl {domain} query='{category}' "
                    f"results={len(results)}",
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
                            source="commoncrawl",
                            tags=["passive", category, *tags],
                            evidence=[
                                Evidence(
                                    source_url=query_url,
                                    note=f"Common Crawl pattern: {pattern}",
                                )
                            ],
                        )
                    )

    for provider, provider_stat in provider_stats.items():
        if provider_stat["errors"]:
            provider_stat["status"] = (
                "partial" if provider_stat["results"] > 0 else "error"
            )
        elif provider_stat["results"] == 0 and provider_stat["queries"] > 0:
            provider_stat["status"] = "ok_no_results"
    stats["providers"] = provider_stats
    stats["hosts"] = len(discovered_hosts)
    stats["findings"] = len(findings)
    if stats["errors"]:
        stats["status"] = "partial" if findings else "error"
    elif findings:
        stats["status"] = "ok"
    else:
        stats["status"] = "ok_no_results"

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


def classify_s3_head_status(status: int, region: str) -> str:
    if status == 200:
        return "confirmed_exists"
    if status in {301, 302, 307, 308, 403}:
        return "likely_exists" if region else "unknown"
    if status in {400, 404}:
        return "unknown"
    return "unknown"


def probe_s3_list_access(bucket: str, timeout: int) -> tuple[int, dict[str, str]]:
    url = f"https://{bucket}.s3.amazonaws.com/?list-type=2&max-keys=0"
    status, _, headers = fetch_url(url, timeout=timeout, method="GET")
    return status, headers


def check_single_bucket_exists(
    bucket: str, timeout: int, s3_list_probe: bool = True
) -> tuple[str, Optional[int], str, str, Optional[int]]:
    url = f"https://{bucket}.s3.amazonaws.com/"
    status, _, headers = fetch_url(url, timeout=timeout, method="HEAD")

    region = headers.get("x-amz-bucket-region") or headers.get("X-Amz-Bucket-Region")
    existence = classify_s3_head_status(status, region or "")
    list_status: Optional[int] = None

    if s3_list_probe and existence == "unknown":
        list_status, list_headers = probe_s3_list_access(bucket, timeout)
        if list_status == 200:
            existence = "confirmed_exists"
        elif list_status == 403:
            existence = "likely_exists"
        if not region:
            region = list_headers.get("x-amz-bucket-region") or list_headers.get(
                "X-Amz-Bucket-Region"
            )

    return bucket, status, existence, region or "", list_status


def collect_s3_bucket_findings(
    context: ScanContext, hosts: set[str], health: Optional[dict[str, Any]] = None
) -> list[Finding]:
    stats = health if health is not None else init_source_health("s3")
    findings: list[Finding] = []
    candidates = sorted(build_bucket_wordlist(context, hosts))
    if not candidates:
        stats["status"] = "ok_no_candidates"
        return findings

    stats["queried"] = len(candidates)
    if len(candidates) > context.max_bucket_candidates:
        log(
            "[s3] candidate list capped at "
            f"{context.max_bucket_candidates} (from {len(candidates)})",
            context.verbose,
            force=True,
        )
        candidates = candidates[: context.max_bucket_candidates]
        stats["queried"] = len(candidates)

    log(f"[s3] checking {len(candidates)} bucket candidates", context.verbose)

    checked = 0
    ambiguous_signals = 0
    suppressed_weak_likely = 0
    with ThreadPoolExecutor(max_workers=context.threads) as pool:
        futures = {
            pool.submit(
                check_single_bucket_exists,
                bucket,
                context.timeout,
                context.s3_list_probe,
            ): bucket
            for bucket in candidates
        }
        for fut in as_completed(futures):
            checked += 1
            bucket = futures[fut]
            try:
                _, status, existence, region, list_status = fut.result()
            except Exception:
                continue

            if context.verbose and checked % 50 == 0:
                log(
                    f"[s3] progress {checked}/{len(candidates)}",
                    context.verbose,
                )

            if status is None or status == 0:
                stats["errors"] += 1
                continue
            # Reduce noise: HEAD 400/404 plus list-probe 403 is weak evidence of existence.
            if existence == "likely_exists" and status in {400, 404} and list_status == 403:
                suppressed_weak_likely += 1
                ambiguous_signals += 1
                continue
            if existence in {"not_exists", "unknown"}:
                if existence == "unknown":
                    ambiguous_signals += 1
                continue

            tags = ["cloud", "s3", "passive"]
            if existence == "confirmed_exists":
                severity = "medium"
                confidence = "high"
                if list_status == 200 and status != 200:
                    title = "Publicly listable S3 bucket (anonymous probe)"
                    description = (
                        "Anonymous ListObjectsV2 probe succeeded (HTTP 200). "
                        "Validate access controls and exposure in a permitted workflow."
                    )
                    tags.append("listable")
                else:
                    title = "Potentially public S3 bucket"
                    description = (
                        "Bucket endpoint returned HTTP 200. Validate access control in a "
                        "permitted environment."
                    )
            elif existence == "likely_exists":
                severity = "low"
                confidence = "medium"
                title = "S3 bucket name likely exists (HEAD signal)"
                description = (
                    "Bucket endpoint response strongly suggests the bucket name exists, "
                    "but anonymous access is not available."
                )
                tags.append("likely-exists")
            region_note = f" region={region}" if region else ""
            list_note = f" list_probe_status={list_status}" if list_status is not None else ""
            findings.append(
                Finding(
                    asset_type="s3_bucket",
                    asset=bucket,
                    severity=severity,
                    confidence=confidence,
                    title=title,
                    description=description,
                    source="aws-s3-head",
                    tags=tags,
                    evidence=[
                        Evidence(
                            source_url=f"https://{bucket}.s3.amazonaws.com/",
                            note=(
                                f"HEAD status={status}. existence={existence}.{region_note}"
                                f"{list_note}"
                            ),
                        )
                    ],
                )
            )

    stats["ambiguous"] = ambiguous_signals
    stats["suppressed_weak_likely"] = suppressed_weak_likely
    stats["hosts"] = len(findings)
    stats["findings"] = len(findings)
    if stats["errors"]:
        stats["status"] = "partial" if findings else "error"
    elif findings:
        stats["status"] = "ok"
    else:
        stats["status"] = "ok_no_results"

    if not findings and ambiguous_signals:
        print(
            "    [s3] no confident bucket hits; responses were ambiguous "
            f"for {ambiguous_signals}/{len(candidates)} candidates"
        )
        print(
            "    [s3] note: unauthenticated HeadBucket may return generic 400/403/404 "
            "that cannot confirm bucket existence"
        )

    return findings


def parse_keywords(value: Optional[str]) -> list[str]:
    if not value:
        return []
    return [x.strip().lower() for x in value.split(",") if x.strip()]


def parse_search_providers(value: Optional[str]) -> list[str]:
    if not value:
        return ["bing", "commoncrawl"]
    ordered: list[str] = []
    for item in value.split(","):
        provider = item.strip().lower()
        if not provider:
            continue
        if provider not in SUPPORTED_SEARCH_PROVIDERS:
            supported = ", ".join(sorted(SUPPORTED_SEARCH_PROVIDERS))
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


def load_domains(single: Optional[str], domain_list: Optional[str]) -> list[str]:
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
            raise ValueError(f"Could not read domain list file '{domain_list}': {exc}") from exc

    return sorted(set(domains))


def run_scan(args: argparse.Namespace) -> dict:
    domains = load_domains(args.domain, args.domain_list)
    if not domains:
        raise ValueError("No valid domains provided. Use -d or -dL.")
    search_providers = parse_search_providers(args.search_providers)

    context = ScanContext(
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
    )

    print(f"[*] Passive scan started for {len(domains)} domain(s)")
    print("[*] Mode: passive OSINT only (no direct target exploitation/scanning)")

    findings: list[Finding] = []
    discovered_hosts: set[str] = set()
    source_health: dict[str, dict[str, Any]] = {
        "subfinder": init_source_health("subfinder", enabled=not args.no_subfinder),
        "amass": init_source_health("amass", enabled=not args.no_amass),
        "ct": init_source_health("crt.sh", enabled=not args.no_ct),
        "search": init_source_health("search", enabled=not args.no_search),
        "s3": init_source_health("s3", enabled=not args.no_s3),
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
        am_hosts, am_findings = collect_amass_subdomains(context, source_health["amass"])
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
            context, source_health["search"]
        )
        discovered_hosts.update(search_hosts)
        findings.extend(search_findings)
        print(f"    [search] indexed findings: {len(search_findings)}")

    if not args.no_s3:
        if args.s3_list_probe:
            print("[*] Checking candidate S3 bucket names (HEAD + optional list probe)...")
        else:
            print("[*] Checking candidate S3 bucket names (HEAD only)...")
        s3_findings = collect_s3_bucket_findings(context, discovered_hosts, source_health["s3"])
        findings.extend(s3_findings)
        print(f"    [s3] matching bucket names: {len(s3_findings)}")

    findings = dedupe_findings(findings)

    legal_notes = [
        "No direct port scanning or exploitation performed.",
        "Search/index signals require validation in an authorized workflow.",
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

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
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
                **asdict(f),
                "evidence": [asdict(e) for e in f.evidence],
            }
            for f in sorted(findings, key=finding_sort_key)
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
    parser.add_argument(
        "--search-providers",
        default="bing,commoncrawl",
        help="Comma-separated search providers (supported: bing, commoncrawl)",
    )
    parser.add_argument("--timeout", type=positive_int, default=10, help="HTTP timeout seconds")
    parser.add_argument(
        "--tool-timeout",
        type=positive_int,
        default=300,
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
        default=800,
        help="Maximum candidate S3 bucket names to check",
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

    try:
        with open(args.output, "w") as out:
            json.dump(report, out, indent=2)
    except OSError as exc:
        print(f"[!] Could not write output file '{args.output}': {exc}")
        sys.exit(1)

    print(f"[+] Report written: {args.output}")
    print(f"[+] Total findings: {report['summary']['total_findings']}")


if __name__ == "__main__":
    main()
