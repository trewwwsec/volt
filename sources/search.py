from __future__ import annotations

import re
from typing import Any, Callable
from urllib import parse

from core import record_source_error
from models import Evidence, Finding, ScanContext


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


def fetch_commoncrawl_index_endpoint(
    timeout: int,
    *,
    fetch_url: Callable[..., tuple[int, str, dict[str, str]]],
    json_loads: Callable[[str], Any],
) -> str | None:
    status, body, _ = fetch_url(
        "https://index.commoncrawl.org/collinfo.json", timeout=timeout
    )
    if status != 200 or not body:
        return None
    try:
        rows = json_loads(body)
    except Exception:
        return None
    if not isinstance(rows, list):
        return None
    ranked_candidates: list[tuple[tuple[int, int], str]] = []
    unranked_candidates: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        endpoint = ""
        cdx_api = row.get("cdx-api")
        if isinstance(cdx_api, str) and cdx_api.startswith("http"):
            endpoint = cdx_api.rstrip("/")
        identifier = row.get("id")
        if not endpoint and isinstance(identifier, str) and identifier.strip():
            suffix = (
                identifier if identifier.endswith("-index") else f"{identifier}-index"
            )
            endpoint = f"https://index.commoncrawl.org/{suffix}"
        if not endpoint:
            continue

        collection_id = ""
        if isinstance(identifier, str):
            collection_id = identifier.strip()
        if not collection_id:
            match = re.search(r"/(CC-MAIN-(\d{4})-(\d{2}))-index/?$", endpoint)
            if match:
                collection_id = match.group(1)

        match = re.match(r"^CC-MAIN-(\d{4})-(\d{2})$", collection_id)
        if match:
            ranked_candidates.append(
                ((int(match.group(1)), int(match.group(2))), endpoint)
            )
        else:
            unranked_candidates.append(endpoint)

    if ranked_candidates:
        ranked_candidates.sort(key=lambda item: item[0], reverse=True)
        return ranked_candidates[0][1]
    if unranked_candidates:
        return unranked_candidates[0]
    return None


def fetch_commoncrawl_results(
    index_endpoint: str,
    pattern: str,
    timeout: int,
    limit: int = 25,
    *,
    fetch_url: Callable[..., tuple[int, str, dict[str, str]]],
    iter_json_records: Callable[[str], list[dict[str, Any]]],
    quote_plus: Callable[[str], str],
) -> tuple[int, list[dict[str, str]], str]:
    filtered_url = (
        f"{index_endpoint}?url={quote_plus(pattern)}&output=json&fl=url,status,mime"
        f"&limit={limit}&filter==status:200"
    )
    status, body, _ = fetch_url(filtered_url, timeout=timeout)
    query_url = filtered_url
    if status in {400, 422}:
        query_url = f"{index_endpoint}?url={quote_plus(pattern)}&output=json&fl=url&limit={limit}"
        status, body, _ = fetch_url(query_url, timeout=timeout)
    if status != 200 or not body:
        return status, [], query_url
    results: list[dict[str, str]] = []
    seen: set[str] = set()
    for row in iter_json_records(body):
        target = row.get("url")
        if not isinstance(target, str) or not target:
            continue
        record_status = row.get("status")
        if isinstance(record_status, str) and record_status != "200":
            continue
        if isinstance(record_status, int) and record_status != 200:
            continue
        if target in seen:
            continue
        seen.add(target)
        results.append({"url": target, "title": "", "snippet": ""})
    return status, results, query_url


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
    context: ScanContext,
    stats: dict[str, Any],
    *,
    build_commoncrawl_patterns: Callable[[str], list[tuple[str, str]]],
    fetch_commoncrawl_index_endpoint: Callable[[int], str | None],
    fetch_commoncrawl_results: Callable[
        [str, str, int], tuple[int, list[dict[str, str]], str]
    ],
    classify_leak: Callable[[str, str], tuple[str, str, str, list[str]]],
    log: Callable[[str, bool, bool], None],
) -> tuple[set[str], list[Finding]]:
    findings: list[Finding] = []
    discovered_hosts: set[str] = set()
    provider_stats: dict[str, dict[str, Any]] = {
        provider: {"queries": 0, "errors": 0, "results": 0, "status": "ok", "notes": []}
        for provider in context.search_providers
    }

    commoncrawl_index = None
    if "commoncrawl" in context.search_providers:
        index_exception = False
        try:
            commoncrawl_index = fetch_commoncrawl_index_endpoint(context.timeout)
        except Exception:
            index_exception = True
            commoncrawl_index = None
        if not commoncrawl_index:
            provider_stats["commoncrawl"]["status"] = "error"
            provider_stats["commoncrawl"]["errors"] += 1
            provider_stats["commoncrawl"]["queries"] += 1
            index_note = (
                "exception while resolving Common Crawl index endpoint"
                if index_exception
                else "failed to resolve Common Crawl index endpoint"
            )
            provider_stats["commoncrawl"]["notes"].append(index_note)
            stats["notes"].append(index_note)
            record_source_error(
                stats,
                "commoncrawl_index_exception"
                if index_exception
                else "commoncrawl_index_unavailable",
                detail=index_note,
            )

    for domain in context.domains:
        if "commoncrawl" in context.search_providers and commoncrawl_index:
            for pattern, category in build_commoncrawl_patterns(domain):
                provider_stats["commoncrawl"]["queries"] += 1
                stats["queried"] += 1
                try:
                    status, results, query_url = fetch_commoncrawl_results(
                        commoncrawl_index, pattern, context.timeout
                    )
                except Exception:
                    provider_stats["commoncrawl"]["errors"] += 1
                    provider_stats["commoncrawl"]["notes"].append(
                        f"domain={domain} query={category} exception"
                    )
                    record_source_error(
                        stats,
                        "commoncrawl_query_exception",
                        detail=f"domain={domain} query={category}",
                    )
                    log(
                        f"[search] provider=commoncrawl {domain} pattern='{pattern}' "
                        "exception during query",
                        context.verbose,
                    )
                    continue
                if status == 404:
                    log(
                        f"[search] provider=commoncrawl {domain} pattern='{pattern}' "
                        "returned no results",
                        context.verbose,
                    )
                    continue
                if status != 200:
                    provider_stats["commoncrawl"]["errors"] += 1
                    provider_stats["commoncrawl"]["notes"].append(
                        f"domain={domain} query={category} status={status}"
                    )
                    record_source_error(
                        stats,
                        f"commoncrawl_http_{status}",
                        detail=f"domain={domain} query={category}",
                    )
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
