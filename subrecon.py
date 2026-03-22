#!/usr/bin/env python3

import argparse
import json
from dataclasses import asdict
from datetime import datetime, timezone
from random import uniform
from time import sleep
from typing import Any, Optional
from urllib import error, parse, request

from parsing import (
    extract_host_from_value as extract_host_from_value_source,
    extract_source_names as extract_source_names_source,
    iter_json_records as iter_json_records_source,
    parse_amass_structured_output as parse_amass_structured_output_source,
    parse_hosts_from_output as parse_hosts_from_output_source,
    parse_structured_hosts_with_sources as parse_structured_hosts_with_sources_source,
    parse_subfinder_structured_output as parse_subfinder_structured_output_source,
    score_provenance_confidence as score_provenance_confidence_source,
)
from cli import build_parser as build_parser_source
from cli import load_domains as load_domains_source
from cli import main as main_source
from cli import parse_keywords as parse_keywords_source
from cli import parse_search_providers as parse_search_providers_source
from cli import positive_int as positive_int_source
from cli import run_scan as run_scan_source
from constants import (
    AMASS_JSON_UNSUPPORTED_ERROR,
    AMASS_SRC_UNSUPPORTED_ERROR,
    AZURE_BLOB_API_VERSION,
    AZURE_BLOB_CNAME_SUFFIXES,
    AZURE_BLOB_LIKELY_EXISTS_ERROR_CODES,
    AZURE_BLOB_REFERENCE_URL,
    CT_HTTP_RETRIES,
    CLOUD_PROBE_HTTP_RETRIES,
    DEFAULT_HTTP_RETRIES,
    DEFAULT_USER_AGENT,
    HTTP_BACKOFF_BASE_SECONDS,
    HTTP_RETRYABLE_STATUS_CODES,
    SEARCH_HTTP_RETRIES,
    SUPPORTED_SEARCH_PROVIDERS,
    TAKEOVER_HTTP_RETRIES,
    TAKEOVER_REFERENCE_URL,
    TAKEOVER_SIGNATURES,
)
from core import check_tool as check_tool_source
from core import init_source_health as init_source_health_source
from core import log as log_source
from core import normalize_domain as normalize_domain_source
from core import normalize_source_health as normalize_source_health_source
from core import record_source_error as record_source_error_source
from core import run_command as run_command_source
from networking import fetch_url as fetch_url_source
from sources.ct import collect_ct_subdomains as collect_ct_subdomains_source
from sources.search import (
    build_commoncrawl_patterns as build_commoncrawl_patterns_source,
    build_dork_queries as build_dork_queries_source,
    classify_leak as classify_leak_source,
    collect_search_index_findings as collect_search_index_findings_source,
    fetch_commoncrawl_index_endpoint as fetch_commoncrawl_index_endpoint_source,
    fetch_commoncrawl_results as fetch_commoncrawl_results_source,
    parse_bing_results as parse_bing_results_source,
)
from sources.storage import (
    build_azure_container_wordlist as build_azure_container_wordlist_source,
    build_bucket_wordlist as build_bucket_wordlist_source,
    build_gcp_bucket_wordlist as build_gcp_bucket_wordlist_source,
    check_single_azure_blob_container as check_single_azure_blob_container_source,
    check_single_bucket_exists as check_single_bucket_exists_source,
    check_single_gcp_bucket_exists as check_single_gcp_bucket_exists_source,
    classify_azure_blob_status as classify_azure_blob_status_source,
    classify_gcp_status as classify_gcp_status_source,
    classify_s3_head_status as classify_s3_head_status_source,
    collect_azure_blob_findings as collect_azure_blob_findings_source,
    collect_gcp_bucket_findings as collect_gcp_bucket_findings_source,
    collect_s3_bucket_findings as collect_s3_bucket_findings_source,
    extract_azure_storage_account_from_cname as extract_azure_storage_account_from_cname_source,
    extract_bucket_candidates_from_hosts as extract_bucket_candidates_from_hosts_source,
    is_valid_azure_container_name as is_valid_azure_container_name_source,
    parse_azure_error_code as parse_azure_error_code_source,
    parse_s3_error_code as parse_s3_error_code_source,
    probe_gcp_list_access as probe_gcp_list_access_source,
    probe_s3_object_access as probe_s3_object_access_source,
    probe_s3_list_access as probe_s3_list_access_source,
    probe_s3_website_access as probe_s3_website_access_source,
    sanitize_azure_container_label as sanitize_azure_container_label_source,
    sanitize_bucket_label as sanitize_bucket_label_source,
    validate_gcp_bucket_name as validate_gcp_bucket_name_source,
    validate_s3_bucket_name as validate_s3_bucket_name_source,
)
from sources.takeover import (
    collect_subdomain_takeover_findings as collect_subdomain_takeover_findings_source,
    fetch_doh_cname_records as fetch_doh_cname_records_source,
    match_takeover_fingerprint as match_takeover_fingerprint_source,
    match_takeover_signature as match_takeover_signature_source,
    probe_takeover_endpoint as probe_takeover_endpoint_source,
)
from sources.tools import (
    collect_amass_subdomains as collect_amass_subdomains_source,
    collect_subfinder_subdomains as collect_subfinder_subdomains_source,
)
from models import Finding, ScanContext
from reporting import dedupe_findings, finding_sort_key, make_summary


def log(msg: str, verbose: bool = False, force: bool = False) -> None:
    return log_source(msg, verbose, force)


def init_source_health(name: str, enabled: bool = True) -> dict[str, Any]:
    return init_source_health_source(name, enabled)


def normalize_domain(value: str) -> str:
    return normalize_domain_source(value)


def normalize_source_health(source_health: dict[str, dict[str, Any]]) -> None:
    return normalize_source_health_source(source_health)


def record_source_error(
    stats: dict[str, Any],
    code: str,
    detail: str = "",
    *,
    timeout: bool = False,
    max_samples: int = 20,
) -> None:
    return record_source_error_source(
        stats,
        code,
        detail,
        timeout=timeout,
        max_samples=max_samples,
    )


def check_tool(name: str) -> bool:
    return check_tool_source(name)


def run_command(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    return run_command_source(cmd, timeout)


def parse_hosts_from_output(raw: str, domain: str) -> set[str]:
    return parse_hosts_from_output_source(
        raw,
        domain,
        normalize_domain=normalize_domain,
    )


def extract_host_from_value(value: Any) -> str:
    return extract_host_from_value_source(
        value,
        normalize_domain=normalize_domain,
        urlparse=parse.urlparse,
    )


def extract_source_names(record: dict[str, Any]) -> set[str]:
    return extract_source_names_source(record)


def iter_json_records(raw: str) -> list[dict[str, Any]]:
    return iter_json_records_source(raw, json_loads=json.loads)


def parse_structured_hosts_with_sources(
    raw: str, domain: str, host_keys: tuple[str, ...]
) -> dict[str, set[str]]:
    return parse_structured_hosts_with_sources_source(
        raw,
        domain,
        host_keys,
        iter_json_records=iter_json_records,
        extract_host_from_value=extract_host_from_value,
        extract_source_names=extract_source_names,
    )


def parse_subfinder_structured_output(raw: str, domain: str) -> dict[str, set[str]]:
    return parse_subfinder_structured_output_source(
        raw,
        domain,
        parse_structured_hosts_with_sources=parse_structured_hosts_with_sources,
    )


def parse_amass_structured_output(raw: str, domain: str) -> dict[str, set[str]]:
    return parse_amass_structured_output_source(
        raw,
        domain,
        parse_structured_hosts_with_sources=parse_structured_hosts_with_sources,
    )


def score_provenance_confidence(sources: set[str]) -> str:
    return score_provenance_confidence_source(sources)


def collect_subfinder_subdomains(
    context: ScanContext, health: Optional[dict[str, Any]] = None
) -> tuple[set[str], list[Finding]]:
    stats = health if health is not None else init_source_health("subfinder")
    return collect_subfinder_subdomains_source(
        context,
        stats,
        check_tool=check_tool,
        run_command=run_command,
        parse_subfinder_structured_output=parse_subfinder_structured_output,
        parse_hosts_from_output=parse_hosts_from_output,
        score_provenance_confidence=score_provenance_confidence,
        log=log,
    )


def collect_amass_subdomains(
    context: ScanContext, health: Optional[dict[str, Any]] = None
) -> tuple[set[str], list[Finding]]:
    stats = health if health is not None else init_source_health("amass")
    return collect_amass_subdomains_source(
        context,
        stats,
        check_tool=check_tool,
        run_command=run_command,
        parse_amass_structured_output=parse_amass_structured_output,
        parse_hosts_from_output=parse_hosts_from_output,
        score_provenance_confidence=score_provenance_confidence,
        log=log,
        amass_src_unsupported_error=AMASS_SRC_UNSUPPORTED_ERROR,
        amass_json_unsupported_error=AMASS_JSON_UNSUPPORTED_ERROR,
    )


def fetch_url(
    url: str,
    timeout: int,
    method: str = "GET",
    headers: Optional[dict[str, str]] = None,
    retries: int = DEFAULT_HTTP_RETRIES,
) -> tuple[int, str, dict[str, str]]:
    return fetch_url_source(
        url,
        timeout,
        method=method,
        headers=headers,
        retries=retries,
        default_user_agent=DEFAULT_USER_AGENT,
        http_retryable_status_codes=HTTP_RETRYABLE_STATUS_CODES,
        http_backoff_base_seconds=HTTP_BACKOFF_BASE_SECONDS,
        request_module=request,
        error_module=error,
        sleep_fn=sleep,
        random_uniform_fn=uniform,
    )


def fetch_url_ct(
    url: str,
    timeout: int,
    method: str = "GET",
    headers: Optional[dict[str, str]] = None,
    retries: int = CT_HTTP_RETRIES,
) -> tuple[int, str, dict[str, str]]:
    return fetch_url(
        url,
        timeout,
        method=method,
        headers=headers,
        retries=retries,
    )


def fetch_url_search(
    url: str,
    timeout: int,
    method: str = "GET",
    headers: Optional[dict[str, str]] = None,
    retries: int = SEARCH_HTTP_RETRIES,
) -> tuple[int, str, dict[str, str]]:
    return fetch_url(
        url,
        timeout,
        method=method,
        headers=headers,
        retries=retries,
    )


def fetch_url_takeover(
    url: str,
    timeout: int,
    method: str = "GET",
    headers: Optional[dict[str, str]] = None,
    retries: int = TAKEOVER_HTTP_RETRIES,
) -> tuple[int, str, dict[str, str]]:
    return fetch_url(
        url,
        timeout,
        method=method,
        headers=headers,
        retries=retries,
    )


def fetch_doh_cname_records(host: str, timeout: int) -> tuple[int, list[str], str]:
    return fetch_doh_cname_records_source(
        host,
        timeout,
        fetch_url=fetch_url_takeover,
        normalize_domain=normalize_domain,
        quote_plus=parse.quote_plus,
        json_loads=json.loads,
    )


def match_takeover_signature(cnames: list[str]) -> tuple[Optional[dict[str, Any]], str]:
    return match_takeover_signature_source(
        cnames,
        takeover_signatures=TAKEOVER_SIGNATURES,
        normalize_domain=normalize_domain,
    )


def probe_takeover_endpoint(host: str, timeout: int) -> tuple[str, int, str]:
    return probe_takeover_endpoint_source(
        host,
        timeout,
        fetch_url=fetch_url_takeover,
    )


def match_takeover_fingerprint(
    body: str, status: int, signature: dict[str, Any]
) -> Optional[str]:
    return match_takeover_fingerprint_source(body, status, signature)


def collect_subdomain_takeover_findings(
    context: ScanContext, hosts: set[str], health: Optional[dict[str, Any]] = None
) -> list[Finding]:
    stats = health if health is not None else init_source_health("takeover")
    return collect_subdomain_takeover_findings_source(
        context,
        hosts,
        stats,
        fetch_doh_cname_records=fetch_doh_cname_records,
        match_takeover_signature=match_takeover_signature,
        probe_takeover_endpoint=probe_takeover_endpoint,
        match_takeover_fingerprint=match_takeover_fingerprint,
        sanitize_bucket_label=sanitize_bucket_label,
        takeover_reference_url=TAKEOVER_REFERENCE_URL,
    )


def collect_ct_subdomains(
    context: ScanContext, health: Optional[dict[str, Any]] = None
) -> tuple[set[str], list[Finding]]:
    stats = health if health is not None else init_source_health("crt.sh")
    return collect_ct_subdomains_source(
        context,
        stats,
        fetch_url=fetch_url_ct,
        normalize_domain=normalize_domain,
        log=log,
    )


def build_dork_queries(domain: str) -> list[tuple[str, str]]:
    return build_dork_queries_source(domain)


def build_commoncrawl_patterns(domain: str) -> list[tuple[str, str]]:
    return build_commoncrawl_patterns_source(domain)


def fetch_commoncrawl_index_endpoint(timeout: int) -> Optional[str]:
    return fetch_commoncrawl_index_endpoint_source(
        timeout,
        fetch_url=fetch_url_search,
        json_loads=json.loads,
    )


def fetch_commoncrawl_results(
    index_endpoint: str, pattern: str, timeout: int, limit: int = 25
) -> tuple[int, list[dict[str, str]], str]:
    return fetch_commoncrawl_results_source(
        index_endpoint,
        pattern,
        timeout,
        limit=limit,
        fetch_url=fetch_url_search,
        iter_json_records=iter_json_records,
        quote_plus=parse.quote_plus,
    )


def parse_bing_results(html: str) -> list[dict[str, str]]:
    return parse_bing_results_source(html)


def classify_leak(url: str, snippet: str) -> tuple[str, str, str, list[str]]:
    return classify_leak_source(url, snippet)


def collect_search_index_findings(
    context: ScanContext, health: Optional[dict[str, Any]] = None
) -> tuple[set[str], list[Finding]]:
    stats = health if health is not None else init_source_health("search")
    return collect_search_index_findings_source(
        context,
        stats,
        build_dork_queries=build_dork_queries,
        build_commoncrawl_patterns=build_commoncrawl_patterns,
        fetch_commoncrawl_index_endpoint=fetch_commoncrawl_index_endpoint,
        fetch_commoncrawl_results=fetch_commoncrawl_results,
        fetch_url=fetch_url_search,
        parse_bing_results=parse_bing_results,
        classify_leak=classify_leak,
        log=log,
    )


def sanitize_bucket_label(value: str) -> str:
    return sanitize_bucket_label_source(value)


def sanitize_azure_container_label(value: str) -> str:
    return sanitize_azure_container_label_source(value)


def validate_s3_bucket_name(value: str) -> tuple[bool, str]:
    return validate_s3_bucket_name_source(value)


def validate_gcp_bucket_name(value: str) -> tuple[bool, str]:
    return validate_gcp_bucket_name_source(value)


def is_valid_azure_container_name(value: str) -> bool:
    return is_valid_azure_container_name_source(value)


def extract_bucket_candidates_from_hosts(hosts: set[str]) -> set[str]:
    return extract_bucket_candidates_from_hosts_source(
        hosts,
        sanitize_bucket_label=sanitize_bucket_label,
    )


def extract_azure_storage_account_from_cname(cname: str) -> str:
    return extract_azure_storage_account_from_cname_source(
        cname,
        normalize_domain=normalize_domain,
        azure_blob_cname_suffixes=AZURE_BLOB_CNAME_SUFFIXES,
    )


def parse_azure_error_code(headers: dict[str, str], body: str) -> str:
    return parse_azure_error_code_source(headers, body)


def parse_s3_error_code(headers: dict[str, str], body: str) -> str:
    return parse_s3_error_code_source(headers, body)


def classify_azure_blob_status(status: int, error_code: str) -> str:
    return classify_azure_blob_status_source(
        status,
        error_code,
        azure_blob_likely_exists_error_codes=AZURE_BLOB_LIKELY_EXISTS_ERROR_CODES,
    )


def build_azure_container_wordlist(
    context: ScanContext, discovered_hosts: set[str]
) -> set[str]:
    return build_azure_container_wordlist_source(
        context,
        discovered_hosts,
        sanitize_azure_container_label=sanitize_azure_container_label,
        is_valid_azure_container_name=is_valid_azure_container_name,
    )


def build_bucket_wordlist(context: ScanContext, discovered_hosts: set[str]) -> set[str]:
    return build_bucket_wordlist_source(
        context,
        discovered_hosts,
        sanitize_bucket_label=sanitize_bucket_label,
        extract_bucket_candidates_from_hosts=extract_bucket_candidates_from_hosts,
    )


def build_gcp_bucket_wordlist(
    context: ScanContext, discovered_hosts: set[str]
) -> set[str]:
    return build_gcp_bucket_wordlist_source(
        context,
        discovered_hosts,
        build_bucket_wordlist=build_bucket_wordlist,
        sanitize_bucket_label=sanitize_bucket_label,
    )


def classify_s3_head_status(status: int, region: str) -> str:
    return classify_s3_head_status_source(status, region)


def probe_s3_list_access(
    bucket: str, timeout: int, region: str = ""
) -> tuple[int, dict[str, str], str]:
    return probe_s3_list_access_source(
        bucket,
        timeout,
        region,
        fetch_url=fetch_url,
        parse_s3_error_code=parse_s3_error_code,
        cloud_probe_http_retries=CLOUD_PROBE_HTTP_RETRIES,
    )


def probe_s3_object_access(
    bucket: str, timeout: int, region: str = ""
) -> tuple[int, dict[str, str], str]:
    return probe_s3_object_access_source(
        bucket,
        timeout,
        region,
        fetch_url=fetch_url,
        parse_s3_error_code=parse_s3_error_code,
        cloud_probe_http_retries=CLOUD_PROBE_HTTP_RETRIES,
    )


def probe_s3_website_access(
    bucket: str, region: str, timeout: int
) -> tuple[int, dict[str, str], str]:
    return probe_s3_website_access_source(
        bucket,
        region,
        timeout,
        fetch_url=fetch_url,
        parse_s3_error_code=parse_s3_error_code,
        cloud_probe_http_retries=CLOUD_PROBE_HTTP_RETRIES,
    )


def check_single_bucket_exists(
    bucket: str,
    timeout: int,
    s3_list_probe: bool = True,
    s3_website_probe: bool = False,
    s3_probe_retries: int = 0,
) -> tuple[str, Optional[int], str, str, Optional[int]]:
    return check_single_bucket_exists_source(
        bucket,
        timeout,
        s3_list_probe=s3_list_probe,
        s3_website_probe=s3_website_probe,
        s3_probe_retries=s3_probe_retries,
        fetch_url=fetch_url,
        classify_s3_head_status=classify_s3_head_status,
        probe_s3_list_access=probe_s3_list_access,
        probe_s3_object_access=probe_s3_object_access,
        probe_s3_website_access=probe_s3_website_access,
        cloud_probe_http_retries=CLOUD_PROBE_HTTP_RETRIES,
    )


def collect_s3_bucket_findings(
    context: ScanContext, hosts: set[str], health: Optional[dict[str, Any]] = None
) -> list[Finding]:
    stats = health if health is not None else init_source_health("s3")
    return collect_s3_bucket_findings_source(
        context,
        hosts,
        stats,
        build_bucket_wordlist=build_bucket_wordlist,
        check_single_bucket_exists=check_single_bucket_exists,
        validate_s3_bucket_name=validate_s3_bucket_name,
        log=log,
    )


def classify_gcp_status(status: int) -> str:
    return classify_gcp_status_source(status)


def probe_gcp_list_access(bucket: str, timeout: int) -> int:
    return probe_gcp_list_access_source(
        bucket,
        timeout,
        fetch_url=fetch_url,
        cloud_probe_http_retries=CLOUD_PROBE_HTTP_RETRIES,
    )


def check_single_gcp_bucket_exists(
    bucket: str, timeout: int
) -> tuple[str, Optional[int], str, Optional[int]]:
    return check_single_gcp_bucket_exists_source(
        bucket,
        timeout,
        fetch_url=fetch_url,
        classify_gcp_status=classify_gcp_status,
        probe_gcp_list_access=probe_gcp_list_access,
        cloud_probe_http_retries=CLOUD_PROBE_HTTP_RETRIES,
    )


def collect_gcp_bucket_findings(
    context: ScanContext, hosts: set[str], health: Optional[dict[str, Any]] = None
) -> list[Finding]:
    stats = health if health is not None else init_source_health("gcp")
    return collect_gcp_bucket_findings_source(
        context,
        hosts,
        stats,
        build_gcp_bucket_wordlist=build_gcp_bucket_wordlist,
        check_single_gcp_bucket_exists=check_single_gcp_bucket_exists,
        validate_gcp_bucket_name=validate_gcp_bucket_name,
        log=log,
    )


def check_single_azure_blob_container(
    account: str, container: str, timeout: int
) -> tuple[str, str, int, str, str, str]:
    return check_single_azure_blob_container_source(
        account,
        container,
        timeout,
        fetch_url=fetch_url,
        parse_azure_error_code=parse_azure_error_code,
        classify_azure_blob_status=classify_azure_blob_status,
        azure_blob_api_version=AZURE_BLOB_API_VERSION,
        cloud_probe_http_retries=CLOUD_PROBE_HTTP_RETRIES,
    )


def collect_azure_blob_findings(
    context: ScanContext, hosts: set[str], health: Optional[dict[str, Any]] = None
) -> list[Finding]:
    stats = health if health is not None else init_source_health("azure")
    return collect_azure_blob_findings_source(
        context,
        hosts,
        stats,
        fetch_doh_cname_records=fetch_doh_cname_records,
        extract_azure_storage_account_from_cname=extract_azure_storage_account_from_cname,
        build_azure_container_wordlist=build_azure_container_wordlist,
        check_single_azure_blob_container=check_single_azure_blob_container,
        azure_blob_reference_url=AZURE_BLOB_REFERENCE_URL,
    )


def parse_keywords(value: Optional[str]) -> list[str]:
    return parse_keywords_source(value)


def parse_search_providers(value: Optional[str]) -> list[str]:
    return parse_search_providers_source(
        value,
        supported_search_providers=SUPPORTED_SEARCH_PROVIDERS,
    )


def positive_int(value: str) -> int:
    return positive_int_source(value)


def load_domains(single: Optional[str], domain_list: Optional[str]) -> list[str]:
    return load_domains_source(
        single,
        domain_list,
        normalize_domain=normalize_domain,
    )


def run_scan(args: argparse.Namespace) -> dict:
    return run_scan_source(
        args,
        load_domains=load_domains,
        parse_search_providers=parse_search_providers,
        parse_keywords=parse_keywords,
        scan_context_cls=ScanContext,
        init_source_health=init_source_health,
        collect_subfinder_subdomains=collect_subfinder_subdomains,
        collect_amass_subdomains=collect_amass_subdomains,
        collect_ct_subdomains=collect_ct_subdomains,
        collect_search_index_findings=collect_search_index_findings,
        collect_s3_bucket_findings=collect_s3_bucket_findings,
        collect_gcp_bucket_findings=collect_gcp_bucket_findings,
        collect_azure_blob_findings=collect_azure_blob_findings,
        collect_subdomain_takeover_findings=collect_subdomain_takeover_findings,
        dedupe_findings=dedupe_findings,
        make_summary=make_summary,
        finding_sort_key=finding_sort_key,
        asdict_fn=asdict,
        normalize_source_health=normalize_source_health,
        now_utc_iso=lambda: datetime.now(timezone.utc).isoformat(),
    )


def build_parser() -> argparse.ArgumentParser:
    return build_parser_source(positive_int=positive_int)


def main() -> None:
    return main_source(build_parser=build_parser, run_scan=run_scan)


if __name__ == "__main__":
    main()
