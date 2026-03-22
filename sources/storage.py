from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_address
import re
from time import time_ns
from typing import Any, Callable, Optional
from urllib.parse import quote

from core import record_source_error
from models import Evidence, Finding, ScanContext


def sanitize_bucket_label(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9.-]", "-", value.lower())
    cleaned = cleaned.strip("-.")
    cleaned = re.sub(r"\.{2,}", ".", cleaned)
    cleaned = re.sub(r"-{2,}", "-", cleaned)
    return cleaned


def validate_s3_bucket_name(value: str) -> tuple[bool, str]:
    candidate = value.strip().lower()
    if not (3 <= len(candidate) <= 63):
        return False, "length"
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*[a-z0-9]", candidate):
        return False, "charset_or_boundary"
    if ".." in candidate:
        return False, "adjacent_periods"
    try:
        ip_address(candidate)
        return False, "ip_address_style"
    except ValueError:
        pass

    reserved_prefixes = ("xn--", "sthree-", "amzn-s3-demo-")
    if candidate.startswith(reserved_prefixes):
        return False, "reserved_prefix"

    reserved_suffixes = ("-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3")
    if candidate.endswith(reserved_suffixes):
        return False, "reserved_suffix"

    # Keep bucket findings focused on true bucket-name signals, not endpoint families.
    if "s3-accesspoint" in candidate or "s3-control" in candidate:
        return False, "endpoint_family"

    return True, ""


def validate_gcp_bucket_name(value: str) -> tuple[bool, str]:
    candidate = value.strip().lower()
    if not candidate:
        return False, "empty"
    if not re.fullmatch(r"[a-z0-9._-]+", candidate):
        return False, "charset"
    if not candidate[0].isalnum() or not candidate[-1].isalnum():
        return False, "charset_or_boundary"
    if len(candidate) < 3:
        return False, "length"

    if "." in candidate:
        if len(candidate) > 222:
            return False, "length"
        if ".." in candidate:
            return False, "adjacent_periods"
        for part in candidate.split("."):
            if not (1 <= len(part) <= 63):
                return False, "dot_component_length"
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part):
                return False, "dot_component_syntax"
    elif len(candidate) > 63:
        return False, "length"

    try:
        ip_address(candidate)
        return False, "ip_address_style"
    except ValueError:
        pass

    if candidate.startswith("goog"):
        return False, "reserved_prefix"
    reserved_substrings = ("google", "g00gle", "g0ogle", "go0gle")
    if any(part in candidate for part in reserved_substrings):
        return False, "reserved_substring"

    return True, ""


def sanitize_azure_container_label(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9-]", "-", value.lower())
    cleaned = re.sub(r"-{2,}", "-", cleaned)
    cleaned = cleaned.strip("-")
    return cleaned


def is_valid_azure_container_name(value: str) -> bool:
    if value in {"$web", "$root", "$logs"}:
        return True
    if not (3 <= len(value) <= 63):
        return False
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*[a-z0-9]", value):
        return False
    return "--" not in value


def extract_bucket_candidates_from_hosts(
    hosts: set[str],
    *,
    sanitize_bucket_label: Callable[[str], str],
) -> set[str]:
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


def extract_azure_storage_account_from_cname(
    cname: str,
    *,
    normalize_domain: Callable[[str], str],
    azure_blob_cname_suffixes: tuple[str, ...],
    azure_blob_web_cname_suffixes: tuple[str, ...],
    azure_blob_dns_zone_cname_suffixes: tuple[str, ...],
) -> str:
    candidate = normalize_domain(cname.rstrip("."))
    if not candidate:
        return ""

    def extract_account_with_suffix(value: str, suffix: str) -> str:
        if value == suffix or not value.endswith(f".{suffix}"):
            return ""
        prefix = value[: -(len(suffix) + 1)]
        if prefix.startswith("asverify."):
            prefix = prefix[len("asverify.") :]
        account = prefix.split(".", 1)[0]
        if re.fullmatch(r"[a-z0-9]{3,24}", account):
            return account
        return ""

    for suffix in azure_blob_cname_suffixes:
        account = extract_account_with_suffix(candidate, suffix)
        if account:
            return account

    for suffix in azure_blob_web_cname_suffixes:
        account = extract_account_with_suffix(candidate, suffix)
        if account:
            return account

    for suffix in azure_blob_dns_zone_cname_suffixes:
        if candidate == suffix or not candidate.endswith(f".{suffix}"):
            continue
        prefix = candidate[: -(len(suffix) + 1)]
        if prefix.startswith("asverify."):
            prefix = prefix[len("asverify.") :]
        labels = [label for label in prefix.split(".") if label]
        if not labels:
            continue
        account = labels[0]
        if len(labels) >= 2 and not re.fullmatch(r"z[0-9]{1,2}", labels[1]):
            continue
        if re.fullmatch(r"[a-z0-9]{3,24}", account):
            return account
    return ""


def build_azure_container_wordlist(
    context: ScanContext,
    discovered_hosts: set[str],
    *,
    sanitize_azure_container_label: Callable[[str], str],
    is_valid_azure_container_name: Callable[[str], bool],
) -> set[str]:
    words: set[str] = set()
    common = {
        "assets",
        "backup",
        "backups",
        "data",
        "files",
        "logs",
        "media",
        "public",
        "static",
        "uploads",
    }

    for domain in context.domains:
        base = domain.split(".")[0]
        words.add(sanitize_azure_container_label(base))
        words.add(sanitize_azure_container_label(domain.replace(".", "-")))

    if context.organization:
        words.add(
            sanitize_azure_container_label(context.organization.replace(" ", "-"))
        )

    for kw in context.keywords:
        words.add(sanitize_azure_container_label(kw))

    for host in discovered_hosts:
        parts = host.split(".")
        if len(parts) > 2:
            words.add(sanitize_azure_container_label(parts[0]))
            words.add(sanitize_azure_container_label("-".join(parts[:-2])))

    words.update(common)

    patterns = [
        "{w}",
        "{w}-assets",
        "{w}-backup",
        "{w}-files",
        "{w}-media",
        "{w}-static",
        "{w}-uploads",
    ]

    candidates: set[str] = set()
    for word in words:
        if not word:
            continue
        for pattern in patterns:
            candidate = sanitize_azure_container_label(pattern.format(w=word))
            if is_valid_azure_container_name(candidate):
                candidates.add(candidate)

    return candidates


def build_bucket_wordlist(
    context: ScanContext,
    discovered_hosts: set[str],
    *,
    sanitize_bucket_label: Callable[[str], str],
    extract_bucket_candidates_from_hosts: Callable[[set[str]], set[str]],
) -> set[str]:
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
        "{w}-backup",
        "{w}-backups",
        "{w}-data",
        "{w}-public",
        "{w}-static",
        "{w}-media",
        "{w}-cdn",
        "{w}-files",
        "{w}-uploads",
    ]

    candidates: set[str] = set()
    for word in words:
        if not word:
            continue
        for pattern in patterns:
            candidate = sanitize_bucket_label(pattern.format(w=word))
            if 3 <= len(candidate) <= 63:
                candidates.add(candidate)

    return candidates


def build_gcp_bucket_wordlist(
    context: ScanContext,
    discovered_hosts: set[str],
    *,
    build_bucket_wordlist: Callable[[ScanContext, set[str]], set[str]],
    sanitize_bucket_label: Callable[[str], str],
) -> set[str]:
    candidates = set(build_bucket_wordlist(context, discovered_hosts))
    dotted_candidates: set[str] = set()

    domain_roots = [
        domain.strip().lower().rstrip(".")
        for domain in context.domains
        if domain and "." in domain
    ]

    common_prefixes = {
        "assets",
        "backup",
        "cdn",
        "data",
        "files",
        "media",
        "static",
        "uploads",
    }

    for root in domain_roots:
        dotted_candidates.add(root)
        for prefix in common_prefixes:
            dotted_candidates.add(f"{prefix}.{root}")

    for kw in context.keywords:
        label = sanitize_bucket_label(kw).replace(".", "-").strip("-")
        if not label:
            continue
        for root in domain_roots:
            dotted_candidates.add(f"{label}.{root}")

    for host in discovered_hosts:
        normalized = host.strip().lower().rstrip(".")
        if not normalized or "." not in normalized:
            continue
        dotted_candidates.add(normalized)
        parts = normalized.split(".")
        if len(parts) >= 2:
            dotted_candidates.add(".".join(parts[-2:]))
        if len(parts) >= 3:
            dotted_candidates.add(".".join(parts[-3:]))

    candidates.update(candidate for candidate in dotted_candidates if candidate)
    return candidates


def build_gcp_xml_api_endpoint(bucket: str, virtual_hosted: bool = False) -> str:
    if virtual_hosted:
        return f"https://{bucket}.storage.googleapis.com"
    return f"https://storage.googleapis.com/{bucket}"


def parse_azure_error_code(headers: dict[str, str], body: str) -> str:
    for key, value in headers.items():
        if key.lower() == "x-ms-error-code" and value.strip():
            return value.strip()

    match = re.search(r"<Code>\s*([A-Za-z0-9]+)\s*</Code>", body)
    if match:
        return match.group(1).strip()
    return ""


def parse_s3_error_code(headers: dict[str, str], body: str) -> str:
    for key, value in headers.items():
        if key.lower() in {"x-amz-error-code", "x-amz-errorcode"} and value.strip():
            return value.strip()

    match = re.search(r"<Code>\s*([A-Za-z0-9]+)\s*</Code>", body)
    if match:
        return match.group(1).strip()
    return ""


def parse_gcp_error_code(body: str) -> str:
    match = re.search(r"<Code>\s*([A-Za-z0-9]+)\s*</Code>", body)
    if match:
        return match.group(1).strip()
    return ""


def classify_azure_blob_status(
    status: int,
    error_code: str,
    *,
    azure_blob_likely_exists_error_codes: set[str],
    azure_blob_not_exists_error_codes: set[str],
) -> str:
    normalized_error = error_code.strip()
    if status == 200:
        return "confirmed_public"
    if normalized_error in azure_blob_not_exists_error_codes:
        return "not_exists"
    if status in {401, 403}:
        if not normalized_error:
            return "likely_exists"
        if normalized_error in azure_blob_likely_exists_error_codes:
            return "likely_exists"
        return "unknown"
    if status == 409 and normalized_error in azure_blob_likely_exists_error_codes:
        return "likely_exists"
    return "unknown"


def classify_s3_head_status(status: int, region: str) -> str:
    if status == 200:
        return "confirmed_exists"
    if status in {301, 302, 307, 308, 403}:
        return "likely_exists" if region else "unknown"
    if status in {400, 404}:
        return "unknown"
    return "unknown"


def build_s3_rest_endpoint(bucket: str, region: str = "") -> str:
    if region:
        return f"https://{bucket}.s3.{region}.amazonaws.com"
    return f"https://{bucket}.s3.amazonaws.com"


def probe_s3_list_access(
    bucket: str,
    timeout: int,
    region: str = "",
    *,
    fetch_url: Callable[..., tuple[int, str, dict[str, str]]],
    parse_s3_error_code: Callable[[dict[str, str], str], str],
    cloud_probe_http_retries: int,
) -> tuple[int, dict[str, str], str]:
    url = f"{build_s3_rest_endpoint(bucket, region)}/?list-type=2&max-keys=0"
    status, body, headers = fetch_url(
        url, timeout=timeout, method="GET", retries=cloud_probe_http_retries
    )
    return status, headers, parse_s3_error_code(headers, body)


def probe_s3_object_access(
    bucket: str,
    timeout: int,
    region: str = "",
    *,
    fetch_url: Callable[..., tuple[int, str, dict[str, str]]],
    parse_s3_error_code: Callable[[dict[str, str], str], str],
    cloud_probe_http_retries: int,
) -> tuple[int, dict[str, str], str]:
    probe_key = f"__subrecon_probe__{time_ns()}"
    url = f"{build_s3_rest_endpoint(bucket, region)}/{probe_key}"
    status, body, headers = fetch_url(
        url, timeout=timeout, method="GET", retries=cloud_probe_http_retries
    )
    return status, headers, parse_s3_error_code(headers, body)


def probe_s3_website_access(
    bucket: str,
    region: str,
    timeout: int,
    *,
    fetch_url: Callable[..., tuple[int, str, dict[str, str]]],
    parse_s3_error_code: Callable[[dict[str, str], str], str],
    cloud_probe_http_retries: int,
) -> tuple[int, dict[str, str], str]:
    # S3 website endpoints are HTTP-only.
    website_hosts = [
        f"{bucket}.s3-website-{region}.amazonaws.com",
        f"{bucket}.s3-website.{region}.amazonaws.com",
    ]
    for host in website_hosts:
        status, body, headers = fetch_url(
            f"http://{host}/",
            timeout=timeout,
            method="GET",
            retries=cloud_probe_http_retries,
        )
        if status != 0:
            return status, headers, parse_s3_error_code(headers, body)
    return 0, {}, ""


def check_single_bucket_exists(
    bucket: str,
    timeout: int,
    s3_list_probe: bool = True,
    s3_website_probe: bool = False,
    s3_probe_retries: int = 0,
    *,
    fetch_url: Callable[..., tuple[int, str, dict[str, str]]],
    classify_s3_head_status: Callable[[int, str], str],
    probe_s3_list_access: Callable[[str, int, str], tuple[int, dict[str, str], str]],
    probe_s3_object_access: Callable[[str, int, str], tuple[int, dict[str, str], str]],
    probe_s3_website_access: Callable[[str, str, int], tuple[int, dict[str, str], str]],
    cloud_probe_http_retries: int,
) -> tuple[str, Optional[int], str, str, Optional[int]]:
    retries = max(cloud_probe_http_retries, int(s3_probe_retries))
    url = f"{build_s3_rest_endpoint(bucket)}/"
    status, _, headers = fetch_url(url, timeout=timeout, method="HEAD", retries=retries)

    region = headers.get("x-amz-bucket-region") or headers.get("X-Amz-Bucket-Region")
    existence = classify_s3_head_status(status, region or "")
    list_status: Optional[int] = None

    if s3_list_probe and existence == "unknown":
        list_region = region or ""
        list_status, list_headers, _list_error_code = probe_s3_list_access(
            bucket, timeout, list_region
        )
        if list_status == 200:
            existence = "confirmed_exists"
        elif list_status == 403:
            existence = "likely_exists"
        elif list_status in {301, 302, 307, 308}:
            existence = "likely_exists"
        if not region:
            region = list_headers.get("x-amz-bucket-region") or list_headers.get(
                "X-Amz-Bucket-Region"
            )

    if existence == "unknown":
        object_status, object_headers, object_error_code = probe_s3_object_access(
            bucket, timeout, region or ""
        )
        if not region:
            region = object_headers.get("x-amz-bucket-region") or object_headers.get(
                "X-Amz-Bucket-Region"
            )
        if object_status == 200:
            existence = "confirmed_exists"
        elif object_status == 403 and object_error_code in {
            "AccessDenied",
            "AllAccessDisabled",
        }:
            existence = "likely_exists"
        elif object_status == 404 and object_error_code == "NoSuchKey":
            existence = "confirmed_exists"
        elif object_status == 404 and object_error_code == "NoSuchBucket":
            existence = "not_exists"

    if s3_website_probe and existence == "unknown" and region:
        website_status, _website_headers, website_error_code = probe_s3_website_access(
            bucket, region, timeout
        )
        if website_status == 200:
            existence = "confirmed_exists"
        elif website_status == 403:
            existence = "likely_exists"
        elif website_status in {301, 302, 307, 308}:
            existence = "likely_exists"
        elif website_status == 404 and website_error_code == "NoSuchBucket":
            existence = "not_exists"

    return bucket, status, existence, region or "", list_status


def collect_s3_bucket_findings(
    context: ScanContext,
    hosts: set[str],
    stats: dict[str, Any],
    *,
    build_bucket_wordlist: Callable[[ScanContext, set[str]], set[str]],
    check_single_bucket_exists: Callable[
        [str, int, bool, bool, int], tuple[str, Optional[int], str, str, Optional[int]]
    ],
    validate_s3_bucket_name: Callable[[str], tuple[bool, str]],
    log: Callable[[str, bool, bool], None],
) -> list[Finding]:
    findings: list[Finding] = []
    raw_candidates = sorted(build_bucket_wordlist(context, hosts))
    reason_counts: dict[str, int] = {}
    candidates: list[str] = []
    for candidate in raw_candidates:
        valid, reason = validate_s3_bucket_name(candidate)
        if valid:
            candidates.append(candidate)
            continue
        if reason:
            reason_counts[reason] = int(reason_counts.get(reason, 0)) + 1

    stats["raw_candidates"] = len(raw_candidates)
    stats["filtered_invalid_candidates"] = len(raw_candidates) - len(candidates)
    stats["filtered_reasons"] = reason_counts
    stats["filtered_endpoint_family"] = int(reason_counts.get("endpoint_family", 0))
    stats["filtered_reserved_name"] = int(
        reason_counts.get("reserved_suffix", 0)
    ) + int(reason_counts.get("reserved_prefix", 0))
    if not candidates:
        stats["status"] = "ok_no_candidates"
        if raw_candidates:
            stats["notes"].append(
                "all generated S3 candidates were invalid by AWS naming rules"
            )
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
                context.s3_website_probe,
                context.s3_probe_retries,
            ): bucket
            for bucket in candidates
        }
        for fut in as_completed(futures):
            checked += 1
            bucket = futures[fut]
            try:
                _, status, existence, region, list_status = fut.result()
            except Exception:
                record_source_error(
                    stats,
                    "s3_worker_exception",
                    detail=f"bucket={bucket}",
                )
                continue

            if context.verbose and checked % 50 == 0:
                log(
                    f"[s3] progress {checked}/{len(candidates)}",
                    context.verbose,
                )

            if status is None or status == 0:
                record_source_error(
                    stats,
                    "s3_probe_failed",
                    detail=f"bucket={bucket} head_status={status}",
                )
                continue
            if (
                existence == "likely_exists"
                and status in {400, 404}
                and list_status == 403
            ):
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
            list_note = (
                f" list_probe_status={list_status}" if list_status is not None else ""
            )
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


def classify_gcp_status(status: int, error_code: str = "") -> str:
    if status == 200:
        return "confirmed_exists"
    if status == 404 and error_code in {"NoSuchKey", "NoSuchObject"}:
        return "confirmed_exists"
    if status == 404 and error_code == "NoSuchBucket":
        return "not_exists"
    if status in {301, 302, 307, 308, 401, 403}:
        return "likely_exists"
    if status in {400, 404}:
        return "unknown"
    return "unknown"


def probe_gcp_list_access(
    bucket: str,
    timeout: int,
    virtual_hosted: bool = False,
    gcp_probe_retries: int = 0,
    *,
    fetch_url: Callable[..., tuple[int, str, dict[str, str]]],
    parse_gcp_error_code: Callable[[str], str],
    cloud_probe_http_retries: int,
) -> tuple[int, str]:
    retries = max(cloud_probe_http_retries, int(gcp_probe_retries))
    url = (
        f"{build_gcp_xml_api_endpoint(bucket, virtual_hosted)}/?list-type=2&max-keys=1"
    )
    status, body, _ = fetch_url(url, timeout=timeout, method="GET", retries=retries)
    return status, parse_gcp_error_code(body)


def probe_gcp_object_access(
    bucket: str,
    timeout: int,
    virtual_hosted: bool = False,
    gcp_probe_retries: int = 0,
    *,
    fetch_url: Callable[..., tuple[int, str, dict[str, str]]],
    parse_gcp_error_code: Callable[[str], str],
    cloud_probe_http_retries: int,
) -> tuple[int, str]:
    retries = max(cloud_probe_http_retries, int(gcp_probe_retries))
    probe_key = f"__subrecon_probe__{time_ns()}"
    url = f"{build_gcp_xml_api_endpoint(bucket, virtual_hosted)}/{probe_key}"
    status, body, _ = fetch_url(url, timeout=timeout, method="GET", retries=retries)
    return status, parse_gcp_error_code(body)


def check_single_gcp_bucket_exists(
    bucket: str,
    timeout: int,
    gcp_dual_endpoint_probe: bool = False,
    gcp_probe_retries: int = 0,
    *,
    fetch_url: Callable[..., tuple[int, str, dict[str, str]]],
    classify_gcp_status: Callable[[int, str], str],
    probe_gcp_list_access: Callable[[str, int, bool, int], tuple[int, str]],
    probe_gcp_object_access: Callable[[str, int, bool, int], tuple[int, str]],
    parse_gcp_error_code: Callable[[str], str],
    cloud_probe_http_retries: int,
) -> tuple[str, Optional[int], str, Optional[int]]:
    retries = max(cloud_probe_http_retries, int(gcp_probe_retries))

    def evaluate_endpoint(virtual_hosted: bool) -> tuple[int, str, Optional[int]]:
        url = f"{build_gcp_xml_api_endpoint(bucket, virtual_hosted)}/"
        status, body, _ = fetch_url(
            url, timeout=timeout, method="HEAD", retries=retries
        )
        existence = classify_gcp_status(status, parse_gcp_error_code(body))
        list_status: Optional[int] = None

        if existence == "unknown":
            list_status, list_error_code = probe_gcp_list_access(
                bucket, timeout, virtual_hosted, gcp_probe_retries
            )
            list_existence = classify_gcp_status(list_status, list_error_code)
            if list_existence != "unknown":
                existence = list_existence

        if existence == "unknown":
            object_status, object_error_code = probe_gcp_object_access(
                bucket, timeout, virtual_hosted, gcp_probe_retries
            )
            object_existence = classify_gcp_status(object_status, object_error_code)
            if object_existence != "unknown":
                existence = object_existence

        return status, existence, list_status

    status, existence, list_status = evaluate_endpoint(False)

    # Optional fallback for endpoint behavior mismatches.
    if gcp_dual_endpoint_probe and "." not in bucket and existence == "unknown":
        fallback_status, fallback_existence, fallback_list_status = evaluate_endpoint(
            True
        )
        if fallback_existence != "unknown":
            status = fallback_status
            existence = fallback_existence
            if fallback_list_status is not None or list_status is None:
                list_status = fallback_list_status

    return bucket, status, existence, list_status


def collect_gcp_bucket_findings(
    context: ScanContext,
    hosts: set[str],
    stats: dict[str, Any],
    *,
    build_gcp_bucket_wordlist: Callable[[ScanContext, set[str]], set[str]],
    check_single_gcp_bucket_exists: Callable[
        [str, int, bool, int], tuple[str, Optional[int], str, Optional[int]]
    ],
    validate_gcp_bucket_name: Callable[[str], tuple[bool, str]],
    log: Callable[[str, bool, bool], None],
) -> list[Finding]:
    findings: list[Finding] = []
    generic_collision_candidates = {
        "assets",
        "backup",
        "backups",
        "cdn",
        "data",
        "data-lake",
        "files",
        "logs",
        "media",
        "my-bucket",
        "mybucket",
        "raw-data",
        "static",
        "terraform-state",
        "terraform-state-prod",
        "test-bucket",
        "tf-state",
        "tfstate",
        "uploads",
    }
    affinity_terms: set[str] = set()

    def add_affinity_terms(value: str) -> None:
        for token in re.split(r"[^a-z0-9]+", value.lower()):
            if len(token) >= 4:
                affinity_terms.add(token)

    for domain in context.domains:
        add_affinity_terms(domain)
    if context.organization:
        add_affinity_terms(context.organization)
    for keyword in context.keywords:
        add_affinity_terms(keyword)

    def has_target_affinity(candidate: str) -> bool:
        normalized = candidate.lower().replace(".", "-")
        return any(term in normalized for term in affinity_terms)

    raw_candidates = sorted(build_gcp_bucket_wordlist(context, hosts))
    reason_counts: dict[str, int] = {}
    candidates: list[str] = []
    for candidate in raw_candidates:
        valid, reason = validate_gcp_bucket_name(candidate)
        if valid:
            candidates.append(candidate)
            continue
        if reason:
            reason_counts[reason] = int(reason_counts.get(reason, 0)) + 1

    stats["raw_candidates"] = len(raw_candidates)
    stats["filtered_invalid_candidates"] = len(raw_candidates) - len(candidates)
    stats["filtered_reasons"] = reason_counts
    stats["filtered_reserved_name"] = int(
        reason_counts.get("reserved_prefix", 0)
    ) + int(reason_counts.get("reserved_substring", 0))
    if not candidates:
        stats["status"] = "ok_no_candidates"
        if raw_candidates:
            stats["notes"].append(
                "all generated GCS candidates were invalid by naming rules"
            )
        return findings

    stats["queried"] = len(candidates)
    if len(candidates) > context.max_bucket_candidates:
        log(
            "[gcp] candidate list capped at "
            f"{context.max_bucket_candidates} (from {len(candidates)})",
            context.verbose,
            force=True,
        )
        candidates = candidates[: context.max_bucket_candidates]
        stats["queried"] = len(candidates)

    checked = 0
    ambiguous = 0
    suppressed_weak_likely = 0
    with ThreadPoolExecutor(max_workers=context.threads) as pool:
        futures = {
            pool.submit(
                check_single_gcp_bucket_exists,
                bucket,
                context.timeout,
                context.gcp_dual_endpoint_probe,
                context.gcp_probe_retries,
            ): bucket
            for bucket in candidates
        }
        for fut in as_completed(futures):
            checked += 1
            bucket = futures[fut]
            try:
                _, status, existence, list_status = fut.result()
            except Exception:
                record_source_error(
                    stats,
                    "gcp_worker_exception",
                    detail=f"bucket={bucket}",
                )
                continue

            if context.verbose and checked % 50 == 0:
                log(f"[gcp] progress {checked}/{len(candidates)}", context.verbose)

            if status is None or status == 0:
                record_source_error(
                    stats,
                    "gcp_probe_failed",
                    detail=f"bucket={bucket} head_status={status}",
                )
                continue
            normalized_candidate = bucket.lower().replace(".", "-")
            if (
                existence == "likely_exists"
                and status == 403
                and normalized_candidate in generic_collision_candidates
                and not has_target_affinity(bucket)
            ):
                suppressed_weak_likely += 1
                ambiguous += 1
                continue
            if existence in {"not_exists", "unknown"}:
                ambiguous += 1
                continue

            tags = ["cloud", "gcp", "passive"]
            if existence == "confirmed_exists":
                severity = "medium"
                confidence = "high"
                if list_status == 200 and status != 200:
                    title = "Publicly listable GCP bucket (anonymous probe)"
                    description = (
                        "Anonymous bucket listing probe succeeded (HTTP 200). "
                        "Validate access controls in a permitted workflow."
                    )
                    tags.append("listable")
                else:
                    title = "Potentially public GCP bucket"
                    description = (
                        "Bucket endpoint returned HTTP 200. Validate access controls "
                        "in a permitted environment."
                    )
            else:
                severity = "low"
                confidence = "medium"
                title = "GCP bucket name likely exists (HTTP signal)"
                description = (
                    "Bucket endpoint response suggests the bucket name exists, "
                    "but anonymous listing access is not available."
                )
                tags.append("likely-exists")

            list_note = (
                f" list_probe_status={list_status}" if list_status is not None else ""
            )
            findings.append(
                Finding(
                    asset_type="gcp_bucket",
                    asset=bucket,
                    severity=severity,
                    confidence=confidence,
                    title=title,
                    description=description,
                    source="gcp-storage-head",
                    tags=tags,
                    evidence=[
                        Evidence(
                            source_url=f"https://storage.googleapis.com/{bucket}/",
                            note=f"HEAD status={status}. existence={existence}.{list_note}",
                        )
                    ],
                )
            )

    stats["ambiguous"] = ambiguous
    stats["suppressed_weak_likely"] = suppressed_weak_likely
    stats["hosts"] = len(findings)
    stats["findings"] = len(findings)
    if stats["errors"]:
        stats["status"] = "partial" if findings else "error"
    elif findings:
        stats["status"] = "ok"
    else:
        stats["status"] = "ok_no_results"

    return findings


def check_single_azure_blob_container(
    account: str,
    container: str,
    timeout: int,
    *,
    fetch_url: Callable[..., tuple[int, str, dict[str, str]]],
    parse_azure_error_code: Callable[[dict[str, str], str], str],
    classify_azure_blob_status: Callable[[int, str], str],
    azure_blob_api_version: str,
    cloud_probe_http_retries: int,
) -> tuple[str, str, int, str, str, str]:
    encoded_container = quote(container, safe="")
    url = (
        f"https://{account}.blob.core.windows.net/{encoded_container}"
        "?restype=container&comp=list&maxresults=1"
    )
    status, body, headers = fetch_url(
        url, timeout=timeout, method="GET", retries=cloud_probe_http_retries
    )
    error_code = parse_azure_error_code(headers, body)
    if error_code == "FeatureVersionMismatch":
        status, body, headers = fetch_url(
            url,
            timeout=timeout,
            method="GET",
            headers={"x-ms-version": azure_blob_api_version},
            retries=cloud_probe_http_retries,
        )
        error_code = parse_azure_error_code(headers, body)
    existence = classify_azure_blob_status(status, error_code)
    return account, container, status, existence, error_code, url


def collect_azure_blob_findings(
    context: ScanContext,
    hosts: set[str],
    stats: dict[str, Any],
    *,
    fetch_doh_cname_records: Callable[[str, int], tuple[int, list[str], str]],
    extract_azure_storage_account_from_cname: Callable[[str], str],
    build_azure_container_wordlist: Callable[[ScanContext, set[str]], set[str]],
    check_single_azure_blob_container: Callable[
        [str, str, int], tuple[str, str, int, str, str, str]
    ],
    azure_blob_reference_url: str,
    azure_blob_system_containers: tuple[str, ...],
) -> list[Finding]:
    findings: list[Finding] = []
    if not hosts:
        stats["status"] = "ok_no_results"
        stats["notes"].append("no discovered hosts available for azure blob checks")
        return findings

    candidates = sorted(host for host in hosts if host and "." in host)
    stats["candidate_hosts"] = len(candidates)
    stats["doh_queries"] = len(candidates)
    stats["queried"] = stats["doh_queries"]

    account_to_hosts: dict[str, set[str]] = {}

    def resolve_account_candidates(host: str) -> tuple[str, int, list[str], str]:
        doh_status, cnames, doh_url = fetch_doh_cname_records(host, context.timeout)
        accounts: set[str] = set()
        host_account = extract_azure_storage_account_from_cname(host)
        if host_account:
            accounts.add(host_account)
        for cname in cnames:
            account = extract_azure_storage_account_from_cname(cname)
            if account:
                accounts.add(account)
        return host, doh_status, sorted(accounts), doh_url

    with ThreadPoolExecutor(max_workers=context.threads) as pool:
        futures = {
            pool.submit(resolve_account_candidates, host): host for host in candidates
        }
        for fut in as_completed(futures):
            try:
                host, doh_status, accounts, _doh_url = fut.result()
            except Exception:
                record_source_error(
                    stats,
                    "azure_doh_worker_exception",
                    detail="unhandled exception resolving azure account candidates",
                )
                continue
            if doh_status == 0:
                record_source_error(
                    stats,
                    "azure_doh_failed",
                    detail=f"host={host}",
                )
                continue
            for account in accounts:
                account_to_hosts.setdefault(account, set()).add(host)

    if not account_to_hosts:
        if stats["errors"]:
            stats["status"] = "partial"
        else:
            stats["status"] = "ok_no_results"
            stats["notes"].append("no azure blob storage CNAME targets found")
        return findings

    regular_container_candidates = sorted(
        build_azure_container_wordlist(context, hosts)
    )
    container_candidates: list[str] = []
    seen_candidates: set[str] = set()
    for container in azure_blob_system_containers:
        if container in seen_candidates:
            continue
        container_candidates.append(container)
        seen_candidates.add(container)
    for container in regular_container_candidates:
        if container in seen_candidates:
            continue
        container_candidates.append(container)
        seen_candidates.add(container)
    if not container_candidates:
        stats["status"] = "ok_no_candidates"
        return findings

    stats["storage_accounts"] = len(account_to_hosts)
    stats["container_candidates"] = len(container_candidates)
    stats["system_container_candidates"] = len(azure_blob_system_containers)

    probe_targets: list[tuple[str, str]] = []
    for account in sorted(account_to_hosts):
        for container in container_candidates:
            if len(probe_targets) >= context.max_bucket_candidates:
                break
            probe_targets.append((account, container))
        if len(probe_targets) >= context.max_bucket_candidates:
            break
    if len(account_to_hosts) * len(container_candidates) > len(probe_targets):
        stats["notes"].append(
            "azure blob probe target list capped by --max-bucket-candidates"
        )
    stats["probes"] = len(probe_targets)
    stats["queried"] = stats["doh_queries"] + stats["probes"]

    likely_exists = 0
    not_exists = 0
    system_container_hits = 0
    system_container_set = set(azure_blob_system_containers)
    error_code_counts: dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=context.threads) as pool:
        futures = {
            pool.submit(
                check_single_azure_blob_container, account, container, context.timeout
            ): (
                account,
                container,
            )
            for account, container in probe_targets
        }
        for fut in as_completed(futures):
            account, container = futures[fut]
            try:
                _, _, status, existence, error_code, url = fut.result()
            except Exception:
                record_source_error(
                    stats,
                    "azure_probe_worker_exception",
                    detail=f"account={account} container={container}",
                )
                continue

            if status == 0:
                record_source_error(
                    stats,
                    "azure_probe_failed",
                    detail=f"account={account} container={container}",
                )
                continue
            if error_code:
                error_code_counts[error_code] = (
                    int(error_code_counts.get(error_code, 0)) + 1
                )

            if existence == "likely_exists":
                likely_exists += 1
                continue
            if existence == "not_exists":
                not_exists += 1
                continue

            if existence != "confirmed_public":
                continue
            if container in system_container_set:
                system_container_hits += 1

            linked_hosts = sorted(account_to_hosts.get(account, set()))
            source_hosts = ", ".join(linked_hosts[:5]) if linked_hosts else "unknown"
            extra = "..." if len(linked_hosts) > 5 else ""
            code_note = f"; x-ms-error-code={error_code}" if error_code else ""
            findings.append(
                Finding(
                    asset_type="azure_blob_container",
                    asset=f"{account}/{container}",
                    severity="high",
                    confidence="high",
                    title="Publicly listable Azure Blob container",
                    description=(
                        "Anonymous List Blobs request succeeded (HTTP 200). "
                        "Validate public access policy and exposed data in an authorized workflow."
                    ),
                    source="azure-blob-list",
                    tags=["cloud", "azure", "blob", "passive", "listable"],
                    evidence=[
                        Evidence(
                            source_url=url,
                            note=f"GET status={status}. existence={existence}{code_note}",
                        ),
                        Evidence(
                            source_url=f"https://{account}.blob.core.windows.net/",
                            note=(
                                "Storage account inferred from discovered host CNAME(s): "
                                f"{source_hosts}{extra}"
                            ),
                        ),
                        Evidence(
                            source_url=azure_blob_reference_url,
                            note=(
                                "Azure Blob public-access behavior reference "
                                "(list/properties probing patterns)."
                            ),
                        ),
                    ],
                )
            )

    stats["likely_exists"] = likely_exists
    stats["not_exists"] = not_exists
    stats["error_code_counts"] = error_code_counts
    stats["system_container_hits"] = system_container_hits
    stats["hosts"] = len(findings)
    stats["findings"] = len(findings)
    if stats["errors"]:
        stats["status"] = "partial" if findings else "error"
    elif findings:
        stats["status"] = "ok"
    else:
        stats["status"] = "ok_no_results"

    return findings
