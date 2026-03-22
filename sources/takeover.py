from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Optional

from core import record_source_error
from models import Evidence, Finding, ScanContext


def fetch_doh_cname_records(
    host: str,
    timeout: int,
    *,
    fetch_url: Callable[..., tuple[int, str, dict[str, str]]],
    normalize_domain: Callable[[str], str],
    quote_plus: Callable[[str], str],
    json_loads: Callable[[str], Any],
) -> tuple[int, list[str], str]:
    query_url = f"https://dns.google/resolve?name={quote_plus(host)}&type=CNAME"
    status, body, _ = fetch_url(
        query_url,
        timeout=timeout,
        headers={"Accept": "application/dns-json"},
    )
    if status != 200 or not body.strip():
        return status, [], query_url

    try:
        payload = json_loads(body)
    except Exception:
        return status, [], query_url

    answers = payload.get("Answer") if isinstance(payload, dict) else None
    if not isinstance(answers, list):
        return status, [], query_url

    cnames: set[str] = set()
    for answer in answers:
        if not isinstance(answer, dict):
            continue
        data = answer.get("data")
        if not isinstance(data, str):
            continue
        cname = normalize_domain(data.rstrip("."))
        if cname:
            cnames.add(cname)
    return status, sorted(cnames), query_url


def match_takeover_signature(
    cnames: list[str],
    *,
    takeover_signatures: list[dict[str, Any]],
    normalize_domain: Callable[[str], str],
) -> tuple[Optional[dict[str, Any]], str]:
    for cname in cnames:
        for signature in takeover_signatures:
            suffixes = signature.get("cname_suffixes", [])
            if not isinstance(suffixes, list):
                continue
            for raw_suffix in suffixes:
                if not isinstance(raw_suffix, str):
                    continue
                suffix = normalize_domain(raw_suffix.rstrip("."))
                if not suffix:
                    continue
                if cname == suffix or cname.endswith(f".{suffix}"):
                    return signature, cname
    return None, ""


def probe_takeover_endpoint(
    host: str,
    timeout: int,
    *,
    fetch_url: Callable[..., tuple[int, str, dict[str, str]]],
) -> tuple[str, int, str]:
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        status, body, _ = fetch_url(url, timeout=timeout)
        if status != 0:
            return url, status, body
    return f"https://{host}/", 0, ""


def match_takeover_fingerprint(
    body: str, status: int, signature: dict[str, Any]
) -> Optional[str]:
    candidates = signature.get("fingerprints", [])
    if not isinstance(candidates, list):
        candidates = []
    body_lower = body.lower()
    for candidate in candidates:
        if not isinstance(candidate, str):
            continue
        if candidate.lower() in body_lower:
            return candidate
    expected_status = signature.get("http_status")
    if isinstance(expected_status, int) and expected_status == status:
        return f"http_status={status}"
    return None


def collect_subdomain_takeover_findings(
    context: ScanContext,
    hosts: set[str],
    stats: dict[str, Any],
    *,
    fetch_doh_cname_records: Callable[[str, int], tuple[int, list[str], str]],
    match_takeover_signature: Callable[
        [list[str]], tuple[Optional[dict[str, Any]], str]
    ],
    probe_takeover_endpoint: Callable[[str, int], tuple[str, int, str]],
    match_takeover_fingerprint: Callable[[str, int, dict[str, Any]], Optional[str]],
    sanitize_bucket_label: Callable[[str], str],
    takeover_reference_url: str,
) -> list[Finding]:
    findings: list[Finding] = []
    if not hosts:
        stats["status"] = "ok_no_results"
        stats["notes"].append("no discovered hosts available for takeover checks")
        return findings

    candidates = sorted(host for host in hosts if host and "." in host)
    stats["queried"] = len(candidates)

    def evaluate(host: str) -> tuple[str, Optional[dict[str, Any]]]:
        doh_status, cnames, doh_url = fetch_doh_cname_records(host, context.timeout)
        if doh_status == 0:
            return "doh_error", {"host": host}
        if not cnames:
            return "no_cname", {"host": host, "doh_url": doh_url}

        signature, matched_cname = match_takeover_signature(cnames)
        if not signature:
            return "no_signature_match", {"host": host, "doh_url": doh_url}

        probe_url, probe_status, body = probe_takeover_endpoint(host, context.timeout)
        if probe_status == 0:
            return "probe_error", {
                "host": host,
                "doh_url": doh_url,
                "matched_cname": matched_cname,
            }

        fingerprint = match_takeover_fingerprint(body, probe_status, signature)
        if not fingerprint:
            return "no_fingerprint_match", {
                "host": host,
                "doh_url": doh_url,
                "matched_cname": matched_cname,
                "probe_url": probe_url,
                "probe_status": probe_status,
            }

        return "confirmed", {
            "host": host,
            "doh_url": doh_url,
            "cnames": cnames,
            "matched_cname": matched_cname,
            "probe_url": probe_url,
            "probe_status": probe_status,
            "fingerprint": fingerprint,
            "signature": signature,
        }

    matched_cname_hosts = 0
    edge_case_hits = 0
    with ThreadPoolExecutor(max_workers=context.threads) as pool:
        futures = {pool.submit(evaluate, host): host for host in candidates}
        for fut in as_completed(futures):
            try:
                state, data = fut.result()
            except Exception:
                record_source_error(
                    stats,
                    "takeover_worker_exception",
                    detail="unhandled exception evaluating candidate host",
                )
                continue

            if state == "doh_error":
                host = str(data.get("host", "")) if isinstance(data, dict) else ""
                record_source_error(
                    stats,
                    "doh_lookup_failed",
                    detail=f"host={host}",
                )
                continue
            if state == "probe_error":
                host = str(data.get("host", "")) if isinstance(data, dict) else ""
                record_source_error(
                    stats,
                    "takeover_probe_failed",
                    detail=f"host={host}",
                )
                matched_cname_hosts += 1
                continue
            if state != "confirmed" or data is None:
                if state in {"no_fingerprint_match"}:
                    matched_cname_hosts += 1
                continue

            signature = data["signature"]
            provider = str(signature.get("provider", "Unknown provider"))
            edge_case = bool(signature.get("edge_case"))
            if edge_case:
                edge_case_hits += 1

            matched_cname_hosts += 1
            title = f"Potential subdomain takeover via {provider}"
            if edge_case:
                title = (
                    f"Potential subdomain takeover signal via {provider} (edge case)"
                )

            findings.append(
                Finding(
                    asset_type="subdomain_takeover",
                    asset=str(data["host"]),
                    severity=str(signature.get("severity", "medium")),
                    confidence=str(signature.get("confidence", "medium")),
                    title=title,
                    description=(
                        "CNAME points to a known takeover-prone provider and the landing page "
                        "matched an unclaimed-service fingerprint."
                    ),
                    source="takeover-fingerprint",
                    tags=[
                        "passive",
                        "takeover",
                        sanitize_bucket_label(provider.replace(" ", "-")),
                        *(["edge-case"] if edge_case else []),
                    ],
                    evidence=[
                        Evidence(
                            source_url=str(data["doh_url"]),
                            note=(
                                f"CNAME chain: {', '.join(data['cnames'][:5])}; "
                                f"matched={data['matched_cname']}"
                            ),
                        ),
                        Evidence(
                            source_url=str(data["probe_url"]),
                            note=(
                                f"HTTP status={data['probe_status']}; "
                                f"matched fingerprint='{data['fingerprint']}'"
                            ),
                        ),
                        Evidence(
                            source_url=takeover_reference_url,
                            note="Provider fingerprint reference dataset.",
                        ),
                    ],
                )
            )

    stats["candidate_hosts"] = len(candidates)
    stats["cname_matches"] = matched_cname_hosts
    stats["edge_case_hits"] = edge_case_hits
    stats["hosts"] = len(findings)
    stats["findings"] = len(findings)
    if stats["errors"]:
        stats["status"] = "partial" if findings else "error"
    elif findings:
        stats["status"] = "ok"
    else:
        stats["status"] = "ok_no_results"
    return findings
