from __future__ import annotations

import json
from typing import Any, Callable
from urllib import parse

from core import record_source_error
from models import Evidence, Finding, ScanContext


def _fetch_crtsh_rows(
    domain: str,
    timeout: int,
    *,
    fetch_url: Callable[..., tuple[int, str, dict[str, str]]],
) -> tuple[list[dict[str, Any]] | None, str | None]:
    query = parse.quote(f"%.{domain}")
    url = f"https://crt.sh/?q={query}&output=json"
    status, body, _ = fetch_url(url, timeout=timeout)
    if status != 200 or not body.strip():
        return None, f"http_{status}"
    try:
        rows = json.loads(body)
    except json.JSONDecodeError:
        return None, "json_decode"
    if not isinstance(rows, list):
        return None, "json_schema"
    return rows, None


def _fetch_certspotter_rows(
    domain: str,
    timeout: int,
    *,
    fetch_url: Callable[..., tuple[int, str, dict[str, str]]],
) -> tuple[list[dict[str, Any]] | None, str | None]:
    encoded = parse.quote(domain)
    url = (
        "https://api.certspotter.com/v1/issuances"
        f"?domain={encoded}&include_subdomains=true&expand=dns_names"
    )
    status, body, _ = fetch_url(url, timeout=timeout)
    if status != 200 or not body.strip():
        return None, f"certspotter_http_{status}"
    try:
        rows = json.loads(body)
    except json.JSONDecodeError:
        return None, "certspotter_json_decode"
    if not isinstance(rows, list):
        return None, "certspotter_json_schema"
    return rows, None


def collect_ct_subdomains(
    context: ScanContext,
    stats: dict[str, Any],
    *,
    fetch_url: Callable[..., tuple[int, str, dict[str, str]]],
    normalize_domain: Callable[[str], str],
    log: Callable[[str, bool, bool], None],
) -> tuple[set[str], list[Finding]]:
    findings: list[Finding] = []
    discovered: set[str] = set()

    for domain in context.domains:
        stats["queried"] += 1
        rows, crt_error = _fetch_crtsh_rows(
            domain, context.timeout, fetch_url=fetch_url
        )
        row_source = "crt.sh"

        if crt_error:
            record_source_error(
                stats,
                crt_error,
                detail=f"domain={domain} query=crt.sh",
            )
            log(f"[ct] {domain}: primary source failed ({crt_error})", context.verbose)

            stats["queried"] += 1
            rows, certspotter_error = _fetch_certspotter_rows(
                domain, context.timeout, fetch_url=fetch_url
            )
            row_source = "certspotter"
            if certspotter_error:
                record_source_error(
                    stats,
                    certspotter_error,
                    detail=f"domain={domain} query=certspotter",
                )
                log(
                    f"[ct] {domain}: fallback source failed ({certspotter_error})",
                    context.verbose,
                )
                continue
            fallback_note = "crt.sh degraded; certspotter fallback used"
            stats["notes"].append(fallback_note)
            log(f"[ct] {domain}: {fallback_note}", context.verbose)

        if not rows:
            continue

        for row in rows:
            if not isinstance(row, dict):
                continue
            names: list[str] = []
            if row_source == "crt.sh":
                names = str(row.get("name_value", "")).splitlines()
            else:
                dns_names = row.get("dns_names")
                if isinstance(dns_names, list):
                    names = [str(item) for item in dns_names]
                elif isinstance(dns_names, str):
                    names = [dns_names]
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
