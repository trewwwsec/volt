from __future__ import annotations

import json
from typing import Any, Callable
from urllib import parse

from core import record_source_error
from models import Evidence, Finding, ScanContext


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
        query = parse.quote(f"%.{domain}")
        url = f"https://crt.sh/?q={query}&output=json"

        status, body, _ = fetch_url(url, timeout=context.timeout)
        if status != 200 or not body.strip():
            record_source_error(
                stats,
                f"http_{status}",
                detail=f"domain={domain} query=crt.sh",
            )
            log(f"[ct] {domain}: no data (status={status})", context.verbose)
            continue

        try:
            rows = json.loads(body)
        except json.JSONDecodeError:
            record_source_error(
                stats,
                "json_decode",
                detail=f"domain={domain} query=crt.sh",
            )
            log(f"[ct] {domain}: failed to parse ct json", context.verbose)
            continue
        if not isinstance(rows, list):
            record_source_error(
                stats,
                "json_schema",
                detail=f"domain={domain} query=crt.sh",
            )
            log(f"[ct] {domain}: unexpected ct json schema", context.verbose)
            continue

        for row in rows:
            if not isinstance(row, dict):
                continue
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
