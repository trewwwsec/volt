from __future__ import annotations

from typing import Any, Callable

from core import record_source_error
from models import Evidence, Finding, ScanContext

AMASS_TIMEOUT_GRACE_SECONDS = 30


def collect_subfinder_subdomains(
    context: ScanContext,
    stats: dict[str, Any],
    *,
    check_tool: Callable[[str], bool],
    run_command: Callable[[list[str], int], tuple[int, str, str]],
    parse_subfinder_structured_output: Callable[[str, str], dict[str, set[str]]],
    parse_hosts_from_output: Callable[[str, str], set[str]],
    score_provenance_confidence: Callable[[set[str]], str],
    log: Callable[[str, bool, bool], None],
) -> tuple[set[str], list[Finding]]:
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
            record_source_error(
                stats,
                "subfinder_timeout",
                detail=f"domain={domain} timeout={context.tool_timeout}s",
                timeout=True,
            )
            print(
                f"    [subfinder] {domain}: timed out after {context.tool_timeout}s "
                "(try increasing --tool-timeout)"
            )
            continue
        if rc != 0 and not parsed:
            err = (stderr or "").strip().splitlines()
            detail = err[-1] if err else "unknown error"
            record_source_error(
                stats,
                "subfinder_command_failed",
                detail=f"domain={domain} rc={rc} detail={detail}",
            )
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
    context: ScanContext,
    stats: dict[str, Any],
    *,
    check_tool: Callable[[str], bool],
    run_command: Callable[[list[str], int], tuple[int, str, str]],
    parse_amass_structured_output: Callable[[str, str], dict[str, set[str]]],
    parse_hosts_from_output: Callable[[str, str], set[str]],
    score_provenance_confidence: Callable[[set[str]], str],
    log: Callable[[str, bool, bool], None],
    amass_src_unsupported_error: str,
    amass_json_unsupported_error: str,
) -> tuple[set[str], list[Finding]]:
    if not check_tool("amass"):
        log("[amass] tool not found; skipping", context.verbose)
        stats["status"] = "skipped_tool_missing"
        stats["notes"].append("amass not installed")
        return set(), []

    hosts: set[str] = set()
    host_sources: dict[str, set[str]] = {}
    structured_domains = 0
    fallback_domains = 0
    src_compat_fallbacks = 0
    json_compat_fallbacks = 0
    timeout_retries = 0
    timeout_exhausted_domains = 0
    for domain in context.domains:
        stats["queried"] += 1
        amass_timeout_minutes = max(1, (context.tool_timeout + 59) // 60)
        amass_command_timeout = (
            amass_timeout_minutes * 60
        ) + AMASS_TIMEOUT_GRACE_SECONDS
        base_cmd = [
            "amass",
            "enum",
            "-passive",
            "-d",
            domain,
            "-timeout",
            str(amass_timeout_minutes),
        ]
        cmd_with_src = [
            *base_cmd,
            "-src",
            "-json",
            "/dev/stdout",
        ]
        cmd_without_src = [
            *base_cmd,
            "-json",
            "/dev/stdout",
        ]
        cmd_plain = [*base_cmd]
        cmd_plain_timeout_retry = [*base_cmd, "-nocolor", "-silent", "-norecursive"]

        rc, stdout, stderr = run_command(cmd_with_src, timeout=amass_command_timeout)
        used_structured_mode = True
        err_text = f"{stderr}\n{stdout}".lower()
        if rc != 0 and amass_src_unsupported_error in err_text:
            src_compat_fallbacks += 1
            note = (
                "amass -src unsupported by local version; falling back to "
                "amass passive json mode without source metadata"
            )
            if note not in stats["notes"]:
                stats["notes"].append(note)
            print(
                f"    [amass] {domain}: local amass does not support -src; retrying without -src"
            )
            rc, stdout, stderr = run_command(
                cmd_without_src, timeout=amass_command_timeout
            )
            err_text = f"{stderr}\n{stdout}".lower()

        if rc != 0 and amass_json_unsupported_error in err_text:
            used_structured_mode = False
            json_compat_fallbacks += 1
            note = (
                "amass -json unsupported by local version; falling back to "
                "plain passive output parsing"
            )
            if note not in stats["notes"]:
                stats["notes"].append(note)
            print(
                f"    [amass] {domain}: local amass does not support -json; retrying plain output mode"
            )
            rc, stdout, stderr = run_command(cmd_plain, timeout=amass_command_timeout)

        structured: dict[str, set[str]] = {}
        if used_structured_mode:
            structured = parse_amass_structured_output(stdout, domain)
        if structured:
            structured_domains += 1
            parsed = set(structured.keys())
            for host, sources in structured.items():
                host_sources.setdefault(host, set()).update(sources)
        else:
            fallback_domains += 1
            parsed = parse_hosts_from_output(f"{stdout}\n{stderr}", domain)
            for host in parsed:
                host_sources.setdefault(host, set())

            if rc == 124 and not parsed:
                timeout_retries += 1
                note = (
                    "amass timed out in structured mode; retrying reliability fallback "
                    "with plain passive output"
                )
                if note not in stats["notes"]:
                    stats["notes"].append(note)
                print(
                    f"    [amass] {domain}: timed out after {context.tool_timeout}s; retrying reliability fallback"
                )
                rc, stdout, stderr = run_command(
                    cmd_plain_timeout_retry,
                    timeout=amass_command_timeout,
                )
                parsed = parse_hosts_from_output(f"{stdout}\n{stderr}", domain)
                for host in parsed:
                    host_sources.setdefault(host, set())

                if rc == 124 and not parsed:
                    timeout_exhausted_domains += 1
                    record_source_error(
                        stats,
                        "amass_timeout",
                        detail=(
                            f"domain={domain} timeout={context.tool_timeout}s "
                            "(structured + fallback)"
                        ),
                        timeout=True,
                    )
                    print(
                        f"    [amass] {domain}: fallback also timed out after {context.tool_timeout}s"
                    )
                    continue

                if rc == 0 and not parsed:
                    note = (
                        "amass reliability fallback returned no hosts in this environment; "
                        "continuing without amass findings"
                    )
                    if note not in stats["notes"]:
                        stats["notes"].append(note)
        hosts.update(parsed)

        if rc != 0 and not parsed:
            err = (stderr or "").strip().splitlines()
            detail = err[-1] if err else "unknown error"
            record_source_error(
                stats,
                "amass_command_failed",
                detail=f"domain={domain} rc={rc} detail={detail}",
            )
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
    stats["src_compat_fallbacks"] = src_compat_fallbacks
    stats["json_compat_fallbacks"] = json_compat_fallbacks
    stats["timeout_retries"] = timeout_retries
    stats["timeout_exhausted_domains"] = timeout_exhausted_domains
    if not hosts and not stats["timeouts"] and not stats["errors"] and stats["queried"]:
        stats["status"] = "ok_no_results"
    if stats["timeouts"] or stats["errors"]:
        if not hosts and stats["timeouts"] and not stats["errors"]:
            stats["status"] = "partial"
        else:
            stats["status"] = "partial" if hosts else "error"
    return hosts, findings
