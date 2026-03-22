from collections import Counter

from models import Finding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    out: list[Finding] = []
    for finding in findings:
        if finding.asset_type in {
            "subdomain",
            "s3_bucket",
            "gcp_bucket",
            "azure_blob_container",
            "subdomain_takeover",
        }:
            key = (finding.asset_type, finding.asset.lower(), "")
        else:
            key = (finding.asset_type, finding.asset.lower(), finding.title.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def finding_sort_key(finding: Finding) -> tuple[int, str, str, str]:
    severity_rank = SEVERITY_ORDER.get(finding.severity.lower(), 99)
    return (
        severity_rank,
        finding.asset_type,
        finding.asset.lower(),
        finding.title.lower(),
    )


def make_summary(findings: list[Finding]) -> dict:
    by_type = Counter(f.asset_type for f in findings)
    by_severity = Counter(f.severity for f in findings)

    return {
        "total_findings": len(findings),
        "by_type": dict(sorted(by_type.items())),
        "by_severity": dict(sorted(by_severity.items())),
    }
