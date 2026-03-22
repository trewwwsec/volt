from dataclasses import dataclass, field
from typing import Optional


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
    search_providers: list[str]
    timeout: int
    tool_timeout: int
    threads: int
    max_bucket_candidates: int
    verbose: bool
    s3_list_probe: bool = True
    s3_website_probe: bool = False
    s3_probe_retries: int = 0
    gcp_dual_endpoint_probe: bool = False
    gcp_probe_retries: int = 0
    azure_blob_object_probe: bool = False
