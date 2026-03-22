from __future__ import annotations

from typing import Any

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (compatible; subrecon-passive/1.0; +https://github.com/)"
)
SUPPORTED_SEARCH_PROVIDERS = {"bing", "commoncrawl"}
TAKEOVER_REFERENCE_URL = "https://github.com/EdOverflow/can-i-take-over-xyz"
AZURE_BLOB_REFERENCE_URL = (
    "https://techcommunity.microsoft.com/blog/azurepaasblog/"
    "public-access-is-not-permitted-on-this-storage-account/3521288"
)
AZURE_BLOB_API_VERSION = "2021-12-02"
TAKEOVER_SIGNATURES: list[dict[str, Any]] = [
    {
        "provider": "Read the Docs",
        "cname_suffixes": ["readthedocs.io"],
        "fingerprints": [
            "The link you have followed or the URL that you entered does not exist."
        ],
        "severity": "high",
        "confidence": "high",
        "edge_case": False,
    },
    {
        "provider": "Bitbucket",
        "cname_suffixes": ["bitbucket.io"],
        "fingerprints": ["Repository not found"],
        "severity": "high",
        "confidence": "high",
        "edge_case": False,
    },
    {
        "provider": "Help Scout Docs",
        "cname_suffixes": ["helpscoutdocs.com"],
        "fingerprints": ["No settings were found for this company:"],
        "severity": "high",
        "confidence": "high",
        "edge_case": False,
    },
    {
        "provider": "Surge",
        "cname_suffixes": ["surge.sh", "na-west1.surge.sh"],
        "fingerprints": ["project not found"],
        "severity": "high",
        "confidence": "high",
        "edge_case": False,
    },
    {
        "provider": "GitHub Pages",
        "cname_suffixes": ["github.io"],
        "fingerprints": ["There isn't a GitHub Pages site here."],
        "severity": "medium",
        "confidence": "low",
        "edge_case": True,
    },
]

AZURE_BLOB_CNAME_SUFFIXES = (
    "blob.core.windows.net",
    "privatelink.blob.core.windows.net",
)
AZURE_BLOB_LIKELY_EXISTS_ERROR_CODES = {
    "AuthorizationFailure",
    "AuthenticationFailed",
    "PublicAccessNotPermitted",
    "AccountIsDisabled",
}
HTTP_RETRYABLE_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504}
DEFAULT_HTTP_RETRIES = 2
HTTP_BACKOFF_BASE_SECONDS = 0.35
CT_HTTP_RETRIES = 2
SEARCH_HTTP_RETRIES = 2
TAKEOVER_HTTP_RETRIES = 1
CLOUD_PROBE_HTTP_RETRIES = 0
AMASS_SRC_UNSUPPORTED_ERROR = "flag provided but not defined: -src"
AMASS_JSON_UNSUPPORTED_ERROR = "flag provided but not defined: -json"
