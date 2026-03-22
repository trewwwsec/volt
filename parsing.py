from __future__ import annotations

import re
from typing import Any, Callable


def parse_hosts_from_output(
    raw: str,
    domain: str,
    *,
    normalize_domain: Callable[[str], str],
) -> set[str]:
    out: set[str] = set()
    for line in raw.splitlines():
        host = normalize_domain(line.replace("*.", ""))
        if not host:
            continue
        if host == domain or host.endswith(f".{domain}"):
            out.add(host)
    return out


def extract_host_from_value(
    value: Any,
    *,
    normalize_domain: Callable[[str], str],
    urlparse: Callable[[str], Any],
) -> str:
    if not isinstance(value, str):
        return ""
    candidate = value.strip()
    if not candidate:
        return ""
    if "://" in candidate:
        parsed = urlparse(candidate)
        if parsed.hostname:
            return normalize_domain(parsed.hostname)
    candidate = candidate.split("/", 1)[0]
    return normalize_domain(candidate.replace("*.", ""))


def extract_source_names(record: dict[str, Any]) -> set[str]:
    out: set[str] = set()

    def add_source(value: Any) -> None:
        if not isinstance(value, str):
            return
        normalized = re.sub(r"\s+", " ", value.strip().lower())
        if normalized:
            out.add(normalized)

    for key in ("source", "src"):
        add_source(record.get(key))

    for key in ("sources",):
        value = record.get(key)
        if isinstance(value, str):
            add_source(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    add_source(item)
                elif isinstance(item, dict):
                    for nested_key in ("name", "source", "id"):
                        if nested_key in item:
                            add_source(item.get(nested_key))
                            break

    tag = record.get("tag")
    if isinstance(tag, str) and tag.strip():
        out.add(f"tag:{tag.strip().lower()}")

    return out


def iter_json_records(
    raw: str,
    *,
    json_loads: Callable[[str], Any],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    text = raw.strip()
    if not text:
        return records

    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = json_loads(text)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, dict):
                        records.append(item)
            return records
        except Exception:
            pass

    for line in raw.splitlines():
        candidate = line.strip()
        if not candidate or not candidate.startswith("{"):
            continue
        try:
            parsed = json_loads(candidate)
        except Exception:
            continue
        if isinstance(parsed, dict):
            records.append(parsed)

    return records


def parse_structured_hosts_with_sources(
    raw: str,
    domain: str,
    host_keys: tuple[str, ...],
    *,
    iter_json_records: Callable[[str], list[dict[str, Any]]],
    extract_host_from_value: Callable[[Any], str],
    extract_source_names: Callable[[dict[str, Any]], set[str]],
) -> dict[str, set[str]]:
    host_sources: dict[str, set[str]] = {}
    for record in iter_json_records(raw):
        host = ""
        for key in host_keys:
            host = extract_host_from_value(record.get(key))
            if host:
                break
        if not host:
            continue
        if not (host == domain or host.endswith(f".{domain}")):
            continue
        host_sources.setdefault(host, set()).update(extract_source_names(record))
    return host_sources


def parse_subfinder_structured_output(
    raw: str,
    domain: str,
    *,
    parse_structured_hosts_with_sources: Callable[
        [str, str, tuple[str, ...]],
        dict[str, set[str]],
    ],
) -> dict[str, set[str]]:
    return parse_structured_hosts_with_sources(
        raw, domain, ("host", "url", "input", "name")
    )


def parse_amass_structured_output(
    raw: str,
    domain: str,
    *,
    parse_structured_hosts_with_sources: Callable[
        [str, str, tuple[str, ...]],
        dict[str, set[str]],
    ],
) -> dict[str, set[str]]:
    return parse_structured_hosts_with_sources(
        raw,
        domain,
        ("name", "host", "hostname", "domain"),
    )


def score_provenance_confidence(sources: set[str]) -> str:
    source_count = len([src for src in sources if not src.startswith("tag:")])
    if source_count >= 3:
        return "high"
    if source_count >= 1:
        return "medium"
    return "low"
