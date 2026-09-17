#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from volt import check_single_bucket_exists

DEFAULT_CANDIDATES = [
    "toolbox2",
    "noaa-goes19",
    "noaa-goes18",
    "noaa-goes17",
    "noaa-goes16",
    "commoncrawl",
    "sentinel-cogs",
    "landsat-pds",
    "aws-public-blockchain",
    "hrrrzarr",
    "digitalcorpora",
]


def parse_candidates(value: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in value.split(","):
        candidate = raw.strip().lower()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        out.append(candidate)
    return out


def is_viable_probe(probe: dict[str, Any]) -> bool:
    existence = probe.get("existence", "")
    status = probe.get("status")
    region = str(probe.get("region") or "").strip()
    if existence == "confirmed_exists":
        return True
    if existence == "likely_exists":
        if status in {200, 301, 302, 307, 308, 403}:
            return True
        # Passive website probe can infer existence from endpoint redirects.
        if status in {400, 404} and region:
            return True
    return False


def choose_best_probe(probes: list[dict[str, Any]]) -> dict[str, Any] | None:
    confirmed = [
        probe for probe in probes if probe.get("existence") == "confirmed_exists"
    ]
    if confirmed:
        return confirmed[0]
    likely = [probe for probe in probes if is_viable_probe(probe)]
    if likely:
        return likely[0]
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Select a live S3 canary target for reliability testing."
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=8,
        help="Per-bucket probe timeout seconds (default: 8).",
    )
    parser.add_argument(
        "--candidates",
        default=",".join(DEFAULT_CANDIDATES),
        help="Comma-separated candidate bucket names.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit structured JSON output instead of bucket name only.",
    )
    args = parser.parse_args()

    candidates = parse_candidates(args.candidates)
    probes: list[dict[str, Any]] = []
    for bucket in candidates:
        _bucket, status, existence, region, list_status = check_single_bucket_exists(
            bucket,
            args.timeout,
            True,
            True,
            0,
        )
        probes.append(
            {
                "bucket": bucket,
                "status": status,
                "existence": existence,
                "region": region,
                "list_status": list_status,
            }
        )

    selected = choose_best_probe(probes)
    if args.json:
        print(
            json.dumps(
                {
                    "selected": selected,
                    "candidates_tested": len(candidates),
                    "probe_timeout": args.timeout,
                    "probes": probes,
                },
                indent=2,
                sort_keys=True,
            )
        )
    elif selected:
        print(selected["bucket"])
    else:
        print("")

    return 0 if selected else 1


if __name__ == "__main__":
    raise SystemExit(main())
