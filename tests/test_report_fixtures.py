import argparse
import json
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

import cli
import volt
from models import Evidence, Finding, ScanContext


FIXTURE_DIR = Path(__file__).parent / "fixtures"


class ReportFixtureTest(unittest.TestCase):
    def test_run_scan_report_fixture_stable(self) -> None:
        args = argparse.Namespace(
            domain="example.com",
            domain_list=None,
            output="/tmp/ignored.json",
            organization=None,
            keywords=None,
            search_providers="commoncrawl",
            timeout=5,
            tool_timeout=30,
            threads=2,
            verbose=False,
            max_bucket_candidates=40,
            s3_list_probe=True,
            no_ct=False,
            no_subfinder=True,
            no_amass=True,
            no_search=True,
            no_s3=False,
            no_gcp=True,
            no_azure=True,
            no_takeover=True,
        )

        def fake_ct(_context, health):
            health["queried"] = 1
            health["hosts"] = 1
            health["findings"] = 1
            health["status"] = "ok"
            return {
                "a.example.com",
            }, [
                Finding(
                    asset_type="subdomain",
                    asset="a.example.com",
                    severity="info",
                    confidence="high",
                    title="Subdomain discovered via CT logs",
                    description="Observed in Certificate Transparency records.",
                    source="crt.sh",
                    tags=["passive", "ct"],
                    evidence=[
                        Evidence(
                            source_url="https://crt.sh/?q=a.example.com",
                            note="Matched CT entry.",
                        )
                    ],
                )
            ]

        def fake_s3(_context, _hosts, health):
            health["queried"] = 1
            health["hosts"] = 1
            health["findings"] = 1
            health["status"] = "ok"
            return [
                Finding(
                    asset_type="s3_bucket",
                    asset="example-assets",
                    severity="medium",
                    confidence="high",
                    title="Potentially public S3 bucket",
                    description="Bucket endpoint returned HTTP 200.",
                    source="aws-s3-head",
                    tags=["cloud", "s3", "passive"],
                    evidence=[
                        Evidence(
                            source_url="https://example-assets.s3.amazonaws.com/",
                            note="HEAD status=200. existence=confirmed_exists.",
                        )
                    ],
                )
            ]

        with patch("builtins.print"):
            report = cli.run_scan(
                args,
                load_domains=lambda _single, _list: ["example.com"],
                parse_search_providers=lambda _value: ["commoncrawl"],
                parse_keywords=lambda _value: [],
                scan_context_cls=ScanContext,
                init_source_health=volt.init_source_health,
                collect_subfinder_subdomains=lambda _ctx, _health: (set(), []),
                collect_amass_subdomains=lambda _ctx, _health: (set(), []),
                collect_ct_subdomains=fake_ct,
                collect_search_index_findings=lambda _ctx, _health: (set(), []),
                collect_s3_bucket_findings=fake_s3,
                collect_gcp_bucket_findings=lambda _ctx, _hosts, _health: [],
                collect_azure_blob_findings=lambda _ctx, _hosts, _health: [],
                collect_subdomain_takeover_findings=lambda _ctx, _hosts, _health: [],
                dedupe_findings=volt.dedupe_findings,
                make_summary=volt.make_summary,
                finding_sort_key=volt.finding_sort_key,
                asdict_fn=asdict,
                normalize_source_health=volt.normalize_source_health,
                now_utc_iso=lambda: "2026-03-22T00:00:00+00:00",
            )

        expected = json.loads(
            (FIXTURE_DIR / "run_scan_reference_fixture.json").read_text()
        )
        self.assertEqual(report, expected)


if __name__ == "__main__":
    unittest.main()
