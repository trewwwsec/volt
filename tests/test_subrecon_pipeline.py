import argparse
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import subrecon
from subrecon_models import Finding, ScanContext


def mk_finding(
    asset_type: str,
    asset: str,
    severity: str,
    title: str,
    source: str = "test",
) -> Finding:
    return Finding(
        asset_type=asset_type,
        asset=asset,
        severity=severity,
        confidence="medium",
        title=title,
        description="desc",
        source=source,
    )


class SubreconPipelineTest(unittest.TestCase):
    def _default_context(self) -> ScanContext:
        return ScanContext(
            domains=["example.com"],
            organization=None,
            keywords=[],
            search_providers=["bing", "commoncrawl"],
            timeout=5,
            tool_timeout=30,
            threads=2,
            max_bucket_candidates=40,
            verbose=False,
            s3_list_probe=True,
        )

    def test_parse_hosts_from_output_filters_target_domain(self) -> None:
        raw = "\n".join(
            [
                "*.a.example.com",
                "b.example.com",
                "example.com",
                "evil.com",
                "",
            ]
        )
        out = subrecon.parse_hosts_from_output(raw, "example.com")
        self.assertEqual(out, {"a.example.com", "b.example.com", "example.com"})

    def test_parse_subfinder_structured_output_extracts_sources(self) -> None:
        raw = "\n".join(
            [
                '{"host":"a.example.com","sources":["crtsh","virustotal"],"source":"chaos"}',
                '{"host":"evil.com","sources":["crtsh"]}',
                "not-json",
            ]
        )
        parsed = subrecon.parse_subfinder_structured_output(raw, "example.com")
        self.assertIn("a.example.com", parsed)
        self.assertEqual(parsed["a.example.com"], {"crtsh", "virustotal", "chaos"})

    def test_parse_amass_structured_output_extracts_sources_and_tag(self) -> None:
        raw = json.dumps(
            [
                {
                    "name": "b.example.com",
                    "source": "crtsh",
                    "sources": [{"name": "dnsdb"}],
                    "tag": "cert",
                },
                {"name": "evil.com", "source": "crtsh"},
            ]
        )
        parsed = subrecon.parse_amass_structured_output(raw, "example.com")
        self.assertIn("b.example.com", parsed)
        self.assertIn("crtsh", parsed["b.example.com"])
        self.assertIn("dnsdb", parsed["b.example.com"])
        self.assertIn("tag:cert", parsed["b.example.com"])

    def test_score_provenance_confidence(self) -> None:
        self.assertEqual(subrecon.score_provenance_confidence(set()), "low")
        self.assertEqual(subrecon.score_provenance_confidence({"crtsh"}), "medium")
        self.assertEqual(
            subrecon.score_provenance_confidence({"crtsh", "dnsdb", "virustotal"}),
            "high",
        )
        self.assertEqual(subrecon.score_provenance_confidence({"tag:cert"}), "low")

    def test_parse_search_providers(self) -> None:
        self.assertEqual(
            subrecon.parse_search_providers("bing,commoncrawl,bing"),
            ["bing", "commoncrawl"],
        )
        with self.assertRaises(ValueError):
            subrecon.parse_search_providers("bing,unknown")

    def test_parse_bing_results_extracts_url_title_snippet(self) -> None:
        html = """
        <li class="b_algo">
          <h2><a href="https://a.example.com/.env">Env File</a></h2>
          <p>dotenv leak indicator</p>
        </li>
        """
        results = subrecon.parse_bing_results(html)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["url"], "https://a.example.com/.env")
        self.assertEqual(results[0]["title"], "Env File")
        self.assertEqual(results[0]["snippet"], "dotenv leak indicator")

    def test_load_domains_supports_single_and_file_with_comments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "domains.txt"
            p.write_text("# comment\nExample.com\n\n.api.example.com\n")
            domains = subrecon.load_domains("WWW.Example.com", str(p))
        self.assertEqual(domains, ["api.example.com", "example.com", "www.example.com"])

    def test_load_domains_missing_file_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            subrecon.load_domains(None, "/tmp/does-not-exist-subrecon-domains.txt")

    def test_positive_int(self) -> None:
        self.assertEqual(subrecon.positive_int("12"), 12)
        with self.assertRaises(argparse.ArgumentTypeError):
            subrecon.positive_int("0")
        with self.assertRaises(argparse.ArgumentTypeError):
            subrecon.positive_int("-2")
        with self.assertRaises(argparse.ArgumentTypeError):
            subrecon.positive_int("abc")

    def test_run_command_success_and_timeout(self) -> None:
        rc, stdout, stderr = subrecon.run_command(["python3", "-c", "print('ok')"], timeout=2)
        self.assertEqual(rc, 0)
        self.assertEqual(stdout.strip(), "ok")
        self.assertEqual(stderr, "")

        rc, _, _ = subrecon.run_command(
            ["python3", "-c", "import time; time.sleep(2)"],
            timeout=1,
        )
        self.assertEqual(rc, 124)

    @patch("subrecon.fetch_url")
    def test_collect_ct_subdomains_parses_rows(self, mock_fetch_url) -> None:
        payload = json.dumps(
            [
                {"name_value": "*.a.example.com\nb.example.com"},
                {"name_value": "evil.com\nexample.com"},
            ]
        )
        mock_fetch_url.return_value = (200, payload, {})

        ctx = self._default_context()
        hosts, findings = subrecon.collect_ct_subdomains(ctx)
        self.assertEqual(hosts, {"a.example.com", "b.example.com", "example.com"})
        self.assertEqual(len(findings), 3)

    @patch("subrecon.fetch_url")
    def test_collect_search_index_findings_filters_to_target_domain(self, mock_fetch_url) -> None:
        html = """
        <li class="b_algo"><h2><a href="https://a.example.com/.env">A</a></h2><p>dotenv</p></li>
        <li class="b_algo"><h2><a href="https://evil.com/.env">E</a></h2><p>dotenv</p></li>
        """
        mock_fetch_url.return_value = (200, html, {})

        ctx = self._default_context()
        hosts, findings = subrecon.collect_search_index_findings(ctx)
        self.assertIn("a.example.com", hosts)
        self.assertNotIn("evil.com", hosts)
        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(all("example.com" in f.asset for f in findings))

    @patch("subrecon.fetch_url")
    def test_collect_search_index_findings_commoncrawl_provider(self, mock_fetch_url) -> None:
        mock_fetch_url.side_effect = [
            # collinfo.json
            (200, '[{"cdx-api":"https://index.commoncrawl.org/CC-MAIN-2026-10-index"}]', {}),
            # one commoncrawl query success
            (200, '{"url":"https://a.example.com/.env"}\n', {}),
            # remaining commoncrawl queries fail quickly
            *[(500, "", {}) for _ in range(20)],
        ]
        ctx = self._default_context()
        ctx.search_providers = ["commoncrawl"]
        health = {"name": "search", "enabled": True, "status": "ok", "queried": 0, "hosts": 0, "findings": 0, "errors": 0, "timeouts": 0, "notes": []}
        hosts, findings = subrecon.collect_search_index_findings(ctx, health)
        self.assertIn("a.example.com", hosts)
        self.assertTrue(any(f.source == "commoncrawl" for f in findings))
        self.assertIn("providers", health)
        self.assertIn("commoncrawl", health["providers"])

    @patch("subrecon.run_command")
    @patch("subrecon.check_tool")
    def test_collect_subfinder_subdomains_provenance_scoring(
        self, mock_check_tool, mock_run_command
    ) -> None:
        mock_check_tool.return_value = True
        mock_run_command.return_value = (
            0,
            "\n".join(
                [
                    '{"host":"a.example.com","sources":["crtsh","dnsdb","virustotal"]}',
                    '{"host":"b.example.com"}',
                ]
            ),
            "",
        )
        hosts, findings = subrecon.collect_subfinder_subdomains(self._default_context())
        self.assertEqual(hosts, {"a.example.com", "b.example.com"})
        by_asset = {f.asset: f for f in findings}
        self.assertEqual(by_asset["a.example.com"].confidence, "high")
        self.assertEqual(by_asset["b.example.com"].confidence, "low")
        self.assertIn("passive sources", by_asset["a.example.com"].evidence[0].note)
        cmd = mock_run_command.call_args[0][0]
        self.assertIn("-oJ", cmd)
        self.assertIn("-cs", cmd)

    @patch("subrecon.run_command")
    @patch("subrecon.check_tool")
    def test_collect_amass_subdomains_provenance_scoring(
        self, mock_check_tool, mock_run_command
    ) -> None:
        mock_check_tool.return_value = True
        mock_run_command.return_value = (
            0,
            json.dumps(
                [
                    {"name": "a.example.com", "source": "crtsh", "sources": [{"name": "dnsdb"}]},
                    {"name": "b.example.com", "tag": "cert"},
                ]
            ),
            "",
        )
        hosts, findings = subrecon.collect_amass_subdomains(self._default_context())
        self.assertEqual(hosts, {"a.example.com", "b.example.com"})
        by_asset = {f.asset: f for f in findings}
        self.assertEqual(by_asset["a.example.com"].confidence, "medium")
        self.assertEqual(by_asset["b.example.com"].confidence, "low")
        cmd = mock_run_command.call_args[0][0]
        self.assertIn("-src", cmd)
        self.assertIn("-json", cmd)

    @patch("subrecon.check_single_bucket_exists")
    def test_collect_s3_bucket_findings_classifies_200_as_medium(self, mock_bucket_check) -> None:
        def fake_check(bucket: str, timeout: int, s3_list_probe: bool = False):
            if bucket == "mybucket":
                return bucket, 200, "confirmed_exists", "us-east-1", None
            if bucket == "example":
                return bucket, 403, "likely_exists", "us-east-1", None
            return bucket, 404, "unknown", "", None

        mock_bucket_check.side_effect = fake_check

        ctx = self._default_context()
        ctx.keywords = ["mybucket"]
        findings = subrecon.collect_s3_bucket_findings(ctx, hosts=set())
        by_asset = {f.asset: f for f in findings}
        self.assertIn("mybucket", by_asset)
        self.assertEqual(by_asset["mybucket"].severity, "medium")
        self.assertIn("example", by_asset)
        self.assertEqual(by_asset["example"].severity, "low")
        self.assertEqual(by_asset["example"].title, "S3 bucket name likely exists (HEAD signal)")

    def test_classify_s3_head_status(self) -> None:
        self.assertEqual(subrecon.classify_s3_head_status(200, "us-east-1"), "confirmed_exists")
        self.assertEqual(subrecon.classify_s3_head_status(403, "us-east-1"), "likely_exists")
        self.assertEqual(subrecon.classify_s3_head_status(403, ""), "unknown")
        self.assertEqual(subrecon.classify_s3_head_status(404, ""), "unknown")

    @patch("builtins.print")
    @patch("subrecon.check_single_bucket_exists")
    def test_collect_s3_bucket_findings_skips_unknown_signals(
        self, mock_bucket_check, _mock_print
    ) -> None:
        mock_bucket_check.return_value = ("example", 404, "unknown", "", None)
        ctx = self._default_context()
        findings = subrecon.collect_s3_bucket_findings(ctx, hosts={"a.example.com"})
        self.assertEqual(findings, [])

    @patch("builtins.print")
    @patch("subrecon.check_single_bucket_exists")
    def test_collect_s3_bucket_findings_suppresses_weak_likely_probe403(
        self, mock_bucket_check, _mock_print
    ) -> None:
        mock_bucket_check.return_value = ("example", 404, "likely_exists", "us-east-1", 403)
        ctx = self._default_context()
        findings = subrecon.collect_s3_bucket_findings(ctx, hosts={"a.example.com"})
        self.assertEqual(findings, [])

    @patch("subrecon.fetch_url")
    def test_check_single_bucket_exists_uses_list_probe_for_ambiguous_head(
        self, mock_fetch_url
    ) -> None:
        # First call: HEAD -> ambiguous 404. Second call: GET list probe -> 200.
        mock_fetch_url.side_effect = [
            (404, "", {"server": "AmazonS3"}),
            (200, "<ListBucketResult/>", {"server": "AmazonS3"}),
        ]
        bucket, status, existence, region, list_status = subrecon.check_single_bucket_exists(
            "noaa-goes19",
            5,
            s3_list_probe=True,
        )
        self.assertEqual(bucket, "noaa-goes19")
        self.assertEqual(status, 404)
        self.assertEqual(existence, "confirmed_exists")
        self.assertEqual(region, "")
        self.assertEqual(list_status, 200)

    @patch("subrecon.fetch_url")
    def test_check_single_bucket_exists_defaults_to_list_probe(self, mock_fetch_url) -> None:
        mock_fetch_url.side_effect = [
            (404, "", {"server": "AmazonS3"}),
            (403, "", {"x-amz-bucket-region": "us-east-1"}),
        ]
        _, _, existence, region, list_status = subrecon.check_single_bucket_exists(
            "example-bucket",
            5,
        )
        self.assertEqual(existence, "likely_exists")
        self.assertEqual(region, "us-east-1")
        self.assertEqual(list_status, 403)

    def test_build_parser_rejects_non_positive_numeric_flags(self) -> None:
        parser = subrecon.build_parser()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(["-d", "example.com", "--timeout", "0"])
            with self.assertRaises(SystemExit):
                parser.parse_args(["-d", "example.com", "--threads", "-1"])
            with self.assertRaises(SystemExit):
                parser.parse_args(["-d", "example.com", "--max-bucket-candidates", "0"])

    def test_build_parser_s3_list_probe_default_and_disable_flag(self) -> None:
        parser = subrecon.build_parser()
        args = parser.parse_args(["-d", "example.com"])
        self.assertTrue(args.s3_list_probe)
        args = parser.parse_args(["-d", "example.com", "--no-s3-list-probe"])
        self.assertFalse(args.s3_list_probe)

    @patch("subrecon.collect_s3_bucket_findings")
    @patch("subrecon.collect_search_index_findings")
    @patch("subrecon.collect_ct_subdomains")
    @patch("subrecon.collect_amass_subdomains")
    @patch("subrecon.collect_subfinder_subdomains")
    @patch("builtins.print")
    def test_run_scan_orchestrates_sources_and_dedupes(
        self,
        _mock_print,
        mock_subfinder,
        mock_amass,
        mock_ct,
        mock_search,
        mock_s3,
    ) -> None:
        sf_finding = mk_finding("subdomain", "a.example.com", "info", "sf")
        ct_finding = mk_finding("subdomain", "a.example.com", "info", "ct")
        search_finding = mk_finding(
            "indexed_leak",
            "https://a.example.com/.env",
            "high",
            "Potential .env exposure indexed",
        )
        s3_finding = mk_finding("s3_bucket", "a-example-assets", "low", "S3 bucket name exists")

        mock_subfinder.return_value = ({"a.example.com"}, [sf_finding])
        mock_amass.return_value = (set(), [])
        mock_ct.return_value = ({"a.example.com"}, [ct_finding])
        mock_search.return_value = ({"a.example.com"}, [search_finding])
        mock_s3.return_value = [s3_finding]

        args = argparse.Namespace(
            domain="example.com",
            domain_list=None,
            output="/tmp/ignored.json",
            organization=None,
            keywords=None,
            search_providers="bing,commoncrawl",
            timeout=5,
            tool_timeout=30,
            threads=2,
            verbose=False,
            max_bucket_candidates=40,
            s3_list_probe=False,
            no_ct=False,
            no_subfinder=False,
            no_amass=False,
            no_search=False,
            no_s3=False,
        )
        report = subrecon.run_scan(args)

        self.assertEqual(report["targets"], ["example.com"])
        self.assertEqual(report["summary"]["total_findings"], 3)
        self.assertEqual(report["summary"]["by_type"]["subdomain"], 1)
        self.assertEqual(report["findings"][0]["severity"], "high")
        self.assertIn("source_health", report)
        self.assertIn("search", report["source_health"])

    def test_run_scan_rejects_unknown_search_provider(self) -> None:
        args = argparse.Namespace(
            domain="example.com",
            domain_list=None,
            output="/tmp/ignored.json",
            organization=None,
            keywords=None,
            search_providers="bing,invalid",
            timeout=5,
            tool_timeout=30,
            threads=2,
            verbose=False,
            max_bucket_candidates=40,
            s3_list_probe=True,
            no_ct=True,
            no_subfinder=True,
            no_amass=True,
            no_search=True,
            no_s3=True,
        )
        with self.assertRaises(ValueError):
            subrecon.run_scan(args)


if __name__ == "__main__":
    unittest.main()
