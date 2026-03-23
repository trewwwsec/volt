import unittest
from unittest.mock import patch

import volt
from volt_models import ScanContext


class UpstreamDriftReliabilityTest(unittest.TestCase):
    def _context(self, providers: list[str]) -> ScanContext:
        return ScanContext(
            domains=["example.com"],
            organization=None,
            keywords=[],
            search_providers=providers,
            timeout=5,
            tool_timeout=30,
            threads=2,
            max_bucket_candidates=40,
            verbose=False,
        )

    @patch("volt.fetch_url")
    def test_collect_ct_subdomains_handles_json_schema_drift(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.return_value = (
            200,
            '{"name_value":"a.example.com"}',
            {},
        )
        health = volt.init_source_health("crt.sh")
        hosts, findings = volt.collect_ct_subdomains(
            self._context(["commoncrawl"]), health
        )
        self.assertEqual(hosts, set())
        self.assertEqual(findings, [])
        self.assertEqual(health["status"], "error")
        self.assertEqual(health.get("error_types", {}).get("json_schema"), 1)

    @patch("volt.fetch_url")
    def test_collect_ct_subdomains_ignores_non_dict_rows(self, mock_fetch_url) -> None:
        mock_fetch_url.return_value = (
            200,
            '[{"name_value":"a.example.com"},"noise",{"name_value":"b.example.com"}]',
            {},
        )
        health = volt.init_source_health("crt.sh")
        hosts, findings = volt.collect_ct_subdomains(
            self._context(["commoncrawl"]), health
        )
        self.assertEqual(hosts, {"a.example.com", "b.example.com"})
        self.assertEqual(len(findings), 2)
        self.assertEqual(health["errors"], 0)

    @patch("volt.parse_bing_results")
    @patch("volt.fetch_url")
    def test_collect_search_index_findings_handles_bing_parse_exceptions(
        self, mock_fetch_url, mock_parse_bing
    ) -> None:
        mock_fetch_url.return_value = (200, "<html></html>", {})
        mock_parse_bing.side_effect = ValueError("upstream markup drift")
        health = volt.init_source_health("search")
        hosts, findings = volt.collect_search_index_findings(
            self._context(["bing"]), health
        )
        self.assertEqual(hosts, set())
        self.assertEqual(findings, [])
        self.assertEqual(health["status"], "error")
        self.assertGreater(health.get("errors", 0), 0)
        self.assertEqual(health["providers"]["bing"]["status"], "error")
        self.assertGreater(health.get("error_types", {}).get("bing_parse_error", 0), 0)

    @patch("volt.fetch_commoncrawl_results")
    @patch("volt.fetch_commoncrawl_index_endpoint")
    def test_collect_search_index_findings_handles_commoncrawl_query_exceptions(
        self, mock_fetch_index, mock_fetch_results
    ) -> None:
        mock_fetch_index.return_value = (
            "https://index.commoncrawl.org/CC-MAIN-2026-10-index"
        )
        mock_fetch_results.side_effect = RuntimeError("temporary upstream failure")
        health = volt.init_source_health("search")
        hosts, findings = volt.collect_search_index_findings(
            self._context(["commoncrawl"]), health
        )
        self.assertEqual(hosts, set())
        self.assertEqual(findings, [])
        self.assertEqual(health["status"], "error")
        self.assertEqual(health["providers"]["commoncrawl"]["status"], "error")
        self.assertGreater(
            health.get("error_types", {}).get("commoncrawl_query_exception", 0), 0
        )

    @patch("volt.fetch_url")
    @patch("volt.fetch_commoncrawl_index_endpoint")
    def test_collect_search_index_findings_handles_commoncrawl_index_exception(
        self, mock_fetch_index, mock_fetch_url
    ) -> None:
        mock_fetch_index.side_effect = RuntimeError("index service unavailable")
        mock_fetch_url.return_value = (500, "", {})
        health = volt.init_source_health("search")
        hosts, findings = volt.collect_search_index_findings(
            self._context(["commoncrawl"]), health
        )
        self.assertEqual(hosts, set())
        self.assertEqual(findings, [])
        self.assertEqual(health["status"], "error")
        self.assertEqual(health["providers"]["commoncrawl"]["status"], "error")
        self.assertEqual(
            health.get("error_types", {}).get("commoncrawl_index_exception"), 1
        )


if __name__ == "__main__":
    unittest.main()
