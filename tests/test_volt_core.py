import unittest

import volt


class CoreHelpersTest(unittest.TestCase):
    def test_normalize_domain(self) -> None:
        self.assertEqual(volt.normalize_domain(" .WWW.Example.COM "), "www.example.com")

    def test_parse_keywords(self) -> None:
        self.assertEqual(
            volt.parse_keywords(" acme, Acme-Pay , ,prod "),
            ["acme", "acme-pay", "prod"],
        )
        self.assertEqual(volt.parse_keywords(None), [])

    def test_dedupe_findings_subdomain_ignores_title(self) -> None:
        one = volt.Finding(
            asset_type="subdomain",
            asset="a.example.com",
            severity="info",
            confidence="high",
            title="from source one",
            description="",
            source="x",
        )
        two = volt.Finding(
            asset_type="subdomain",
            asset="A.EXAMPLE.COM",
            severity="info",
            confidence="high",
            title="from source two",
            description="",
            source="y",
        )
        out = volt.dedupe_findings([one, two])
        self.assertEqual(len(out), 1)

    def test_dedupe_findings_indexed_leak_keeps_distinct_titles(self) -> None:
        one = volt.Finding(
            asset_type="indexed_leak",
            asset="https://a.example.com/.env",
            severity="high",
            confidence="medium",
            title="Potential .env exposure indexed",
            description="",
            source="commoncrawl",
        )
        two = volt.Finding(
            asset_type="indexed_leak",
            asset="https://a.example.com/.env",
            severity="high",
            confidence="medium",
            title="Potential sensitive file indexed",
            description="",
            source="commoncrawl",
        )
        out = volt.dedupe_findings([one, two])
        self.assertEqual(len(out), 2)

    def test_dedupe_findings_takeover_ignores_title(self) -> None:
        one = volt.Finding(
            asset_type="subdomain_takeover",
            asset="orphan.example.com",
            severity="high",
            confidence="high",
            title="provider one",
            description="",
            source="takeover-fingerprint",
        )
        two = volt.Finding(
            asset_type="subdomain_takeover",
            asset="ORPHAN.EXAMPLE.COM",
            severity="high",
            confidence="high",
            title="provider two",
            description="",
            source="takeover-fingerprint",
        )
        out = volt.dedupe_findings([one, two])
        self.assertEqual(len(out), 1)

    def test_dedupe_findings_gcp_ignores_title(self) -> None:
        one = volt.Finding(
            asset_type="gcp_bucket",
            asset="acme-assets",
            severity="medium",
            confidence="high",
            title="one",
            description="",
            source="gcp-storage-head",
        )
        two = volt.Finding(
            asset_type="gcp_bucket",
            asset="ACME-ASSETS",
            severity="medium",
            confidence="high",
            title="two",
            description="",
            source="gcp-storage-head",
        )
        out = volt.dedupe_findings([one, two])
        self.assertEqual(len(out), 1)

    def test_dedupe_findings_azure_ignores_title(self) -> None:
        one = volt.Finding(
            asset_type="azure_blob_container",
            asset="acmestorage/acme-assets",
            severity="high",
            confidence="high",
            title="one",
            description="",
            source="azure-blob-list",
        )
        two = volt.Finding(
            asset_type="azure_blob_container",
            asset="ACMESTORAGE/ACME-ASSETS",
            severity="high",
            confidence="high",
            title="two",
            description="",
            source="azure-blob-list",
        )
        out = volt.dedupe_findings([one, two])
        self.assertEqual(len(out), 1)

    def test_sanitize_bucket_label(self) -> None:
        self.assertEqual(
            volt.sanitize_bucket_label("Acme Corp..Prod__Logs"),
            "acme-corp.prod-logs",
        )

    def test_extract_bucket_candidates_from_hosts(self) -> None:
        candidates = volt.extract_bucket_candidates_from_hosts(
            {"cdn.dev.example.com", "assets.s3.amazonaws.com"}
        )
        self.assertIn("cdn-dev-example-com", candidates)
        self.assertIn("cdn-dev", candidates)
        self.assertIn("assets", candidates)

    def test_finding_sort_key_orders_by_severity_priority(self) -> None:
        info = volt.Finding(
            asset_type="subdomain",
            asset="info.example.com",
            severity="info",
            confidence="high",
            title="info",
            description="",
            source="x",
        )
        high = volt.Finding(
            asset_type="subdomain",
            asset="high.example.com",
            severity="high",
            confidence="high",
            title="high",
            description="",
            source="x",
        )
        ordered = sorted([info, high], key=volt.finding_sort_key)
        self.assertEqual([f.severity for f in ordered], ["high", "info"])


if __name__ == "__main__":
    unittest.main()
