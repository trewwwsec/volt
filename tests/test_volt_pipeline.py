import argparse
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Optional
from unittest.mock import patch

import volt
from volt_models import Finding, ScanContext


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


class DummyHTTPResponse:
    def __init__(
        self, status: int, body: str = "", headers: Optional[dict[str, str]] = None
    ):
        self.status = status
        self._body = body
        self.headers = headers or {}

    def read(self) -> bytes:
        return self._body.encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False


class VoltPipelineTest(unittest.TestCase):
    def _default_context(self) -> ScanContext:
        return ScanContext(
            domains=["example.com"],
            organization=None,
            keywords=[],
            search_providers=["commoncrawl"],
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
        out = volt.parse_hosts_from_output(raw, "example.com")
        self.assertEqual(out, {"a.example.com", "b.example.com", "example.com"})

    def test_parse_subfinder_structured_output_extracts_sources(self) -> None:
        raw = "\n".join(
            [
                '{"host":"a.example.com","sources":["crtsh","virustotal"],"source":"chaos"}',
                '{"host":"evil.com","sources":["crtsh"]}',
                "not-json",
            ]
        )
        parsed = volt.parse_subfinder_structured_output(raw, "example.com")
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
        parsed = volt.parse_amass_structured_output(raw, "example.com")
        self.assertIn("b.example.com", parsed)
        self.assertIn("crtsh", parsed["b.example.com"])
        self.assertIn("dnsdb", parsed["b.example.com"])
        self.assertIn("tag:cert", parsed["b.example.com"])

    def test_score_provenance_confidence(self) -> None:
        self.assertEqual(volt.score_provenance_confidence(set()), "low")
        self.assertEqual(volt.score_provenance_confidence({"crtsh"}), "medium")
        self.assertEqual(
            volt.score_provenance_confidence({"crtsh", "dnsdb", "virustotal"}),
            "high",
        )
        self.assertEqual(volt.score_provenance_confidence({"tag:cert"}), "low")

    def test_parse_search_providers(self) -> None:
        self.assertEqual(
            volt.parse_search_providers(None),
            ["commoncrawl"],
        )
        self.assertEqual(
            volt.parse_search_providers("commoncrawl,commoncrawl"),
            ["commoncrawl"],
        )
        with self.assertRaises(ValueError):
            volt.parse_search_providers("invalid")

    def test_load_domains_supports_single_and_file_with_comments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "domains.txt"
            p.write_text("# comment\nExample.com\n\n.api.example.com\n")
            domains = volt.load_domains("WWW.Example.com", str(p))
        self.assertEqual(domains, ["api.example.com", "example.com", "www.example.com"])

    def test_load_domains_missing_file_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            volt.load_domains(None, "/tmp/does-not-exist-volt-domains.txt")

    def test_positive_int(self) -> None:
        self.assertEqual(volt.positive_int("12"), 12)
        with self.assertRaises(argparse.ArgumentTypeError):
            volt.positive_int("0")
        with self.assertRaises(argparse.ArgumentTypeError):
            volt.positive_int("-2")
        with self.assertRaises(argparse.ArgumentTypeError):
            volt.positive_int("abc")

    def test_record_source_error_tracks_counts_and_samples(self) -> None:
        health = volt.init_source_health("search")
        volt.record_source_error(
            health,
            "commoncrawl_http_500",
            detail="domain=example.com query=dotenv",
        )
        volt.record_source_error(
            health,
            "commoncrawl_http_500",
            detail="domain=example.com query=dotenv",
        )
        volt.record_source_error(
            health,
            "subfinder_timeout",
            detail="domain=example.com timeout=30s",
            timeout=True,
        )
        self.assertEqual(health["errors"], 2)
        self.assertEqual(health["timeouts"], 1)
        self.assertEqual(health["error_types"]["commoncrawl_http_500"], 2)
        self.assertEqual(health["error_types"]["subfinder_timeout"], 1)
        self.assertEqual(len(health["error_samples"]), 2)

    def test_normalize_source_health_sorts_and_dedupes(self) -> None:
        source_health = {
            "search": {
                "notes": ["z-note", "a-note", "a-note", ""],
                "error_types": {"b": 2, "a": 1},
                "error_samples": [
                    {"code": "b", "detail": "z"},
                    {"code": "a", "detail": "a"},
                    {"code": "a", "detail": "a"},
                ],
                "providers": {
                    "commoncrawl": {
                        "status": "partial",
                        "notes": ["n2", "n1", "n1"],
                    }
                },
            }
        }
        volt.normalize_source_health(source_health)
        self.assertEqual(source_health["search"]["notes"], ["a-note", "z-note"])
        self.assertEqual(
            list(source_health["search"]["error_types"].keys()),
            ["a", "b"],
        )
        self.assertEqual(
            source_health["search"]["error_samples"],
            [
                {"code": "a", "detail": "a"},
                {"code": "b", "detail": "z"},
            ],
        )
        self.assertEqual(
            source_health["search"]["providers"]["commoncrawl"]["notes"], ["n1", "n2"]
        )

    def test_normalize_source_health_adds_operator_guidance_for_degraded_statuses(
        self,
    ) -> None:
        source_health = {
            "ct": {
                "status": "partial",
                "errors": 1,
                "timeouts": 1,
                "findings": 0,
                "notes": [],
            }
        }
        volt.normalize_source_health(source_health)
        notes = source_health["ct"]["notes"]
        self.assertTrue(
            any(
                note.startswith("operator_action: source reliability is degraded")
                for note in notes
            )
        )
        self.assertTrue(
            any("increase timeout budget" in note for note in notes),
        )
        self.assertTrue(
            any("review error_types/error_samples" in note for note in notes),
        )
        self.assertTrue(
            any(
                "zero findings may reflect degraded source coverage" in note
                for note in notes
            ),
        )

    def test_run_command_success_and_timeout(self) -> None:
        rc, stdout, stderr = volt.run_command(
            ["python3", "-c", "print('ok')"], timeout=2
        )
        self.assertEqual(rc, 0)
        self.assertEqual(stdout.strip(), "ok")
        self.assertEqual(stderr, "")

        rc, _, _ = volt.run_command(
            ["python3", "-c", "import time; time.sleep(2)"],
            timeout=1,
        )
        self.assertEqual(rc, 124)

    @patch("volt.sleep")
    @patch("volt.request.urlopen")
    def test_fetch_url_retries_on_urlerror_then_succeeds(
        self, mock_urlopen, mock_sleep
    ) -> None:
        mock_urlopen.side_effect = [
            volt.error.URLError("temporary failure"),
            DummyHTTPResponse(200, "ok", {"server": "test"}),
        ]
        status, body, headers = volt.fetch_url("https://example.com", timeout=2)
        self.assertEqual(status, 200)
        self.assertEqual(body, "ok")
        self.assertEqual(headers.get("server"), "test")
        self.assertEqual(mock_urlopen.call_count, 2)
        mock_sleep.assert_called_once()

    @patch("volt.sleep")
    @patch("volt.request.urlopen")
    def test_fetch_url_retries_on_retryable_http_status_then_succeeds(
        self, mock_urlopen, mock_sleep
    ) -> None:
        transient = volt.error.HTTPError(
            "https://example.com",
            503,
            "Service Unavailable",
            {},
            io.BytesIO(b"upstream unavailable"),
        )
        mock_urlopen.side_effect = [
            transient,
            DummyHTTPResponse(200, "ok", {"server": "test"}),
        ]
        status, body, _ = volt.fetch_url("https://example.com", timeout=2)
        self.assertEqual(status, 200)
        self.assertEqual(body, "ok")
        self.assertEqual(mock_urlopen.call_count, 2)
        mock_sleep.assert_called_once()

    @patch("volt.sleep")
    @patch("volt.request.urlopen")
    def test_fetch_url_does_not_retry_non_retryable_http_status(
        self, mock_urlopen, mock_sleep
    ) -> None:
        not_found = volt.error.HTTPError(
            "https://example.com",
            404,
            "Not Found",
            {},
            io.BytesIO(b"missing"),
        )
        mock_urlopen.side_effect = [not_found]
        status, body, _ = volt.fetch_url("https://example.com", timeout=2)
        self.assertEqual(status, 404)
        self.assertEqual(body, "missing")
        self.assertEqual(mock_urlopen.call_count, 1)
        mock_sleep.assert_not_called()

    @patch("volt.fetch_url")
    def test_collect_ct_subdomains_parses_rows(self, mock_fetch_url) -> None:
        payload = json.dumps(
            [
                {"name_value": "*.a.example.com\nb.example.com"},
                {"name_value": "evil.com\nexample.com"},
            ]
        )
        mock_fetch_url.return_value = (200, payload, {})

        ctx = self._default_context()
        hosts, findings = volt.collect_ct_subdomains(ctx)
        self.assertEqual(hosts, {"a.example.com", "b.example.com", "example.com"})
        self.assertEqual(len(findings), 3)
        first_call = mock_fetch_url.call_args_list[0]
        self.assertEqual(first_call.kwargs.get("retries"), volt.CT_HTTP_RETRIES)

    @patch("volt.fetch_url")
    def test_collect_ct_subdomains_partial_when_some_domains_fail(
        self, mock_fetch_url
    ) -> None:
        def fake_fetch(
            url: str,
            timeout: int,
            method: str = "GET",
            headers: Optional[dict[str, str]] = None,
            retries: int = 0,
        ) -> tuple[int, str, dict[str, str]]:
            del timeout, method, headers, retries
            if "crt.sh" in url and "example.com" in url:
                return (500, "", {})
            if "api.certspotter.com" in url and "domain=example.com" in url:
                return (200, '[{"dns_names":["ok.example.com"]}]', {})
            if "crt.sh" in url and "example.org" in url:
                return (200, '[{"name_value":"ok.example.org"}]', {})
            return (0, "", {})

        mock_fetch_url.side_effect = fake_fetch
        ctx = self._default_context()
        ctx.domains = ["example.com", "example.org"]
        health = volt.init_source_health("crt.sh")
        hosts, findings = volt.collect_ct_subdomains(ctx, health)
        self.assertEqual(hosts, {"ok.example.com", "ok.example.org"})
        self.assertEqual(len(findings), 2)
        self.assertEqual(health["errors"], 1)
        self.assertEqual(health["status"], "partial")

    @patch("volt.fetch_url")
    def test_collect_ct_subdomains_uses_certspotter_fallback_on_crt_failure(
        self, mock_fetch_url
    ) -> None:
        def fake_fetch(
            url: str,
            timeout: int,
            method: str = "GET",
            headers: Optional[dict[str, str]] = None,
            retries: int = 0,
        ) -> tuple[int, str, dict[str, str]]:
            del timeout, method, headers
            if "crt.sh" in url:
                return (503, "", {})
            if "api.certspotter.com" in url:
                return (
                    200,
                    '[{"dns_names":["a.example.com","*.b.example.com","evil.com"]}]',
                    {},
                )
            return (0, "", {})

        mock_fetch_url.side_effect = fake_fetch
        ctx = self._default_context()
        ctx.domains = ["example.com"]
        health = volt.init_source_health("crt.sh")
        hosts, findings = volt.collect_ct_subdomains(ctx, health)
        self.assertEqual(hosts, {"a.example.com", "b.example.com"})
        self.assertEqual(len(findings), 2)
        self.assertEqual(health["status"], "partial")
        self.assertEqual(health["errors"], 1)
        self.assertIn("crt.sh degraded; certspotter fallback used", health["notes"])
        retries = [call.kwargs.get("retries") for call in mock_fetch_url.call_args_list]
        self.assertTrue(all(value == volt.CT_HTTP_RETRIES for value in retries))

    @patch("volt.fetch_commoncrawl_results")
    @patch("volt.fetch_commoncrawl_index_endpoint")
    def test_collect_search_index_findings_filters_to_target_domain(
        self, mock_fetch_index, mock_fetch_results
    ) -> None:
        mock_fetch_index.return_value = (
            "https://index.commoncrawl.org/CC-MAIN-2026-10-index"
        )
        mock_fetch_results.return_value = (
            200,
            [
                {"url": "https://a.example.com/.env", "title": "", "snippet": ""},
                {"url": "https://evil.com/.env", "title": "", "snippet": ""},
            ],
            "https://index.commoncrawl.org/CC-MAIN-2026-10-index?url=test",
        )

        ctx = self._default_context()
        hosts, findings = volt.collect_search_index_findings(ctx)
        self.assertIn("a.example.com", hosts)
        self.assertNotIn("evil.com", hosts)
        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(all("example.com" in f.asset for f in findings))

    @patch("volt.fetch_commoncrawl_results")
    @patch("volt.fetch_commoncrawl_index_endpoint")
    def test_collect_search_index_findings_commoncrawl_provider(
        self, mock_fetch_index, mock_fetch_results
    ) -> None:
        mock_fetch_index.return_value = (
            "https://index.commoncrawl.org/CC-MAIN-2026-10-index"
        )
        mock_fetch_results.side_effect = [
            (
                200,
                [{"url": "https://a.example.com/.env", "title": "", "snippet": ""}],
                "https://index.commoncrawl.org/CC-MAIN-2026-10-index?url=dotenv",
            ),
            *[
                (
                    500,
                    [],
                    "https://index.commoncrawl.org/CC-MAIN-2026-10-index?url=other",
                )
                for _ in range(11)
            ],
        ]
        ctx = self._default_context()
        ctx.search_providers = ["commoncrawl"]
        health = {
            "name": "search",
            "enabled": True,
            "status": "ok",
            "queried": 0,
            "hosts": 0,
            "findings": 0,
            "errors": 0,
            "timeouts": 0,
            "notes": [],
        }
        hosts, findings = volt.collect_search_index_findings(ctx, health)
        self.assertIn("a.example.com", hosts)
        self.assertTrue(any(f.source == "commoncrawl" for f in findings))
        self.assertIn("providers", health)
        self.assertIn("commoncrawl", health["providers"])

    @patch("volt.fetch_url")
    def test_collect_search_index_findings_commoncrawl_index_failure_sets_error(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.return_value = (500, "", {})
        ctx = self._default_context()
        ctx.search_providers = ["commoncrawl"]
        health = volt.init_source_health("search")
        hosts, findings = volt.collect_search_index_findings(ctx, health)
        self.assertEqual(hosts, set())
        self.assertEqual(findings, [])
        self.assertEqual(health["status"], "error")
        self.assertIn("failed to resolve Common Crawl index endpoint", health["notes"])
        self.assertEqual(health["providers"]["commoncrawl"]["status"], "error")

    @patch("volt.fetch_commoncrawl_results")
    @patch("volt.fetch_commoncrawl_index_endpoint")
    def test_collect_search_index_findings_commoncrawl_404_is_not_error(
        self, mock_fetch_index, mock_fetch_results
    ) -> None:
        mock_fetch_index.return_value = (
            "https://index.commoncrawl.org/CC-MAIN-2026-10-index"
        )
        mock_fetch_results.side_effect = [
            (
                200,
                [{"url": "https://a.example.com/.env", "title": "", "snippet": ""}],
                "https://index.commoncrawl.org/CC-MAIN-2026-10-index?url=dotenv",
            ),
            (
                404,
                [],
                "https://index.commoncrawl.org/CC-MAIN-2026-10-index?url=dotenv2",
            ),
            *[
                (
                    200,
                    [],
                    "https://index.commoncrawl.org/CC-MAIN-2026-10-index?url=other",
                )
                for _ in range(10)
            ],
        ]
        ctx = self._default_context()
        ctx.search_providers = ["commoncrawl"]
        health = volt.init_source_health("search")
        hosts, findings = volt.collect_search_index_findings(ctx, health)
        self.assertEqual(hosts, {"a.example.com"})
        self.assertTrue(any(f.source == "commoncrawl" for f in findings))
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["errors"], 0)
        self.assertEqual(health["providers"]["commoncrawl"]["status"], "ok")
        self.assertNotIn("commoncrawl_http_404", health.get("error_types", {}))

    @patch("volt.run_command")
    @patch("volt.check_tool")
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
        hosts, findings = volt.collect_subfinder_subdomains(self._default_context())
        self.assertEqual(hosts, {"a.example.com", "b.example.com"})
        by_asset = {f.asset: f for f in findings}
        self.assertEqual(by_asset["a.example.com"].confidence, "high")
        self.assertEqual(by_asset["b.example.com"].confidence, "low")
        self.assertIn("passive sources", by_asset["a.example.com"].evidence[0].note)
        cmd = mock_run_command.call_args[0][0]
        self.assertIn("-oJ", cmd)
        self.assertIn("-cs", cmd)

    @patch("volt.run_command")
    @patch("volt.check_tool")
    def test_collect_amass_subdomains_provenance_scoring(
        self, mock_check_tool, mock_run_command
    ) -> None:
        mock_check_tool.return_value = True
        mock_run_command.side_effect = [
            (0, "amass v5.0.1", ""),
            (
                0,
                json.dumps(
                    [
                        {
                            "name": "a.example.com",
                            "source": "crtsh",
                            "sources": [{"name": "dnsdb"}],
                        },
                        {"name": "b.example.com", "tag": "cert"},
                    ]
                ),
                "",
            ),
        ]
        hosts, findings = volt.collect_amass_subdomains(self._default_context())
        self.assertEqual(hosts, {"a.example.com", "b.example.com"})
        by_asset = {f.asset: f for f in findings}
        self.assertEqual(by_asset["a.example.com"].confidence, "medium")
        self.assertEqual(by_asset["b.example.com"].confidence, "low")
        cmd = mock_run_command.call_args[0][0]
        self.assertIn("-src", cmd)
        self.assertIn("-json", cmd)
        self.assertEqual(mock_run_command.call_args.kwargs.get("timeout"), 90)

    @patch("volt.run_command")
    @patch("volt.check_tool")
    @patch("builtins.print")
    def test_collect_amass_subdomains_retries_without_src_when_unsupported(
        self, _mock_print, mock_check_tool, mock_run_command
    ) -> None:
        mock_check_tool.return_value = True
        mock_run_command.side_effect = [
            (0, "amass v5.0.1", ""),
            (1, "", "flag provided but not defined: -src"),
            (0, json.dumps([{"name": "a.example.com"}]), ""),
        ]
        health = volt.init_source_health("amass")
        hosts, findings = volt.collect_amass_subdomains(self._default_context(), health)
        self.assertEqual(hosts, {"a.example.com"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(mock_run_command.call_count, 3)
        healthcheck_cmd = mock_run_command.call_args_list[0][0][0]
        first_cmd = mock_run_command.call_args_list[1][0][0]
        second_cmd = mock_run_command.call_args_list[2][0][0]
        self.assertEqual(healthcheck_cmd, ["amass", "-version"])
        self.assertIn("-src", first_cmd)
        self.assertNotIn("-src", second_cmd)
        self.assertEqual(health.get("src_compat_fallbacks"), 1)
        self.assertTrue(any("-src unsupported" in note for note in health["notes"]))

    @patch("volt.run_command")
    @patch("volt.check_tool")
    @patch("builtins.print")
    def test_collect_amass_subdomains_retries_plain_output_when_json_unsupported(
        self, _mock_print, mock_check_tool, mock_run_command
    ) -> None:
        mock_check_tool.return_value = True
        mock_run_command.side_effect = [
            (0, "amass v5.0.1", ""),
            (1, "", "flag provided but not defined: -src"),
            (1, "", "flag provided but not defined: -json"),
            (0, "a.example.com\nevil.com\n", ""),
        ]
        health = volt.init_source_health("amass")
        hosts, findings = volt.collect_amass_subdomains(self._default_context(), health)
        self.assertEqual(hosts, {"a.example.com"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(mock_run_command.call_count, 4)
        first_cmd = mock_run_command.call_args_list[1][0][0]
        second_cmd = mock_run_command.call_args_list[2][0][0]
        third_cmd = mock_run_command.call_args_list[3][0][0]
        self.assertIn("-src", first_cmd)
        self.assertIn("-json", second_cmd)
        self.assertNotIn("-src", third_cmd)
        self.assertNotIn("-json", third_cmd)
        self.assertIn("-nocolor", third_cmd)
        self.assertNotIn("-silent", third_cmd)
        self.assertIn("-norecursive", third_cmd)
        self.assertEqual(health.get("src_compat_fallbacks"), 1)
        self.assertEqual(health.get("json_compat_fallbacks"), 1)
        self.assertTrue(any("-json unsupported" in note for note in health["notes"]))

    @patch("volt.run_command")
    @patch("volt.check_tool")
    @patch("builtins.print")
    def test_collect_amass_subdomains_timeout_retry_marks_partial(
        self, _mock_print, mock_check_tool, mock_run_command
    ) -> None:
        mock_check_tool.return_value = True
        mock_run_command.side_effect = [
            (0, "amass v5.0.1", ""),
            (1, "", "flag provided but not defined: -src"),
            (1, "", "flag provided but not defined: -json"),
            (124, "", ""),
            (124, "", ""),
        ]
        health = volt.init_source_health("amass")
        hosts, findings = volt.collect_amass_subdomains(self._default_context(), health)
        self.assertEqual(hosts, set())
        self.assertEqual(findings, [])
        self.assertEqual(mock_run_command.call_count, 5)
        fallback_cmd = mock_run_command.call_args_list[-1][0][0]
        self.assertIn("-nocolor", fallback_cmd)
        self.assertNotIn("-silent", fallback_cmd)
        self.assertIn("-norecursive", fallback_cmd)
        self.assertEqual(health.get("timeouts"), 1)
        self.assertEqual(health.get("errors"), 0)
        self.assertEqual(health.get("status"), "partial")
        self.assertEqual(health.get("timeout_retries"), 1)
        self.assertEqual(health.get("timeout_exhausted_domains"), 1)
        self.assertEqual(health.get("error_types", {}).get("amass_timeout"), 1)

    @patch("volt.run_command")
    @patch("volt.check_tool")
    @patch("builtins.print")
    def test_collect_amass_subdomains_ok_no_results_after_empty_completion(
        self, _mock_print, mock_check_tool, mock_run_command
    ) -> None:
        mock_check_tool.return_value = True
        mock_run_command.side_effect = [
            (0, "amass v5.0.1", ""),
            (1, "", "flag provided but not defined: -src"),
            (1, "", "flag provided but not defined: -json"),
            (0, "", ""),
        ]
        health = volt.init_source_health("amass")
        hosts, findings = volt.collect_amass_subdomains(self._default_context(), health)
        self.assertEqual(hosts, set())
        self.assertEqual(findings, [])
        self.assertEqual(health.get("timeouts"), 0)
        self.assertEqual(health.get("errors"), 0)
        self.assertEqual(health.get("status"), "partial")
        self.assertEqual(health.get("compat_empty_output_domains"), 1)
        self.assertTrue(
            any(
                "compatibility mode produced no plain output" in note
                for note in health["notes"]
            )
        )

    @patch("volt.run_command")
    @patch("volt.check_tool")
    @patch("builtins.print")
    def test_collect_amass_subdomains_marks_error_when_tool_unhealthy(
        self, _mock_print, mock_check_tool, mock_run_command
    ) -> None:
        mock_check_tool.return_value = True
        mock_run_command.side_effect = [
            (1, "", ""),
            (1, "", ""),
        ]
        health = volt.init_source_health("amass")
        hosts, findings = volt.collect_amass_subdomains(self._default_context(), health)
        self.assertEqual(hosts, set())
        self.assertEqual(findings, [])
        self.assertEqual(health.get("queried"), 0)
        self.assertEqual(health.get("errors"), 1)
        self.assertEqual(health.get("timeouts"), 0)
        self.assertEqual(health.get("status"), "error")
        self.assertEqual(
            health.get("error_types", {}).get("amass_tool_unhealthy"),
            1,
        )
        self.assertTrue(
            any("installed but unresponsive" in note for note in health["notes"])
        )
        self.assertEqual(
            mock_run_command.call_args_list[0][0][0],
            ["amass", "-version"],
        )
        self.assertEqual(
            mock_run_command.call_args_list[1][0][0],
            ["amass", "enum", "-h"],
        )

    @patch("volt.run_command")
    @patch("volt.check_tool")
    @patch("builtins.print")
    def test_collect_amass_subdomains_health_probe_timeout_is_inconclusive(
        self, _mock_print, mock_check_tool, mock_run_command
    ) -> None:
        mock_check_tool.return_value = True
        mock_run_command.side_effect = [
            (124, "", ""),
            (124, "", ""),
            (1, "", "flag provided but not defined: -src"),
            (1, "", "flag provided but not defined: -json"),
            (0, "a.example.com\n", ""),
        ]
        health = volt.init_source_health("amass")
        hosts, findings = volt.collect_amass_subdomains(self._default_context(), health)
        self.assertEqual(hosts, {"a.example.com"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(health.get("status"), "ok")
        self.assertEqual(health.get("errors"), 0)
        self.assertEqual(
            health.get("error_types", {}).get("amass_tool_unhealthy"),
            None,
        )
        self.assertEqual(
            mock_run_command.call_args_list[0][0][0],
            ["amass", "-version"],
        )
        self.assertEqual(
            mock_run_command.call_args_list[1][0][0],
            ["amass", "enum", "-h"],
        )
        self.assertIn("-src", mock_run_command.call_args_list[2][0][0])

    @patch("volt.check_single_bucket_exists")
    def test_collect_s3_bucket_findings_classifies_200_as_medium(
        self, mock_bucket_check
    ) -> None:
        def fake_check(
            bucket: str,
            timeout: int,
            s3_list_probe: bool = False,
            s3_website_probe: bool = False,
            s3_probe_retries: int = 0,
        ):
            if bucket == "mybucket":
                return bucket, 200, "confirmed_exists", "us-east-1", None
            if bucket == "example":
                return bucket, 403, "likely_exists", "us-east-1", None
            return bucket, 404, "unknown", "", None

        mock_bucket_check.side_effect = fake_check

        ctx = self._default_context()
        ctx.keywords = ["mybucket"]
        findings = volt.collect_s3_bucket_findings(ctx, hosts=set())
        by_asset = {f.asset: f for f in findings}
        self.assertIn("mybucket", by_asset)
        self.assertEqual(by_asset["mybucket"].severity, "medium")
        self.assertIn("example", by_asset)
        self.assertEqual(by_asset["example"].severity, "low")
        self.assertEqual(
            by_asset["example"].title, "S3 bucket name likely exists (HEAD signal)"
        )

    def test_classify_s3_head_status(self) -> None:
        self.assertEqual(
            volt.classify_s3_head_status(200, "us-east-1"), "confirmed_exists"
        )
        self.assertEqual(
            volt.classify_s3_head_status(403, "us-east-1"), "likely_exists"
        )
        self.assertEqual(volt.classify_s3_head_status(403, ""), "unknown")
        self.assertEqual(volt.classify_s3_head_status(404, ""), "unknown")

    def test_classify_gcp_status(self) -> None:
        self.assertEqual(volt.classify_gcp_status(200), "confirmed_exists")
        self.assertEqual(volt.classify_gcp_status(403), "likely_exists")
        self.assertEqual(volt.classify_gcp_status(404), "unknown")
        self.assertEqual(volt.classify_gcp_status(404, "NoSuchBucket"), "not_exists")

    def test_classify_azure_blob_status(self) -> None:
        self.assertEqual(
            volt.classify_azure_blob_status(200, ""),
            "confirmed_public",
        )
        self.assertEqual(
            volt.classify_azure_blob_status(403, "AuthorizationFailure"),
            "likely_exists",
        )
        self.assertEqual(
            volt.classify_azure_blob_status(404, "ContainerNotFound"),
            "not_exists",
        )
        self.assertEqual(
            volt.classify_azure_blob_status(401, "NoAuthenticationInformation"),
            "likely_exists",
        )
        self.assertEqual(
            volt.classify_azure_blob_status(403, "SomeUnknownCode"),
            "unknown",
        )

    def test_is_valid_azure_container_name_accepts_system_containers(self) -> None:
        self.assertTrue(volt.is_valid_azure_container_name("$web"))
        self.assertTrue(volt.is_valid_azure_container_name("$root"))
        self.assertTrue(volt.is_valid_azure_container_name("$logs"))

    def test_parse_azure_error_code_prefers_header(self) -> None:
        code = volt.parse_azure_error_code(
            {"x-ms-error-code": "AuthorizationFailure"},
            "<Error><Code>FeatureVersionMismatch</Code></Error>",
        )
        self.assertEqual(code, "AuthorizationFailure")

    def test_parse_azure_error_code_falls_back_to_body(self) -> None:
        code = volt.parse_azure_error_code(
            {},
            "<Error><Code>FeatureVersionMismatch</Code></Error>",
        )
        self.assertEqual(code, "FeatureVersionMismatch")

    def test_parse_s3_error_code_prefers_header(self) -> None:
        code = volt.parse_s3_error_code(
            {"x-amz-error-code": "NoSuchBucket"},
            "<Error><Code>AccessDenied</Code></Error>",
        )
        self.assertEqual(code, "NoSuchBucket")

    def test_parse_s3_error_code_falls_back_to_body(self) -> None:
        code = volt.parse_s3_error_code(
            {},
            "<Error><Code>NoSuchKey</Code></Error>",
        )
        self.assertEqual(code, "NoSuchKey")

    def test_parse_gcp_error_code_falls_back_to_body(self) -> None:
        code = volt.parse_gcp_error_code("<Error><Code>NoSuchBucket</Code></Error>")
        self.assertEqual(code, "NoSuchBucket")

    def test_extract_azure_storage_account_from_cname_supports_extended_suffixes(
        self,
    ) -> None:
        self.assertEqual(
            volt.extract_azure_storage_account_from_cname(
                "acmestorage.blob.core.usgovcloudapi.net"
            ),
            "acmestorage",
        )
        self.assertEqual(
            volt.extract_azure_storage_account_from_cname(
                "acmestorage.z05.blob.storage.azure.net"
            ),
            "acmestorage",
        )
        self.assertEqual(
            volt.extract_azure_storage_account_from_cname(
                "asverify.acmestorage.web.core.windows.net"
            ),
            "acmestorage",
        )

    def test_validate_s3_bucket_name_filters_reserved_and_invalid(self) -> None:
        self.assertEqual(volt.validate_s3_bucket_name("valid-bucket"), (True, ""))
        self.assertEqual(
            volt.validate_s3_bucket_name("xn--bucket"),
            (False, "reserved_prefix"),
        )
        self.assertEqual(
            volt.validate_s3_bucket_name("example-s3alias"),
            (False, "reserved_suffix"),
        )
        self.assertEqual(
            volt.validate_s3_bucket_name("192.168.0.1"),
            (False, "ip_address_style"),
        )

    def test_validate_gcp_bucket_name_filters_reserved_and_invalid(self) -> None:
        self.assertEqual(volt.validate_gcp_bucket_name("valid-bucket"), (True, ""))
        self.assertEqual(
            volt.validate_gcp_bucket_name("assets.example.com"),
            (True, ""),
        )
        self.assertEqual(
            volt.validate_gcp_bucket_name("goog-bucket"),
            (False, "reserved_prefix"),
        )
        self.assertEqual(
            volt.validate_gcp_bucket_name("my-g00gle-bucket"),
            (False, "reserved_substring"),
        )
        self.assertEqual(
            volt.validate_gcp_bucket_name("192.168.0.1"),
            (False, "ip_address_style"),
        )

    def test_build_gcp_bucket_wordlist_includes_dotful_candidates(self) -> None:
        ctx = self._default_context()
        ctx.keywords = ["portal"]
        ctx.max_bucket_candidates = 200
        candidates = volt.build_gcp_bucket_wordlist(
            ctx, {"assets.example.com", "api.dev.example.com"}
        )
        self.assertIn("example.com", candidates)
        self.assertIn("assets.example.com", candidates)
        self.assertIn("api.dev.example.com", candidates)
        self.assertIn("portal.example.com", candidates)

    @patch("builtins.print")
    @patch("volt.check_single_bucket_exists")
    def test_collect_s3_bucket_findings_skips_unknown_signals(
        self, mock_bucket_check, _mock_print
    ) -> None:
        mock_bucket_check.return_value = ("example", 404, "unknown", "", None)
        ctx = self._default_context()
        findings = volt.collect_s3_bucket_findings(ctx, hosts={"a.example.com"})
        self.assertEqual(findings, [])

    def test_collect_s3_bucket_findings_filters_invalid_candidates(self) -> None:
        ctx = self._default_context()
        ctx.keywords = ["192.168.0.1"]
        health = volt.init_source_health("s3")
        volt.collect_s3_bucket_findings(ctx, hosts=set(), health=health)
        self.assertGreater(health.get("filtered_invalid_candidates", 0), 0)
        self.assertGreater(
            health.get("filtered_reasons", {}).get("ip_address_style", 0), 0
        )

    @patch("volt.check_single_gcp_bucket_exists")
    def test_collect_gcp_bucket_findings_classifies_200_as_medium(
        self, mock_gcp_check
    ) -> None:
        def fake_check(
            bucket: str,
            timeout: int,
            gcp_dual_endpoint_probe: bool = False,
            gcp_probe_retries: int = 0,
        ):
            if bucket == "mybucket":
                return bucket, 200, "confirmed_exists", None
            if bucket == "example":
                return bucket, 403, "likely_exists", None
            return bucket, 404, "unknown", None

        mock_gcp_check.side_effect = fake_check
        ctx = self._default_context()
        ctx.keywords = ["mybucket"]
        ctx.max_bucket_candidates = 200
        findings = volt.collect_gcp_bucket_findings(ctx, hosts=set())
        by_asset = {f.asset: f for f in findings}
        self.assertIn("mybucket", by_asset)
        self.assertEqual(by_asset["mybucket"].severity, "medium")
        self.assertIn("example", by_asset)
        self.assertEqual(by_asset["example"].severity, "low")
        self.assertEqual(
            by_asset["example"].title, "GCP bucket name likely exists (HTTP signal)"
        )

    def test_collect_gcp_bucket_findings_filters_invalid_candidates(self) -> None:
        ctx = self._default_context()
        ctx.domains = []
        ctx.organization = ""
        ctx.keywords = ["goog-sensitive"]
        health = volt.init_source_health("gcp")
        findings = volt.collect_gcp_bucket_findings(ctx, hosts=set(), health=health)
        self.assertEqual(findings, [])
        self.assertEqual(health.get("status"), "ok_no_candidates")
        self.assertGreater(health.get("raw_candidates", 0), 0)
        self.assertGreater(health.get("filtered_invalid_candidates", 0), 0)
        self.assertGreater(
            health.get("filtered_reasons", {}).get("reserved_prefix", 0), 0
        )

    @patch("volt.check_single_gcp_bucket_exists")
    def test_collect_gcp_bucket_findings_suppresses_weak_likely_generic_name(
        self, mock_gcp_check
    ) -> None:
        def fake_check(
            bucket: str,
            timeout: int,
            gcp_dual_endpoint_probe: bool = False,
            gcp_probe_retries: int = 0,
        ):
            if bucket == "backup":
                return bucket, 403, "likely_exists", None
            return bucket, 404, "unknown", None

        mock_gcp_check.side_effect = fake_check
        ctx = self._default_context()
        ctx.keywords = []
        ctx.max_bucket_candidates = 200
        health = volt.init_source_health("gcp")
        findings = volt.collect_gcp_bucket_findings(
            ctx, hosts={"backup.example.com"}, health=health
        )
        self.assertEqual(findings, [])
        self.assertGreater(health.get("suppressed_weak_likely", 0), 0)

    @patch("volt.check_single_gcp_bucket_exists")
    def test_collect_gcp_bucket_findings_keeps_likely_with_target_affinity(
        self, mock_gcp_check
    ) -> None:
        def fake_check(
            bucket: str,
            timeout: int,
            gcp_dual_endpoint_probe: bool = False,
            gcp_probe_retries: int = 0,
        ):
            if bucket == "backup":
                return bucket, 403, "likely_exists", None
            return bucket, 404, "unknown", None

        mock_gcp_check.side_effect = fake_check
        ctx = self._default_context()
        ctx.domains = []
        ctx.organization = ""
        ctx.keywords = ["acme", "backup"]
        ctx.max_bucket_candidates = 200
        findings = volt.collect_gcp_bucket_findings(ctx, hosts=set())
        self.assertTrue(any(f.asset == "backup" for f in findings))

    @patch("volt.fetch_url")
    def test_check_single_gcp_bucket_exists_uses_nosuchbucket_signal(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.side_effect = [
            (404, "", {}),
            (404, "<Error><Code>NoSuchBucket</Code></Error>", {}),
        ]
        _, status, existence, list_status = volt.check_single_gcp_bucket_exists(
            "definitely-not-real-gcs-bucket-xyz987",
            5,
        )
        self.assertEqual(status, 404)
        self.assertEqual(existence, "not_exists")
        self.assertEqual(list_status, 404)
        self.assertEqual(mock_fetch_url.call_count, 2)

    @patch("volt.fetch_url")
    def test_check_single_gcp_bucket_exists_uses_object_probe_for_nosuchkey(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.side_effect = [
            (404, "", {}),
            (404, "<Error><Code>NotFound</Code></Error>", {}),
            (404, "<Error><Code>NoSuchKey</Code></Error>", {}),
        ]
        _, status, existence, list_status = volt.check_single_gcp_bucket_exists(
            "gcp-public-data-landsat",
            5,
        )
        self.assertEqual(status, 404)
        self.assertEqual(existence, "confirmed_exists")
        self.assertEqual(list_status, 404)
        self.assertEqual(mock_fetch_url.call_count, 3)
        self.assertIn(
            "gcp-public-data-landsat/__volt_probe__",
            mock_fetch_url.call_args_list[2].args[0],
        )

    @patch("volt.fetch_url")
    def test_check_single_gcp_bucket_exists_uses_dual_endpoint_fallback(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.side_effect = [
            (404, "", {}),
            (404, "<Error><Code>NotFound</Code></Error>", {}),
            (404, "<Error><Code>NotFound</Code></Error>", {}),
            (403, "", {}),
        ]
        _, status, existence, list_status = volt.check_single_gcp_bucket_exists(
            "examplebucket",
            5,
            gcp_dual_endpoint_probe=True,
        )
        self.assertEqual(status, 403)
        self.assertEqual(existence, "likely_exists")
        self.assertEqual(list_status, 404)
        self.assertEqual(mock_fetch_url.call_count, 4)
        self.assertIn(
            "https://examplebucket.storage.googleapis.com/",
            mock_fetch_url.call_args_list[3].args[0],
        )

    @patch("volt.fetch_url")
    def test_check_single_gcp_bucket_exists_respects_gcp_probe_retry_override(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.side_effect = [
            (404, "", {}),
            (404, "<Error><Code>NoSuchBucket</Code></Error>", {}),
        ]
        volt.check_single_gcp_bucket_exists(
            "retry-test-gcs-bucket",
            5,
            gcp_probe_retries=1,
        )
        self.assertEqual(mock_fetch_url.call_args_list[0].kwargs.get("retries"), 1)

    @patch("builtins.print")
    @patch("volt.check_single_bucket_exists")
    def test_collect_s3_bucket_findings_suppresses_weak_likely_probe403(
        self, mock_bucket_check, _mock_print
    ) -> None:
        mock_bucket_check.return_value = (
            "example",
            404,
            "likely_exists",
            "us-east-1",
            403,
        )
        ctx = self._default_context()
        findings = volt.collect_s3_bucket_findings(ctx, hosts={"a.example.com"})
        self.assertEqual(findings, [])

    @patch("volt.check_single_bucket_exists")
    def test_collect_s3_bucket_findings_error_when_all_checks_fail(
        self, mock_bucket_check
    ) -> None:
        mock_bucket_check.return_value = ("example", 0, "unknown", "", None)
        ctx = self._default_context()
        health = volt.init_source_health("s3")
        findings = volt.collect_s3_bucket_findings(
            ctx, hosts={"a.example.com"}, health=health
        )
        self.assertEqual(findings, [])
        self.assertGreater(health["errors"], 0)
        self.assertEqual(health["status"], "error")

    @patch("volt.check_single_bucket_exists")
    def test_collect_s3_bucket_findings_partial_when_some_checks_succeed(
        self, mock_bucket_check
    ) -> None:
        first = {"seen": False}

        def fake_check(*_args, **_kwargs):
            if not first["seen"]:
                first["seen"] = True
                return ("example", 0, "unknown", "", None)
            return ("example", 404, "unknown", "", 404)

        mock_bucket_check.side_effect = fake_check
        ctx = self._default_context()
        health = volt.init_source_health("s3")
        findings = volt.collect_s3_bucket_findings(
            ctx, hosts={"a.example.com"}, health=health
        )
        self.assertEqual(findings, [])
        self.assertGreater(health["errors"], 0)
        self.assertEqual(health["status"], "partial")

    @patch("volt.check_single_azure_blob_container")
    @patch("volt.probe_azure_blob_object_access")
    @patch("volt.fetch_doh_cname_records")
    def test_collect_azure_blob_findings_detects_public_container(
        self, mock_fetch_doh, _mock_probe_object, mock_check_azure
    ) -> None:
        mock_fetch_doh.return_value = (
            200,
            ["acmestorage.blob.core.windows.net"],
            "https://dns.google/resolve?name=app.example.com&type=CNAME",
        )

        def fake_check(
            account: str,
            container: str,
            timeout: int,
            azure_probe_retries: int = 0,
        ):
            if account == "acmestorage" and container == "example":
                return (
                    account,
                    container,
                    200,
                    "confirmed_public",
                    "",
                    "https://example",
                )
            return (
                account,
                container,
                404,
                "unknown",
                "ContainerNotFound",
                "https://example",
            )

        mock_check_azure.side_effect = fake_check

        ctx = self._default_context()
        ctx.keywords = ["example"]
        health = volt.init_source_health("azure")
        findings = volt.collect_azure_blob_findings(ctx, {"app.example.com"}, health)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].asset_type, "azure_blob_container")
        self.assertEqual(findings[0].asset, "acmestorage/example")
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["findings"], 1)

    @patch("volt.check_single_azure_blob_container")
    @patch("volt.probe_azure_blob_object_access")
    @patch("volt.fetch_doh_cname_records")
    def test_collect_azure_blob_findings_includes_system_containers(
        self, mock_fetch_doh, _mock_probe_object, mock_check_azure
    ) -> None:
        mock_fetch_doh.return_value = (
            200,
            ["acmestorage.blob.core.windows.net"],
            "https://dns.google/resolve?name=app.example.com&type=CNAME",
        )

        def fake_check(
            account: str,
            container: str,
            timeout: int,
            azure_probe_retries: int = 0,
        ):
            if account == "acmestorage" and container == "$web":
                return (
                    account,
                    container,
                    200,
                    "confirmed_public",
                    "",
                    "https://example",
                )
            return (
                account,
                container,
                404,
                "unknown",
                "ContainerNotFound",
                "https://example",
            )

        mock_check_azure.side_effect = fake_check
        ctx = self._default_context()
        ctx.domains = []
        ctx.organization = ""
        ctx.keywords = []
        ctx.max_bucket_candidates = 20
        health = volt.init_source_health("azure")
        findings = volt.collect_azure_blob_findings(ctx, {"app.example.com"}, health)
        self.assertTrue(any(f.asset == "acmestorage/$web" for f in findings))
        self.assertGreater(health.get("system_container_hits", 0), 0)

    @patch("volt.check_single_azure_blob_container")
    @patch("volt.probe_azure_blob_object_access")
    @patch("volt.fetch_doh_cname_records")
    def test_collect_azure_blob_findings_infers_account_from_host_without_cname(
        self, mock_fetch_doh, _mock_probe_object, mock_check_azure
    ) -> None:
        mock_fetch_doh.return_value = (
            200,
            [],
            "https://dns.google/resolve?name=acmestorage.blob.core.windows.net&type=CNAME",
        )

        def fake_check(
            account: str,
            container: str,
            timeout: int,
            azure_probe_retries: int = 0,
        ):
            if account == "acmestorage" and container == "example":
                return (
                    account,
                    container,
                    200,
                    "confirmed_public",
                    "",
                    "https://example",
                )
            return (
                account,
                container,
                404,
                "unknown",
                "ContainerNotFound",
                "https://example",
            )

        mock_check_azure.side_effect = fake_check
        ctx = self._default_context()
        ctx.domains = []
        ctx.organization = ""
        ctx.keywords = ["example"]
        ctx.max_bucket_candidates = 200
        health = volt.init_source_health("azure")
        findings = volt.collect_azure_blob_findings(
            ctx, {"acmestorage.blob.core.windows.net"}, health
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].asset, "acmestorage/example")
        self.assertEqual(health["status"], "ok")

    @patch("volt.check_single_azure_blob_container")
    @patch("volt.probe_azure_blob_object_access")
    @patch("volt.fetch_doh_cname_records")
    def test_collect_azure_blob_findings_tracks_error_code_telemetry(
        self, mock_fetch_doh, _mock_probe_object, mock_check_azure
    ) -> None:
        mock_fetch_doh.return_value = (
            200,
            ["acmestorage.blob.core.windows.net"],
            "https://dns.google/resolve?name=app.example.com&type=CNAME",
        )

        def fake_check(
            account: str,
            container: str,
            timeout: int,
            azure_probe_retries: int = 0,
        ):
            if container == "$web":
                return (
                    account,
                    container,
                    401,
                    "likely_exists",
                    "NoAuthenticationInformation",
                    "https://example",
                )
            if container == "$root":
                return (
                    account,
                    container,
                    404,
                    "not_exists",
                    "ContainerNotFound",
                    "https://example",
                )
            return (
                account,
                container,
                404,
                "unknown",
                "",
                "https://example",
            )

        mock_check_azure.side_effect = fake_check
        ctx = self._default_context()
        ctx.domains = []
        ctx.organization = ""
        ctx.keywords = []
        ctx.max_bucket_candidates = 3
        health = volt.init_source_health("azure")
        findings = volt.collect_azure_blob_findings(ctx, {"app.example.com"}, health)
        self.assertEqual(findings, [])
        self.assertEqual(health.get("likely_exists"), 1)
        self.assertEqual(health.get("not_exists"), 1)
        self.assertEqual(
            health.get("error_code_counts", {}).get("NoAuthenticationInformation"), 1
        )
        self.assertEqual(
            health.get("error_code_counts", {}).get("ContainerNotFound"), 1
        )

    @patch("volt.check_single_azure_blob_container")
    @patch("volt.probe_azure_blob_object_access")
    @patch("volt.fetch_doh_cname_records")
    def test_collect_azure_blob_findings_detects_blob_only_public_access(
        self, mock_fetch_doh, mock_probe_object, mock_check_azure
    ) -> None:
        mock_fetch_doh.return_value = (
            200,
            ["acmestorage.blob.core.windows.net"],
            "https://dns.google/resolve?name=app.example.com&type=CNAME",
        )

        def fake_check(
            account: str,
            container: str,
            timeout: int,
            azure_probe_retries: int = 0,
        ):
            if container == "example":
                return (
                    account,
                    container,
                    403,
                    "likely_exists",
                    "NoAuthenticationInformation",
                    "https://example",
                )
            return (
                account,
                container,
                404,
                "unknown",
                "",
                "https://example",
            )

        def fake_probe(
            account: str,
            container: str,
            object_path: str,
            timeout: int,
            azure_probe_retries: int = 0,
        ):
            if container == "example" and object_path == "index.html":
                return (
                    200,
                    "",
                    f"https://{account}.blob.core.windows.net/example/index.html",
                )
            return (
                404,
                "BlobNotFound",
                f"https://{account}.blob.core.windows.net/{container}/{object_path}",
            )

        mock_check_azure.side_effect = fake_check
        mock_probe_object.side_effect = fake_probe
        ctx = self._default_context()
        ctx.domains = []
        ctx.organization = ""
        ctx.keywords = ["example"]
        ctx.max_bucket_candidates = 40
        ctx.azure_blob_object_probe = True
        health = volt.init_source_health("azure")
        findings = volt.collect_azure_blob_findings(ctx, {"app.example.com"}, health)
        self.assertTrue(any(f.asset == "acmestorage/example" for f in findings))
        self.assertGreater(health.get("blob_only_hits", 0), 0)
        self.assertGreater(health.get("blob_object_probes", 0), 0)

    @patch("volt.fetch_doh_cname_records")
    def test_collect_azure_blob_findings_partial_when_doh_errors(
        self, mock_fetch_doh
    ) -> None:
        mock_fetch_doh.return_value = (
            0,
            [],
            "https://dns.google/resolve?name=app.example.com&type=CNAME",
        )
        ctx = self._default_context()
        health = volt.init_source_health("azure")
        findings = volt.collect_azure_blob_findings(ctx, {"app.example.com"}, health)
        self.assertEqual(findings, [])
        self.assertEqual(health["errors"], 1)
        self.assertEqual(health["status"], "partial")

    @patch("volt.fetch_url")
    def test_check_single_bucket_exists_uses_list_probe_for_ambiguous_head(
        self, mock_fetch_url
    ) -> None:
        # First call: HEAD -> ambiguous 404. Second call: GET list probe -> 200.
        mock_fetch_url.side_effect = [
            (404, "", {"server": "AmazonS3"}),
            (200, "<ListBucketResult/>", {"server": "AmazonS3"}),
        ]
        bucket, status, existence, region, list_status = (
            volt.check_single_bucket_exists(
                "noaa-goes19",
                5,
                s3_list_probe=True,
            )
        )
        self.assertEqual(bucket, "noaa-goes19")
        self.assertEqual(status, 404)
        self.assertEqual(existence, "confirmed_exists")
        self.assertEqual(region, "")
        self.assertEqual(list_status, 200)
        head_call = mock_fetch_url.call_args_list[0]
        self.assertEqual(head_call.kwargs.get("retries"), volt.CLOUD_PROBE_HTTP_RETRIES)

    @patch("volt.fetch_url")
    def test_check_single_bucket_exists_defaults_to_list_probe(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.side_effect = [
            (404, "", {"server": "AmazonS3", "x-amz-bucket-region": "us-east-1"}),
            (403, "", {"x-amz-bucket-region": "us-east-1"}),
        ]
        _, _, existence, region, list_status = volt.check_single_bucket_exists(
            "example-bucket",
            5,
        )
        self.assertEqual(existence, "likely_exists")
        self.assertEqual(region, "us-east-1")
        self.assertEqual(list_status, 403)
        self.assertIn(
            "example-bucket.s3.us-east-1.amazonaws.com",
            mock_fetch_url.call_args_list[1].args[0],
        )

    @patch("volt.fetch_url")
    def test_check_single_bucket_exists_uses_object_probe_for_nosuchkey_signal(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.side_effect = [
            (404, "", {"server": "AmazonS3", "x-amz-bucket-region": "us-east-1"}),
            (404, "<Error><Code>NoSuchBucket</Code></Error>", {"server": "AmazonS3"}),
            (404, "<Error><Code>NoSuchKey</Code></Error>", {"server": "AmazonS3"}),
        ]
        _, status, existence, _, list_status = volt.check_single_bucket_exists(
            "noaa-goes16",
            5,
        )
        self.assertEqual(status, 404)
        self.assertEqual(list_status, 404)
        self.assertEqual(existence, "confirmed_exists")
        self.assertEqual(mock_fetch_url.call_count, 3)
        self.assertIn(
            "noaa-goes16.s3.us-east-1.amazonaws.com",
            mock_fetch_url.call_args_list[2].args[0],
        )

    @patch("volt.fetch_url")
    def test_check_single_bucket_exists_uses_website_probe_when_enabled(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.side_effect = [
            (404, "", {"server": "AmazonS3", "x-amz-bucket-region": "us-east-1"}),
            (404, "<Error><Code>AccessDenied</Code></Error>", {"server": "AmazonS3"}),
            (404, "<Error><Code>AccessDenied</Code></Error>", {"server": "AmazonS3"}),
            (403, "", {}),
        ]
        _, _, existence, region, _ = volt.check_single_bucket_exists(
            "example-website-bucket",
            5,
            s3_website_probe=True,
        )
        self.assertEqual(existence, "likely_exists")
        self.assertEqual(region, "us-east-1")
        self.assertIn(
            "example-website-bucket.s3-website-us-east-1.amazonaws.com",
            mock_fetch_url.call_args_list[3].args[0],
        )

    @patch("volt.fetch_url")
    def test_check_single_bucket_exists_respects_s3_probe_retry_override(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.side_effect = [
            (404, "", {"server": "AmazonS3"}),
            (404, "<Error><Code>NoSuchBucket</Code></Error>", {"server": "AmazonS3"}),
            (404, "<Error><Code>NoSuchBucket</Code></Error>", {"server": "AmazonS3"}),
        ]
        volt.check_single_bucket_exists(
            "retry-test-bucket",
            5,
            s3_probe_retries=1,
        )
        self.assertEqual(mock_fetch_url.call_args_list[0].kwargs.get("retries"), 1)

    @patch("volt.fetch_url")
    def test_check_single_bucket_exists_uses_object_probe_for_nosuchbucket_signal(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.side_effect = [
            (404, "", {"server": "AmazonS3"}),
            (404, "<Error><Code>NoSuchBucket</Code></Error>", {"server": "AmazonS3"}),
            (404, "<Error><Code>NoSuchBucket</Code></Error>", {"server": "AmazonS3"}),
        ]
        _, _, existence, _, _ = volt.check_single_bucket_exists(
            "definitely-not-real-volt-bucket-xyz987",
            5,
        )
        self.assertEqual(existence, "unknown")

    @patch("volt.fetch_url")
    def test_check_single_bucket_exists_website_probe_infers_region_when_unknown(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.side_effect = [
            (404, "", {"server": "AmazonS3"}),
            (404, "<Error><Code>NoSuchBucket</Code></Error>", {"server": "AmazonS3"}),
            (404, "<Error><Code>NoSuchBucket</Code></Error>", {"server": "AmazonS3"}),
            (
                400,
                "<Error><Code>IncorrectEndpoint</Code></Error>",
                {
                    "x-amz-error-code": "IncorrectEndpoint",
                    "x-amz-error-detail-endpoint": (
                        "toolbox2.s3-website-us-west-2.amazonaws.com"
                    ),
                },
            ),
            (200, "", {}),
        ]
        _, _, existence, region, _ = volt.check_single_bucket_exists(
            "toolbox2",
            5,
            s3_website_probe=True,
        )
        self.assertEqual(existence, "confirmed_exists")
        self.assertIn(region, {"", "us-west-2"})

    @patch("volt.fetch_url")
    def test_check_single_azure_blob_container_uses_cloud_probe_retry_policy(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.side_effect = [
            (200, "", {}),
            (200, "", {}),
        ]
        _, _, status, _, _, _ = volt.check_single_azure_blob_container(
            "azureopendatastorage",
            "mlsamples",
            5,
        )
        self.assertEqual(status, 200)
        self.assertEqual(mock_fetch_url.call_count, 2)
        self.assertEqual(mock_fetch_url.call_args_list[0].kwargs.get("method"), "HEAD")
        self.assertEqual(mock_fetch_url.call_args_list[1].kwargs.get("method"), "GET")
        self.assertEqual(
            mock_fetch_url.call_args_list[0].kwargs.get("retries"),
            volt.CLOUD_PROBE_HTTP_RETRIES,
        )

    @patch("volt.fetch_url")
    def test_check_single_azure_blob_container_respects_probe_retry_override(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.side_effect = [
            (404, "<Error><Code>ContainerNotFound</Code></Error>", {}),
        ]
        volt.check_single_azure_blob_container(
            "azureopendatastorage",
            "definitely-not-real-container-xyz",
            5,
            azure_probe_retries=1,
        )
        self.assertEqual(mock_fetch_url.call_args_list[0].kwargs.get("retries"), 1)

    @patch("volt.fetch_url")
    def test_probe_azure_blob_object_access_respects_probe_retry_override(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.return_value = (
            404,
            "<Error><Code>BlobNotFound</Code></Error>",
            {},
        )
        status, error_code, url = volt.probe_azure_blob_object_access(
            "azureopendatastorage",
            "$web",
            "index.html",
            5,
            azure_probe_retries=1,
        )
        self.assertEqual(status, 404)
        self.assertEqual(error_code, "BlobNotFound")
        self.assertIn("/%24web/index.html", url)
        self.assertEqual(mock_fetch_url.call_args_list[0].kwargs.get("retries"), 1)

    @patch("volt.fetch_url")
    def test_check_single_azure_blob_container_encodes_system_container_name(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.return_value = (200, "", {})
        volt.check_single_azure_blob_container(
            "azureopendatastorage",
            "$web",
            5,
        )
        self.assertIn(
            "/%24web?restype=container&comp=list&maxresults=1",
            mock_fetch_url.call_args.args[0],
        )

    @patch("volt.fetch_url")
    def test_check_single_azure_blob_container_retries_with_version_header(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.side_effect = [
            (409, "<Error><Code>FeatureVersionMismatch</Code></Error>", {}),
            (200, "", {}),
            (200, "", {}),
        ]
        _, _, status, existence, _, _ = volt.check_single_azure_blob_container(
            "azureopendatastorage",
            "nyctlc",
            5,
        )
        self.assertEqual(status, 200)
        self.assertEqual(existence, "confirmed_public")
        self.assertEqual(mock_fetch_url.call_count, 3)
        self.assertEqual(
            mock_fetch_url.call_args_list[1].kwargs.get("headers"),
            {"x-ms-version": volt.AZURE_BLOB_API_VERSION},
        )

    @patch("volt.fetch_url")
    def test_check_single_azure_blob_container_short_circuits_on_not_exists_head(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.return_value = (
            404,
            "<Error><Code>ContainerNotFound</Code></Error>",
            {},
        )
        _, _, status, existence, error_code, url = (
            volt.check_single_azure_blob_container(
                "azureopendatastorage",
                "definitely-not-real-container-xyz",
                5,
            )
        )
        self.assertEqual(status, 404)
        self.assertEqual(existence, "not_exists")
        self.assertEqual(error_code, "ContainerNotFound")
        self.assertEqual(mock_fetch_url.call_count, 1)
        self.assertIn("?restype=container", url)
        self.assertNotIn("comp=list", url)

    def test_match_takeover_signature(self) -> None:
        signature, cname = volt.match_takeover_signature(["foo.readthedocs.io"])
        self.assertIsNotNone(signature)
        self.assertEqual(cname, "foo.readthedocs.io")
        self.assertEqual(signature["provider"], "Read the Docs")

    @patch("volt.fetch_url")
    def test_collect_subdomain_takeover_findings_detects_confirmed(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.side_effect = [
            # DNS-over-HTTPS CNAME query
            (
                200,
                json.dumps(
                    {
                        "Answer": [
                            {
                                "name": "docs.example.com.",
                                "type": 5,
                                "data": "foo.readthedocs.io.",
                            }
                        ]
                    }
                ),
                {},
            ),
            # HTTPS landing page probe
            (
                404,
                "The link you have followed or the URL that you entered does not exist.",
                {},
            ),
        ]
        ctx = self._default_context()
        health = volt.init_source_health("takeover")
        findings = volt.collect_subdomain_takeover_findings(
            ctx,
            {"docs.example.com"},
            health,
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.asset_type, "subdomain_takeover")
        self.assertEqual(finding.asset, "docs.example.com")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["findings"], 1)
        for call in mock_fetch_url.call_args_list:
            self.assertEqual(call.kwargs.get("retries"), volt.TAKEOVER_HTTP_RETRIES)

    @patch("volt.fetch_url")
    def test_collect_subdomain_takeover_findings_requires_fingerprint(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.side_effect = [
            (
                200,
                json.dumps(
                    {
                        "Answer": [
                            {
                                "name": "docs.example.com.",
                                "type": 5,
                                "data": "foo.readthedocs.io.",
                            }
                        ]
                    }
                ),
                {},
            ),
            (200, "Welcome to docs", {}),
        ]
        ctx = self._default_context()
        health = volt.init_source_health("takeover")
        findings = volt.collect_subdomain_takeover_findings(
            ctx,
            {"docs.example.com"},
            health,
        )
        self.assertEqual(findings, [])
        self.assertEqual(health["status"], "ok_no_results")
        for call in mock_fetch_url.call_args_list:
            self.assertEqual(call.kwargs.get("retries"), volt.TAKEOVER_HTTP_RETRIES)

    @patch("volt.fetch_url")
    def test_collect_subdomain_takeover_findings_partial_on_probe_error(
        self, mock_fetch_url
    ) -> None:
        def fake_fetch(url: str, timeout: int, **kwargs):
            if "dns.google/resolve" in url and "good.example.com" in url:
                return (
                    200,
                    json.dumps(
                        {
                            "Answer": [
                                {"data": "foo.readthedocs.io."},
                            ]
                        }
                    ),
                    {},
                )
            if "dns.google/resolve" in url and "bad.example.com" in url:
                return (
                    200,
                    json.dumps(
                        {
                            "Answer": [
                                {"data": "foo.readthedocs.io."},
                            ]
                        }
                    ),
                    {},
                )
            if "good.example.com" in url:
                return (
                    404,
                    "The link you have followed or the URL that you entered does not exist.",
                    {},
                )
            if "bad.example.com" in url:
                return (0, "", {})
            return (0, "", {})

        mock_fetch_url.side_effect = fake_fetch
        ctx = self._default_context()
        ctx.threads = 1
        health = volt.init_source_health("takeover")
        findings = volt.collect_subdomain_takeover_findings(
            ctx, {"bad.example.com", "good.example.com"}, health
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].asset, "good.example.com")
        self.assertEqual(health["errors"], 1)
        self.assertEqual(health["status"], "partial")

    @patch("volt.fetch_url")
    def test_fetch_commoncrawl_index_endpoint_uses_search_retry_policy(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.return_value = (
            200,
            '[{"cdx-api":"https://index.commoncrawl.org/CC-MAIN-2026-10-index"}]',
            {},
        )
        endpoint = volt.fetch_commoncrawl_index_endpoint(timeout=5)
        self.assertEqual(
            endpoint, "https://index.commoncrawl.org/CC-MAIN-2026-10-index"
        )
        self.assertEqual(mock_fetch_url.call_count, 1)
        self.assertEqual(
            mock_fetch_url.call_args.kwargs.get("retries"),
            volt.SEARCH_HTTP_RETRIES,
        )

    @patch("volt.fetch_url")
    def test_fetch_commoncrawl_index_endpoint_falls_back_to_id(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.return_value = (200, '[{"id":"CC-MAIN-2026-10"}]', {})
        endpoint = volt.fetch_commoncrawl_index_endpoint(timeout=5)
        self.assertEqual(
            endpoint, "https://index.commoncrawl.org/CC-MAIN-2026-10-index"
        )

    @patch("volt.fetch_url")
    def test_fetch_commoncrawl_index_endpoint_prefers_newest_cc_main(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.return_value = (
            200,
            json.dumps(
                [
                    {"id": "CC-MAIN-2024-20"},
                    {"id": "CC-MAIN-2026-05"},
                    {"id": "CC-MAIN-2025-50"},
                ]
            ),
            {},
        )
        endpoint = volt.fetch_commoncrawl_index_endpoint(timeout=5)
        self.assertEqual(
            endpoint, "https://index.commoncrawl.org/CC-MAIN-2026-05-index"
        )

    @patch("volt.fetch_url")
    def test_fetch_commoncrawl_results_dedupes_duplicate_urls(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.return_value = (
            200,
            "\n".join(
                [
                    '{"url":"https://a.example.com/.env"}',
                    '{"url":"https://a.example.com/.env"}',
                    '{"url":"https://b.example.com/.sql"}',
                ]
            ),
            {},
        )
        status, results, query_url = volt.fetch_commoncrawl_results(
            "https://index.commoncrawl.org/CC-MAIN-2026-10-index",
            "*.example.com/*.env",
            timeout=5,
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(results), 2)
        self.assertEqual(
            sorted(item["url"] for item in results),
            ["https://a.example.com/.env", "https://b.example.com/.sql"],
        )
        self.assertIn("output=json", query_url)
        self.assertIn("filter==status:200", query_url)

    @patch("volt.fetch_url")
    def test_fetch_commoncrawl_results_falls_back_when_filter_not_supported(
        self, mock_fetch_url
    ) -> None:
        mock_fetch_url.side_effect = [
            (422, "", {}),
            (200, '{"url":"https://a.example.com/.env"}\n', {}),
        ]
        status, results, query_url = volt.fetch_commoncrawl_results(
            "https://index.commoncrawl.org/CC-MAIN-2026-10-index",
            "*.example.com/*.env",
            timeout=5,
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(results), 1)
        self.assertNotIn("filter==status:200", query_url)

    def test_build_parser_rejects_non_positive_numeric_flags(self) -> None:
        parser = volt.build_parser()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(["-d", "example.com", "--timeout", "0"])
            with self.assertRaises(SystemExit):
                parser.parse_args(["-d", "example.com", "--threads", "-1"])
            with self.assertRaises(SystemExit):
                parser.parse_args(["-d", "example.com", "--max-bucket-candidates", "0"])

    def test_build_parser_version_flag(self) -> None:
        parser = volt.build_parser()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            with self.assertRaises(SystemExit) as exc:
                parser.parse_args(["--version"])
        self.assertEqual(exc.exception.code, 0)
        self.assertIn(volt.__version__, stdout.getvalue())

    def test_build_parser_s3_list_probe_default_and_disable_flag(self) -> None:
        parser = volt.build_parser()
        args = parser.parse_args(["-d", "example.com"])
        self.assertTrue(args.s3_list_probe)
        args = parser.parse_args(["-d", "example.com", "--no-s3-list-probe"])
        self.assertFalse(args.s3_list_probe)

    def test_build_parser_s3_website_probe_and_retry_defaults(self) -> None:
        parser = volt.build_parser()
        args = parser.parse_args(["-d", "example.com"])
        self.assertFalse(args.s3_website_probe)
        self.assertEqual(args.s3_probe_retries, 0)
        args = parser.parse_args(
            ["-d", "example.com", "--s3-website-probe", "--s3-probe-retries", "1"]
        )
        self.assertTrue(args.s3_website_probe)
        self.assertEqual(args.s3_probe_retries, 1)

    def test_build_parser_takeover_default_and_disable_flag(self) -> None:
        parser = volt.build_parser()
        args = parser.parse_args(["-d", "example.com"])
        self.assertFalse(args.no_takeover)
        args = parser.parse_args(["-d", "example.com", "--no-takeover"])
        self.assertTrue(args.no_takeover)

    def test_build_parser_gcp_default_and_disable_flag(self) -> None:
        parser = volt.build_parser()
        args = parser.parse_args(["-d", "example.com"])
        self.assertFalse(args.no_gcp)
        self.assertFalse(args.gcp_dual_endpoint_probe)
        self.assertEqual(args.gcp_probe_retries, 0)
        args = parser.parse_args(["-d", "example.com", "--no-gcp"])
        self.assertTrue(args.no_gcp)
        args = parser.parse_args(["-d", "example.com", "--gcp-dual-endpoint-probe"])
        self.assertTrue(args.gcp_dual_endpoint_probe)
        args = parser.parse_args(["-d", "example.com", "--gcp-probe-retries", "1"])
        self.assertEqual(args.gcp_probe_retries, 1)

    def test_build_parser_azure_default_and_disable_flag(self) -> None:
        parser = volt.build_parser()
        args = parser.parse_args(["-d", "example.com"])
        self.assertFalse(args.no_azure)
        self.assertFalse(args.azure_blob_object_probe)
        self.assertEqual(args.azure_probe_retries, 0)
        args = parser.parse_args(["-d", "example.com", "--no-azure"])
        self.assertTrue(args.no_azure)
        args = parser.parse_args(["-d", "example.com", "--azure-object-probe"])
        self.assertTrue(args.azure_blob_object_probe)
        args = parser.parse_args(["-d", "example.com", "--azure-probe-retries", "1"])
        self.assertEqual(args.azure_probe_retries, 1)

    def test_build_parser_reliability_defaults(self) -> None:
        parser = volt.build_parser()
        args = parser.parse_args(["-d", "example.com"])
        self.assertEqual(args.tool_timeout, 120)
        self.assertEqual(args.max_bucket_candidates, 300)

    def test_build_parser_search_provider_default_and_override(self) -> None:
        parser = volt.build_parser()
        args = parser.parse_args(["-d", "example.com"])
        self.assertEqual(args.search_providers, "commoncrawl")
        args = parser.parse_args(
            ["-d", "example.com", "--search-providers", "commoncrawl"]
        )
        self.assertEqual(args.search_providers, "commoncrawl")

    @patch("volt.collect_subdomain_takeover_findings")
    @patch("volt.collect_azure_blob_findings")
    @patch("volt.collect_gcp_bucket_findings")
    @patch("volt.collect_s3_bucket_findings")
    @patch("volt.collect_search_index_findings")
    @patch("volt.collect_ct_subdomains")
    @patch("volt.collect_amass_subdomains")
    @patch("volt.collect_subfinder_subdomains")
    @patch("builtins.print")
    def test_run_scan_orchestrates_sources_and_dedupes(
        self,
        _mock_print,
        mock_subfinder,
        mock_amass,
        mock_ct,
        mock_search,
        mock_s3,
        mock_gcp,
        mock_azure,
        mock_takeover,
    ) -> None:
        sf_finding = mk_finding("subdomain", "a.example.com", "info", "sf")
        ct_finding = mk_finding("subdomain", "a.example.com", "info", "ct")
        search_finding = mk_finding(
            "indexed_leak",
            "https://a.example.com/.env",
            "high",
            "Potential .env exposure indexed",
        )
        s3_finding = mk_finding(
            "s3_bucket", "a-example-assets", "low", "S3 bucket name exists"
        )

        mock_subfinder.return_value = ({"a.example.com"}, [sf_finding])
        mock_amass.return_value = (set(), [])
        mock_ct.return_value = ({"a.example.com"}, [ct_finding])
        mock_search.return_value = ({"a.example.com"}, [search_finding])
        mock_s3.return_value = [s3_finding]
        mock_gcp.return_value = []
        mock_azure.return_value = []
        mock_takeover.return_value = []

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
            s3_list_probe=False,
            no_ct=False,
            no_subfinder=False,
            no_amass=False,
            no_search=False,
            no_s3=False,
            no_gcp=False,
            no_azure=False,
            no_takeover=False,
        )
        report = volt.run_scan(args)

        self.assertEqual(report["targets"], ["example.com"])
        self.assertEqual(report["summary"]["total_findings"], 3)
        self.assertEqual(report["summary"]["by_type"]["subdomain"], 1)
        self.assertEqual(report["findings"][0]["severity"], "high")
        self.assertIn("source_health", report)
        self.assertIn("search", report["source_health"])
        self.assertIn("gcp", report["source_health"])
        self.assertIn("azure", report["source_health"])
        self.assertIn("takeover", report["source_health"])
        mock_gcp.assert_called_once()
        mock_azure.assert_called_once()
        mock_takeover.assert_called_once()

    def test_run_scan_rejects_unknown_search_provider(self) -> None:
        args = argparse.Namespace(
            domain="example.com",
            domain_list=None,
            output="/tmp/ignored.json",
            organization=None,
            keywords=None,
            search_providers="invalid",
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
            no_gcp=True,
            no_azure=True,
            no_takeover=True,
        )
        with self.assertRaises(ValueError):
            volt.run_scan(args)

    @patch("builtins.print")
    @patch("volt.collect_subdomain_takeover_findings")
    @patch("volt.collect_azure_blob_findings")
    @patch("volt.collect_gcp_bucket_findings")
    @patch("volt.collect_s3_bucket_findings")
    @patch("volt.collect_search_index_findings")
    @patch("volt.collect_ct_subdomains")
    @patch("volt.collect_amass_subdomains")
    @patch("volt.collect_subfinder_subdomains")
    def test_run_scan_emits_source_health_warning_lines_when_degraded(
        self,
        mock_subfinder,
        mock_amass,
        mock_ct,
        mock_search,
        mock_s3,
        mock_gcp,
        mock_azure,
        mock_takeover,
        mock_print,
    ) -> None:
        mock_subfinder.return_value = (set(), [])
        mock_amass.return_value = (set(), [])
        mock_search.return_value = (set(), [])
        mock_s3.return_value = []
        mock_gcp.return_value = []
        mock_azure.return_value = []
        mock_takeover.return_value = []

        def fake_ct(_context, health):
            health["status"] = "partial"
            health["errors"] = 1
            health["timeouts"] = 0
            health["findings"] = 0
            health["notes"].append("ct upstream unavailable")
            return set(), []

        mock_ct.side_effect = fake_ct

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
            s3_list_probe=False,
            no_ct=False,
            no_subfinder=True,
            no_amass=True,
            no_search=True,
            no_s3=True,
            no_gcp=True,
            no_azure=True,
            no_takeover=True,
        )
        volt.run_scan(args)

        printed = "\n".join(str(call.args[0]) for call in mock_print.call_args_list)
        self.assertIn("[!] Source reliability warnings:", printed)
        self.assertIn("[health] ct: status=partial errors=1 timeouts=0", printed)


if __name__ == "__main__":
    unittest.main()
