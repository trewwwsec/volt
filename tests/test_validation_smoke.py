import json
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.validation_smoke import SOURCES, run_case


class ValidationSmokeTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.report = self.root / "report.json"
        self.data = {
            "targets": ["example.test"],
            "inventory": {"discovered_hosts": []},
            "findings": [],
            "summary": {"total_findings": 0},
            "source_health": {
                source: {"enabled": False, "status": "disabled"} for source in SOURCES
            },
        }

    def child(self, text, returncode=0):
        code = (
            "from pathlib import Path; import sys; "
            f"Path({str(self.report)!r}).write_text({text!r}, encoding='utf-8'); "
            f"sys.exit({returncode})"
        )
        return [sys.executable, "-c", code]

    def run_child(self, argv, **kwargs):
        return run_case(argv, self.report, cwd=self.root, timeout=10, **kwargs)

    def test_disabled_report_passes_offline_contract(self):
        result = self.run_child(self.child(json.dumps(self.data)), offline=True)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["source_status"], "disabled")

    def test_nonzero_exit_fails_even_with_valid_report(self):
        result = self.run_child(self.child(json.dumps(self.data), 7))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["returncode"], 7)
        self.assertEqual(result["report_status"], "valid")

    def test_absent_report_cannot_reuse_stale_success(self):
        self.report.write_text(json.dumps(self.data), encoding="utf-8")
        result = self.run_child([sys.executable, "-c", "pass"])
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["report_status"], "missing")

    def test_malformed_reports_fail(self):
        wrong = dict(self.data, source_health={})
        for text in ("{", "[]", json.dumps(wrong)):
            with self.subTest(text=text):
                result = self.run_child(self.child(text))
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["report_status"], "invalid")

    def test_source_degradation_is_not_clean_success(self):
        self.data["source_health"]["ct"] = {"enabled": True, "status": "partial"}
        argv = self.child(json.dumps(self.data))
        result = self.run_child(argv)
        self.assertEqual(result["command_status"], "success")
        self.assertEqual(result["report_status"], "valid")
        self.assertEqual(result["status"], "degraded")
        self.assertEqual(self.run_child(argv, offline=True)["status"], "failed")

    def test_unknown_health_is_invalid_not_healthy(self):
        self.data["source_health"]["ct"] = {"enabled": True, "status": "pending"}
        result = self.run_child(self.child(json.dumps(self.data)))
        self.assertEqual(result["report_status"], "invalid")

    def test_offline_report_must_match_target_and_empty_results(self):
        for key, value in (
            ("targets", ["unexpected.test"]),
            ("findings", [{}]),
            ("inventory", {"discovered_hosts": ["host.example.test"]}),
        ):
            with self.subTest(key=key):
                data = dict(self.data, **{key: value})
                result = self.run_child(self.child(json.dumps(data)), offline=True)
                self.assertEqual(result["status"], "failed")

    def test_timeout_retains_serializable_output(self):
        argv = [
            sys.executable,
            "-c",
            "import time; print('started', flush=True); time.sleep(60)",
        ]
        result = run_case(argv, self.report, cwd=self.root, timeout=1)
        self.assertEqual(result["command_status"], "timeout")
        self.assertEqual(result["status"], "failed")
        json.dumps(result)
        self.assertIsInstance(result["stdout_tail"], str)

    def test_launch_failure_is_reported(self):
        result = self.run_child([str(self.root / "missing-executable")])
        self.assertEqual(result["command_status"], "launch_error")
        self.assertEqual(result["status"], "failed")
