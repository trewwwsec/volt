import argparse
import json
import os
import subprocess
import tempfile
from pathlib import Path


SOURCES = ("subfinder", "amass", "ct", "search", "s3", "gcp", "azure", "takeover")
HEALTHY = {"ok", "ok_no_results", "ok_no_candidates"}
DEGRADED = {"partial", "error", "skipped_tool_missing"}


def inspect_report(report: object) -> tuple[dict[str, str], str]:
    if not isinstance(report, dict):
        raise ValueError("report must be an object")
    targets = report.get("targets")
    inventory = report.get("inventory")
    summary = report.get("summary")
    findings = report.get("findings")
    health = report.get("source_health")
    if (
        not isinstance(targets, list)
        or not targets
        or not all(isinstance(x, str) for x in targets)
    ):
        raise ValueError("targets must be a nonempty string list")
    if not isinstance(inventory, dict) or not isinstance(
        inventory.get("discovered_hosts"), list
    ):
        raise ValueError("inventory.discovered_hosts must be a list")
    if not all(isinstance(x, str) for x in inventory["discovered_hosts"]):
        raise ValueError("discovered hosts must be strings")
    if not isinstance(findings, list) or not all(isinstance(x, dict) for x in findings):
        raise ValueError("findings must be an object list")
    if not isinstance(summary, dict) or type(summary.get("total_findings")) is not int:
        raise ValueError("summary.total_findings must be an integer")
    if summary["total_findings"] != len(findings):
        raise ValueError("total_findings must match findings")
    if not isinstance(health, dict) or set(health) != set(SOURCES):
        raise ValueError("source_health must contain the eight expected sources")
    statuses = {}
    for source, entry in health.items():
        if not isinstance(entry, dict) or type(entry.get("enabled")) is not bool:
            raise ValueError(f"invalid enabled state for {source}")
        status = entry.get("status")
        if not isinstance(status, str) or status not in HEALTHY | DEGRADED | {
            "disabled"
        }:
            raise ValueError(f"unknown health status for {source}")
        if (status == "disabled") != (entry["enabled"] is False):
            raise ValueError(f"inconsistent disabled state for {source}")
        statuses[source] = status
    values = set(statuses.values())
    aggregate = "degraded" if values & DEGRADED else "healthy"
    if values == {"disabled"}:
        aggregate = "disabled"
    return statuses, aggregate


def decoded(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def run_case(
    argv: list[str],
    report_path: Path,
    *,
    cwd: Path,
    timeout: float,
    offline: bool = False,
) -> dict[str, object]:
    report_path = report_path.resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.unlink(missing_ok=True)
    result: dict[str, object] = {
        "command_status": "launch_error",
        "returncode": None,
        "report_status": "missing",
        "source_health": {},
        "source_status": "unavailable",
        "status": "failed",
        "problems": [],
    }
    problems: list[str] = []
    stdout = stderr = ""
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    try:
        process = subprocess.run(
            argv,
            cwd=cwd,
            env=environment,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        stdout, stderr = decoded(process.stdout), decoded(process.stderr)
        result["returncode"] = process.returncode
        result["command_status"] = "success" if process.returncode == 0 else "failed"
        if process.returncode:
            problems.append(f"command exited {process.returncode}")
    except subprocess.TimeoutExpired as exc:
        stdout, stderr = decoded(exc.stdout), decoded(exc.stderr)
        result["command_status"] = "timeout"
        problems.append(f"command exceeded {timeout} seconds")
    except OSError as exc:
        problems.append(f"could not launch command: {exc}")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        statuses, aggregate = inspect_report(report)
        result.update(
            report_status="valid", source_health=statuses, source_status=aggregate
        )
        if offline and (
            report["targets"] != ["example.test"]
            or report["findings"] != []
            or report["inventory"]["discovered_hosts"] != []
            or aggregate != "disabled"
        ):
            problems.append(
                "offline contract requires the expected target, empty results, "
                "and every source disabled"
            )
    except FileNotFoundError:
        problems.append("expected report was not created")
    except (OSError, UnicodeError, ValueError) as exc:
        result["report_status"] = "invalid"
        problems.append(f"invalid report: {exc}")
    if not problems:
        result["status"] = (
            "degraded" if result["source_status"] == "degraded" else "passed"
        )
    result.update(
        problems=problems, stdout_tail=stdout[-4000:], stderr_tail=stderr[-4000:]
    )
    (report_path.parent / "stdout.log").write_text(stdout, encoding="utf-8")
    (report_path.parent / "stderr.log").write_text(stderr, encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline installed-volt validation")
    parser.add_argument("--executable", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    executable = args.executable.resolve()
    output_dir = args.output_dir.resolve()
    report_path = output_dir / "offline-installed.json"
    argv = [str(executable), "-d", "example.test"]
    argv.extend(f"--no-{source}" for source in SOURCES)
    argv.extend(["-o", str(report_path)])
    with tempfile.TemporaryDirectory(prefix="volt-installed-cwd-") as directory:
        result = run_case(
            argv, report_path, cwd=Path(directory), timeout=30, offline=True
        )
    summary = json.dumps({"offline_installed": result}, indent=2, sort_keys=True)
    (output_dir / "summary.json").write_text(summary + "\n", encoding="utf-8")
    print(summary)
    return {"passed": 0, "failed": 1, "degraded": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
