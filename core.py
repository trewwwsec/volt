from __future__ import annotations

import shutil
import subprocess
from typing import Any


def log(msg: str, verbose: bool = False, force: bool = False) -> None:
    if force or verbose:
        print(msg)


def init_source_health(name: str, enabled: bool = True) -> dict[str, Any]:
    return {
        "name": name,
        "enabled": enabled,
        "status": "disabled" if not enabled else "ok",
        "queried": 0,
        "hosts": 0,
        "findings": 0,
        "errors": 0,
        "timeouts": 0,
        "error_types": {},
        "error_samples": [],
        "notes": [],
    }


def record_source_error(
    stats: dict[str, Any],
    code: str,
    detail: str = "",
    *,
    timeout: bool = False,
    max_samples: int = 20,
) -> None:
    counter = "timeouts" if timeout else "errors"
    stats[counter] = int(stats.get(counter, 0)) + 1

    normalized_code = code.strip().lower() if code else "error"
    error_types = stats.setdefault("error_types", {})
    error_types[normalized_code] = int(error_types.get(normalized_code, 0)) + 1

    if not detail:
        return

    samples = stats.setdefault("error_samples", [])
    sample = {"code": normalized_code, "detail": detail.strip()}
    if sample in samples:
        return
    if len(samples) >= max_samples:
        return
    samples.append(sample)


def normalize_source_health(source_health: dict[str, dict[str, Any]]) -> None:
    for stats in source_health.values():
        notes = stats.get("notes")
        if isinstance(notes, list):
            stats["notes"] = sorted(
                {
                    str(note).strip()
                    for note in notes
                    if isinstance(note, str) and note.strip()
                }
            )

        error_types = stats.get("error_types")
        if isinstance(error_types, dict):
            ordered = {k: int(error_types[k]) for k in sorted(error_types)}
            stats["error_types"] = ordered

        samples = stats.get("error_samples")
        if isinstance(samples, list):
            normalized: list[dict[str, str]] = []
            for sample in samples:
                if not isinstance(sample, dict):
                    continue
                code = str(sample.get("code", "")).strip().lower()
                detail = str(sample.get("detail", "")).strip()
                if not code and not detail:
                    continue
                normalized.append({"code": code or "error", "detail": detail})
            deduped = {(item["code"], item["detail"]): item for item in normalized}
            stats["error_samples"] = sorted(
                deduped.values(),
                key=lambda item: (item["code"], item["detail"]),
            )

        providers = stats.get("providers")
        if isinstance(providers, dict):
            for provider_stats in providers.values():
                if not isinstance(provider_stats, dict):
                    continue
                provider_notes = provider_stats.get("notes")
                if isinstance(provider_notes, list):
                    provider_stats["notes"] = sorted(
                        {
                            str(note).strip()
                            for note in provider_notes
                            if isinstance(note, str) and note.strip()
                        }
                    )


def normalize_domain(value: str) -> str:
    return value.strip().lower().lstrip(".")


def check_tool(name: str) -> bool:
    return shutil.which(name) is not None


def run_command(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return 124, stdout, stderr
    except Exception as exc:
        return 1, "", str(exc)

    return proc.returncode, proc.stdout, proc.stderr
