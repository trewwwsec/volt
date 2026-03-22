from __future__ import annotations

from typing import Any, Optional


def fetch_url(
    url: str,
    timeout: int,
    method: str = "GET",
    headers: Optional[dict[str, str]] = None,
    retries: int = 2,
    *,
    default_user_agent: str,
    http_retryable_status_codes: set[int],
    http_backoff_base_seconds: float,
    request_module: Any,
    error_module: Any,
    sleep_fn: Any,
    random_uniform_fn: Any,
) -> tuple[int, str, dict[str, str]]:
    req_headers = {"User-Agent": default_user_agent}
    if headers:
        req_headers.update(headers)

    attempts = max(0, retries)

    def sleep_with_backoff(attempt: int) -> None:
        base_delay = http_backoff_base_seconds * (2**attempt)
        jitter = base_delay * max(0.0, min(1.0, random_uniform_fn(0.0, 0.25)))
        sleep_fn(base_delay + jitter)

    for attempt in range(attempts + 1):
        req = request_module.Request(url, headers=req_headers, method=method)
        try:
            with request_module.urlopen(req, timeout=timeout) as resp:
                body = ""
                if method != "HEAD":
                    body = resp.read().decode("utf-8", errors="replace")
                return resp.status, body, dict(resp.headers.items())
        except error_module.HTTPError as exc:
            body = ""
            if method != "HEAD":
                try:
                    body = exc.read().decode("utf-8", errors="replace")
                except Exception:
                    body = ""
            status = exc.code
            headers_out = dict(exc.headers.items()) if exc.headers else {}
            if attempt < attempts and status in http_retryable_status_codes:
                sleep_with_backoff(attempt)
                continue
            return status, body, headers_out
        except error_module.URLError:
            if attempt < attempts:
                sleep_with_backoff(attempt)
                continue
            return 0, "", {}
        except Exception:
            if attempt < attempts:
                sleep_with_backoff(attempt)
                continue
            return 0, "", {}

    return 0, "", {}
