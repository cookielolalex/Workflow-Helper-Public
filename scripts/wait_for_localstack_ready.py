#!/usr/bin/env python3
"""Wait for LocalStack's READY init hook to finish successfully."""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

DEFAULT_URL = "http://localhost:4566/_localstack/init/ready"
DEFAULT_TIMEOUT_SECONDS = 120.0
DEFAULT_INTERVAL_SECONDS = 1.0


def _init_hooks(status: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        hook
        for hook in status.get("scripts", [])
        if hook.get("stage") == "READY"
        and str(hook.get("name", "")).rsplit("/", maxsplit=1)[-1] == "init.sh"
    ]


def _successful(status: dict[str, Any]) -> bool:
    hooks = _init_hooks(status)
    return (
        status.get("completed") is True
        and len(hooks) == 1
        and hooks[0].get("state") == "SUCCESSFUL"
    )


def _terminal_failure(status: dict[str, Any]) -> bool:
    return any(
        str(hook.get("state", "")).upper() in {"ERROR", "FAILED"}
        for hook in _init_hooks(status)
    )


def fetch_status(url: str) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=5) as response:
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise ValueError(f"LocalStack READY endpoint returned non-object JSON: {payload!r}")
    return payload


def wait_until_ready(
    fetch: Callable[[], dict[str, Any]],
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if interval_seconds < 0:
        raise ValueError("interval_seconds must be non-negative")

    deadline = monotonic() + timeout_seconds
    last_status: dict[str, Any] | None = None
    last_error: Exception | None = None

    while True:
        try:
            last_status = fetch()
            last_error = None
            if _successful(last_status):
                return last_status
            if _terminal_failure(last_status):
                raise RuntimeError(
                    f"LocalStack READY init hook failed terminally: {last_status}"
                )
        except (OSError, ValueError, urllib.error.URLError) as exc:
            last_error = exc

        if monotonic() >= deadline:
            detail = last_status if last_status is not None else repr(last_error)
            raise TimeoutError(
                f"LocalStack READY init hook did not become successful within "
                f"{timeout_seconds:g}s; last observation: {detail}"
            )
        sleep(interval_seconds)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL_SECONDS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    status = wait_until_ready(
        lambda: fetch_status(args.url),
        timeout_seconds=args.timeout,
        interval_seconds=args.interval,
    )
    print(json.dumps(status, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
