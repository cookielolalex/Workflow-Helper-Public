"""Serialized, fail-closed boundary for future ChatGPT-authenticated analysis."""

from __future__ import annotations

import os
from collections.abc import Callable
from threading import Lock
from typing import TypeVar

MAX_CODEX_CONCURRENCY = 1
_API_KEY_ENVIRONMENT_VARIABLES = ("OPENAI_API_KEY", "CODEX_API_KEY")
T = TypeVar("T")


class SerializedAnalysisDispatcher:
    """Runs one isolated analysis operation at a time without API-key fallback."""

    def __init__(self) -> None:
        self._lock = Lock()

    def run(self, operation: Callable[[], T]) -> T:
        configured_keys = [name for name in _API_KEY_ENVIRONMENT_VARIABLES if os.getenv(name)]
        if configured_keys:
            names = ", ".join(configured_keys)
            raise RuntimeError(f"API-key fallback is disabled; remove: {names}")
        if not self._lock.acquire(blocking=False):
            raise RuntimeError("analysis concurrency cap reached")
        try:
            return operation()
        finally:
            self._lock.release()
