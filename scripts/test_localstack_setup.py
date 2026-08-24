#!/usr/bin/env python3
"""Regression tests for the LocalStack Compose initialization hook."""

from __future__ import annotations

import stat
import unittest
from pathlib import Path

from scripts import wait_for_localstack_ready as ready


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
INIT_HOOK = REPOSITORY_ROOT / "scripts" / "localstack-init.sh"

RUNNING = {
    "completed": False,
    "scripts": [{"stage": "READY", "name": "init.sh", "state": "RUNNING"}],
}
SUCCESSFUL = {
    "completed": True,
    "scripts": [{"stage": "READY", "name": "init.sh", "state": "SUCCESSFUL"}],
}
FAILED = {
    "completed": True,
    "scripts": [{"stage": "READY", "name": "init.sh", "state": "FAILED"}],
}


class LocalStackSetupTests(unittest.TestCase):
    def test_init_hook_has_executable_file_mode(self) -> None:
        mode = stat.S_IMODE(INIT_HOOK.stat().st_mode)

        self.assertEqual(
            mode,
            0o755,
            f"{INIT_HOOK.relative_to(REPOSITORY_ROOT)} must have mode 100755; "
            f"found {mode:04o}",
        )

    def test_running_ready_status_is_retried_until_successful(self) -> None:
        observations = iter([RUNNING, SUCCESSFUL])

        result = ready.wait_until_ready(
            lambda: next(observations),
            timeout_seconds=1,
            interval_seconds=0,
        )

        self.assertEqual(result, SUCCESSFUL)

    def test_terminal_failed_ready_hook_fails_immediately(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "failed terminally"):
            ready.wait_until_ready(
                lambda: FAILED,
                timeout_seconds=1,
                interval_seconds=0,
            )

    def test_stuck_running_ready_status_times_out(self) -> None:
        ticks = iter([0.0, 0.0, 1.1])

        with self.assertRaisesRegex(TimeoutError, "last observation"):
            ready.wait_until_ready(
                lambda: RUNNING,
                timeout_seconds=1,
                interval_seconds=0,
                monotonic=lambda: next(ticks),
            )


if __name__ == "__main__":
    unittest.main()
