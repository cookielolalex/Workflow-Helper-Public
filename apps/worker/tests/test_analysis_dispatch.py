from threading import Event, Thread

import pytest

from workflow_worker.analysis_dispatch import SerializedAnalysisDispatcher


def test_dispatcher_rejects_api_key_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-only-value")

    with pytest.raises(RuntimeError, match="API-key fallback"):
        SerializedAnalysisDispatcher().run(lambda: "not-run")


def test_dispatcher_allows_only_one_active_operation() -> None:
    dispatcher = SerializedAnalysisDispatcher()
    started = Event()
    release = Event()

    def blocking_operation() -> None:
        started.set()
        release.wait(timeout=2)

    thread = Thread(target=lambda: dispatcher.run(blocking_operation))
    thread.start()
    assert started.wait(timeout=2)

    with pytest.raises(RuntimeError, match="concurrency cap"):
        dispatcher.run(lambda: "not-run")

    release.set()
    thread.join(timeout=2)
    assert not thread.is_alive()
