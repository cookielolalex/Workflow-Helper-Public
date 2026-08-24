import io
import json
import zipfile
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from workflow_worker.handler import MAX_EVENT_LINE_BYTES, UnsafePackageError, process_package


def _package_with_events(session_id, events: list[dict[str, object]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(
            "metadata.json",
            json.dumps({"schema_version": "1.0", "session_id": str(session_id)}),
        )
        archive.writestr("events.jsonl", "\n".join(json.dumps(event) for event in events))
    return output.getvalue()


def test_package_is_converted_to_timeline() -> None:
    session_id = uuid4()
    started = datetime(2026, 8, 16, tzinfo=UTC)
    events = [
        {
            "event_id": str(uuid4()),
            "occurred_at": started.isoformat(),
            "event_type": "session_started",
            "source": "agent",
        },
        {
            "event_id": str(uuid4()),
            "occurred_at": (started + timedelta(seconds=10)).isoformat(),
            "event_type": "session_ended",
            "source": "agent",
        },
    ]

    result = process_package(session_id, _package_with_events(session_id, events))
    assert result.session_id == session_id
    assert result.meaningful_event_count == 2
    assert result.timeline[-1].offset_seconds == 10


def test_unsafe_member_path_is_rejected() -> None:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("../events.jsonl", "{}")

    with pytest.raises(UnsafePackageError):
        process_package(uuid4(), output.getvalue())


def test_oversized_event_line_is_rejected_before_json_parsing() -> None:
    session_id = uuid4()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(
            "metadata.json",
            json.dumps({"schema_version": "1.0", "session_id": str(session_id)}),
        )
        archive.writestr("events.jsonl", b"{" + (b" " * MAX_EVENT_LINE_BYTES) + b"}\n")

    with pytest.raises(UnsafePackageError, match="line 1 exceeds"):
        process_package(session_id, output.getvalue())


@pytest.mark.parametrize(
    "change",
    [
        {"event_type": "screen_recorded"},
        {"source": "unknown"},
        {"unexpected": True},
        {"details": {"nested": {"not": "allowed"}}},
    ],
)
def test_noncanonical_event_is_rejected(change: dict[str, object]) -> None:
    session_id = uuid4()
    event = {
        "event_id": str(uuid4()),
        "occurred_at": "2026-08-16T04:00:00Z",
        "event_type": "session_started",
        "source": "agent",
        **change,
    }

    with pytest.raises(UnsafePackageError, match="line 1 is invalid"):
        process_package(session_id, _package_with_events(session_id, [event]))


def test_metadata_session_binding_is_required() -> None:
    session_id = uuid4()
    mismatched = _package_with_events(uuid4(), [])

    with pytest.raises(UnsafePackageError, match="session_id does not match"):
        process_package(session_id, mismatched)
