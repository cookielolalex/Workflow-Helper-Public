from datetime import UTC, datetime, timedelta
from uuid import uuid4

from workflow_worker.models import CadEvent
from workflow_worker.pipeline import process_events


def test_repeated_low_value_events_are_compacted() -> None:
    started = datetime(2026, 8, 16, tzinfo=UTC)
    events = [
        CadEvent(
            event_id=uuid4(),
            occurred_at=started,
            event_type="session_started",
            source="agent",
        ),
        CadEvent(
            event_id=uuid4(),
            occurred_at=started + timedelta(seconds=1),
            event_type="foreground_changed",
            source="agent",
        ),
        CadEvent(
            event_id=uuid4(),
            occurred_at=started + timedelta(seconds=2),
            event_type="foreground_changed",
            source="agent",
        ),
        CadEvent(
            event_id=uuid4(),
            occurred_at=started + timedelta(seconds=3),
            event_type="session_ended",
            source="agent",
        ),
    ]

    result = process_events(uuid4(), events)
    assert result.event_count == 4
    assert result.meaningful_event_count == 3
    assert result.warnings == []
