from collections.abc import Iterable
from datetime import datetime
from uuid import UUID

from .models import CadEvent, EventType, ProcessingResult, TimelineItem

LOW_VALUE_EVENT_TYPES = {EventType.FOREGROUND_CHANGED}


def _summary(event: CadEvent) -> str:
    if event.event_type == EventType.CAD_COMMAND and event.command_name:
        return f"AutoCAD command: {event.command_name}"
    labels = {
        EventType.SESSION_STARTED: "Approved CAD session started",
        EventType.SESSION_PAUSED: "Capture paused",
        EventType.SESSION_RESUMED: "Capture resumed",
        EventType.SESSION_ENDED: "Approved CAD session ended",
        EventType.DRAWING_OPENED: "Drawing opened",
        EventType.DRAWING_SAVED: "Drawing saved",
        EventType.DRAWING_CLOSED: "Drawing closed",
        EventType.IDLE_STARTED: "Idle interval started",
        EventType.IDLE_ENDED: "Idle interval ended",
    }
    return labels.get(event.event_type, event.event_type.replace("_", " ").capitalize())


def build_timeline(events: Iterable[CadEvent]) -> list[TimelineItem]:
    ordered = sorted(events, key=lambda value: value.occurred_at)
    if not ordered:
        return []
    session_start: datetime = ordered[0].occurred_at
    timeline: list[TimelineItem] = []
    previous_signature: tuple[str, str | None] | None = None

    for event in ordered:
        signature = (event.event_type, event.command_name)
        if event.event_type in LOW_VALUE_EVENT_TYPES and signature == previous_signature:
            continue
        previous_signature = signature
        timeline.append(
            TimelineItem(
                offset_seconds=max(0.0, (event.occurred_at - session_start).total_seconds()),
                event_type=event.event_type,
                summary=_summary(event),
                source_event_id=event.event_id,
            )
        )
    return timeline


def process_events(session_id: UUID, events: list[CadEvent]) -> ProcessingResult:
    timeline = build_timeline(events)
    warnings: list[str] = []
    if not events:
        warnings.append("No CAD events were present; review the capture integration.")
    if not any(event.event_type == EventType.SESSION_ENDED for event in events):
        warnings.append("Session end event is missing; package may be incomplete.")

    return ProcessingResult(
        session_id=session_id,
        event_count=len(events),
        meaningful_event_count=len(timeline),
        timeline=timeline,
        keyframes=[],
        warnings=warnings,
    )
