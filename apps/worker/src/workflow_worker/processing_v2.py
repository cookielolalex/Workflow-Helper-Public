import hashlib
import json
import math
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, model_validator

from .models import CadEvent, EventType, ProcessingResult, StrictModel, TimelineItem
from .pipeline import process_events

MAX_OPERATION_SEGMENTS = 1000
MAX_OPERATION_OFFSET_SECONDS = 604800


class OperationSegment(StrictModel):
    sequence: int = Field(ge=1, le=MAX_OPERATION_SEGMENTS)
    start_offset_seconds: float = Field(
        ge=0,
        le=MAX_OPERATION_OFFSET_SECONDS,
        allow_inf_nan=False,
    )
    end_offset_seconds: float = Field(
        ge=0,
        le=MAX_OPERATION_OFFSET_SECONDS,
        allow_inf_nan=False,
    )
    command_names: list[str] = Field(min_length=1, max_length=64)
    drawing_ref: str = Field(min_length=1, max_length=255)
    summary: str = Field(min_length=1, max_length=512)
    source_event_ids: list[UUID] = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def validate_values(self) -> "OperationSegment":
        if len(set(self.command_names)) != len(self.command_names):
            raise ValueError("command_names must be unique")
        if any(not 1 <= len(value) <= 128 for value in self.command_names):
            raise ValueError("command_names must contain bounded non-empty strings")
        if len(set(self.source_event_ids)) != len(self.source_event_ids):
            raise ValueError("source_event_ids must be unique")
        if self.start_offset_seconds > self.end_offset_seconds:
            raise ValueError("operation segment bounds are reversed")
        return self


class ProcessingResultV2(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    session_id: UUID
    event_count: int = Field(ge=0)
    meaningful_event_count: int = Field(ge=0)
    timeline: list[TimelineItem]
    operation_segments: list[OperationSegment] = Field(max_length=MAX_OPERATION_SEGMENTS)
    keyframes: list[Annotated[str, Field(min_length=1, max_length=1024)]]
    warnings: list[Annotated[str, Field(min_length=1, max_length=2000)]]

    @model_validator(mode="after")
    def validate_operation_segments(self) -> "ProcessingResultV2":
        timeline_events: dict[UUID, float] = {}
        for event in self.timeline:
            if not math.isfinite(event.offset_seconds):
                raise ValueError("timeline offsets must be finite")
            if event.source_event_id in timeline_events:
                raise ValueError("timeline source_event_id values must be unique")
            timeline_events[event.source_event_id] = event.offset_seconds

        previous_end = -1.0
        used_source_event_ids: set[UUID] = set()
        for expected_sequence, segment in enumerate(self.operation_segments, start=1):
            if segment.sequence != expected_sequence:
                raise ValueError("operation segment sequence must be contiguous")
            if segment.start_offset_seconds > segment.end_offset_seconds:
                raise ValueError("operation segment bounds are reversed")
            if segment.start_offset_seconds < previous_end:
                raise ValueError("operation segments overlap or are unordered")
            for source_event_id in segment.source_event_ids:
                if source_event_id not in timeline_events:
                    raise ValueError("operation segment source evidence is not in the timeline")
                if source_event_id in used_source_event_ids:
                    raise ValueError("timeline source evidence is assigned more than once")
                offset = timeline_events[source_event_id]
                if not segment.start_offset_seconds <= offset <= segment.end_offset_seconds:
                    raise ValueError("timeline source evidence is outside segment bounds")
                used_source_event_ids.add(source_event_id)
            previous_end = segment.end_offset_seconds
        return self


class ProcessingCompletionV2(ProcessingResultV2):
    output_object_key: str = Field(
        pattern=r"^sessions/[0-9a-f-]{36}/timeline-v2\.json$"
    )
    idempotency_key: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def validate_output_key_and_digest(self) -> "ProcessingCompletionV2":
        expected = f"sessions/{self.session_id}/timeline-v2.json"
        if self.output_object_key != expected:
            raise ValueError("output_object_key does not match session_id")
        canonical = canonical_completion_bytes(
            self.model_dump(mode="json", exclude={"idempotency_key"})
        )
        if self.idempotency_key != hashlib.sha256(canonical).hexdigest():
            raise ValueError("idempotency_key is not the canonical payload digest")
        return self

    def as_result(self) -> ProcessingResultV2:
        return ProcessingResultV2.model_validate(
            self.model_dump(exclude={"output_object_key", "idempotency_key"})
        )


def canonical_completion_bytes(payload: dict[str, object]) -> bytes:
    return json.dumps(
        payload,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def completion_for_v2(
    result: ProcessingResultV2,
    output_object_key: str,
) -> ProcessingCompletionV2:
    stable_payload = {
        **result.model_dump(mode="json"),
        "output_object_key": output_object_key,
    }
    return ProcessingCompletionV2(
        **stable_payload,
        idempotency_key=hashlib.sha256(
            canonical_completion_bytes(stable_payload)
        ).hexdigest(),
    )


def artifact_bytes_v2(result: ProcessingResultV2) -> bytes:
    return result.model_dump_json(indent=2).encode("utf-8")


def process_events_v2(session_id: UUID, events: list[CadEvent]) -> ProcessingResultV2:
    if len({event.event_id for event in events}) != len(events):
        raise ValueError("source event_id values must be unique")
    base: ProcessingResult = process_events(session_id, events)
    events_by_id = {event.event_id: event for event in events}
    segments: list[OperationSegment] = []
    missing_metadata = 0

    for timeline_event in base.timeline:
        source = events_by_id[timeline_event.source_event_id]
        if source.event_type != EventType.CAD_COMMAND:
            continue
        command_name = source.command_name
        drawing_ref = source.drawing_ref
        if (
            not command_name
            or not command_name.strip()
            or not drawing_ref
            or not drawing_ref.strip()
        ):
            missing_metadata += 1
            continue
        if len(segments) >= MAX_OPERATION_SEGMENTS:
            raise ValueError(
                f"operation segment count exceeds {MAX_OPERATION_SEGMENTS}"
            )
        offset = timeline_event.offset_seconds
        if not math.isfinite(offset) or not 0 <= offset <= MAX_OPERATION_OFFSET_SECONDS:
            raise ValueError("qualifying command offset is outside the finite published range")
        segments.append(
            OperationSegment(
                sequence=len(segments) + 1,
                start_offset_seconds=offset,
                end_offset_seconds=offset,
                command_names=[command_name],
                drawing_ref=drawing_ref,
                summary=timeline_event.summary,
                source_event_ids=[timeline_event.source_event_id],
            )
        )

    warnings = list(base.warnings)
    if missing_metadata:
        warnings.append(
            f"{missing_metadata} CAD command timeline event(s) lacked nonblank command_name "
            "or drawing_ref; no operation segment was inferred."
        )
    return ProcessingResultV2(
        session_id=base.session_id,
        event_count=base.event_count,
        meaningful_event_count=base.meaningful_event_count,
        timeline=base.timeline,
        operation_segments=segments,
        keyframes=base.keyframes,
        warnings=warnings,
    )
