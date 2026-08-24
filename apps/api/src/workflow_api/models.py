import hashlib
import json
import math
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import Annotated, Any, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic.config import ExtraValues
from pydantic_core import PydanticCustomError

_MAX_JSON_INTEGER = Decimal(536_870_912)


def _preserve_nonfinite_json_number(value: str) -> float:
    return float(value)


def _normalize_lossless_json_numbers(value: object) -> object:
    if isinstance(value, Decimal):
        try:
            if (
                value.is_finite()
                and -_MAX_JSON_INTEGER <= value <= _MAX_JSON_INTEGER
                and value == value.to_integral_value()
            ):
                return int(value)
        except InvalidOperation:
            pass
        return None
    if isinstance(value, list):
        return [_normalize_lossless_json_numbers(item) for item in value]
    if isinstance(value, dict):
        return {
            key: _normalize_lossless_json_numbers(item) for key, item in value.items()
        }
    return value


def _lossless_json_value(json_data: str | bytes | bytearray) -> object:
    try:
        parsed = json.loads(
            json_data,
            parse_int=Decimal,
            parse_float=Decimal,
            parse_constant=_preserve_nonfinite_json_number,
        )
    except InvalidOperation:
        return None
    return _normalize_lossless_json_numbers(parsed)


class ProcessingStatus(StrEnum):
    REGISTERED = "registered"
    UPLOADED = "uploaded"
    PROCESSING = "processing"
    PROCESSED = "processed"
    FAILED = "failed"


class ReviewStatus(StrEnum):
    NOT_READY = "not_ready"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    NEEDS_CHANGES = "needs_changes"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EventType(StrEnum):
    SESSION_STARTED = "session_started"
    SESSION_PAUSED = "session_paused"
    SESSION_RESUMED = "session_resumed"
    SESSION_ENDED = "session_ended"
    DRAWING_OPENED = "drawing_opened"
    DRAWING_SAVED = "drawing_saved"
    DRAWING_CLOSED = "drawing_closed"
    CAD_COMMAND = "cad_command"
    FOREGROUND_CHANGED = "foreground_changed"
    IDLE_STARTED = "idle_started"
    IDLE_ENDED = "idle_ended"


class EventSource(StrEnum):
    AGENT = "agent"
    AUTOCAD = "autocad"
    REVIEWER = "reviewer"
    SYSTEM = "system"


class ArtifactProvider(StrEnum):
    S3 = "s3"
    GOOGLE_DRIVE = "google_drive"


class ArtifactRole(StrEnum):
    RAW_PACKAGE = "raw_package"
    TIMELINE = "timeline"
    CROP = "crop"
    MANIFEST = "manifest"


class FrozenStrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ArtifactRef(FrozenStrictModel):
    provider: ArtifactProvider
    file_id: str = Field(min_length=1, max_length=1024)
    revision: str = Field(min_length=1, max_length=255)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size_bytes: int = Field(ge=0, le=536870912)
    mime_type: str = Field(min_length=1, max_length=255)
    role: ArtifactRole

    @field_validator("size_bytes", mode="before")
    @classmethod
    def validate_json_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise PydanticCustomError("int_type", "size_bytes must be a JSON integer")
        return value

    @classmethod
    def model_validate_json(
        cls,
        json_data: str | bytes | bytearray,
        *,
        strict: bool | None = None,
        extra: ExtraValues | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        normalized = json.dumps(_lossless_json_value(json_data), separators=(",", ":"))
        return super().model_validate_json(
            normalized,
            strict=strict,
            extra=extra,
            context=context,
            by_alias=by_alias,
            by_name=by_name,
        )


class ProcessingJobV2(FrozenStrictModel):
    schema_version: Literal["2.0"]
    job_id: UUID
    session_id: UUID
    input_artifact: ArtifactRef

    @classmethod
    def model_validate_json(
        cls,
        json_data: str | bytes | bytearray,
        *,
        strict: bool | None = None,
        extra: ExtraValues | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        normalized = json.dumps(_lossless_json_value(json_data), separators=(",", ":"))
        return super().model_validate_json(
            normalized,
            strict=strict,
            extra=extra,
            context=context,
            by_alias=by_alias,
            by_name=by_name,
        )


type JsonScalar = str | int | float | bool | None


class SessionCreate(BaseModel):
    schema_version: str = Field(pattern=r"^1\.0$")
    session_id: UUID
    machine_id: str = Field(min_length=8, max_length=128)
    project_id: str | None = Field(default=None, max_length=128)
    started_at: datetime
    ended_at: datetime
    active_duration_seconds: int = Field(ge=0)
    approved_process: str = Field(default="acad", max_length=128)
    package_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    package_size_bytes: int = Field(gt=0)


class Artifact(StrictModel):
    artifact_id: UUID
    kind: Literal[
        "drawing", "input", "output", "recording", "event_log", "keyframe", "clip", "other"
    ]
    file_name: str = Field(min_length=1, max_length=255)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size_bytes: int = Field(ge=0)
    storage_key: str | None = None


class PackageCadEvent(StrictModel):
    event_id: UUID
    occurred_at: datetime
    event_type: EventType
    source: EventSource
    command_name: str | None = Field(default=None, max_length=128)
    drawing_ref: str | None = Field(default=None, max_length=255)
    details: dict[str, JsonScalar] = Field(default_factory=dict)


class IdleInterval(StrictModel):
    started_at: datetime
    ended_at: datetime


class PackageLabel(StrictModel):
    label_id: UUID
    category: Literal[
        "drawing_setup",
        "geometry_creation",
        "geometry_modification",
        "dimensioning",
        "hole_cutout_placement",
        "component_placement",
        "annotation",
        "layer_property_change",
        "reuse_prior_geometry",
        "correction_rework",
        "checking_verification",
        "export_plot",
        "uncertain",
    ]
    provenance: Literal["observed", "deterministic", "ai_inferred", "human_supplied"]
    confidence: float = Field(ge=0, le=1)
    approval_status: Literal["unreviewed", "approved", "rejected", "needs_changes"]
    start_offset_seconds: float | None = Field(default=None, ge=0)
    end_offset_seconds: float | None = Field(default=None, ge=0)
    reviewer_note: str | None = Field(default=None, max_length=2000)


class PackageMetadata(StrictModel):
    """The metadata.json shape defined by contracts/session.schema.json."""

    schema_version: Literal["1.0"]
    session_id: UUID
    machine_id: str = Field(min_length=8, max_length=128)
    project_id: str | None = Field(default=None, max_length=128)
    started_at: datetime
    ended_at: datetime
    active_duration_seconds: int = Field(ge=0)
    approved_process: str = Field(max_length=128)
    drawing_files: list[Artifact]
    input_artifacts: list[Artifact]
    output_artifacts: list[Artifact]
    recording: Artifact | None = None
    cad_events: list[PackageCadEvent]
    idle_intervals: list[IdleInterval]
    processing_status: Literal[
        "local", "registered", "uploaded", "processing", "processed", "failed"
    ]
    review_status: Literal["not_ready", "pending", "approved", "rejected", "needs_changes"]
    labels: list[PackageLabel]
    skills: list[UUID]
    raw_expires_at: datetime | None = None

    def assert_matches_registration(self, registration: "SessionCreate") -> None:
        identity_fields = (
            "schema_version",
            "session_id",
            "machine_id",
            "project_id",
            "started_at",
            "ended_at",
            "active_duration_seconds",
            "approved_process",
        )
        mismatches = [
            name for name in identity_fields if getattr(self, name) != getattr(registration, name)
        ]
        if mismatches:
            raise ValueError("metadata.json does not match registration: " + ", ".join(mismatches))


class TimelineItem(StrictModel):
    offset_seconds: float = Field(ge=0)
    event_type: EventType
    summary: str = Field(min_length=1, max_length=512)
    source_event_id: UUID


class ProcessingResult(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    session_id: UUID
    event_count: int = Field(ge=0)
    meaningful_event_count: int = Field(ge=0)
    timeline: list[TimelineItem]
    keyframes: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ProcessingCompletion(ProcessingResult):
    output_object_key: str = Field(min_length=1, max_length=1024)
    idempotency_key: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def validate_output_key(self) -> "ProcessingCompletion":
        expected = f"sessions/{self.session_id}/timeline.json"
        if self.output_object_key != expected:
            raise ValueError("output_object_key does not match session_id")
        canonical = json.dumps(
            self.model_dump(mode="json", exclude={"idempotency_key"}),
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        expected_idempotency_key = hashlib.sha256(canonical).hexdigest()
        if self.idempotency_key != expected_idempotency_key:
            raise ValueError("idempotency_key is not the canonical payload digest")
        return self

    def as_result(self) -> ProcessingResult:
        return ProcessingResult.model_validate(
            self.model_dump(exclude={"output_object_key", "idempotency_key"})
        )


class OperationSegment(StrictModel):
    sequence: int = Field(ge=1, le=1000)
    start_offset_seconds: float = Field(ge=0, le=604800, allow_inf_nan=False)
    end_offset_seconds: float = Field(ge=0, le=604800, allow_inf_nan=False)
    command_names: list[str] = Field(min_length=1, max_length=64)
    drawing_ref: str = Field(min_length=1, max_length=255)
    summary: str = Field(min_length=1, max_length=512)
    source_event_ids: list[UUID] = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def validate_unique_values(self) -> "OperationSegment":
        if len(set(self.command_names)) != len(self.command_names):
            raise ValueError("command_names must be unique")
        if any(not 1 <= len(command_name) <= 128 for command_name in self.command_names):
            raise ValueError("command_names must contain bounded non-empty strings")
        if len(set(self.source_event_ids)) != len(self.source_event_ids):
            raise ValueError("source_event_ids must be unique")
        return self


class ProcessingResultV2(StrictModel):
    schema_version: Literal["2.0"] = "2.0"
    session_id: UUID
    event_count: int = Field(ge=0)
    meaningful_event_count: int = Field(ge=0)
    timeline: list[TimelineItem]
    operation_segments: list[OperationSegment] = Field(max_length=1000)
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
    output_object_key: str = Field(min_length=1, max_length=1024)
    idempotency_key: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def validate_output_key_and_digest(self) -> "ProcessingCompletionV2":
        expected = f"sessions/{self.session_id}/timeline-v2.json"
        if self.output_object_key != expected:
            raise ValueError("output_object_key does not match session_id")
        canonical = json.dumps(
            self.model_dump(mode="json", exclude={"idempotency_key"}),
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        expected_idempotency_key = hashlib.sha256(canonical).hexdigest()
        if self.idempotency_key != expected_idempotency_key:
            raise ValueError("idempotency_key is not the canonical payload digest")
        return self

    def as_result(self) -> ProcessingResultV2:
        return ProcessingResultV2.model_validate(
            self.model_dump(exclude={"output_object_key", "idempotency_key"})
        )


type ProcessingResultPayload = Annotated[
    ProcessingResult | ProcessingResultV2,
    Field(discriminator="schema_version"),
]
type ProcessingCompletionPayload = Annotated[
    ProcessingCompletion | ProcessingCompletionV2,
    Field(discriminator="schema_version"),
]


class SessionRecord(SessionCreate):
    processing_status: ProcessingStatus = ProcessingStatus.REGISTERED
    review_status: ReviewStatus = ReviewStatus.NOT_READY
    raw_object_key: str | None = None
    processed_prefix: str | None = None
    processing_output: ProcessingResultPayload | None = None
    processing_completion_id: str | None = None
    processing_completed_at: datetime | None = None
    raw_expires_at: datetime
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_create(cls, value: SessionCreate, retention_days: int) -> "SessionRecord":
        now = datetime.now(UTC)
        return cls(
            **value.model_dump(),
            raw_expires_at=now + timedelta(days=retention_days),
            created_at=now,
            updated_at=now,
        )


class SessionList(BaseModel):
    items: list[SessionRecord]
    count: int


class UploadUrlResponse(BaseModel):
    method: str = "PUT"
    upload_url: str
    object_key: str
    expires_in_seconds: int
    required_headers: dict[str, str]


class UploadComplete(BaseModel):
    object_key: str
    etag: str | None = None


class HealthResponse(BaseModel):
    status: str
    service: str
    environment: str
