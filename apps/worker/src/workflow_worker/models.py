import json
from datetime import datetime
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import Any, Literal, Self
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


class ArtifactRef(StrictModel):
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


class ProcessingJobV2(StrictModel):
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


class ProcessingJob(StrictModel):
    schema_version: str = Field(pattern=r"^1\.0$")
    session_id: UUID
    object_key: str = Field(
        pattern=r"^sessions/[0-9a-f-]{36}/packages/[a-f0-9]{64}\.zip$"
    )

    @model_validator(mode="after")
    def object_key_matches_session(self) -> "ProcessingJob":
        prefix = f"sessions/{self.session_id}/packages/"
        if not self.object_key.startswith(prefix):
            raise ValueError("object_key does not match session_id")
        return self


class CadEvent(StrictModel):
    event_id: UUID
    occurred_at: datetime
    event_type: EventType
    source: EventSource
    command_name: str | None = Field(default=None, max_length=128)
    drawing_ref: str | None = Field(default=None, max_length=255)
    details: dict[str, JsonScalar] = Field(default_factory=dict)


class TimelineItem(StrictModel):
    offset_seconds: float = Field(ge=0)
    event_type: EventType
    summary: str
    source_event_id: UUID


class ProcessingResult(StrictModel):
    schema_version: str = "1.0"
    session_id: UUID
    event_count: int = Field(ge=0)
    meaningful_event_count: int = Field(ge=0)
    timeline: list[TimelineItem]
    keyframes: list[str]
    warnings: list[str]


class ProcessingCompletion(ProcessingResult):
    output_object_key: str = Field(
        pattern=r"^sessions/[0-9a-f-]{36}/timeline\.json$"
    )
    idempotency_key: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def output_key_matches_session(self) -> "ProcessingCompletion":
        expected = f"sessions/{self.session_id}/timeline.json"
        if self.output_object_key != expected:
            raise ValueError("output_object_key does not match session_id")
        return self
