import hashlib
import json
import math
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from workflow_worker.models import (
    ArtifactProvider,
    ArtifactRef,
    ArtifactRole,
    CadEvent,
    ProcessingJob,
    ProcessingJobV2,
)
from workflow_worker.processing_v2 import (
    MAX_OPERATION_SEGMENTS,
    OperationSegment,
    ProcessingCompletionV2,
    ProcessingResultV2,
    canonical_completion_bytes,
    completion_for_v2,
    process_events_v2,
)

STARTED = datetime(2026, 8, 16, tzinfo=UTC)
JOB_ID = UUID("11111111-1111-4111-8111-111111111111")
SESSION_ID = UUID("22222222-2222-4222-8222-222222222222")


def _job_payload(
    *,
    provider: object = "s3",
    role: object = "raw_package",
) -> dict[str, object]:
    return {
        "schema_version": "2.0",
        "job_id": str(JOB_ID),
        "session_id": str(SESSION_ID),
        "input_artifact": {
            "provider": provider,
            "file_id": "synthetic/artifact.zip",
            "revision": "revision-1",
            "sha256": "a" * 64,
            "size_bytes": 1,
            "mime_type": "application/zip",
            "role": role,
        },
    }


@pytest.mark.parametrize("provider", ["s3", "google_drive"])
@pytest.mark.parametrize("role", ["raw_package", "timeline", "crop", "manifest"])
def test_processing_job_v2_accepts_exact_providers_and_all_roles(
    provider: str,
    role: str,
) -> None:
    job = ProcessingJobV2.model_validate_json(
        json.dumps(_job_payload(provider=provider, role=role))
    )

    assert job.model_dump(mode="json") == _job_payload(provider=provider, role=role)
    assert job.job_id == JOB_ID
    assert job.session_id == SESSION_ID
    assert job.input_artifact.provider == ArtifactProvider(provider)
    assert job.input_artifact.role == ArtifactRole(role)


@pytest.mark.parametrize("missing", ["schema_version", "job_id", "session_id", "input_artifact"])
def test_processing_job_v2_rejects_missing_fields(missing: str) -> None:
    payload = _job_payload()
    del payload[missing]

    with pytest.raises(ValidationError):
        ProcessingJobV2.model_validate(payload)


@pytest.mark.parametrize(
    "missing",
    ["provider", "file_id", "revision", "sha256", "size_bytes", "mime_type", "role"],
)
def test_artifact_ref_rejects_missing_fields(missing: str) -> None:
    artifact = dict(_job_payload()["input_artifact"])
    del artifact[missing]

    with pytest.raises(ValidationError):
        ArtifactRef.model_validate(artifact)


def test_processing_job_v2_rejects_extra_unknown_and_hybrid_fields() -> None:
    extra = _job_payload() | {"unexpected": True}
    hybrid = _job_payload() | {
        "object_key": f"sessions/{SESSION_ID}/packages/{'a' * 64}.zip"
    }
    nested_extra = _job_payload()
    nested_extra["input_artifact"] = dict(nested_extra["input_artifact"], bucket="raw")

    for payload in (extra, hybrid, nested_extra):
        with pytest.raises(ValidationError):
            ProcessingJobV2.model_validate(payload)


@pytest.mark.parametrize("schema_version", ["1.0", "3.0", 2.0, 2, None, True])
def test_processing_job_v2_rejects_wrong_or_non_string_versions(
    schema_version: object,
) -> None:
    payload = _job_payload()
    payload["schema_version"] = schema_version

    with pytest.raises(ValidationError):
        ProcessingJobV2.model_validate(payload)


@pytest.mark.parametrize("field", ["job_id", "session_id"])
@pytest.mark.parametrize("bad_uuid", ["", "not-a-uuid", 123, True])
def test_processing_job_v2_rejects_bad_uuids(field: str, bad_uuid: object) -> None:
    payload = _job_payload()
    payload[field] = bad_uuid

    with pytest.raises(ValidationError):
        ProcessingJobV2.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider", "unknown"),
        ("provider", 1),
        ("role", "unknown"),
        ("role", 1),
    ],
)
def test_artifact_ref_rejects_unknown_or_wrong_type_enums(field: str, value: object) -> None:
    payload = _job_payload()
    artifact = dict(payload["input_artifact"])
    artifact[field] = value

    with pytest.raises(ValidationError):
        ArtifactRef.model_validate(artifact)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("file_id", ""),
        ("file_id", "f" * 1025),
        ("revision", ""),
        ("revision", "r" * 256),
        ("mime_type", ""),
        ("mime_type", "m" * 256),
        ("sha256", "a" * 63),
        ("sha256", "a" * 65),
        ("sha256", "A" * 64),
        ("sha256", "g" * 64),
    ],
)
def test_artifact_ref_rejects_string_and_digest_bound_violations(
    field: str,
    value: str,
) -> None:
    artifact = dict(_job_payload()["input_artifact"])
    artifact[field] = value

    with pytest.raises(ValidationError):
        ArtifactRef.model_validate(artifact)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("file_id", "f"),
        ("file_id", "f" * 1024),
        ("revision", "r"),
        ("revision", "r" * 255),
        ("mime_type", "m"),
        ("mime_type", "m" * 255),
        ("sha256", "f" * 64),
    ],
)
def test_artifact_ref_accepts_exact_string_and_digest_boundaries(
    field: str,
    value: str,
) -> None:
    artifact = dict(_job_payload()["input_artifact"])
    artifact[field] = value

    parsed = ArtifactRef.model_validate(artifact)

    assert parsed.model_dump(mode="json")[field] == value


@pytest.mark.parametrize("size_bytes", [0, 536870912, 1.0])
def test_artifact_ref_accepts_json_schema_integer_boundaries(size_bytes: object) -> None:
    payload = _job_payload()
    artifact = dict(payload["input_artifact"])
    artifact["size_bytes"] = size_bytes
    payload["input_artifact"] = artifact

    parsed = ProcessingJobV2.model_validate_json(json.dumps(payload))

    assert parsed.input_artifact.size_bytes == int(size_bytes)
    assert isinstance(parsed.input_artifact.size_bytes, int)


@pytest.mark.parametrize(
    "size_bytes",
    [True, "1", 1.5, math.nan, math.inf, -math.inf, -1, 536870913],
)
def test_artifact_ref_rejects_non_json_schema_integer_values(size_bytes: object) -> None:
    payload = _job_payload()
    artifact = dict(payload["input_artifact"])
    artifact["size_bytes"] = size_bytes
    payload["input_artifact"] = artifact

    with pytest.raises(ValidationError):
        ProcessingJobV2.model_validate_json(json.dumps(payload))


def test_processing_job_v1_regression_and_mutual_cross_version_rejection() -> None:
    v1_payload = {
        "schema_version": "1.0",
        "session_id": str(SESSION_ID),
        "object_key": f"sessions/{SESSION_ID}/packages/{'a' * 64}.zip",
    }
    v1 = ProcessingJob.model_validate_json(json.dumps(v1_payload))

    assert v1.model_dump(mode="json") == v1_payload
    with pytest.raises(ValidationError):
        ProcessingJobV2.model_validate(v1_payload)
    with pytest.raises(ValidationError):
        ProcessingJob.model_validate(_job_payload())


def _event(
    *,
    event_id: UUID | None = None,
    seconds: float = 0,
    event_type: str = "cad_command",
    command_name: str | None = "LINE",
    drawing_ref: str | None = "drawing-001",
) -> CadEvent:
    return CadEvent(
        event_id=event_id or uuid4(),
        occurred_at=STARTED + timedelta(seconds=seconds),
        event_type=event_type,
        source="autocad",
        command_name=command_name,
        drawing_ref=drawing_ref,
    )


def test_v2_empty_result_preserves_v1_timeline_and_warnings() -> None:
    result = process_events_v2(uuid4(), [])

    assert result.schema_version == "2.0"
    assert result.event_count == result.meaningful_event_count == 0
    assert result.timeline == []
    assert result.operation_segments == []
    assert result.warnings == [
        "No CAD events were present; review the capture integration.",
        "Session end event is missing; package may be incomplete.",
    ]


def test_v2_segments_follow_stable_v1_timeline_order_and_exact_evidence() -> None:
    early = _event(seconds=0, event_type="session_started", command_name=None, drawing_ref=None)
    tied_first = _event(seconds=2, command_name=" LINE ", drawing_ref="drawing-a")
    tied_second = _event(seconds=2, command_name="TRIM", drawing_ref="drawing-b")
    late = _event(seconds=5, event_type="session_ended", command_name=None, drawing_ref=None)

    result = process_events_v2(uuid4(), [late, tied_first, early, tied_second])

    assert [item.source_event_id for item in result.timeline] == [
        early.event_id,
        tied_first.event_id,
        tied_second.event_id,
        late.event_id,
    ]
    assert [segment.sequence for segment in result.operation_segments] == [1, 2]
    assert result.operation_segments[0].model_dump() == {
        "sequence": 1,
        "start_offset_seconds": 2.0,
        "end_offset_seconds": 2.0,
        "command_names": [" LINE "],
        "drawing_ref": "drawing-a",
        "summary": "AutoCAD command:  LINE ",
        "source_event_ids": [tied_first.event_id],
    }
    assert result.operation_segments[1].source_event_ids == [tied_second.event_id]


@pytest.mark.parametrize(
    ("command_name", "drawing_ref"),
    [(None, "drawing"), ("", "drawing"), ("  ", "drawing"), ("LINE", None), ("LINE", " ")],
)
def test_missing_command_metadata_stays_in_timeline_without_inference(
    command_name: str | None,
    drawing_ref: str | None,
) -> None:
    event = _event(command_name=command_name, drawing_ref=drawing_ref)

    result = process_events_v2(uuid4(), [event])

    assert [item.source_event_id for item in result.timeline] == [event.event_id]
    assert result.operation_segments == []
    assert result.warnings[-1] == (
        "1 CAD command timeline event(s) lacked nonblank command_name or drawing_ref; "
        "no operation segment was inferred."
    )


def test_duplicate_timeline_evidence_fails_closed() -> None:
    duplicated = uuid4()
    events = [_event(event_id=duplicated, seconds=0), _event(event_id=duplicated, seconds=1)]

    with pytest.raises(ValueError, match="source event_id values must be unique"):
        process_events_v2(uuid4(), events)


def test_exactly_1000_commands_are_supported_and_1001_fails_closed() -> None:
    events = [
        _event(event_id=UUID(int=index + 1), seconds=index)
        for index in range(MAX_OPERATION_SEGMENTS + 1)
    ]

    accepted = process_events_v2(uuid4(), events[:MAX_OPERATION_SEGMENTS])
    assert len(accepted.operation_segments) == MAX_OPERATION_SEGMENTS
    assert accepted.operation_segments[-1].sequence == MAX_OPERATION_SEGMENTS

    with pytest.raises(ValueError, match="operation segment count exceeds 1000"):
        process_events_v2(uuid4(), events)


def test_qualifying_offset_at_maximum_is_supported_and_above_fails_closed() -> None:
    accepted = process_events_v2(
        uuid4(),
        [
            _event(seconds=0, event_type="session_started", command_name=None, drawing_ref=None),
            _event(seconds=604800),
        ],
    )
    assert accepted.operation_segments[0].start_offset_seconds == 604800

    with pytest.raises(ValueError, match="outside the finite published range"):
        process_events_v2(
            uuid4(),
            [
                _event(
                    seconds=0,
                    event_type="session_started",
                    command_name=None,
                    drawing_ref=None,
                ),
                _event(seconds=604801),
            ],
        )


@pytest.mark.parametrize(
    "change",
    [
        {"extra": True},
        {"schema_version": "3.0"},
    ],
)
def test_v2_result_rejects_extra_fields_and_unknown_versions(change: dict[str, object]) -> None:
    payload = process_events_v2(uuid4(), []).model_dump(mode="json") | change
    with pytest.raises(ValidationError):
        ProcessingResultV2.model_validate(payload)


@pytest.mark.parametrize(
    "change",
    [
        {"start_offset_seconds": math.nan},
        {"end_offset_seconds": math.inf},
        {"start_offset_seconds": 2.0, "end_offset_seconds": 1.0},
    ],
)
def test_numeric_and_reversed_segment_bounds_fail_closed(change: dict[str, object]) -> None:
    segment = {
        "sequence": 1,
        "start_offset_seconds": 1.0,
        "end_offset_seconds": 1.0,
        "command_names": ["LINE"],
        "drawing_ref": "drawing",
        "summary": "AutoCAD command: LINE",
        "source_event_ids": [uuid4()],
    } | change
    with pytest.raises(ValidationError):
        OperationSegment.model_validate(segment)


def test_evidence_membership_and_cross_segment_reuse_fail_closed() -> None:
    result = process_events_v2(uuid4(), [_event()])
    payload = result.model_dump()
    payload["operation_segments"][0]["source_event_ids"] = [uuid4()]
    with pytest.raises(ValidationError, match="source evidence is not in the timeline"):
        ProcessingResultV2.model_validate(payload)

    payload = result.model_dump()
    repeated = dict(payload["operation_segments"][0])
    repeated["sequence"] = 2
    payload["operation_segments"].append(repeated)
    with pytest.raises(ValidationError, match="source evidence is assigned more than once"):
        ProcessingResultV2.model_validate(payload)


def test_unordered_segment_bounds_fail_closed() -> None:
    result = process_events_v2(uuid4(), [_event(seconds=1), _event(seconds=2)])
    payload = result.model_dump()
    payload["operation_segments"][0]["end_offset_seconds"] = 0.75
    payload["operation_segments"][1]["start_offset_seconds"] = 0.5

    with pytest.raises(ValidationError, match="overlap or are unordered"):
        ProcessingResultV2.model_validate(payload)


def test_completion_digest_is_exact_canonical_json_excluding_only_digest() -> None:
    session_id = UUID("11111111-1111-4111-8111-111111111111")
    result = process_events_v2(session_id, [_event()])
    completion = completion_for_v2(result, f"sessions/{session_id}/timeline-v2.json")
    payload = completion.model_dump(mode="json", exclude={"idempotency_key"})

    assert completion.idempotency_key == hashlib.sha256(
        json.dumps(
            payload,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()
    assert canonical_completion_bytes(payload) == canonical_completion_bytes(
        dict(reversed(list(payload.items())))
    )


def test_completion_rejects_key_session_mismatch() -> None:
    result = process_events_v2(uuid4(), [])
    completion = completion_for_v2(
        result,
        f"sessions/{result.session_id}/timeline-v2.json",
    )
    payload = completion.model_dump(mode="json")
    payload["output_object_key"] = f"sessions/{uuid4()}/timeline-v2.json"
    payload["idempotency_key"] = hashlib.sha256(
        canonical_completion_bytes(
            {key: value for key, value in payload.items() if key != "idempotency_key"}
        )
    ).hexdigest()

    with pytest.raises(ValidationError, match="output_object_key does not match session_id"):
        ProcessingCompletionV2.model_validate(payload)
