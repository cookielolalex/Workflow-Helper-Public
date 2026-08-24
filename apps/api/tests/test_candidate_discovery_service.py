from __future__ import annotations

import errno
import hashlib
import importlib
import os
import sqlite3
from dataclasses import replace
from pathlib import Path
from uuid import UUID

import pytest

from workflow_api.candidate_discovery_service import (
    CandidateDiscoveryService,
    CandidateDiscoveryUnavailableError,
    CandidateDiscoveryValidationError,
    CandidateReviewOutcomeRecord,
    CandidateReviewQueueRecord,
)
from workflow_api.candidate_publication_service import (
    CandidatePublicationRequest,
    CandidatePublicationService,
)
from workflow_api.candidate_publication_store import (
    CandidatePublicationCursor,
    CandidatePublicationMetadata,
    SQLiteCandidatePublicationStore,
    _restricted_jcs,
)
from workflow_api.control_auth import (
    AuthenticatedPrincipal,
    AuthorizationDeniedError,
    ControlRole,
)
from workflow_api.control_scope import TenantWorkspaceScope
from workflow_api.control_service import ControlService
from workflow_api.control_store import ControlStoreError, SQLiteControlStore
from workflow_api.models import (
    ArtifactProvider,
    ArtifactRef,
    ArtifactRole,
    EventType,
    OperationSegment,
    ProcessingJobV2,
    ProcessingResultV2,
    TimelineItem,
)
from workflow_api.processing_job_v2_identity import processing_job_v2_payload_digest

SCOPE = TenantWorkspaceScope("tenant-synthetic", "workspace-synthetic")
OTHER_SCOPE = TenantWorkspaceScope("tenant-other", "workspace-synthetic")
CORRELATION = "corr-discovery-synthetic"


def _synthetic_uuid(digit: str) -> UUID:
    return UUID(f"{digit * 8}-{digit * 4}-4{digit * 3}-8{digit * 3}-{digit * 12}")


def _evidence(digit: str) -> dict[str, object]:
    job_id = _synthetic_uuid(digit)
    base = int(digit, 16)
    session_id = _synthetic_uuid(format((base + 1) % 16, "x"))
    event_id = _synthetic_uuid(format((base + 2) % 16, "x"))
    second_event_id = _synthetic_uuid(format((base + 3) % 16, "x"))
    job = ProcessingJobV2(
        schema_version="2.0",
        job_id=job_id,
        session_id=session_id,
        input_artifact=ArtifactRef(
            provider=ArtifactProvider.S3,
            file_id=f"raw-package-{digit}",
            revision="raw-revision-0001",
            sha256="a" * 64,
            size_bytes=4096,
            mime_type="application/zip",
            role=ArtifactRole.RAW_PACKAGE,
        ),
    )
    timeline = [
        TimelineItem(
            offset_seconds=1,
            event_type=EventType.CAD_COMMAND,
            summary="synthetic command",
            source_event_id=event_id,
        ),
        TimelineItem(
            offset_seconds=2,
            event_type=EventType.CAD_COMMAND,
            summary="synthetic command",
            source_event_id=second_event_id,
        ),
    ]
    result = ProcessingResultV2(
        schema_version="2.0",
        session_id=session_id,
        event_count=2,
        meaningful_event_count=2,
        timeline=timeline,
        operation_segments=[
            OperationSegment(
                sequence=1,
                start_offset_seconds=1,
                end_offset_seconds=1,
                command_names=["LINE"],
                drawing_ref=f"drawing-{digit}",
                summary="synthetic operation",
                source_event_ids=[event_id],
            ),
            OperationSegment(
                sequence=2,
                start_offset_seconds=2,
                end_offset_seconds=2,
                command_names=["LINE"],
                drawing_ref=f"drawing-{digit}",
                summary="synthetic operation",
                source_event_ids=[second_event_id],
            ),
        ],
        keyframes=[],
        warnings=[],
    )
    artifact = ArtifactRef(
        provider=ArtifactProvider.GOOGLE_DRIVE,
        file_id=f"timeline-{digit}",
        revision="timeline-revision-0001",
        sha256=(digit * 64),
        size_bytes=128,
        mime_type="application/json",
        role=ArtifactRole.TIMELINE,
    ).model_dump(mode="json")
    manifest = {
        "schema_version": "1.0",
        "job_id": str(job_id),
        "session_id": str(session_id),
        "payload_digest": processing_job_v2_payload_digest(job),
        "payload_digest_scheme": "workflow-helper.processing-job-v2.payload.sha256-jcs.v1",
        "outputs": [{"store_namespace": "google-drive://synthetic", "artifact_ref": artifact}],
    }
    manifest_jcs = _restricted_jcs(manifest).encode("utf-8")
    source_digest = hashlib.sha256(
        b"workflow-helper\0processing-job-v2\0result-digest\0sha256-jcs-v1\0"
        + manifest_jcs
    ).hexdigest()
    return {
        "envelope_version": "1.0",
        "job": job,
        "result": result,
        "result_manifest": {
            **manifest,
            "result_manifest_jcs": manifest_jcs.decode("utf-8"),
            "source_result_sha256": source_digest,
        },
        "timeline_binding": {"store_namespace": "google-drive://synthetic", "artifact_ref": artifact},
        "drawing_ref": f"drawing-{digit}",
        "occurrences": [
            {"event_id": str(event_id), "command_name": "LINE", "segment_sequence": 1},
            {
                "event_id": str(second_event_id),
                "command_name": "LINE",
                "segment_sequence": 2,
            },
        ],
        "rejected_alternative_count": 0,
        "qualifying_run_length": 2,
    }


def _publication_request(
    evidence: dict[str, object],
    scope: TenantWorkspaceScope = SCOPE,
    *,
    now: int,
) -> CandidatePublicationRequest:
    return CandidatePublicationRequest(
        scope=scope,
        job=evidence["job"],
        result=evidence["result"],
        result_manifest=evidence["result_manifest"],
        timeline_binding=evidence["timeline_binding"],
        drawing_ref=evidence["drawing_ref"],
        timeline_commands=evidence["occurrences"],
        rejected_alternative_count=evidence["rejected_alternative_count"],
        qualifying_run_length=evidence["qualifying_run_length"],
        reservation_owner_id="writer_synthetic_01",
        lease_duration_seconds=30,
        now=now,
    )


def _setup(
    tmp_path: Path,
) -> tuple[SQLiteCandidatePublicationStore, SQLiteControlStore, ControlService, CandidateDiscoveryService]:
    control_store = SQLiteControlStore(tmp_path / "control.sqlite3")
    publication_store = SQLiteCandidatePublicationStore(
        tmp_path / "publication.sqlite3",
        control_database_path=control_store,
    )
    control_service = ControlService(control_store)
    return (
        publication_store,
        control_store,
        control_service,
        CandidateDiscoveryService(publication_store, control_service),
    )


def _reviewer(scope: TenantWorkspaceScope = SCOPE) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        "reviewer_synthetic_01",
        frozenset({ControlRole.REVIEWER}),
        scope,
    )


def _publish(
    publication_store: SQLiteCandidatePublicationStore,
    digit: str,
    *,
    scope: TenantWorkspaceScope = SCOPE,
    now: int,
) -> CandidatePublicationMetadata:
    evidence = _evidence(digit)
    response = CandidatePublicationService(publication_store).publish(
        _publication_request(evidence, scope, now=now)
    )
    assert type(response) is CandidatePublicationMetadata
    return response


def _approve(
    control_service: ControlService,
    metadata: CandidatePublicationMetadata,
    *,
    principal: AuthenticatedPrincipal | None = None,
    correlation_id: str = "corr-review-synthetic",
) -> None:
    control_service.append_candidate_review(
        principal or _reviewer(),
        publication=metadata,
        status="approved",
        idempotency_key=f"review-{metadata.publication_key}",
        correlation_id=correlation_id,
    )


def _transition(
    control_service: ControlService,
    metadata: CandidatePublicationMetadata,
    status: str,
    *,
    suffix: str,
) -> None:
    control_service.append_candidate_review(
        _reviewer(),
        publication=metadata,
        status=status,
        idempotency_key=f"review-{suffix}-{metadata.publication_key}",
        correlation_id=f"corr-review-{suffix}",
    )


def test_import_and_construction_are_inert_and_types_are_exact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publication_store, _control_store, control_service, _ = _setup(tmp_path)
    before = sorted(path.name for path in tmp_path.iterdir())

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("discovery construction must not open SQLite")

    monkeypatch.setattr(sqlite3, "connect", forbidden)
    module = importlib.import_module("workflow_api.candidate_discovery_service")
    assert module.CandidateDiscoveryService(publication_store, control_service)
    assert sorted(path.name for path in tmp_path.iterdir()) == before

    with pytest.raises(TypeError):
        CandidateDiscoveryService(object(), control_service)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        CandidateDiscoveryService(publication_store, object())  # type: ignore[arg-type]


def test_happy_path_is_authenticated_scoped_and_metadata_only(tmp_path: Path) -> None:
    publication_store, _control_store, _control_service, service = _setup(tmp_path)
    metadata = _publish(publication_store, "1", now=1_000_000)
    rows = service.list_finalized_unreviewed(
        _reviewer(), correlation_id=CORRELATION, limit=1
    )

    assert rows == [metadata]
    assert type(rows[0]) is CandidatePublicationMetadata
    assert not hasattr(rows[0], "canonical_bytes")
    assert not hasattr(rows[0], "derivation_evidence_jcs")
    assert not hasattr(rows[0], "reservation_owner_id")
    assert not hasattr(rows[0], "reservation_epoch")
    assert not hasattr(rows[0], "reservation_expires_at_us")
    assert rows[0].cursor is not None
    assert not any(
        isinstance(value, str) and value.startswith("whscope1|")
        for value in (rows[0].tenant_id, rows[0].workspace_id, rows[0].publication_key, rows[0].review_target_id)
    )


def test_review_queue_reads_verified_evidence_and_returns_only_informed_fields(
    tmp_path: Path,
) -> None:
    publication_store, _control_store, _control_service, service = _setup(tmp_path)
    metadata = _publish(publication_store, "1", now=1_000_000)

    rows = service.list_review_queue(_reviewer(), correlation_id=CORRELATION)

    assert rows == [
        CandidateReviewQueueRecord(
            publication_key=metadata.publication_key,
            review_target_id=metadata.review_target_id,
            command_sequence=("LINE", "LINE"),
            occurrence_count=2,
            provenance="observed",
            review_status="unreviewed",
            finalized_at_us=metadata.finalized_at_us,
        )
    ]
    assert set(rows[0].__slots__) == {
        "publication_key",
        "review_target_id",
        "command_sequence",
        "occurrence_count",
        "provenance",
        "review_status",
        "finalized_at_us",
    }


def test_review_queue_includes_pending_and_suppresses_every_terminal_state(
    tmp_path: Path,
) -> None:
    publication_store, _control_store, control_service, service = _setup(tmp_path)
    metadata = _publish(publication_store, "1", now=1_000_000)
    _transition(control_service, metadata, "pending", suffix="pending")

    rows = service.list_review_queue(_reviewer(), correlation_id=CORRELATION)
    assert len(rows) == 1
    assert rows[0].review_status == "pending"

    _transition(control_service, metadata, "needs_changes", suffix="terminal")
    assert service.list_review_queue(_reviewer(), correlation_id=CORRELATION) == []


def test_review_queue_distinguishes_absence_from_invalid_row_local_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publication_store, _control_store, control_service, service = _setup(tmp_path)
    denied = _publish(publication_store, "1", now=1_000_000)
    unavailable = _publish(publication_store, "4", now=1_100_000)
    invalid_call = _publish(publication_store, "7", now=1_200_000)
    wrong_type = _publish(publication_store, "a", now=1_300_000)
    mismatched = _publish(publication_store, "d", now=1_400_000)
    genuinely_absent = _publish(publication_store, "2", now=1_500_000)
    original = control_service.read_candidate_review
    _transition(control_service, mismatched, "pending", suffix="mismatched")
    mismatched_projection = original(
        _reviewer(),
        review_target_id=mismatched.review_target_id,
        correlation_id=CORRELATION,
    )
    assert mismatched_projection is not None

    def defective_reads(*args: object, **kwargs: object):
        target = kwargs["review_target_id"]
        if target == denied.review_target_id:
            raise AuthorizationDeniedError("row-local denial")
        if target == unavailable.review_target_id:
            raise ControlStoreError("row-local control failure")
        if target == invalid_call.review_target_id:
            raise TypeError("row-local invalid result")
        if target == wrong_type.review_target_id:
            return object()
        if target == mismatched.review_target_id:
            return replace(mismatched_projection, target_id=denied.review_target_id)
        return original(*args, **kwargs)

    monkeypatch.setattr(control_service, "read_candidate_review", defective_reads)

    rows = service.list_review_queue(_reviewer(), correlation_id=CORRELATION)

    assert [row.publication_key for row in rows] == [genuinely_absent.publication_key]
    assert rows[0].review_status == "unreviewed"


@pytest.mark.parametrize(
    "failure",
    [
        AuthorizationDeniedError("row-local second-read denial"),
        ControlStoreError("row-local second-read control failure"),
    ],
)
def test_review_queue_second_read_failure_suppresses_row_and_keeps_later_valid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    publication_store, _control_store, control_service, service = _setup(tmp_path)
    raced = _publish(publication_store, "1", now=1_000_000)
    later = _publish(publication_store, "4", now=1_100_000)
    original = control_service.read_candidate_review
    raced_reads = 0

    def fail_second_read(*args: object, **kwargs: object):
        nonlocal raced_reads
        if kwargs["review_target_id"] == raced.review_target_id:
            raced_reads += 1
            if raced_reads == 2:
                raise failure
        return original(*args, **kwargs)

    monkeypatch.setattr(control_service, "read_candidate_review", fail_second_read)

    rows = service.list_review_queue(_reviewer(), correlation_id=CORRELATION)

    assert [row.publication_key for row in rows] == [later.publication_key]
    assert raced_reads == 2


def test_review_queue_global_authority_and_page_failures_remain_fatal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publication_store, _control_store, _control_service, service = _setup(tmp_path)
    _publish(publication_store, "1", now=1_000_000)

    monkeypatch.setattr(
        service,
        "_verify_authority",
        lambda: (_ for _ in ()).throw(
            CandidateDiscoveryUnavailableError("global authority failure")
        ),
    )
    with pytest.raises(CandidateDiscoveryUnavailableError, match="global authority failure"):
        service.list_review_queue(_reviewer(), correlation_id=CORRELATION)

    monkeypatch.undo()
    monkeypatch.setattr(
        publication_store,
        "list_finalized",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("page failure")),
    )
    with pytest.raises(CandidateDiscoveryUnavailableError, match="authority is unavailable"):
        service.list_review_queue(_reviewer(), correlation_id=CORRELATION)


@pytest.mark.parametrize("status", ["approved", "rejected", "needs_changes"])
def test_review_outcomes_return_only_verified_terminal_display_evidence(
    tmp_path: Path,
    status: str,
) -> None:
    publication_store, _control_store, control_service, service = _setup(tmp_path)
    metadata = _publish(publication_store, "1", now=1_000_000)
    if status in {"rejected", "needs_changes"}:
        _transition(control_service, metadata, "pending", suffix=f"pending-{status}")
    _transition(control_service, metadata, status, suffix=status)

    rows = service.list_review_outcomes(_reviewer(), correlation_id=CORRELATION)

    assert rows == [
        CandidateReviewOutcomeRecord(
            command_sequence=("LINE", "LINE"),
            occurrence_count=2,
            provenance="observed",
            review_status=status,
            decided_at_us=rows[0].decided_at_us,
        )
    ]
    assert rows[0].decided_at_us > 0
    assert set(rows[0].__slots__) == {
        "command_sequence",
        "occurrence_count",
        "provenance",
        "review_status",
        "decided_at_us",
    }


def test_review_outcomes_suppress_active_corrupt_and_post_correlation_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publication_store, _control_store, control_service, service = _setup(tmp_path)
    metadata = _publish(publication_store, "1", now=1_000_000)
    assert service.list_review_outcomes(_reviewer(), correlation_id=CORRELATION) == []
    _transition(control_service, metadata, "pending", suffix="pending")
    assert service.list_review_outcomes(_reviewer(), correlation_id=CORRELATION) == []
    _transition(control_service, metadata, "needs_changes", suffix="terminal")
    record = publication_store.get_finalized(SCOPE, metadata.publication_key)

    monkeypatch.setattr(
        publication_store,
        "get_finalized",
        lambda *_args, **_kwargs: replace(record, derivation_evidence_jcs=b"{}"),
    )
    assert service.list_review_outcomes(_reviewer(), correlation_id=CORRELATION) == []
    monkeypatch.setattr(publication_store, "get_finalized", lambda *_args, **_kwargs: record)

    original = service._review_projection
    reads = 0

    def raced_projection(*args: object, **kwargs: object):
        nonlocal reads
        reads += 1
        projection = original(*args, **kwargs)
        return projection if reads == 1 else replace(projection, version=projection.version + 1)

    monkeypatch.setattr(service, "_review_projection", raced_projection)
    assert service.list_review_outcomes(_reviewer(), correlation_id=CORRELATION) == []
    assert reads == 2


def test_review_outcomes_page_past_full_active_and_corrupt_page(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publication_store, _control_store, control_service, service = _setup(tmp_path)
    terminal = _publish(publication_store, "1", now=1_000_000)
    _transition(control_service, terminal, "pending", suffix="page-pending")
    _transition(control_service, terminal, "needs_changes", suffix="page-terminal")
    record = publication_store.get_finalized(SCOPE, terminal.publication_key)
    projection = control_service.read_candidate_review(
        _reviewer(), review_target_id=terminal.review_target_id, correlation_id=CORRELATION
    )
    assert projection is not None
    active = [
        replace(
            terminal,
            publication_key=f"candidate-publication:1.0:{UUID(int=index + 100, version=4)}",
            finalized_at_us=index + 1,
        )
        for index in range(99)
    ]
    corrupt = replace(
        terminal,
        publication_key=f"candidate-publication:1.0:{UUID(int=999, version=4)}",
        finalized_at_us=100,
    )
    calls: list[CandidatePublicationCursor | None] = []

    def pages(
        _scope: TenantWorkspaceScope,
        *,
        limit: int,
        cursor: CandidatePublicationCursor | None,
    ) -> list[CandidatePublicationMetadata]:
        assert limit == 100
        calls.append(cursor)
        return [*active, corrupt] if cursor is None else [terminal]

    def projections(metadata: CandidatePublicationMetadata, *_args: object, **_kwargs: object):
        return projection if metadata in {corrupt, terminal} else None

    original_get = publication_store.get_finalized

    def finalized(_scope: TenantWorkspaceScope, publication_key: str):
        if publication_key == corrupt.publication_key:
            return replace(
                record,
                publication_key=corrupt.publication_key,
                finalized_at_us=corrupt.finalized_at_us,
                derivation_evidence_jcs=b"{}",
            )
        return original_get(SCOPE, publication_key)

    monkeypatch.setattr(publication_store, "list_finalized", pages)
    monkeypatch.setattr(publication_store, "get_finalized", finalized)
    monkeypatch.setattr(service, "_review_projection", projections)

    rows = service.list_review_outcomes(_reviewer(), correlation_id=CORRELATION)
    assert [row.review_status for row in rows] == ["needs_changes"]
    assert len(calls) == 2
    assert calls[1] == corrupt.cursor


def test_review_outcomes_stop_on_nonadvancing_page_and_cap_at_exactly_100(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publication_store, _control_store, control_service, service = _setup(tmp_path)
    metadata = _publish(publication_store, "1", now=1_000_000)
    _transition(control_service, metadata, "approved", suffix="cap-terminal")
    record = publication_store.get_finalized(SCOPE, metadata.publication_key)
    projection = control_service.read_candidate_review(
        _reviewer(), review_target_id=metadata.review_target_id, correlation_id=CORRELATION
    )
    assert projection is not None
    calls = 0

    def duplicate_page(*_args: object, **_kwargs: object) -> list[CandidatePublicationMetadata]:
        nonlocal calls
        calls += 1
        return [metadata] * 100

    monkeypatch.setattr(publication_store, "list_finalized", duplicate_page)
    monkeypatch.setattr(service, "_review_projection", lambda *_args, **_kwargs: projection)
    assert len(service.list_review_outcomes(_reviewer(), correlation_id=CORRELATION)) == 1
    assert calls == 2

    rows = [
        replace(
            metadata,
            publication_key=f"candidate-publication:1.0:{UUID(int=index + 2_000, version=4)}",
            finalized_at_us=index + 1,
        )
        for index in range(100)
    ]
    records = {
        row.publication_key: replace(
            record,
            publication_key=row.publication_key,
            finalized_at_us=row.finalized_at_us,
        )
        for row in rows
    }
    calls = 0

    def full_page(*_args: object, **_kwargs: object) -> list[CandidatePublicationMetadata]:
        nonlocal calls
        calls += 1
        return rows

    monkeypatch.setattr(publication_store, "list_finalized", full_page)
    monkeypatch.setattr(
        publication_store,
        "get_finalized",
        lambda _scope, publication_key: records[publication_key],
    )
    outcomes = service.list_review_outcomes(_reviewer(), correlation_id=CORRELATION)
    assert len(outcomes) == 100
    assert calls == 1


def test_review_outcomes_authority_and_store_failures_are_generic_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publication_store, _control_store, control_service, service = _setup(tmp_path)
    metadata = _publish(publication_store, "1", now=1_000_000)

    def store_failure(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("private store failure")

    monkeypatch.setattr(publication_store, "list_finalized", store_failure)
    with pytest.raises(CandidateDiscoveryUnavailableError, match="authority is unavailable"):
        service.list_review_outcomes(_reviewer(), correlation_id=CORRELATION)

    monkeypatch.undo()
    monkeypatch.setattr(
        control_service,
        "read_candidate_review",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ControlStoreError("private control failure")),
    )
    assert publication_store.list_finalized(SCOPE, limit=100) == [metadata]
    with pytest.raises(CandidateDiscoveryUnavailableError, match="authority is unavailable"):
        service.list_review_outcomes(_reviewer(), correlation_id=CORRELATION)


def test_review_queue_pages_past_terminal_corrupt_and_raced_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publication_store, _control_store, _control_service, service = _setup(tmp_path)
    raced = _publish(publication_store, "1", now=2_000_000)
    unreviewed = _publish(publication_store, "4", now=3_000_000)
    pending = _publish(publication_store, "7", now=4_000_000)
    terminal = [
        replace(
            raced,
            publication_key=f"candidate-publication:1.0:{UUID(int=index + 100, version=4)}",
            finalized_at_us=1_000_000 + index,
        )
        for index in range(98)
    ]
    corrupt = replace(
        raced,
        publication_key=f"candidate-publication:1.0:{UUID(int=999, version=4)}",
        finalized_at_us=1_100_000,
    )
    first_page = [*terminal, corrupt, raced]
    calls: list[CandidatePublicationCursor | None] = []

    def list_pages(
        _scope: TenantWorkspaceScope,
        *,
        limit: int,
        cursor: CandidatePublicationCursor | None,
    ) -> list[CandidatePublicationMetadata]:
        assert limit == 100
        calls.append(cursor)
        return first_page if cursor is None else [unreviewed, pending]

    raced_reads = 0

    def effective_status(
        metadata: CandidatePublicationMetadata,
        *_args: object,
        **_kwargs: object,
    ) -> str | None:
        nonlocal raced_reads
        if metadata.publication_key == corrupt.publication_key:
            return "unreviewed"
        if metadata.publication_key == raced.publication_key:
            raced_reads += 1
            return "unreviewed" if raced_reads == 1 else None
        if metadata.publication_key == unreviewed.publication_key:
            return "unreviewed"
        if metadata.publication_key == pending.publication_key:
            return "pending"
        return None

    monkeypatch.setattr(publication_store, "list_finalized", list_pages)
    monkeypatch.setattr(service, "_effective_review_status", effective_status)

    rows = service.list_review_queue(_reviewer(), correlation_id=CORRELATION)

    assert [row.publication_key for row in rows] == [
        unreviewed.publication_key,
        pending.publication_key,
    ]
    assert [row.review_status for row in rows] == ["unreviewed", "pending"]
    assert raced_reads == 2
    assert len(calls) == 2
    assert calls[0] is None
    assert calls[1] == first_page[-1].cursor


def test_review_queue_stops_on_a_nonadvancing_duplicate_page(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publication_store, _control_store, _control_service, service = _setup(tmp_path)
    metadata = _publish(publication_store, "1", now=1_000_000)
    calls = 0

    def duplicate_page(*_args: object, **_kwargs: object) -> list[CandidatePublicationMetadata]:
        nonlocal calls
        calls += 1
        return [metadata] * 100

    monkeypatch.setattr(publication_store, "list_finalized", duplicate_page)
    rows = service.list_review_queue(_reviewer(), correlation_id=CORRELATION)

    assert [row.publication_key for row in rows] == [metadata.publication_key]
    assert calls == 2


def test_review_queue_suppresses_metadata_mismatch_corruption_and_post_read_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publication_store, _control_store, control_service, service = _setup(tmp_path)
    metadata = _publish(publication_store, "1", now=1_000_000)
    record = publication_store.get_finalized(SCOPE, metadata.publication_key)

    monkeypatch.setattr(
        publication_store,
        "get_finalized",
        lambda *_args, **_kwargs: replace(record, job_id="mismatched-job"),
    )
    assert service.list_review_queue(_reviewer(), correlation_id=CORRELATION) == []

    monkeypatch.setattr(
        publication_store,
        "get_finalized",
        lambda *_args, **_kwargs: replace(record, derivation_evidence_jcs=b"{}"),
    )
    assert service.list_review_queue(_reviewer(), correlation_id=CORRELATION) == []

    raced = False

    def review_after_verified_read(*_args: object, **_kwargs: object):
        nonlocal raced
        if not raced:
            raced = True
            _approve(control_service, metadata, correlation_id="corr-review-after-read")
        return record

    monkeypatch.setattr(publication_store, "get_finalized", review_after_verified_read)
    assert service.list_review_queue(_reviewer(), correlation_id=CORRELATION) == []
    assert raced is True


def test_authorization_and_server_scope_are_checked_before_publication_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publication_store, _control_store, _control_service, service = _setup(tmp_path)
    called = False

    def forbidden(*_args: object, **_kwargs: object) -> list[CandidatePublicationMetadata]:
        nonlocal called
        called = True
        raise AssertionError("publication access occurred before authorization")

    monkeypatch.setattr(publication_store, "list_finalized_unreviewed", forbidden)
    with pytest.raises(AuthorizationDeniedError):
        service.list_finalized_unreviewed(
            AuthenticatedPrincipal("subject_roleless", frozenset(), SCOPE),
            correlation_id=CORRELATION,
        )
    with pytest.raises(AuthorizationDeniedError):
        service.list_finalized_unreviewed(
            AuthenticatedPrincipal("reviewer_synthetic_01", frozenset({ControlRole.REVIEWER}), None),
            correlation_id=CORRELATION,
        )
    assert called is False


def test_missing_mismatched_unavailable_and_incomplete_binding_fail_closed(tmp_path: Path) -> None:
    control_store = SQLiteControlStore(tmp_path / "control.sqlite3")
    control_service = ControlService(control_store)
    no_binding = SQLiteCandidatePublicationStore(tmp_path / "no-binding.sqlite3")
    with pytest.raises(CandidateDiscoveryUnavailableError):
        CandidateDiscoveryService(no_binding, control_service).list_finalized_unreviewed(
            _reviewer(), correlation_id=CORRELATION
        )

    other_control = SQLiteControlStore(tmp_path / "other-control.sqlite3")
    mismatched = SQLiteCandidatePublicationStore(
        tmp_path / "mismatched.sqlite3", control_database_path=other_control
    )
    with pytest.raises(CandidateDiscoveryUnavailableError):
        CandidateDiscoveryService(mismatched, control_service).list_finalized_unreviewed(
            _reviewer(), correlation_id=CORRELATION
        )

    incomplete_path = tmp_path / "incomplete.sqlite3"
    with sqlite3.connect(incomplete_path):
        pass
    incomplete = SQLiteCandidatePublicationStore(
        tmp_path / "incomplete-publication.sqlite3",
        control_database_path=incomplete_path,
    )
    with pytest.raises(CandidateDiscoveryUnavailableError):
        CandidateDiscoveryService(incomplete, control_service).list_finalized_unreviewed(
            _reviewer(), correlation_id=CORRELATION
        )

    unavailable = tmp_path / "unavailable.sqlite3"
    unavailable_control = SQLiteControlStore(unavailable)
    unavailable_publication = SQLiteCandidatePublicationStore(
        tmp_path / "unavailable-publication.sqlite3",
        control_database_path=unavailable_control,
    )
    unavailable_service = CandidateDiscoveryService(
        unavailable_publication, ControlService(unavailable_control)
    )
    unavailable.unlink()
    with pytest.raises(CandidateDiscoveryUnavailableError):
        unavailable_service.list_finalized_unreviewed(
            _reviewer(), correlation_id=CORRELATION
        )


def test_hardlink_alias_of_control_authority_fails_closed(tmp_path: Path) -> None:
    control_path = tmp_path / "control.sqlite3"
    control_store = SQLiteControlStore(control_path)
    publication_path = tmp_path / "publication-hardlink.sqlite3"
    try:
        os.link(control_path, publication_path)
    except OSError as exc:
        unavailable = {
            code
            for code in (
                errno.EACCES,
                errno.EINVAL,
                errno.ENOSYS,
                errno.ENOTSUP,
                errno.EOPNOTSUPP,
                errno.EPERM,
                errno.EXDEV,
            )
            if code is not None
        }
        if exc.errno in unavailable:
            pytest.skip("hard links are unavailable on this filesystem")
        raise

    publication_store = SQLiteCandidatePublicationStore(
        publication_path,
        control_database_path=control_store,
    )
    service = CandidateDiscoveryService(publication_store, ControlService(control_store))
    with pytest.raises(CandidateDiscoveryUnavailableError):
        service.list_finalized_unreviewed(_reviewer(), correlation_id=CORRELATION)


def test_reviewed_rows_are_suppressed_and_cursor_is_stable(tmp_path: Path) -> None:
    publication_store, _control_store, control_service, service = _setup(tmp_path)
    first = _publish(publication_store, "1", now=1_000_000)
    second = _publish(publication_store, "4", now=1_100_000)
    _approve(control_service, first)

    rows = service.list_finalized_unreviewed(
        _reviewer(), correlation_id=CORRELATION, limit=1
    )
    assert rows == [second]
    assert service.list_finalized_unreviewed(
        _reviewer(), correlation_id=CORRELATION, cursor=rows[0].cursor
    ) == []


def test_review_race_is_revalidated_and_does_not_hide_later_effective_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publication_store, _control_store, control_service, service = _setup(tmp_path)
    first = _publish(publication_store, "1", now=1_000_000)
    second = _publish(publication_store, "4", now=1_100_000)
    original = control_service.read_candidate_review
    raced = False

    def read_with_race(*args: object, **kwargs: object):
        nonlocal raced
        target = kwargs["review_target_id"]
        if not raced and target == first.review_target_id:
            raced = True
            _approve(control_service, first, correlation_id="corr-race-review")
        return original(*args, **kwargs)

    monkeypatch.setattr(control_service, "read_candidate_review", read_with_race)
    rows = service.list_finalized_unreviewed(
        _reviewer(), correlation_id=CORRELATION, limit=1
    )
    assert raced is True
    assert rows == [second]


def test_corrupt_cross_scope_and_unauthorized_rows_are_suppressed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publication_store, _control_store, control_service, service = _setup(tmp_path)
    corrupt = _publish(publication_store, "1", now=1_000_000)
    _publish(publication_store, "4", scope=OTHER_SCOPE, now=1_100_000)
    with sqlite3.connect(publication_store.database_path) as connection:
        connection.execute("DROP TRIGGER candidate_publications_no_update_finalized")
        connection.execute("DROP TRIGGER candidate_publications_bytes_once")
        connection.execute(
            "UPDATE candidate_publications SET canonical_bytes = zeroblob(byte_length) "
            "WHERE publication_key = ?",
            (corrupt.publication_key,),
        )

    monkeypatch.setattr(
        publication_store,
        "list_finalized_unreviewed",
        lambda *_args, **_kwargs: [
            publication_store.get_finalized(OTHER_SCOPE, _publish(publication_store, "7", scope=OTHER_SCOPE, now=1_200_000).publication_key)
        ],
    )
    monkeypatch.setattr(
        control_service,
        "read_candidate_review",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AuthorizationDeniedError("action forbidden")),
    )
    assert service.list_finalized_unreviewed(
        _reviewer(), correlation_id=CORRELATION
    ) == []


def test_malformed_cursor_and_unbounded_limit_are_rejected_without_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _publication_store, _control_store, _control_service, service = _setup(tmp_path)
    monkeypatch.setattr(
        service,
        "_verify_authority",
        lambda: (_ for _ in ()).throw(AssertionError("read occurred")),
    )
    for value in (0, 101, True, "1"):
        with pytest.raises(CandidateDiscoveryValidationError):
            service.list_finalized_unreviewed(
                _reviewer(), correlation_id=CORRELATION, limit=value  # type: ignore[arg-type]
            )
    with pytest.raises(CandidateDiscoveryValidationError):
        service.list_finalized_unreviewed(
            _reviewer(), correlation_id=CORRELATION, cursor={"scope": SCOPE}
        )  # type: ignore[arg-type]


def test_read_does_not_mutate_control_database(tmp_path: Path) -> None:
    publication_store, control_store, _control_service, service = _setup(tmp_path)
    _publish(publication_store, "1", now=1_000_000)
    before = Path(control_store._database_path).read_bytes()
    service.list_finalized_unreviewed(_reviewer(), correlation_id=CORRELATION)
    after = Path(control_store._database_path).read_bytes()
    assert after == before
