from __future__ import annotations

import copy
import hashlib
import sqlite3
from pathlib import Path, PureWindowsPath
from urllib.parse import quote, urlsplit
from uuid import UUID

import pytest

from workflow_api.candidate_publication_store import (
    CandidatePublicationConflictError,
    CandidatePublicationCorruptionError,
    CandidatePublicationCursor,
    CandidatePublicationStaleReservationError,
    CandidatePublicationUnavailableError,
    NoCandidateError,
    SQLiteCandidatePublicationStore,
    _restricted_jcs,
    _sqlite_readonly_uri,
    build_candidate_publication_body,
    candidate_publication_key,
    canonical_candidate_content_bytes,
    canonical_candidate_publication_bytes,
)
from workflow_api.control_scope import TenantWorkspaceScope, _qualify
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
JOB_ID = UUID("11111111-1111-4111-8111-111111111111")
SESSION_ID = UUID("22222222-2222-4222-8222-222222222222")
EVENT_1 = UUID("90000000-0000-4000-8000-000000000001")
EVENT_2 = UUID("90000000-0000-4000-8000-000000000002")
GOLDEN_NAMESPACE = "google-drive://SYNTHETIC_CUSTOMER/SYNTHETIC_SHARED_DRIVE"
GOLDEN_EVENT_ID_BASE = 0x90000000000040008000000000000000


def _job() -> ProcessingJobV2:
    return ProcessingJobV2(
        schema_version="2.0",
        job_id=JOB_ID,
        session_id=SESSION_ID,
        input_artifact=ArtifactRef(
            provider=ArtifactProvider.S3,
            file_id="raw-package-synthetic",
            revision="raw-revision-0001",
            sha256="a" * 64,
            size_bytes=4096,
            mime_type="application/zip",
            role=ArtifactRole.RAW_PACKAGE,
        ),
    )


def _result(*, one_event: bool = False) -> ProcessingResultV2:
    event_ids = [EVENT_1] if one_event else [EVENT_1, EVENT_2]
    timeline = [
        TimelineItem(
            offset_seconds=index,
            event_type=EventType.CAD_COMMAND,
            summary="observed command",
            source_event_id=event_id,
        )
        for index, event_id in enumerate(event_ids, start=1)
    ]
    segments = [
        OperationSegment(
            sequence=index,
            start_offset_seconds=index,
            end_offset_seconds=index,
            command_names=["LINE"],
            drawing_ref="drawing-α",
            summary="one synthetic command",
            source_event_ids=[event_id],
        )
        for index, event_id in enumerate(event_ids, start=1)
    ]
    return ProcessingResultV2(
        schema_version="2.0",
        session_id=SESSION_ID,
        event_count=len(event_ids),
        meaningful_event_count=len(event_ids),
        timeline=timeline,
        operation_segments=segments,
        keyframes=[],
        warnings=[],
    )


def _evidence(*, one_event: bool = False, artifact_sha: str = "b" * 64) -> dict[str, object]:
    job = _job()
    result = _result(one_event=one_event)
    artifact = ArtifactRef(
        provider=ArtifactProvider.GOOGLE_DRIVE,
        file_id="timeline-synthetic",
        revision="timeline-revision-0001",
        sha256=artifact_sha,
        size_bytes=128,
        mime_type="application/json",
        role=ArtifactRole.TIMELINE,
    ).model_dump(mode="json")
    manifest = {
        "schema_version": "1.0",
        "job_id": str(JOB_ID),
        "session_id": str(SESSION_ID),
        "payload_digest": processing_job_v2_payload_digest(job),
        "payload_digest_scheme": "workflow-helper.processing-job-v2.payload.sha256-jcs.v1",
        "outputs": [{"store_namespace": "google-drive://synthetic", "artifact_ref": artifact}],
    }
    manifest_jcs = _restricted_jcs(manifest).encode("utf-8")
    source_h = hashlib.sha256(
        b"workflow-helper\0processing-job-v2\0result-digest\0sha256-jcs-v1\0" + manifest_jcs
    ).hexdigest()
    occurrences = [
        {"event_id": str(EVENT_1), "command_name": "LINE", "segment_sequence": 1}
    ]
    if not one_event:
        occurrences.append(
            {"event_id": str(EVENT_2), "command_name": "LINE", "segment_sequence": 2}
        )
    return {
        "envelope_version": "1.0",
        "job": job.model_dump(mode="json"),
        "result": result.model_dump(mode="json"),
        "result_manifest": {**manifest, "result_manifest_jcs": manifest_jcs.decode(), "source_result_sha256": source_h},
        "timeline_binding": {"store_namespace": "google-drive://synthetic", "artifact_ref": artifact},
        "drawing_ref": "drawing-α",
        "occurrences": occurrences,
        "rejected_alternative_count": 0,
        "qualifying_run_length": len(occurrences),
    }


def _golden_uuid(digit: str) -> UUID:
    return UUID(
        f"{digit * 8}-{digit * 4}-4{digit * 3}-8{digit * 3}-{digit * 12}"
    )


def _golden_event_id(index: int) -> UUID:
    return UUID(int=GOLDEN_EVENT_ID_BASE + index)


def _golden_evidence(
    *,
    label: str,
    job_digit: str,
    session_digit: str,
    artifact_digit: str,
    size_bytes: int,
    drawing_ref: str,
    commands: list[str],
    namespace: str = GOLDEN_NAMESPACE,
) -> dict[str, object]:
    job_id = _golden_uuid(job_digit)
    session_id = _golden_uuid(session_digit)
    job = ProcessingJobV2(
        schema_version="2.0",
        job_id=job_id,
        session_id=session_id,
        input_artifact=ArtifactRef(
            provider=ArtifactProvider.S3,
            file_id=f"raw-input-{label}",
            revision="raw-revision-0001",
            sha256="0" * 64,
            size_bytes=4096,
            mime_type="application/zip",
            role=ArtifactRole.RAW_PACKAGE,
        ),
    )
    event_ids = [_golden_event_id(index) for index in range(1, len(commands) + 1)]
    timeline = [
        TimelineItem(
            offset_seconds=index,
            event_type=EventType.CAD_COMMAND,
            summary="observed command",
            source_event_id=event_id,
        )
        for index, event_id in enumerate(event_ids, start=1)
    ]
    segments = [
        OperationSegment(
            sequence=index,
            start_offset_seconds=index,
            end_offset_seconds=index,
            command_names=[command],
            drawing_ref=drawing_ref,
            summary="one synthetic command",
            source_event_ids=[event_id],
        )
        for index, (command, event_id) in enumerate(zip(commands, event_ids), start=1)
    ]
    result = ProcessingResultV2(
        schema_version="2.0",
        session_id=session_id,
        event_count=len(commands),
        meaningful_event_count=len(commands),
        timeline=timeline,
        operation_segments=segments,
        keyframes=[],
        warnings=[],
    )
    artifact = ArtifactRef(
        provider=ArtifactProvider.GOOGLE_DRIVE,
        file_id=f"timeline-{label}",
        revision="timeline-revision-0001",
        sha256=artifact_digit * 64,
        size_bytes=size_bytes,
        mime_type="application/json",
        role=ArtifactRole.TIMELINE,
    ).model_dump(mode="json")
    manifest = {
        "schema_version": "1.0",
        "job_id": str(job_id),
        "session_id": str(session_id),
        "payload_digest": processing_job_v2_payload_digest(job),
        "payload_digest_scheme": "workflow-helper.processing-job-v2.payload.sha256-jcs.v1",
        "outputs": [{"store_namespace": namespace, "artifact_ref": artifact}],
    }
    manifest_jcs = _restricted_jcs(manifest).encode("utf-8")
    source_h = hashlib.sha256(
        b"workflow-helper\0processing-job-v2\0result-digest\0sha256-jcs-v1\0"
        + manifest_jcs
    ).hexdigest()
    occurrences = [
        {
            "event_id": str(event_id),
            "command_name": command,
            "segment_sequence": index,
        }
        for index, (command, event_id) in enumerate(zip(commands, event_ids), start=1)
    ]
    return {
        "envelope_version": "1.0",
        "job": job.model_dump(mode="json"),
        "result": result.model_dump(mode="json"),
        "result_manifest": {
            **manifest,
            "result_manifest_jcs": manifest_jcs.decode("utf-8"),
            "source_result_sha256": source_h,
        },
        "timeline_binding": {"store_namespace": namespace, "artifact_ref": artifact},
        "drawing_ref": drawing_ref,
        "occurrences": occurrences,
        "rejected_alternative_count": 0,
        "qualifying_run_length": len(commands),
    }


def _reserve(store: SQLiteCandidatePublicationStore, *, owner: str = "writer-a", now: int = 1_000_000):
    return store.reserve(SCOPE, _evidence(), owner, 30, now=now)


def test_import_and_schema_are_dormant_until_explicit_construction(tmp_path: Path) -> None:
    path = tmp_path / "candidate.sqlite"
    assert not path.exists()
    store = SQLiteCandidatePublicationStore(path)
    assert path.exists()
    with sqlite3.connect(path) as connection:
        names = {
            row[0]
            for row in connection.execute(
                "select name from sqlite_master where type in ('table', 'index', 'trigger')"
            )
        }
    assert "candidate_publications" in names
    assert "candidate_publications_discovery_idx" in names
    assert store.database_path == str(path)


def test_candidate_body_and_projection_use_exact_zero_and_unicode_bytes() -> None:
    evidence = _evidence()
    body = build_candidate_publication_body(evidence)
    full = canonical_candidate_publication_bytes(evidence)
    content = canonical_candidate_content_bytes(body)
    assert body["confidence"] == 0
    assert type(body["confidence"]) is int
    assert body["approval_status"] == "unreviewed"
    assert body["human_approval_evidence"] is None
    assert body["ordered_actions"][0]["instruction"].endswith("source_event_id=" + str(EVENT_1))
    assert "drawing-α".encode() in full
    assert hashlib.sha256(full).hexdigest()
    assert hashlib.sha256(content).hexdigest()
    assert full.endswith(b"}") and not full.endswith(b"\n")


def test_decision116_exact_two_command_duplicate_golden_vector() -> None:
    evidence = _golden_evidence(
        label="v2",
        job_digit="1",
        session_digit="2",
        artifact_digit="1",
        size_bytes=128,
        drawing_ref="drawing-α",
        commands=["LINE", "LINE"],
    )
    body = build_candidate_publication_body(evidence)
    content = canonical_candidate_content_bytes(body)
    full = canonical_candidate_publication_bytes(evidence)
    assert evidence["result_manifest"]["source_result_sha256"] == (
        "193971c6e12df7c77e9acd759c8b6ad75e496a75ad2d2eaeed6dd1e7891be9c0"
    )
    assert len(content) == 2256
    assert hashlib.sha256(content).hexdigest() == (
        "6c2215aeac60d834c9c5585ec70167775b628a603c0e42c5985d86b65cda64bb"
    )
    assert len(full) == 2318
    assert hashlib.sha256(full).hexdigest() == (
        "0a0b0fe9d1e2ebf8972fdfe8b7be65b27c247ece4fe919c3150c87804139ab36"
    )
    assert [item["instruction"] for item in body["ordered_actions"]].count(
        'AutoCAD command: "LINE"; source_event_id=90000000-0000-4000-8000-000000000001'
    ) == 1
    assert body["ordered_actions"][1]["instruction"].endswith(
        "90000000-0000-4000-8000-000000000002"
    )


def test_decision116_exact_64_command_upper_boundary_golden_vector() -> None:
    evidence = _golden_evidence(
        label="v64",
        job_digit="3",
        session_digit="4",
        artifact_digit="2",
        size_bytes=8192,
        drawing_ref="drawing-64",
        commands=["LINE" if index % 2 else "ARC" for index in range(1, 65)],
    )
    content = canonical_candidate_content_bytes(build_candidate_publication_body(evidence))
    full = canonical_candidate_publication_bytes(evidence)
    assert evidence["result_manifest"]["source_result_sha256"] == (
        "a800838d4c9fba835e036efb23a57bf75ef79894bab650c4812805ac89f30ffc"
    )
    assert len(content) == 10466
    assert hashlib.sha256(content).hexdigest() == (
        "1ceb0dad1a7e422be749190b5e7c66b33c72dc73ac15c66cc28a53edfc0590e7"
    )
    assert len(full) == 10528
    assert hashlib.sha256(full).hexdigest() == (
        "3d94b459396c4ec855988e3629ea341f71b893c8152a8d4eb8cb806fcc6b52e6"
    )


@pytest.mark.parametrize(
    ("label", "job_digit", "session_digit", "artifact_digit", "count"),
    (("v1", "5", "6", "3", 1), ("v65", "7", "8", "4", 65)),
)
def test_decision116_inclusive_run_boundaries_reject_one_and_65(
    label: str,
    job_digit: str,
    session_digit: str,
    artifact_digit: str,
    count: int,
) -> None:
    evidence = _golden_evidence(
        label=label,
        job_digit=job_digit,
        session_digit=session_digit,
        artifact_digit=artifact_digit,
        size_bytes=128 if count == 1 else 8320,
        drawing_ref=f"drawing-{label}",
        commands=["LINE"] * count,
    )
    with pytest.raises(NoCandidateError):
        build_candidate_publication_body(evidence)


def test_non_cad_event_cannot_leave_an_earlier_run_candidate() -> None:
    evidence = _golden_evidence(
        label="noncad-boundary",
        job_digit="9",
        session_digit="a",
        artifact_digit="5",
        size_bytes=512,
        drawing_ref="drawing-noncad",
        commands=["LINE", "LINE", "LINE"],
    )
    result = evidence["result"]
    timeline = result["timeline"]
    timeline[2:2] = [
        {
            "offset_seconds": 3,
            "event_type": "foreground_changed",
            "summary": "synthetic boundary",
            "source_event_id": str(_golden_event_id(4)),
        }
    ]
    result["event_count"] = 4
    result["meaningful_event_count"] = 3
    with pytest.raises(NoCandidateError):
        build_candidate_publication_body(evidence)


def test_drawing_change_cannot_leave_an_earlier_run_candidate() -> None:
    evidence = _golden_evidence(
        label="drawing-boundary",
        job_digit="b",
        session_digit="c",
        artifact_digit="6",
        size_bytes=512,
        drawing_ref="drawing-A",
        commands=["LINE", "LINE", "ARC"],
    )
    evidence["result"]["operation_segments"][2]["drawing_ref"] = "drawing-B"
    with pytest.raises(NoCandidateError):
        build_candidate_publication_body(evidence)


def test_unicode_and_duplicate_identity_are_not_normalized() -> None:
    nfc = _golden_evidence(
        label="unicode-nfc",
        job_digit="f",
        session_digit="1",
        artifact_digit="8",
        size_bytes=256,
        drawing_ref="café",
        commands=["ÉLINE", "LINE"],
    )
    nfd = _golden_evidence(
        label="unicode-nfd",
        job_digit="2",
        session_digit="3",
        artifact_digit="9",
        size_bytes=256,
        drawing_ref="cafe\u0301",
        commands=["E\u0301LINE", "LINE"],
    )
    nfc_full = canonical_candidate_publication_bytes(nfc)
    nfc_content = canonical_candidate_content_bytes(build_candidate_publication_body(nfc))
    nfd_full = canonical_candidate_publication_bytes(nfd)
    nfd_content = canonical_candidate_content_bytes(build_candidate_publication_body(nfd))
    assert hashlib.sha256(nfc_content).hexdigest() == (
        "7f25ab29de811483881575564ddb92399a5fa6ff42675b579a4fe9dd603cf72f"
    )
    assert hashlib.sha256(nfc_full).hexdigest() == (
        "550a0773171035c5cea0b61e34db3cf8e4199941f267a2984a4cb732a675239b"
    )
    assert hashlib.sha256(nfd_content).hexdigest() == (
        "8e505afe7470163f2e6dbe29e13e088713153fce063b0122e0ca2e0ef25ef9d9"
    )
    assert hashlib.sha256(nfd_full).hexdigest() == (
        "4b4f5dfdbd0a2ec40c48bdb075371e7e7f10eaf5ed4ba4bfa773fb10d3fd9a3b"
    )
    assert nfc_full != nfd_full and nfc_content != nfd_content


def test_changed_namespace_is_an_immutable_identity_conflict(tmp_path: Path) -> None:
    evidence = _golden_evidence(
        label="v2",
        job_digit="1",
        session_digit="2",
        artifact_digit="1",
        size_bytes=128,
        drawing_ref="drawing-α",
        commands=["LINE", "LINE"],
    )
    changed = copy.deepcopy(evidence)
    changed_namespace = "google-drive://SYNTHETIC_CUSTOMER/OTHER_SHARED_DRIVE"
    changed["result_manifest"]["outputs"][0]["store_namespace"] = changed_namespace
    changed["result_manifest"].pop("source_result_sha256")
    changed_manifest = {
        key: value
        for key, value in changed["result_manifest"].items()
        if key not in {"result_manifest_jcs"}
    }
    changed_manifest.pop("source_result_sha256", None)
    changed_manifest_jcs = _restricted_jcs(changed_manifest).encode("utf-8")
    changed["result_manifest"]["result_manifest_jcs"] = changed_manifest_jcs.decode("utf-8")
    changed["timeline_binding"]["store_namespace"] = changed_namespace
    store = SQLiteCandidatePublicationStore(tmp_path / "candidate.sqlite")
    store.reserve(SCOPE, evidence, "writer-a", 30, now=1_000_000)
    with pytest.raises(CandidatePublicationConflictError):
        store.reserve(SCOPE, changed, "writer-a", 30, now=1_000_001)


def test_reserve_finalize_replay_and_defensive_read(tmp_path: Path) -> None:
    store = SQLiteCandidatePublicationStore(tmp_path / "candidate.sqlite")
    reserved = _reserve(store)
    assert reserved.state == "reserved"
    assert reserved.canonical_bytes is None
    assert reserved.reservation_epoch == 1
    candidate_bytes = canonical_candidate_publication_bytes(_evidence())
    finalized = store.finalize(
        SCOPE,
        reserved.publication_key,
        "writer-a",
        1,
        candidate_bytes,
        now=1_100_000,
    )
    assert finalized.state == "finalized"
    assert finalized.canonical_bytes == candidate_bytes
    replay = store.reserve(SCOPE, _evidence(), "writer-a", 30, now=1_200_000)
    assert replay == finalized
    first = store.read_finalized_bytes(SCOPE, reserved.publication_key)
    second = store.read_finalized_bytes(SCOPE, reserved.publication_key)
    assert first == second == candidate_bytes
    assert first is not second


def test_restart_preserves_reserved_and_finalized_state(tmp_path: Path) -> None:
    path = tmp_path / "candidate.sqlite"
    first_store = SQLiteCandidatePublicationStore(path)
    reserved = _reserve(first_store, now=1_000_000)
    del first_store

    restarted = SQLiteCandidatePublicationStore(path)
    resumed = restarted.reserve(SCOPE, _evidence(), "writer-a", 30, now=1_000_001)
    assert resumed.reservation_epoch == 1
    candidate_bytes = canonical_candidate_publication_bytes(_evidence())
    restarted.finalize(
        SCOPE,
        reserved.publication_key,
        "writer-a",
        resumed.reservation_epoch,
        candidate_bytes,
        now=1_100_000,
    )
    del restarted

    after_crash = SQLiteCandidatePublicationStore(path)
    readback = after_crash.get_finalized(SCOPE, reserved.publication_key)
    assert readback.full_sha256 == hashlib.sha256(candidate_bytes).hexdigest()
    assert after_crash.read_finalized_bytes(SCOPE, reserved.publication_key) == candidate_bytes


def test_expired_orphan_is_reacquired_and_fenced_after_restart(tmp_path: Path) -> None:
    path = tmp_path / "candidate.sqlite"
    original = SQLiteCandidatePublicationStore(path)
    first = _reserve(original, now=1_000_000)
    del original

    restarted = SQLiteCandidatePublicationStore(path)
    second = restarted.reserve(SCOPE, _evidence(), "writer-b", 30, now=31_000_001)
    assert second.reservation_epoch == 2
    with pytest.raises(CandidatePublicationStaleReservationError):
        restarted.finalize(
            SCOPE,
            first.publication_key,
            "writer-a",
            first.reservation_epoch,
            canonical_candidate_publication_bytes(_evidence()),
            now=31_000_002,
        )
    restarted.finalize(
        SCOPE,
        second.publication_key,
        "writer-b",
        second.reservation_epoch,
        canonical_candidate_publication_bytes(_evidence()),
        now=31_100_000,
    )
    assert SQLiteCandidatePublicationStore(path).get_finalized(
        SCOPE, second.publication_key
    ).reservation_epoch == 2


def test_expired_reacquire_fences_stale_writer(tmp_path: Path) -> None:
    store = SQLiteCandidatePublicationStore(tmp_path / "candidate.sqlite")
    first = _reserve(store, now=1_000_000)
    second = store.reserve(SCOPE, _evidence(), "writer-b", 30, now=31_000_001)
    assert second.reservation_epoch == 2
    assert second.reservation_owner_id == "writer-b"
    with pytest.raises(CandidatePublicationStaleReservationError):
        store.finalize(
            SCOPE,
            first.publication_key,
            "writer-a",
            1,
            canonical_candidate_publication_bytes(_evidence()),
            now=31_000_002,
        )
    store.finalize(
        SCOPE,
        first.publication_key,
        "writer-b",
        2,
        canonical_candidate_publication_bytes(_evidence()),
        now=31_100_000,
    )


def test_live_reservation_conflict_and_scoped_identity(tmp_path: Path) -> None:
    store = SQLiteCandidatePublicationStore(tmp_path / "candidate.sqlite")
    reserved = _reserve(store)
    with pytest.raises(CandidatePublicationUnavailableError):
        store.reserve(SCOPE, _evidence(), "writer-b", 30, now=1_000_001)
    with pytest.raises(CandidatePublicationConflictError):
        store.reserve(SCOPE, _evidence(artifact_sha="c" * 64), "writer-a", 30, now=1_000_002)
    other = store.reserve(OTHER_SCOPE, _evidence(), "writer-b", 30, now=1_000_003)
    assert other.publication_key == reserved.publication_key


def test_no_candidate_and_byte_conflict_do_not_create_finalized_bytes(tmp_path: Path) -> None:
    store = SQLiteCandidatePublicationStore(tmp_path / "candidate.sqlite")
    with pytest.raises(NoCandidateError):
        store.reserve(SCOPE, _evidence(one_event=True), "writer-a", 30, now=1_000_000)
    reserved = _reserve(store)
    changed = bytearray(canonical_candidate_publication_bytes(_evidence()))
    changed[-2] = ord("x")
    with pytest.raises(CandidatePublicationConflictError):
        store.finalize(SCOPE, reserved.publication_key, "writer-a", 1, bytes(changed), now=1_100_000)
    assert store.list_finalized_unreviewed(SCOPE) == []


def test_finalized_rows_are_sqlite_immutable(tmp_path: Path) -> None:
    path = tmp_path / "candidate.sqlite"
    store = SQLiteCandidatePublicationStore(path)
    reserved = _reserve(store)
    store.finalize(
        SCOPE,
        reserved.publication_key,
        "writer-a",
        1,
        canonical_candidate_publication_bytes(_evidence()),
        now=1_100_000,
    )
    with sqlite3.connect(path) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "delete from candidate_publications where tenant_id = ? and workspace_id = ?",
                (SCOPE.tenant_id, SCOPE.workspace_id),
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "update candidate_publications set canonical_bytes = x'00' where tenant_id = ? and workspace_id = ?",
                (SCOPE.tenant_id, SCOPE.workspace_id),
            )


def test_direct_finalized_blob_corruption_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "candidate.sqlite"
    store = SQLiteCandidatePublicationStore(path)
    reserved = _reserve(store)
    store.finalize(
        SCOPE,
        reserved.publication_key,
        "writer-a",
        1,
        canonical_candidate_publication_bytes(_evidence()),
        now=1_100_000,
    )
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER candidate_publications_no_update_finalized")
        connection.execute("DROP TRIGGER candidate_publications_bytes_once")
        connection.execute(
            "UPDATE candidate_publications SET canonical_bytes = zeroblob(byte_length) "
            "WHERE tenant_id = ? AND workspace_id = ? AND publication_key = ?",
            (SCOPE.tenant_id, SCOPE.workspace_id, reserved.publication_key),
        )
    with pytest.raises(CandidatePublicationCorruptionError):
        store.get_finalized(SCOPE, reserved.publication_key)
    assert store.list_finalized_unreviewed(SCOPE) == []


@pytest.mark.parametrize(
    ("stored_evidence", "message"),
    (
        (b"\xff", "UTF-8"),
        (b"{", "JSON"),
        (b"[]", "admitted"),
    ),
)
def test_reserved_corrupt_derivation_evidence_fails_before_finalize_or_reacquire(
    tmp_path: Path,
    stored_evidence: bytes,
    message: str,
) -> None:
    path = tmp_path / "candidate.sqlite"
    store = SQLiteCandidatePublicationStore(path)
    reserved = _reserve(store)
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER candidate_publications_identity_immutable")
        connection.execute(
            "UPDATE candidate_publications SET derivation_evidence_jcs = ? "
            "WHERE tenant_id = ? AND workspace_id = ? AND publication_key = ?",
            (sqlite3.Binary(stored_evidence), SCOPE.tenant_id, SCOPE.workspace_id, reserved.publication_key),
        )

    candidate_bytes = canonical_candidate_publication_bytes(_evidence())
    with pytest.raises(CandidatePublicationCorruptionError, match=message):
        store.finalize(
            SCOPE,
            reserved.publication_key,
            "writer-a",
            reserved.reservation_epoch,
            candidate_bytes,
            now=1_100_000,
        )
    with pytest.raises(CandidatePublicationCorruptionError, match=message):
        store.reserve(SCOPE, _evidence(), "writer-a", 30, now=1_100_001)

    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT state, reservation_owner_id, reservation_epoch, canonical_bytes "
            "FROM candidate_publications WHERE publication_key = ?",
            (reserved.publication_key,),
        ).fetchone()
    assert row == ("reserved", "writer-a", reserved.reservation_epoch, None)
    assert store.list_finalized_unreviewed(SCOPE) == []


def test_deeply_nested_stored_derivation_evidence_fails_before_mutation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "candidate.sqlite"
    store = SQLiteCandidatePublicationStore(path)
    reserved = _reserve(store)
    deeply_nested_json = b"[" * 10_000 + b"]" * 10_000
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER candidate_publications_identity_immutable")
        connection.execute(
            "UPDATE candidate_publications SET derivation_evidence_jcs = ? "
            "WHERE tenant_id = ? AND workspace_id = ? AND publication_key = ?",
            (
                sqlite3.Binary(deeply_nested_json),
                SCOPE.tenant_id,
                SCOPE.workspace_id,
                reserved.publication_key,
            ),
        )

    candidate_bytes = canonical_candidate_publication_bytes(_evidence())
    with pytest.raises(CandidatePublicationCorruptionError):
        store.finalize(
            SCOPE,
            reserved.publication_key,
            "writer-a",
            reserved.reservation_epoch,
            candidate_bytes,
            now=1_100_000,
        )
    with pytest.raises(CandidatePublicationCorruptionError):
        store.reserve(SCOPE, _evidence(), "writer-a", 30, now=1_100_001)

    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT state, reservation_owner_id, reservation_epoch, canonical_bytes, updated_at_us "
            "FROM candidate_publications WHERE publication_key = ?",
            (reserved.publication_key,),
        ).fetchone()
    assert row == ("reserved", "writer-a", reserved.reservation_epoch, None, 1_000_000)


@pytest.mark.parametrize(
    "stored_evidence",
    (b"\xff", b"{", b"[]"),
)
def test_finalized_corrupt_derivation_evidence_fails_closed_for_detail_bytes_and_discovery(
    tmp_path: Path,
    stored_evidence: bytes,
) -> None:
    path = tmp_path / "candidate.sqlite"
    store = SQLiteCandidatePublicationStore(path)
    reserved = _reserve(store)
    candidate_bytes = canonical_candidate_publication_bytes(_evidence())
    store.finalize(
        SCOPE,
        reserved.publication_key,
        "writer-a",
        reserved.reservation_epoch,
        candidate_bytes,
        now=1_100_000,
    )
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER candidate_publications_no_update_finalized")
        connection.execute("DROP TRIGGER candidate_publications_identity_immutable")
        connection.execute(
            "UPDATE candidate_publications SET derivation_evidence_jcs = ? "
            "WHERE tenant_id = ? AND workspace_id = ? AND publication_key = ?",
            (sqlite3.Binary(stored_evidence), SCOPE.tenant_id, SCOPE.workspace_id, reserved.publication_key),
        )

    with pytest.raises(CandidatePublicationCorruptionError):
        store.get_finalized(SCOPE, reserved.publication_key)
    with pytest.raises(CandidatePublicationCorruptionError):
        store.read_finalized_bytes(SCOPE, reserved.publication_key)
    with pytest.raises(CandidatePublicationCorruptionError):
        store.reserve(SCOPE, _evidence(), "writer-a", 30, now=1_200_000)
    assert store.list_finalized_unreviewed(SCOPE) == []

    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT state, canonical_bytes FROM candidate_publications WHERE publication_key = ?",
            (reserved.publication_key,),
        ).fetchone()
    assert row == ("finalized", candidate_bytes)


def test_encoded_readonly_uri_is_portable_and_discovery_uses_it(tmp_path: Path) -> None:
    control_path = tmp_path / "control folder #?.sqlite"
    posix_uri = _sqlite_readonly_uri(control_path)
    assert posix_uri == (
        f"file://{quote(control_path.resolve().as_posix(), safe='/')}?mode=ro"
    )
    assert urlsplit(posix_uri).netloc == ""
    assert "%20" in posix_uri
    assert "%23" in posix_uri
    assert "%3F" in posix_uri
    drive_uri = _sqlite_readonly_uri(r"C:\Control Folder\review #?.sqlite")
    assert drive_uri == "file:///C:/Control%20Folder/review%20%23%3F.sqlite?mode=ro"
    assert urlsplit(drive_uri).netloc == ""
    unc_uri = _sqlite_readonly_uri(r"\\server\share\review.sqlite")
    assert unc_uri == "file:////server/share/review.sqlite?mode=ro"
    assert urlsplit(unc_uri).netloc == ""
    assert urlsplit(unc_uri).query == "mode=ro"

    _create_review_projection_database(control_path)
    with sqlite3.connect(posix_uri, uri=True) as connection:
        assert connection.execute("SELECT 1").fetchone() == (1,)
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("CREATE TABLE readonly_probe (value INTEGER)")
    store = SQLiteCandidatePublicationStore(
        tmp_path / "candidate.sqlite", control_database_path=control_path
    )
    reserved = _reserve(store)
    store.finalize(
        SCOPE,
        reserved.publication_key,
        "writer-a",
        reserved.reservation_epoch,
        canonical_candidate_publication_bytes(_evidence()),
        now=1_100_000,
    )
    rows = store.list_finalized_unreviewed(SCOPE)
    assert [row.publication_key for row in rows] == [reserved.publication_key]


@pytest.mark.parametrize(
    ("resolved_path", "expected_uri"),
    (
        (
            PureWindowsPath(r"C:\Control Folder\resolved #?.sqlite"),
            "file:///C:/Control%20Folder/resolved%20%23%3F.sqlite?mode=ro",
        ),
        (
            PureWindowsPath(r"\\server\share\resolved #?.sqlite"),
            "file:////server/share/resolved%20%23%3F.sqlite?mode=ro",
        ),
    ),
)
def test_resolution_produced_windows_paths_have_no_uri_authority(
    monkeypatch: pytest.MonkeyPatch,
    resolved_path: PureWindowsPath,
    expected_uri: str,
) -> None:
    monkeypatch.setattr(
        Path,
        "resolve",
        lambda self, strict=False: resolved_path,
    )
    uri = _sqlite_readonly_uri("synthetic-control.sqlite")
    assert uri == expected_uri
    assert urlsplit(uri).netloc == ""
    assert urlsplit(uri).query == "mode=ro"


def _create_review_projection_database(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE review_events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                target_id TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                content_digest TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                status TEXT NOT NULL,
                provenance_json TEXT NOT NULL,
                detail_json TEXT NOT NULL,
                occurred_at INTEGER NOT NULL
            );
            CREATE TABLE review_projection (
                target_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                version INTEGER NOT NULL,
                last_event_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                provenance_json TEXT NOT NULL,
                detail_json TEXT NOT NULL,
                occurred_at INTEGER NOT NULL
            );
            """
        )


@pytest.mark.parametrize(
    "status",
    ("pending", "approved", "rejected", "needs_changes", "unknown"),
)
def test_review_projection_statuses_are_excluded_fail_closed(
    tmp_path: Path,
    status: str,
) -> None:
    control_path = tmp_path / f"control-{status}.sqlite"
    _create_review_projection_database(control_path)
    store = SQLiteCandidatePublicationStore(
        tmp_path / f"candidate-{status}.sqlite",
        control_database_path=control_path,
    )
    reserved = _reserve(store)
    store.finalize(
        SCOPE,
        reserved.publication_key,
        "writer-a",
        1,
        canonical_candidate_publication_bytes(_evidence()),
        now=1_100_000,
    )
    target = _qualify(SCOPE, "review_target", reserved.review_target_id)
    with sqlite3.connect(control_path) as connection:
        connection.execute(
            "INSERT INTO review_events "
            "(event_id,target_id,idempotency_key,content_digest,actor_id,status," 
            "provenance_json,detail_json,occurred_at) VALUES (?,?,?,?,?,?,?,?,?)",
            ("event-1", target, "idem-1", "d" * 64, "reviewer", status, "{}", "{}", 1),
        )
        connection.execute(
            "INSERT INTO review_projection "
            "(target_id,status,version,last_event_id,actor_id,provenance_json,detail_json,occurred_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (target, status, 1, "event-1", "reviewer", "{}", "{}", 1),
        )
    assert store.list_finalized_unreviewed(SCOPE) == []


def test_corrupt_unreviewed_review_projection_is_excluded(tmp_path: Path) -> None:
    control_path = tmp_path / "control.sqlite"
    _create_review_projection_database(control_path)
    store = SQLiteCandidatePublicationStore(
        tmp_path / "candidate.sqlite", control_database_path=control_path
    )
    reserved = _reserve(store)
    store.finalize(
        SCOPE,
        reserved.publication_key,
        "writer-a",
        1,
        canonical_candidate_publication_bytes(_evidence()),
        now=1_100_000,
    )
    target = _qualify(SCOPE, "review_target", reserved.review_target_id)
    with sqlite3.connect(control_path) as connection:
        connection.execute(
            "INSERT INTO review_events "
            "(event_id,target_id,idempotency_key,content_digest,actor_id,status," 
            "provenance_json,detail_json,occurred_at) VALUES (?,?,?,?,?,?,?,?,?)",
            ("event-1", target, "idem-1", "d" * 64, "reviewer", "unreviewed", "{}", "{}", 1),
        )
        connection.execute(
            "INSERT INTO review_projection "
            "(target_id,status,version,last_event_id,actor_id,provenance_json,detail_json,occurred_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (target, "unreviewed", 1, "event-1", "reviewer", "not-json", "{}", 1),
        )
    assert store.list_finalized_unreviewed(SCOPE) == []


def test_discovery_limit_counts_effective_rows_and_cursor_continues(
    tmp_path: Path,
) -> None:
    control_path = tmp_path / "control.sqlite"
    _create_review_projection_database(control_path)
    store = SQLiteCandidatePublicationStore(
        tmp_path / "candidate.sqlite", control_database_path=control_path
    )
    approved_evidence = _golden_evidence(
        label="approved",
        job_digit="a",
        session_digit="b",
        artifact_digit="a",
        size_bytes=128,
        drawing_ref="drawing-approved",
        commands=["LINE", "LINE"],
    )
    approved = store.reserve(SCOPE, approved_evidence, "writer-a", 30, now=1_000_000)
    store.finalize(
        SCOPE,
        approved.publication_key,
        "writer-a",
        approved.reservation_epoch,
        canonical_candidate_publication_bytes(approved_evidence),
        now=1_100_000,
    )
    valid_evidence = _golden_evidence(
        label="valid",
        job_digit="c",
        session_digit="d",
        artifact_digit="b",
        size_bytes=128,
        drawing_ref="drawing-valid",
        commands=["LINE", "LINE"],
    )
    valid = store.reserve(SCOPE, valid_evidence, "writer-a", 30, now=1_200_000)
    store.finalize(
        SCOPE,
        valid.publication_key,
        "writer-a",
        valid.reservation_epoch,
        canonical_candidate_publication_bytes(valid_evidence),
        now=1_300_000,
    )
    target = _qualify(SCOPE, "review_target", approved.review_target_id)
    with sqlite3.connect(control_path) as connection:
        connection.execute(
            "INSERT INTO review_events "
            "(event_id,target_id,idempotency_key,content_digest,actor_id,status,"
            "provenance_json,detail_json,occurred_at) VALUES (?,?,?,?,?,?,?,?,?)",
            ("event-approved", target, "idem-approved", "d" * 64, "reviewer", "approved", "{}", "{}", 1),
        )
        connection.execute(
            "INSERT INTO review_projection "
            "(target_id,status,version,last_event_id,actor_id,provenance_json,detail_json,occurred_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (target, "approved", 1, "event-approved", "reviewer", "{}", "{}", 1),
        )

    rows = store.list_finalized_unreviewed(SCOPE, limit=1)
    assert [row.publication_key for row in rows] == [valid.publication_key]
    assert not hasattr(rows[0], "canonical_bytes")
    assert not hasattr(rows[0], "derivation_evidence_jcs")
    assert rows[0].cursor is not None
    assert store.list_finalized_unreviewed(SCOPE, limit=1, cursor=rows[0].cursor) == []


def test_bounded_unreviewed_discovery_and_cursor(tmp_path: Path) -> None:
    store = SQLiteCandidatePublicationStore(tmp_path / "candidate.sqlite")
    reserved = _reserve(store)
    store.finalize(
        SCOPE,
        reserved.publication_key,
        "writer-a",
        1,
        canonical_candidate_publication_bytes(_evidence()),
        now=1_100_000,
    )
    rows = store.list_finalized_unreviewed(SCOPE, limit=1)
    assert len(rows) == 1
    assert not hasattr(rows[0], "canonical_bytes")
    assert not hasattr(rows[0], "derivation_evidence_jcs")
    assert rows[0].publication_key == candidate_publication_key(str(JOB_ID))
    assert isinstance(rows[0].cursor, CandidatePublicationCursor)
    assert store.list_finalized_unreviewed(SCOPE, cursor=rows[0].cursor) == []


def test_review_projection_database_is_fail_closed_when_schema_is_missing(tmp_path: Path) -> None:
    control_path = tmp_path / "control.sqlite"
    with sqlite3.connect(control_path):
        pass
    store = SQLiteCandidatePublicationStore(
        tmp_path / "candidate.sqlite", control_database_path=control_path
    )
    reserved = _reserve(store)
    store.finalize(
        SCOPE,
        reserved.publication_key,
        "writer-a",
        1,
        canonical_candidate_publication_bytes(_evidence()),
        now=1_100_000,
    )
    assert store.list_finalized_unreviewed(SCOPE) == []


def test_invalid_lease_and_mutable_byte_types_fail_before_mutation(tmp_path: Path) -> None:
    store = SQLiteCandidatePublicationStore(tmp_path / "candidate.sqlite")
    for value in (True, 0, -1, 1801, 1.5):
        with pytest.raises(ValueError):
            store.reserve(SCOPE, _evidence(), "writer-a", value)  # type: ignore[arg-type]
    assert store.list_finalized_unreviewed(SCOPE) == []
