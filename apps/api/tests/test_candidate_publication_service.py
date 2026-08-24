from __future__ import annotations

import hashlib
import importlib
import os
import sqlite3
from pathlib import Path
from uuid import UUID

import pytest

from workflow_api.candidate_authority import CandidateAuthorityUnavailableError
from workflow_api.candidate_publication_service import (
    CandidatePublicationRequest,
    CandidatePublicationService,
    CandidatePublicationServiceValidationError,
)
from workflow_api.candidate_publication_store import (
    CandidatePublicationConflictError,
    CandidatePublicationCorruptionError,
    CandidatePublicationNotFoundError,
    CandidatePublicationStaleReservationError,
    CandidatePublicationUnavailableError,
    SQLiteCandidatePublicationStore,
    _restricted_jcs,
    canonical_candidate_publication_bytes,
)
from workflow_api.control_auth import AuthenticatedPrincipal, ControlRole
from workflow_api.control_scope import TenantWorkspaceScope, _qualify
from workflow_api.control_service import ControlService
from workflow_api.control_store import ControlConflictError, SQLiteControlStore
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


def _evidence(*, one_event: bool = False, artifact_sha: str = "b" * 64) -> dict[str, object]:
    job = ProcessingJobV2(
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
    result = ProcessingResultV2(
        schema_version="2.0",
        session_id=SESSION_ID,
        event_count=len(event_ids),
        meaningful_event_count=len(event_ids),
        timeline=timeline,
        operation_segments=segments,
        keyframes=[],
        warnings=[],
    )
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
        b"workflow-helper\0processing-job-v2\0result-digest\0sha256-jcs-v1\0"
        + manifest_jcs
    ).hexdigest()
    occurrences = [
        {"event_id": str(event_id), "command_name": "LINE", "segment_sequence": index}
        for index, event_id in enumerate(event_ids, start=1)
    ]
    return {
        "envelope_version": "1.0",
        "job": job,
        "result": result,
        "result_manifest": {
            **manifest,
            "result_manifest_jcs": manifest_jcs.decode("utf-8"),
            "source_result_sha256": source_h,
        },
        "timeline_binding": {
            "store_namespace": "google-drive://synthetic",
            "artifact_ref": artifact,
        },
        "drawing_ref": "drawing-α",
        "occurrences": occurrences,
        "rejected_alternative_count": 0,
        "qualifying_run_length": len(occurrences),
    }


def _request(
    evidence: dict[str, object] | None = None,
    *,
    scope: TenantWorkspaceScope = SCOPE,
    owner: str = "writer-a",
    now: int = 1_000_000,
) -> CandidatePublicationRequest:
    evidence = _evidence() if evidence is None else evidence
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
        reservation_owner_id=owner,
        lease_duration_seconds=30,
        now=now,
    )


def _service(tmp_path: Path) -> tuple[SQLiteCandidatePublicationStore, CandidatePublicationService]:
    store = SQLiteCandidatePublicationStore(tmp_path / "candidate.sqlite")
    return store, CandidatePublicationService(store)


def _row(store: SQLiteCandidatePublicationStore, scope: TenantWorkspaceScope = SCOPE):
    with sqlite3.connect(store.database_path) as connection:
        return connection.execute(
            "SELECT state, canonical_bytes, reservation_owner_id, reservation_epoch "
            "FROM candidate_publications WHERE tenant_id = ? AND workspace_id = ?",
            (scope.tenant_id, scope.workspace_id),
        ).fetchone()


def test_import_and_service_construction_are_dormant(tmp_path: Path, monkeypatch) -> None:
    store, _ = _service(tmp_path)
    before = sorted(path.name for path in tmp_path.iterdir())

    def forbidden(*_args, **_kwargs):
        raise AssertionError("service construction must not open SQLite")

    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr(os, "environ", {})
    service_module = importlib.import_module("workflow_api.candidate_publication_service")
    service = service_module.CandidatePublicationService(store)

    assert service is not None
    assert sorted(path.name for path in tmp_path.iterdir()) == before


def test_happy_path_delegates_exact_bytes_and_returns_safe_finalized_metadata(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store, service = _service(tmp_path)
    request = _request()
    expected_bytes = canonical_candidate_publication_bytes(
        {
            "envelope_version": request.envelope_version,
            "job": request.job,
            "result": request.result,
            "result_manifest": request.result_manifest,
            "timeline_binding": request.timeline_binding,
            "drawing_ref": request.drawing_ref,
            "occurrences": request.timeline_commands,
            "rejected_alternative_count": request.rejected_alternative_count,
            "qualifying_run_length": request.qualifying_run_length,
        }
    )
    observed: dict[str, object] = {}
    original_finalize = store.finalize

    def finalize(*args, **kwargs):
        observed["bytes"] = kwargs["canonical_bytes"]
        observed["owner"] = kwargs["reservation_owner_id"]
        observed["epoch"] = kwargs["reservation_epoch"]
        return original_finalize(*args, **kwargs)

    monkeypatch.setattr(store, "finalize", finalize)
    response = service.publish(request)

    assert response.state == "finalized"
    assert observed == {"bytes": expected_bytes, "owner": "writer-a", "epoch": 1}
    assert not hasattr(response, "canonical_bytes")
    assert not hasattr(response, "derivation_evidence_jcs")
    assert not hasattr(response, "artifact_ref")
    assert not hasattr(response, "store_namespace")
    assert store.read_finalized_bytes(SCOPE, response.publication_key) == expected_bytes


def test_explicit_publication_inputs_are_admitted_without_an_opaque_evidence_argument(
    tmp_path: Path,
) -> None:
    store, service = _service(tmp_path)
    request = _request()

    response = service.publish(
        scope=request.scope,
        job=request.job,
        result=request.result,
        result_manifest=request.result_manifest,
        timeline_binding=request.timeline_binding,
        drawing_ref=request.drawing_ref,
        timeline_commands=request.timeline_commands,
        rejected_alternative_count=request.rejected_alternative_count,
        qualifying_run_length=request.qualifying_run_length,
        reservation_owner_id=request.reservation_owner_id,
        lease_duration_seconds=request.lease_duration_seconds,
        now=request.now,
    )

    assert response.state == "finalized"
    assert store.get_finalized(SCOPE, response.publication_key).state == "finalized"


def test_exact_finalized_replay_returns_same_verified_metadata_without_finalize(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store, service = _service(tmp_path)
    request = _request()
    first = service.publish(request)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("finalized replay must not finalize again")

    monkeypatch.setattr(store, "finalize", forbidden)
    replay = service.publish(request)
    assert replay == first
    assert replay == store.get_finalized(SCOPE, first.publication_key).without_bytes()


def test_invalid_or_incomplete_evidence_fails_before_first_mutation(tmp_path: Path) -> None:
    store, service = _service(tmp_path)
    incomplete = _request()
    object.__setattr__(incomplete, "timeline_commands", [])
    with pytest.raises(CandidatePublicationServiceValidationError):
        service.publish(incomplete)
    assert _row(store) is None

    invalid = _request(_evidence(one_event=True))
    with pytest.raises(ValueError):
        service.publish(invalid)
    assert _row(store) is None


def test_exact_scope_and_model_contracts_are_required_before_mutation(tmp_path: Path) -> None:
    store, service = _service(tmp_path)
    request = _request()
    object.__setattr__(request, "scope", (SCOPE.tenant_id, SCOPE.workspace_id))
    with pytest.raises(CandidatePublicationServiceValidationError):
        service.publish(request)
    assert _row(store) is None

    request = _request()
    object.__setattr__(request, "job", request.job.model_copy())
    object.__setattr__(request, "result", request.result.model_copy())
    # Exact model instances are accepted; their defensive values are not
    # replaced by mappings or worker-owned lookalikes.
    assert service.publish(request).state == "finalized"


def test_changed_immutable_evidence_conflicts_without_mutation(tmp_path: Path) -> None:
    store, service = _service(tmp_path)
    first = service.publish(_request())
    before = _row(store)
    changed = _request(_evidence(artifact_sha="c" * 64))

    with pytest.raises(CandidatePublicationConflictError):
        service.publish(changed)
    assert _row(store) == before
    assert store.read_finalized_bytes(SCOPE, first.publication_key)


def test_reservation_conflict_and_fencing_errors_propagate(tmp_path: Path) -> None:
    store, service = _service(tmp_path)
    reserved = store.reserve(SCOPE, _evidence(), "writer-a", 30, now=1_000_000)
    with pytest.raises(CandidatePublicationUnavailableError):
        service.publish(_request(owner="writer-b", now=1_000_001))
    assert _row(store) == ("reserved", None, "writer-a", reserved.reservation_epoch)

    with pytest.raises(CandidatePublicationStaleReservationError):
        store.finalize(
            SCOPE,
            reserved.publication_key,
            "writer-b",
            reserved.reservation_epoch,
            canonical_candidate_publication_bytes(_evidence()),
            now=1_000_002,
        )
    assert _row(store) == ("reserved", None, "writer-a", reserved.reservation_epoch)


def test_corruption_is_not_repaired_or_hidden_by_service(tmp_path: Path) -> None:
    store, service = _service(tmp_path)
    first = service.publish(_request())
    with sqlite3.connect(store.database_path) as connection:
        connection.execute("DROP TRIGGER candidate_publications_no_update_finalized")
        connection.execute("DROP TRIGGER candidate_publications_bytes_once")
        connection.execute(
            "UPDATE candidate_publications SET canonical_bytes = zeroblob(byte_length) "
            "WHERE tenant_id = ? AND workspace_id = ? AND publication_key = ?",
            (SCOPE.tenant_id, SCOPE.workspace_id, first.publication_key),
        )

    with pytest.raises(CandidatePublicationCorruptionError):
        service.publish(_request())
    assert _row(store)[0] == "finalized"


def test_scope_is_forwarded_exactly_and_other_scope_cannot_replay_first_scope(
    tmp_path: Path,
) -> None:
    store, service = _service(tmp_path)
    first = service.publish(_request())

    with pytest.raises(CandidatePublicationNotFoundError):
        store.get_finalized(OTHER_SCOPE, first.publication_key)
    # The service returns a public projection and never the qualified internal
    # row key that could be used to cross this scope boundary.
    assert all(
        not (isinstance(value, str) and value.startswith("whscope1|"))
        for value in (
            first.tenant_id,
            first.workspace_id,
            first.publication_key,
            first.review_target_id,
        )
    )


def test_review_authority_binding_fails_before_finalized_lookup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control_store = SQLiteControlStore(tmp_path / "control.sqlite3")
    control_service = ControlService(control_store)
    publication_store = SQLiteCandidatePublicationStore(
        tmp_path / "publication.sqlite3",
        control_database_path=control_store,
    )
    service = CandidatePublicationService(publication_store, control_service)
    principal = AuthenticatedPrincipal(
        "reviewer_synthetic_01",
        frozenset({ControlRole.REVIEWER}),
        SCOPE,
    )
    publication_key = "candidate-publication:1.0:11111111-1111-4111-8111-111111111111"
    review_target = (
        "candidate-skill:1.0:11111111-1111-4111-8111-111111111111:sha256:"
        + "a" * 64
    )
    capability = control_service.authorize_candidate_review(
        principal,
        publication_key=publication_key,
        review_target_id=review_target,
        correlation_id="corr-authority-order",
        idempotency_key="idem-authority-order",
    )
    looked_up = False

    def forbidden_lookup(*_args: object, **_kwargs: object) -> object:
        nonlocal looked_up
        looked_up = True
        raise AssertionError("get_finalized ran before authority verification")

    monkeypatch.setattr(publication_store, "get_finalized", forbidden_lookup)
    publication_store._control_database_path = str(tmp_path / "missing-control.sqlite3")

    with pytest.raises(CandidateAuthorityUnavailableError):
        service.review_candidate(
            principal,
            control_service,
            publication_key=publication_key,
            review_target_id=review_target,
            idempotency_key="idem-authority-order",
            status="approved",
            correlation_id="corr-authority-order",
            capability=capability,
        )
    assert looked_up is False


def test_review_capability_rejects_cross_service_and_tampered_bindings(
    tmp_path: Path,
) -> None:
    scope = SCOPE
    principal = AuthenticatedPrincipal(
        "reviewer_synthetic_01",
        frozenset({ControlRole.REVIEWER}),
        scope,
    )
    publication_key = "candidate-publication:1.0:11111111-1111-4111-8111-111111111111"
    review_target = (
        "candidate-skill:1.0:11111111-1111-4111-8111-111111111111:sha256:"
        + "a" * 64
    )
    service_a = ControlService(SQLiteControlStore(tmp_path / "control-a.sqlite3"))
    service_b = ControlService(SQLiteControlStore(tmp_path / "control-b.sqlite3"))
    capability = service_a.authorize_candidate_review(
        principal,
        publication_key=publication_key,
        review_target_id=review_target,
        correlation_id="corr-capability",
        idempotency_key="idem-capability",
    )

    with pytest.raises(ControlConflictError):
        service_b.append_candidate_review(
            principal,
            publication_key=publication_key,
            review_target_id=review_target,
            idempotency_key="idem-capability",
            status="approved",
            content_sha256="a" * 64,
            full_sha256="b" * 64,
            source_result_sha256="c" * 64,
            correlation_id="corr-capability",
            capability=capability,
        )
    object.__setattr__(capability, "correlation_id", "corr-tampered")
    with pytest.raises(ControlConflictError):
        service_a.validate_candidate_review_capability(
            capability,
            principal,
            publication_key=publication_key,
            review_target_id=review_target,
            correlation_id="corr-tampered",
            idempotency_key="idem-capability",
        )


def test_review_capability_variants_reject_before_publication_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every opaque-capability mismatch is controlled and pre-read."""

    control_store = SQLiteControlStore(tmp_path / "control.sqlite3")
    control_service = ControlService(control_store)
    publication_store = SQLiteCandidatePublicationStore(
        tmp_path / "publication.sqlite3",
        control_database_path=control_store,
    )
    service = CandidatePublicationService(publication_store, control_service)
    principal = AuthenticatedPrincipal(
        "reviewer_synthetic_01",
        frozenset({ControlRole.REVIEWER}),
        SCOPE,
    )
    publication_key = "candidate-publication:1.0:11111111-1111-4111-8111-111111111111"
    review_target = (
        "candidate-skill:1.0:11111111-1111-4111-8111-111111111111:sha256:"
        + "a" * 64
    )
    other_publication_key = (
        "candidate-publication:1.0:22222222-2222-4222-8222-222222222222"
    )
    other_review_target = (
        "candidate-skill:1.0:22222222-2222-4222-8222-222222222222:sha256:"
        + "b" * 64
    )

    def issue(
        *,
        authority: ControlService = control_service,
        publication: str = publication_key,
        target: str = review_target,
        correlation: str = "corr-capability",
        idempotency: str = "idem-capability",
    ):
        return authority.authorize_candidate_review(
            principal,
            publication_key=publication,
            review_target_id=target,
            correlation_id=correlation,
            idempotency_key=idempotency,
        )

    stale = issue()
    object.__setattr__(stale, "correlation_id", "corr-stale")
    cross_service_store = SQLiteControlStore(tmp_path / "cross-service.sqlite3")
    cross_service = ControlService(cross_service_store)
    cross_service_publications = SQLiteCandidatePublicationStore(
        tmp_path / "cross-service-publication.sqlite3",
        control_database_path=cross_service_store,
    )
    cross_service_publication = CandidatePublicationService(
        cross_service_publications,
        cross_service,
    )

    reads = 0

    def forbidden_lookup(*_args: object, **_kwargs: object) -> object:
        nonlocal reads
        reads += 1
        raise AssertionError("capability rejection reached the publication read")

    monkeypatch.setattr(publication_store, "get_finalized", forbidden_lookup)
    monkeypatch.setattr(cross_service_publications, "get_finalized", forbidden_lookup)

    attempts = (
        (object(), service, control_service, {}),
        (stale, service, control_service, {"correlation_id": "corr-stale"}),
        (
            issue(),
            service,
            control_service,
            {"scope": OTHER_SCOPE},
        ),
        (
            issue(),
            service,
            control_service,
            {
                "publication_key": other_publication_key,
                "review_target_id": other_review_target,
            },
        ),
        (
            issue(),
            service,
            control_service,
            {
                "review_target_id": other_review_target,
            },
        ),
        (
            issue(),
            service,
            control_service,
            {"correlation_id": "corr-other"},
        ),
        (
            issue(),
            service,
            control_service,
            {"idempotency_key": "idem-other"},
        ),
        (
            issue(),
            cross_service_publication,
            cross_service,
            {},
        ),
    )
    for capability, review_service, authority, changes in attempts:
        inputs = {
            "publication_key": publication_key,
            "review_target_id": review_target,
            "idempotency_key": "idem-capability",
            "status": "approved",
            "correlation_id": "corr-capability",
            "capability": capability,
        }
        inputs.update(changes)
        with pytest.raises(ControlConflictError):
            review_service.review_candidate(
                principal,
                authority,
                **inputs,
            )
    assert reads == 0


def test_review_lifecycle_cas_and_idempotency_are_atomic(
    tmp_path: Path,
) -> None:
    control_store = SQLiteControlStore(tmp_path / "control.sqlite3")
    control_service = ControlService(control_store)
    publication_store = SQLiteCandidatePublicationStore(
        tmp_path / "publication.sqlite3",
        control_database_path=control_store,
    )
    service = CandidatePublicationService(publication_store, control_service)
    principal = AuthenticatedPrincipal(
        "reviewer_synthetic_01",
        frozenset({ControlRole.REVIEWER}),
        SCOPE,
    )
    metadata = service.publish(_request())
    common = {
        "principal": principal,
        "control_service": control_service,
        "scope": SCOPE,
        "publication_key": metadata.publication_key,
        "review_target_id": metadata.review_target_id,
        "status": "approved",
        "reason": "synthetic acceptance",
        "evidence": {"checked": True},
        "correlation_id": "corr-review-lifecycle",
        "idempotency_key": "idem-review-lifecycle",
    }

    first = service.review_candidate(**common)
    replay = service.review_candidate(**common)
    assert replay.event_id == first.event_id
    assert replay.content_digest == first.content_digest

    with pytest.raises(ControlConflictError, match="idempotency"):
        service.review_candidate(
            **{
                **common,
                "status": "rejected",
            }
        )
    with pytest.raises(ControlConflictError, match="transition"):
        service.review_candidate(
            **{
                **common,
                "idempotency_key": "idem-review-lifecycle-transition",
                "status": "pending",
            }
        )
    with pytest.raises(ControlConflictError, match="expected prior"):
        service.review_candidate(
            **{
                **common,
                "idempotency_key": "idem-review-lifecycle-cas",
                "expected_prior_state": "unreviewed",
                "expected_prior_version": 0,
                "expected_prior_event_id": None,
            }
        )

    projection = control_service.read_candidate_review(
        principal,
        review_target_id=metadata.review_target_id,
        correlation_id="corr-review-lifecycle-read",
    )
    assert projection is not None
    assert projection.status == "approved"
    assert projection.version == 1
    assert len(
        control_store.list_candidate_review_events(
            _qualify(SCOPE, "review_target", metadata.review_target_id),
            after_sequence=0,
            limit=10,
        )
    ) == 1
