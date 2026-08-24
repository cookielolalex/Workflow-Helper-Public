from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from workflow_api.candidate_discovery_service import (
    CandidateDiscoveryService,
    CandidateDiscoveryUnavailableError,
    CandidateDiscoveryValidationError,
    CandidateReviewOutcomeRecord,
    CandidateReviewQueueRecord,
)
from workflow_api.candidate_publication_service import CandidatePublicationService
from workflow_api.candidate_publication_store import (
    CandidatePublicationError,
    CandidatePublicationMetadata,
    SQLiteCandidatePublicationStore,
)
from workflow_api.control_auth import (
    AuthenticatedPrincipal,
    AuthorizationDeniedError,
    ControlRole,
)
from workflow_api.control_scope import TenantWorkspaceScope, _qualify
from workflow_api.control_service import ControlService
from workflow_api.control_store import _UNSET, SQLiteControlStore
from workflow_api.dependencies import get_authenticated_principal, get_control_service
from workflow_api.main import app as main_app
from workflow_api.routes.candidate_discovery import (
    get_candidate_discovery_service,
    get_candidate_publication_service,
    router,
)

SCOPE = TenantWorkspaceScope("tenant-synthetic", "workspace-synthetic")
CORRELATION = "corr-route-synthetic"


def _principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        "reviewer_synthetic_01",
        frozenset({ControlRole.REVIEWER}),
        SCOPE,
    )


def _metadata(
    digit: str = "1", *, finalized_at_us: int = 1_000_000
) -> CandidatePublicationMetadata:
    uuid = f"{digit * 8}-{digit * 4}-4000-8000-{digit * 12}"
    return CandidatePublicationMetadata(
        tenant_id=SCOPE.tenant_id,
        workspace_id=SCOPE.workspace_id,
        publication_key=f"candidate-publication:1.0:{uuid}",
        schema_version="1.0",
        job_id=f"job-{digit}",
        session_id=f"session-{digit}",
        source_result_sha256="a" * 64,
        derivation_evidence_sha256="b" * 64,
        review_target_id=f"candidate-skill:1.0:{uuid}:sha256:" + "c" * 64,
        content_sha256="c" * 64,
        full_sha256="d" * 64,
        publication_identity="e" * 64,
        byte_length=123,
        state="finalized",
        reserved_at_us=900_000,
        updated_at_us=950_000,
        finalized_at_us=finalized_at_us,
        writer_epoch=7,
    )


@pytest.fixture
def service(tmp_path: Path) -> CandidateDiscoveryService:
    control_store = SQLiteControlStore(tmp_path / "control.sqlite3")
    publication_store = SQLiteCandidatePublicationStore(
        tmp_path / "publication.sqlite3",
        control_database_path=control_store,
    )
    return CandidateDiscoveryService(publication_store, ControlService(control_store))


@pytest.fixture
def isolated_app(service: CandidateDiscoveryService) -> FastAPI:
    application = FastAPI()
    application.include_router(router)
    application.dependency_overrides[get_authenticated_principal] = _principal
    application.dependency_overrides[get_candidate_discovery_service] = lambda: service
    return application


def test_main_app_keeps_dormant_route_unreachable() -> None:
    response = TestClient(main_app).get(
        "/v1/control/candidate-publications?correlation_id=" + CORRELATION
    )
    assert response.status_code == 404
    queue = TestClient(main_app).get(
        "/v1/control/candidate-publications/review-queue"
    )
    assert queue.status_code == 404
    outcomes = TestClient(main_app).get(
        "/v1/control/candidate-publications/review-outcomes"
    )
    assert outcomes.status_code == 404


def test_default_service_dependency_fails_closed_without_a_fallback() -> None:
    application = FastAPI()
    application.include_router(router)
    application.dependency_overrides[get_authenticated_principal] = _principal

    response = TestClient(application).get(
        "/v1/control/candidate-publications?correlation_id=" + CORRELATION
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "candidate discovery unavailable"}


def test_review_denial_is_audited_before_publication_lookup(
    service: CandidateDiscoveryService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A denied review cannot probe whether its publication key exists."""

    control_service = service._control_service
    publication_service = CandidatePublicationService(
        service._publication_store,
        control_service,
    )
    looked_up = False

    def forbidden_lookup(*_args: object, **_kwargs: object) -> object:
        nonlocal looked_up
        looked_up = True
        raise AssertionError("publication lookup occurred before review authorization")

    monkeypatch.setattr(
        publication_service._store,
        "get_finalized",
        forbidden_lookup,
    )
    denied = AuthenticatedPrincipal("reviewer_synthetic_01", frozenset(), SCOPE)
    application = FastAPI()
    application.include_router(router)
    application.dependency_overrides[get_authenticated_principal] = lambda: denied
    application.dependency_overrides[get_control_service] = lambda: control_service
    application.dependency_overrides[get_candidate_publication_service] = (
        lambda: publication_service
    )

    publication_key = "candidate-publication:1.0:11111111-1111-4111-8111-111111111111"
    review_target = (
        "candidate-skill:1.0:11111111-1111-4111-8111-111111111111:sha256:"
        + "a" * 64
    )
    response = TestClient(application).post(
        f"/v1/control/candidate-publications/{publication_key}/review",
        json={
            "review_target_id": review_target,
            "correlation_id": "corr-denied-review",
            "idempotency_key": "idem-denied-review",
            "status": "approved",
        },
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "action forbidden"}
    assert looked_up is False
    events = control_service._store.list_audit_events()
    assert len(events) == 1
    assert events[0].action == "review.append"
    assert events[0].result == "denied"


def test_denied_review_is_non_oracle_for_cross_target_and_missing_publications(
    service: CandidateDiscoveryService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Identity mismatch and missing rows remain the same denied response."""

    control_service = service._control_service
    publication_service = CandidatePublicationService(
        service._publication_store,
        control_service,
    )
    looked_up = 0

    def forbidden_lookup(*_args: object, **_kwargs: object) -> object:
        nonlocal looked_up
        looked_up += 1
        raise AssertionError("denied review reached publication lookup")

    monkeypatch.setattr(publication_service._store, "get_finalized", forbidden_lookup)
    denied = AuthenticatedPrincipal("reviewer_synthetic_01", frozenset(), SCOPE)
    application = FastAPI()
    application.include_router(router)
    application.dependency_overrides[get_authenticated_principal] = lambda: denied
    application.dependency_overrides[get_control_service] = lambda: control_service
    application.dependency_overrides[get_candidate_publication_service] = (
        lambda: publication_service
    )

    publication_one = "candidate-publication:1.0:11111111-1111-4111-8111-111111111111"
    publication_two = "candidate-publication:1.0:22222222-2222-4222-8222-222222222222"
    target_two = (
        "candidate-skill:1.0:22222222-2222-4222-8222-222222222222:sha256:"
        + "b" * 64
    )
    responses = [
        TestClient(application).post(
            f"/v1/control/candidate-publications/{publication_one}/review",
            json={
                "review_target_id": target_two,
                "correlation_id": "corr-denied-cross-target",
                "idempotency_key": "idem-denied-cross-target",
                "status": "approved",
            },
        ),
        TestClient(application).post(
            f"/v1/control/candidate-publications/{publication_two}/review",
            json={
                "review_target_id": target_two,
                "correlation_id": "corr-denied-missing",
                "idempotency_key": "idem-denied-missing",
                "status": "approved",
            },
        ),
    ]

    assert [(response.status_code, response.json()) for response in responses] == [
        (403, {"detail": "action forbidden"}),
        (403, {"detail": "action forbidden"}),
    ]
    assert looked_up == 0
    events = control_service._store.list_audit_events()
    assert len(events) == 2
    assert all(event.action == "review.append" for event in events)
    assert all(event.result == "denied" for event in events)


def test_review_post_success_replay_and_lifecycle_idempotency_conflicts(
    service: CandidateDiscoveryService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The route exposes one successful event and stable conflict mapping."""

    control_service = service._control_service
    publication_service = CandidatePublicationService(
        service._publication_store,
        control_service,
    )
    metadata = _metadata()
    monkeypatch.setattr(
        service._publication_store,
        "get_finalized",
        lambda *_args, **_kwargs: metadata,
    )
    application = FastAPI()
    application.include_router(router)
    application.dependency_overrides[get_authenticated_principal] = _principal
    application.dependency_overrides[get_control_service] = lambda: control_service
    application.dependency_overrides[get_candidate_publication_service] = (
        lambda: publication_service
    )
    path = f"/v1/control/candidate-publications/{metadata.publication_key}/review"
    payload = {
        "review_target_id": metadata.review_target_id,
        "correlation_id": "corr-post-review",
        "idempotency_key": "idem-post-review",
        "status": "approved",
        "reason": "synthetic acceptance",
        "evidence": {"checked": True},
    }

    first = TestClient(application).post(path, json=payload)
    replay = TestClient(application).post(path, json=payload)
    idempotency_conflict = TestClient(application).post(
        path,
        json={**payload, "status": "rejected"},
    )
    lifecycle_conflict = TestClient(application).post(
        path,
        json={
            **payload,
            "idempotency_key": "idem-post-lifecycle",
            "status": "pending",
        },
    )

    assert first.status_code == 200, first.text
    assert first.json() == {"status": "approved"}
    assert replay.status_code == 200, replay.text
    assert replay.json() == first.json()
    assert idempotency_conflict.status_code == 409
    assert idempotency_conflict.json() == {
        "detail": "request conflicts with current state"
    }
    assert lifecycle_conflict.status_code == 409
    assert lifecycle_conflict.json() == {
        "detail": "request conflicts with current state"
    }
    events = control_service._store.list_candidate_review_events(
        _qualify(SCOPE, "review_target", metadata.review_target_id),
        after_sequence=0,
        limit=10,
    )
    assert len(events) == 1
    assert events[0].status == "approved"


@pytest.mark.parametrize("terminal_status", ("rejected", "needs_changes"))
def test_review_post_supports_pending_terminal_transitions(
    service: CandidateDiscoveryService,
    monkeypatch: pytest.MonkeyPatch,
    terminal_status: str,
) -> None:
    control_service = service._control_service
    publication_service = CandidatePublicationService(
        service._publication_store,
        control_service,
    )
    metadata = _metadata()
    monkeypatch.setattr(
        service._publication_store,
        "get_finalized",
        lambda *_args, **_kwargs: metadata,
    )
    application = FastAPI()
    application.include_router(router)
    application.dependency_overrides[get_authenticated_principal] = _principal
    application.dependency_overrides[get_control_service] = lambda: control_service
    application.dependency_overrides[get_candidate_publication_service] = (
        lambda: publication_service
    )
    path = f"/v1/control/candidate-publications/{metadata.publication_key}/review"
    common = {
        "review_target_id": metadata.review_target_id,
        "correlation_id": "corr-pending-terminal",
    }
    pending = TestClient(application).post(
        path,
        json={
            **common,
            "idempotency_key": f"idem-pending-{terminal_status}",
            "status": "pending",
        },
    )
    terminal = TestClient(application).post(
        path,
        json={
            **common,
            "idempotency_key": f"idem-terminal-{terminal_status}",
            "status": terminal_status,
        },
    )

    assert pending.status_code == 200, pending.text
    assert pending.json() == {"status": "pending"}
    assert terminal.status_code == 200, terminal.text
    assert terminal.json() == {"status": terminal_status}
    events = control_service._store.list_candidate_review_events(
        _qualify(SCOPE, "review_target", metadata.review_target_id),
        after_sequence=0,
        limit=10,
    )
    assert [event.status for event in events] == ["pending", terminal_status]


def test_review_post_reason_omission_replays_but_explicit_null_conflicts(
    service: CandidateDiscoveryService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Omitted reason stays unset so replay can restore the persisted reason."""

    control_service = service._control_service
    publication_service = CandidatePublicationService(
        service._publication_store,
        control_service,
    )
    metadata = _metadata()
    monkeypatch.setattr(
        service._publication_store,
        "get_finalized",
        lambda *_args, **_kwargs: metadata,
    )
    seen_reasons: list[object] = []
    original_review_candidate = publication_service.review_candidate

    def record_reason(*args: object, **kwargs: object) -> object:
        seen_reasons.append(kwargs["reason"])
        return original_review_candidate(*args, **kwargs)

    monkeypatch.setattr(publication_service, "review_candidate", record_reason)
    application = FastAPI()
    application.include_router(router)
    application.dependency_overrides[get_authenticated_principal] = _principal
    application.dependency_overrides[get_control_service] = lambda: control_service
    application.dependency_overrides[get_candidate_publication_service] = (
        lambda: publication_service
    )
    path = f"/v1/control/candidate-publications/{metadata.publication_key}/review"
    payload = {
        "review_target_id": metadata.review_target_id,
        "correlation_id": "corr-reason-replay",
        "idempotency_key": "idem-reason-replay",
        "status": "approved",
        "reason": "synthetic acceptance",
    }

    first = TestClient(application).post(path, json=payload)
    explicit_null = TestClient(application).post(
        path,
        json={**payload, "reason": None},
    )
    omitted = TestClient(application).post(
        path,
        json={key: value for key, value in payload.items() if key != "reason"},
    )

    assert first.status_code == 200, first.text
    assert first.json() == {"status": "approved"}
    assert explicit_null.status_code == 409
    assert explicit_null.json() == {
        "detail": "request conflicts with current state"
    }
    assert omitted.status_code == 200, omitted.text
    assert omitted.json() == first.json()
    assert seen_reasons == ["synthetic acceptance", None, _UNSET]
    events = control_service._store.list_candidate_review_events(
        _qualify(SCOPE, "review_target", metadata.review_target_id),
        after_sequence=0,
        limit=10,
    )
    assert len(events) == 1
    assert events[0].status == "approved"


def test_authentication_precedes_service_resolution_and_preserves_401() -> None:
    application = FastAPI()
    application.include_router(router)
    service_called = False

    def rejected_authentication() -> AuthenticatedPrincipal:
        raise HTTPException(status_code=401, detail="identity rejected")

    def forbidden_fallback() -> CandidateDiscoveryService:
        nonlocal service_called
        service_called = True
        raise AssertionError("service resolution occurred before authentication")

    application.dependency_overrides[get_authenticated_principal] = rejected_authentication
    application.dependency_overrides[get_candidate_discovery_service] = forbidden_fallback

    response = TestClient(application).get(
        "/v1/control/candidate-publications?correlation_id=" + CORRELATION
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "identity rejected"}
    assert service_called is False


def test_session_security_failure_is_generic_503() -> None:
    application = FastAPI()
    application.include_router(router)

    def rejected_session() -> AuthenticatedPrincipal:
        raise HTTPException(status_code=503, detail="session security unavailable")

    application.dependency_overrides[get_authenticated_principal] = rejected_session

    response = TestClient(application).get(
        "/v1/control/candidate-publications?correlation_id=" + CORRELATION
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "session security unavailable"}


@pytest.mark.parametrize(
    "path",
    (
        "/v1/control/candidate-publications",
        "/v1/control/candidate-publications?correlation_id=",
        "/v1/control/candidate-publications?correlation_id=corr&limit=0",
        "/v1/control/candidate-publications?correlation_id=corr&limit=101",
        "/v1/control/candidate-publications?correlation_id=corr&limit=not-an-integer",
    ),
)
def test_invalid_request_is_bounded_and_does_not_read(
    isolated_app: FastAPI,
    service: CandidateDiscoveryService,
    path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    def should_not_read(*_args: object, **_kwargs: object) -> list[CandidatePublicationMetadata]:
        nonlocal called
        called = True
        raise AssertionError("invalid request reached the discovery service")

    monkeypatch.setattr(service, "list_finalized_unreviewed", should_not_read)
    response = TestClient(isolated_app).get(path)

    assert response.status_code == 422
    assert response.json() == {"detail": "invalid request"}
    assert called is False


def test_cursor_and_limit_are_forwarded_unchanged_and_next_cursor_is_opaque(
    isolated_app: FastAPI,
    service: CandidateDiscoveryService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata = _metadata()
    calls: list[tuple[AuthenticatedPrincipal, str, int, str | None]] = []

    def discover(
        principal: AuthenticatedPrincipal,
        *,
        correlation_id: str,
        limit: int,
        cursor: str | None,
    ) -> list[CandidatePublicationMetadata]:
        calls.append((principal, correlation_id, limit, cursor))
        return [metadata]

    monkeypatch.setattr(service, "list_finalized_unreviewed", discover)
    response = TestClient(isolated_app).get(
        "/v1/control/candidate-publications"
        "?correlation_id=" + CORRELATION + "&limit=1&cursor=%5Bopaque%5D"
    )

    assert response.status_code == 200, response.text
    assert calls == [(_principal(), CORRELATION, 1, "[opaque]")]
    assert response.json()["next_cursor"] == metadata.cursor.encode()


def test_response_is_strict_metadata_only_and_excludes_scope_internal_fields(
    isolated_app: FastAPI,
    service: CandidateDiscoveryService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata = _metadata()
    monkeypatch.setattr(
        service,
        "list_finalized_unreviewed",
        lambda *_args, **_kwargs: [metadata],
    )

    response = TestClient(isolated_app).get(
        "/v1/control/candidate-publications?correlation_id=" + CORRELATION + "&limit=1"
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {"items", "count", "next_cursor"}
    assert body["count"] == 1
    assert set(body["items"][0]) == {
        "publication_key",
        "schema_version",
        "job_id",
        "session_id",
        "source_result_sha256",
        "derivation_evidence_sha256",
        "review_target_id",
        "content_sha256",
        "full_sha256",
        "publication_identity",
        "byte_length",
        "state",
        "finalized_at_us",
    }
    forbidden = {
        "tenant_id",
        "workspace_id",
        "canonical_bytes",
        "derivation_evidence_jcs",
        "reservation_owner_id",
        "reservation_epoch",
        "reservation_expires_at_us",
        "reserved_at_us",
        "updated_at_us",
        "writer_epoch",
        "actor_id",
        "status",
        "detail",
        "raw",
        "body",
        "url",
        "uri",
        "token",
        "credential",
    }
    assert forbidden.isdisjoint(body["items"][0])


def test_review_queue_route_is_static_exact_and_display_safe(
    isolated_app: FastAPI,
    service: CandidateDiscoveryService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata = _metadata()
    row = CandidateReviewQueueRecord(
        publication_key=metadata.publication_key,
        review_target_id=metadata.review_target_id,
        command_sequence=("LINE", "TRIM", "LINE", "TRIM"),
        occurrence_count=4,
        provenance="observed",
        review_status="pending",
        finalized_at_us=metadata.finalized_at_us,
    )
    calls: list[tuple[AuthenticatedPrincipal, str]] = []

    def review_queue(
        principal: AuthenticatedPrincipal,
        *,
        correlation_id: str,
    ) -> list[CandidateReviewQueueRecord]:
        calls.append((principal, correlation_id))
        return [row]

    monkeypatch.setattr(service, "list_review_queue", review_queue)
    response = TestClient(isolated_app).get(
        "/v1/control/candidate-publications/review-queue"
    )

    assert response.status_code == 200, response.text
    assert calls == [(_principal(), "candidate-review-queue")]
    assert response.json() == {
        "items": [
            {
                "publication_key": metadata.publication_key,
                "review_target_id": metadata.review_target_id,
                "command_sequence": ["LINE", "TRIM", "LINE", "TRIM"],
                "occurrence_count": 4,
                "provenance": "observed",
                "review_status": "pending",
                "finalized_at_us": metadata.finalized_at_us,
            }
        ],
        "count": 1,
    }
    assert set(response.json()["items"][0]) == {
        "publication_key",
        "review_target_id",
        "command_sequence",
        "occurrence_count",
        "provenance",
        "review_status",
        "finalized_at_us",
    }
    route_paths = [route.path for route in router.routes]
    assert route_paths.index(
        "/v1/control/candidate-publications/review-queue"
    ) < route_paths.index(
        "/v1/control/candidate-publications/{publication_key}/review"
    )


def test_review_queue_invalid_service_result_fails_closed(
    isolated_app: FastAPI,
    service: CandidateDiscoveryService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        service,
        "list_review_queue",
        lambda *_args, **_kwargs: [object()],
    )
    response = TestClient(isolated_app).get(
        "/v1/control/candidate-publications/review-queue"
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "candidate discovery unavailable"}


def test_review_outcomes_route_is_static_exact_identifier_free_and_bounded(
    isolated_app: FastAPI,
    service: CandidateDiscoveryService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = CandidateReviewOutcomeRecord(
        command_sequence=("LINE", "TRIM", "LINE", "TRIM"),
        occurrence_count=4,
        provenance="observed",
        review_status="needs_changes",
        decided_at_us=2_000_000,
    )
    calls: list[tuple[AuthenticatedPrincipal, str]] = []

    def outcomes(
        principal: AuthenticatedPrincipal,
        *,
        correlation_id: str,
    ) -> list[CandidateReviewOutcomeRecord]:
        calls.append((principal, correlation_id))
        return [row]

    monkeypatch.setattr(service, "list_review_outcomes", outcomes)
    response = TestClient(isolated_app).get(
        "/v1/control/candidate-publications/review-outcomes"
    )

    assert response.status_code == 200, response.text
    assert calls == [(_principal(), "candidate-review-outcomes")]
    assert response.json() == {
        "items": [
            {
                "command_sequence": ["LINE", "TRIM", "LINE", "TRIM"],
                "occurrence_count": 4,
                "provenance": "observed",
                "review_status": "needs_changes",
                "decided_at_us": 2_000_000,
            }
        ],
        "count": 1,
    }
    forbidden = {
        "publication_key",
        "review_target_id",
        "actor_id",
        "reason",
        "evidence",
        "hash",
        "artifact_ref",
    }
    assert forbidden.isdisjoint(response.json()["items"][0])
    route_paths = [route.path for route in router.routes]
    assert route_paths.index(
        "/v1/control/candidate-publications/review-outcomes"
    ) < route_paths.index(
        "/v1/control/candidate-publications/{publication_key}/review"
    )


def test_review_outcomes_invalid_service_result_fails_closed(
    isolated_app: FastAPI,
    service: CandidateDiscoveryService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(service, "list_review_outcomes", lambda *_args, **_kwargs: [object()])
    response = TestClient(isolated_app).get(
        "/v1/control/candidate-publications/review-outcomes"
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "candidate discovery unavailable"}


def test_review_outcomes_authority_failure_is_generic(
    isolated_app: FastAPI,
    service: CandidateDiscoveryService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(*_args: object, **_kwargs: object) -> None:
        raise CandidateDiscoveryUnavailableError("private authority path")

    monkeypatch.setattr(service, "list_review_outcomes", unavailable)
    response = TestClient(isolated_app).get(
        "/v1/control/candidate-publications/review-outcomes"
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "candidate discovery unavailable"}


def test_empty_results_are_200_and_do_not_become_existence_oracles(
    isolated_app: FastAPI,
    service: CandidateDiscoveryService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        service,
        "list_finalized_unreviewed",
        lambda *_args, **_kwargs: [],
    )

    response = TestClient(isolated_app).get(
        "/v1/control/candidate-publications?correlation_id=" + CORRELATION
    )

    assert response.status_code == 200
    assert response.json() == {"items": [], "count": 0, "next_cursor": None}


@pytest.mark.parametrize(
    "error, status_code, detail",
    (
        (AuthorizationDeniedError("secret denial"), 403, "action forbidden"),
        (CandidateDiscoveryValidationError("secret validation"), 422, "invalid request"),
        (CandidateDiscoveryUnavailableError("secret unavailable"), 503, "candidate discovery unavailable"),
        (CandidatePublicationError("secret corruption"), 503, "candidate discovery unavailable"),
        (RuntimeError("secret schema path"), 503, "candidate discovery unavailable"),
    ),
)
def test_service_errors_are_generic(
    isolated_app: FastAPI,
    service: CandidateDiscoveryService,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    status_code: int,
    detail: str,
) -> None:
    def fail(*_args: object, **_kwargs: object) -> list[CandidatePublicationMetadata]:
        raise error

    monkeypatch.setattr(service, "list_finalized_unreviewed", fail)
    response = TestClient(isolated_app).get(
        "/v1/control/candidate-publications?correlation_id=" + CORRELATION
    )

    assert response.status_code == status_code
    assert response.json() == {"detail": detail}
    assert "secret" not in response.text


def test_discovery_route_performs_no_mutation(service: CandidateDiscoveryService) -> None:
    control_path = Path(service._control_service._store._database_path)
    publication_path = Path(service._publication_store.database_path)
    control_before = control_path.read_bytes()
    publication_before = publication_path.read_bytes()

    application = FastAPI()
    application.include_router(router)
    application.dependency_overrides[get_authenticated_principal] = _principal
    application.dependency_overrides[get_candidate_discovery_service] = lambda: service
    response = TestClient(application).get(
        "/v1/control/candidate-publications?correlation_id=" + CORRELATION
    )

    assert response.status_code == 200
    assert response.json() == {"items": [], "count": 0, "next_cursor": None}
    assert control_path.read_bytes() == control_before
    assert publication_path.read_bytes() == publication_before


def test_import_is_inert(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib
    import sqlite3

    import workflow_api.routes.candidate_discovery as module

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("route import opened SQLite")

    monkeypatch.setattr(sqlite3, "connect", forbidden)
    assert importlib.reload(module).router.routes
