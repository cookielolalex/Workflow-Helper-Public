import dataclasses
import hashlib
import io
import json
import sqlite3
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import pytest
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

from workflow_api.artifact_gateway import ArtifactAuthority, ArtifactGatewayUnavailableError
from workflow_api.aws_clients import AwsGateway, ProcessingQueueError
from workflow_api.config import Settings, get_settings
from workflow_api.control_auth import AuthenticatedPrincipal, ControlRole
from workflow_api.control_scope import TenantWorkspaceScope
from workflow_api.dependencies import (
    get_artifact_gateway,
    get_provider_neutral_security_composition,
    get_runtime_settings,
)
from workflow_api.identity import (
    AuthenticationAssurance,
    AuthenticationContext,
    AuthenticationMethod,
    GroupRoleBinding,
    GroupRoleMapping,
    SubjectScopeBinding,
    SubjectScopePolicy,
    VerifiedIdentityEvidence,
)
from workflow_api.legacy_session_composition import ProviderNeutralSecurityComposition
from workflow_api.legacy_session_security import (
    LegacySessionAudience,
    LegacySessionTransport,
    LegacyWorkloadContext,
    ReplayDecision,
)
from workflow_api.legacy_session_store import (
    LegacyWorkloadPrincipalConflictError,
    SQLiteLegacySessionStore,
)
from workflow_api.main import app
from workflow_api.models import SessionCreate, SessionRecord
from workflow_api.session_security import SessionSecurityContext, SessionTransport

SCOPE = TenantWorkspaceScope("tenant-synthetic", "workspace-synthetic")
OTHER_SCOPE = TenantWorkspaceScope("tenant-other", "workspace-other")
AUTHORITY = ArtifactAuthority(SCOPE, "capture_uploader-synthetic")
CURRENT_STORE: SQLiteLegacySessionStore | None = None


def _principal(
    role: ControlRole,
    *,
    subject: str | None = None,
    scope: TenantWorkspaceScope = SCOPE,
) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        subject or f"{role.value}-synthetic",
        frozenset({role}),
        scope,
    )


class HermeticWorkloadProvider:
    def __init__(
        self,
        *,
        capture_principal: AuthenticatedPrincipal | None = None,
        worker_principal: AuthenticatedPrincipal | None = None,
        mutate=None,
    ) -> None:
        self.capture_principal = capture_principal or _principal(ControlRole.CAPTURE_UPLOADER)
        self.worker_principal = worker_principal or _principal(
            ControlRole.DETERMINISTIC_WORKER
        )
        self.mutate = mutate
        self.calls = 0

    def get_workload_context(self, *, method, path, body_sha256, headers):
        self.calls += 1
        worker = path.startswith("/v1/internal/")
        now = datetime.now(UTC)
        context = LegacyWorkloadContext(
            principal=self.worker_principal if worker else self.capture_principal,
            audience=(
                LegacySessionAudience.PROCESSING_COMPLETION
                if worker
                else LegacySessionAudience.CAPTURE_UPLOAD
            ),
            transport=(
                LegacySessionTransport.WORKER_WORKLOAD
                if worker
                else LegacySessionTransport.CAPTURE_WORKLOAD
            ),
            method=method,
            path=path,
            body_sha256=body_sha256,
            proof_identifier_digest=hashlib.sha256(str(uuid4()).encode()).hexdigest(),
            issued_at=now - timedelta(seconds=1),
            expires_at=now + timedelta(minutes=1),
            generation=1,
            active_generation=1,
            revoked=False,
            replay_decision=ReplayDecision.ACCEPT,
        )
        return self.mutate(context) if self.mutate else context


class HermeticBrowserProvider:
    def __init__(self, principal: AuthenticatedPrincipal) -> None:
        self.principal = principal

    def get_session_security_context(self) -> SessionSecurityContext:
        now = datetime.now(UTC)
        return SessionSecurityContext(
            principal=self.principal,
            session_identifier_digest="a" * 64,
            session_generation=1,
            active_generation=1,
            issued_at=now - timedelta(minutes=2),
            authenticated_at=now - timedelta(minutes=2),
            last_seen_at=now - timedelta(seconds=1),
            idle_expires_at=now + timedelta(minutes=10),
            absolute_expires_at=now + timedelta(hours=1),
            revoked=False,
            transport=SessionTransport.BROWSER_COOKIE,
            allowed_browser_origin="https://review.example.com",
            csrf_token_digest="b" * 64,
        )


class HermeticAuthenticator:
    def __init__(self, principal: AuthenticatedPrincipal) -> None:
        self.principal = principal
        self.calls = 0

    def authenticate(self) -> VerifiedIdentityEvidence:
        self.calls += 1
        return VerifiedIdentityEvidence(
            self.principal.subject,
            tuple(f"group-{role.value}" for role in sorted(self.principal.roles)),
            AuthenticationContext(
                AuthenticationAssurance.MULTI_FACTOR,
                (AuthenticationMethod.PASSWORD, AuthenticationMethod.TOTP),
            ),
            self.principal.scope,
        )


def _register_workload_principal(
    store: SQLiteLegacySessionStore,
    principal: AuthenticatedPrincipal,
    *,
    role: ControlRole,
    audience: LegacySessionAudience,
    transport: LegacySessionTransport,
) -> None:
    if principal.roles != frozenset({role}) or principal.scope is None:
        return
    try:
        store.register_workload_principal(
            principal_subject=principal.subject,
            scope=principal.scope,
            audience=audience,
            role=role,
            transport=transport,
        )
    except LegacyWorkloadPrincipalConflictError:
        pass


def _install_authorization(
    *,
    capture_principal: AuthenticatedPrincipal | None = None,
    worker_principal: AuthenticatedPrincipal | None = None,
    reviewer_principal: AuthenticatedPrincipal | None = None,
    workload_provider=None,
) -> None:
    assert CURRENT_STORE is not None
    reviewer = reviewer_principal or _principal(ControlRole.REVIEWER)
    verifier = workload_provider or HermeticWorkloadProvider(
        capture_principal=capture_principal,
        worker_principal=worker_principal,
    )
    capture = verifier.capture_principal if isinstance(verifier, HermeticWorkloadProvider) else None
    worker = verifier.worker_principal if isinstance(verifier, HermeticWorkloadProvider) else None
    if capture is not None:
        _register_workload_principal(
            CURRENT_STORE,
            capture,
            role=ControlRole.CAPTURE_UPLOADER,
            audience=LegacySessionAudience.CAPTURE_UPLOAD,
            transport=LegacySessionTransport.CAPTURE_WORKLOAD,
        )
    if worker is not None:
        _register_workload_principal(
            CURRENT_STORE,
            worker,
            role=ControlRole.DETERMINISTIC_WORKER,
            audience=LegacySessionAudience.PROCESSING_COMPLETION,
            transport=LegacySessionTransport.WORKER_WORKLOAD,
        )
    authenticator = HermeticAuthenticator(reviewer)
    mapping = GroupRoleMapping(
        tuple(
            GroupRoleBinding(f"group-{role.value}", (role,))
            for role in sorted(reviewer.roles)
        )
    )
    assert reviewer.scope is not None
    composition = ProviderNeutralSecurityComposition(
        group_role_mapping=mapping,
        subject_scope_policy=SubjectScopePolicy(
            (SubjectScopeBinding(reviewer.subject, reviewer.scope),)
        ),
        authenticator_factory=lambda request: authenticator,
        browser_session_provider_factory=lambda request: HermeticBrowserProvider(reviewer),
        workload_credential_verifier_factory=lambda request: verifier,
        store=CURRENT_STORE,
    )
    app.dependency_overrides[get_provider_neutral_security_composition] = lambda: composition
    app.dependency_overrides[get_runtime_settings] = lambda: Settings.model_construct(
        raw_retention_days=14,
        max_package_size_bytes=512 * 1024 * 1024,
    )


@pytest.fixture(autouse=True)
def hermetic_authorization(tmp_path: Path) -> None:
    global CURRENT_STORE
    CURRENT_STORE = SQLiteLegacySessionStore(tmp_path / "legacy-sessions.sqlite3")
    _install_authorization()
    yield
    app.dependency_overrides.clear()
    CURRENT_STORE = None


def test_register_and_fetch_session() -> None:
    client = TestClient(app)
    session_id = str(uuid4())
    payload = {
        "schema_version": "1.0",
        "session_id": session_id,
        "machine_id": "machine-test-001",
        "project_id": "synthetic",
        "started_at": "2026-08-16T04:00:00Z",
        "ended_at": "2026-08-16T04:01:00Z",
        "active_duration_seconds": 60,
        "approved_process": "acad",
        "package_sha256": "a" * 64,
        "package_size_bytes": 1024,
    }

    created = client.post("/v1/sessions", json=payload)
    assert created.status_code == 201
    assert created.json()["processing_status"] == "registered"

    fetched = client.get(f"/v1/sessions/{session_id}")
    assert fetched.status_code == 200
    assert fetched.json()["machine_id"] == "machine-test-001"


def test_upload_completion_is_verified_before_queueing() -> None:
    class FakeGateway:
        verified = False
        queued = False

        def verify_package_upload(
            self,
            authority: ArtifactAuthority,
            object_key: str,
            registration: SessionRecord,
        ) -> None:
            assert authority == AUTHORITY
            assert object_key.endswith(f"/{'b' * 64}.zip")
            assert registration.package_sha256 == "b" * 64
            assert registration.package_size_bytes == 2048
            self.verified = True

        def enqueue_processing(
            self, authority: ArtifactAuthority, session_id, object_key: str
        ) -> None:
            assert authority == AUTHORITY
            assert self.verified
            self.queued = True

    fake_gateway = FakeGateway()
    app.dependency_overrides[get_artifact_gateway] = lambda: fake_gateway
    try:
        client = TestClient(app)
        session_id = str(uuid4())
        payload = {
            "schema_version": "1.0",
            "session_id": session_id,
            "machine_id": "machine-test-002",
            "project_id": "synthetic",
            "started_at": "2026-08-16T04:00:00Z",
            "ended_at": "2026-08-16T04:01:00Z",
            "active_duration_seconds": 60,
            "approved_process": "acad",
            "package_sha256": "b" * 64,
            "package_size_bytes": 2048,
        }
        assert client.post("/v1/sessions", json=payload).status_code == 201

        object_key = f"sessions/{session_id}/packages/{'b' * 64}.zip"
        completed = client.post(
            f"/v1/sessions/{session_id}/uploaded",
            json={"object_key": object_key},
        )
        assert completed.status_code == 202
        assert completed.json()["processing_status"] == "uploaded"
        assert fake_gateway.queued

        duplicate = client.post(
            f"/v1/sessions/{session_id}/uploaded",
            json={"object_key": object_key},
        )
        assert duplicate.status_code == 202
        assert fake_gateway.queued
    finally:
        app.dependency_overrides.clear()


def test_failed_enqueue_can_be_retried_and_completed() -> None:
    class FlakyGateway:
        verification_count = 0
        queue_attempts = 0
        queued = False

        def verify_package_upload(
            self,
            authority: ArtifactAuthority,
            object_key: str,
            registration: SessionRecord,
        ) -> None:
            assert authority == AUTHORITY
            self.verification_count += 1

        def enqueue_processing(
            self, authority: ArtifactAuthority, session_id, object_key: str
        ) -> None:
            assert authority == AUTHORITY
            self.queue_attempts += 1
            if self.queue_attempts == 1:
                raise ArtifactGatewayUnavailableError("synthetic queue outage")
            self.queued = True

    gateway = FlakyGateway()
    app.dependency_overrides[get_artifact_gateway] = lambda: gateway
    try:
        client = TestClient(app)
        session_id = str(uuid4())
        sha256 = "f" * 64
        registration = _registration_payload(session_id, sha256, 4096)
        assert client.post("/v1/sessions", json=registration).status_code == 201
        object_key = f"sessions/{session_id}/packages/{sha256}.zip"

        first = client.post(
            f"/v1/sessions/{session_id}/uploaded", json={"object_key": object_key}
        )
        assert first.status_code == 503
        assert first.headers["retry-after"] == "1"
        pending = client.get(f"/v1/sessions/{session_id}")
        assert pending.status_code == 200
        assert pending.json()["processing_status"] == "uploaded"

        retry = client.post(
            f"/v1/sessions/{session_id}/uploaded", json={"object_key": object_key}
        )
        assert retry.status_code == 202
        assert retry.json()["processing_status"] == "uploaded"
        assert gateway.verification_count == 2
        assert gateway.queue_attempts == 2
        assert gateway.queued

        completion = _processing_completion(session_id)
        processed = client.post(
            f"/v1/internal/sessions/{session_id}/processing-completion", json=completion
        )
        assert processed.status_code == 200
        assert processed.json()["processing_status"] == "processed"
        assert processed.json()["review_status"] == "pending"

        duplicate = client.post(
            f"/v1/sessions/{session_id}/uploaded", json={"object_key": object_key}
        )
        assert duplicate.status_code == 202
        assert gateway.queue_attempts == 2
    finally:
        app.dependency_overrides.clear()


def test_upload_completion_fails_closed_without_production_queue() -> None:
    gateway = object.__new__(AwsGateway)
    production = Settings(
        environment="production",
        processing_queue_url=None,
    )
    gateway._settings = production
    gateway.verify_package_upload = lambda authority, object_key, registration: None
    gateway.enqueue_processing = lambda authority, session_id, object_key: (_ for _ in ()).throw(
        ArtifactGatewayUnavailableError("synthetic queue unavailable")
    )
    app.dependency_overrides[get_artifact_gateway] = lambda: gateway
    app.dependency_overrides[get_settings] = lambda: production
    try:
        client = TestClient(app)
        session_id = str(uuid4())
        sha256 = "9" * 64
        registration = _registration_payload(session_id, sha256, 4096)
        assert client.post("/v1/sessions", json=registration).status_code == 201
        object_key = f"sessions/{session_id}/packages/{sha256}.zip"

        response = client.post(
            f"/v1/sessions/{session_id}/uploaded",
            json={"object_key": object_key},
        )

        assert response.status_code == 503
        assert response.headers["retry-after"] == "1"
        pending = client.get(f"/v1/sessions/{session_id}")
        assert pending.status_code == 200
        assert pending.json()["processing_status"] == "uploaded"
    finally:
        app.dependency_overrides.clear()


def test_missing_development_queue_remains_a_no_op() -> None:
    gateway = object.__new__(AwsGateway)
    gateway._settings = Settings(environment="development", processing_queue_url=None)

    gateway.enqueue_processing(AUTHORITY, uuid4(), "sessions/synthetic/package.zip")


def test_aws_gateway_requires_exact_authority_before_provider_behavior() -> None:
    gateway = object.__new__(AwsGateway)

    class ExplodingProvider:
        def __getattr__(self, name):
            raise AssertionError(f"provider must not be reached: {name}")

    gateway._settings = ExplodingProvider()
    gateway._presign_s3 = ExplodingProvider()
    gateway._s3 = ExplodingProvider()
    gateway._sqs = ExplodingProvider()
    session_id = uuid4()
    record = SessionRecord.from_create(
        SessionCreate.model_validate(
            _registration_payload(str(session_id), "a" * 64, 1_024)
        ),
        14,
    )
    for rejected in (None, object()):
        with pytest.raises(TypeError, match="exact artifact authority"):
            gateway.create_package_upload(rejected, session_id, "a" * 64, 1_024)
        with pytest.raises(TypeError, match="exact artifact authority"):
            gateway.verify_package_upload(rejected, "unused", record)
        with pytest.raises(TypeError, match="exact artifact authority"):
            gateway.enqueue_processing(rejected, session_id, "unused")


def test_processing_completion_is_idempotent_and_timeline_is_exposed() -> None:
    class FakeGateway:
        queue_count = 0

        def verify_package_upload(
            self,
            authority: ArtifactAuthority,
            object_key: str,
            registration: SessionRecord,
        ) -> None:
            assert authority == AUTHORITY

        def enqueue_processing(
            self, authority: ArtifactAuthority, session_id, object_key: str
        ) -> None:
            assert authority == AUTHORITY
            self.queue_count += 1

    gateway = FakeGateway()
    app.dependency_overrides[get_artifact_gateway] = lambda: gateway
    try:
        client = TestClient(app)
        session_id = str(uuid4())
        sha256 = "c" * 64
        registration = _registration_payload(session_id, sha256, 4096)
        assert client.post("/v1/sessions", json=registration).status_code == 201
        object_key = f"sessions/{session_id}/packages/{sha256}.zip"
        assert client.post(
            f"/v1/sessions/{session_id}/uploaded", json={"object_key": object_key}
        ).status_code == 202

        completion = {
            "schema_version": "1.0",
            "session_id": session_id,
            "event_count": 2,
            "meaningful_event_count": 1,
            "timeline": [
                {
                    "offset_seconds": 1.5,
                    "event_type": "cad_command",
                    "summary": "LINE",
                    "source_event_id": str(uuid4()),
                }
            ],
            "keyframes": [],
            "warnings": [],
            "output_object_key": f"sessions/{session_id}/timeline.json",
        }
        completion["idempotency_key"] = _idempotency_key(completion)
        first = client.post(
            f"/v1/internal/sessions/{session_id}/processing-completion", json=completion
        )
        second = client.post(
            f"/v1/internal/sessions/{session_id}/processing-completion", json=completion
        )
        assert first.status_code == second.status_code == 200
        assert first.json()["processing_status"] == "processed"
        assert first.json()["review_status"] == "pending"
        assert first.json()["processing_completed_at"] == second.json()["processing_completed_at"]
        timeline = client.get(f"/v1/sessions/{session_id}/timeline")
        assert timeline.status_code == 200
        expected_timeline = {
            key: value
            for key, value in completion.items()
            if key not in {"output_object_key", "idempotency_key"}
        }
        assert timeline.json() == expected_timeline
        assert first.json()["schema_version"] == "1.0"
        assert first.json()["processing_output"] == expected_timeline
        assert gateway.queue_count == 1

        changed = {**completion, "event_count": 3}
        changed["idempotency_key"] = _idempotency_key(
            {key: value for key, value in changed.items() if key != "idempotency_key"}
        )
        assert client.post(
            f"/v1/internal/sessions/{session_id}/processing-completion", json=changed
        ).status_code == 409
    finally:
        app.dependency_overrides.clear()


def test_processing_v2_completion_round_trips_and_cross_version_replay_conflicts() -> None:
    class FakeGateway:
        def verify_package_upload(self, authority, object_key, registration) -> None:
            assert authority == AUTHORITY

        def enqueue_processing(self, authority, session_id, object_key) -> None:
            assert authority == AUTHORITY

    app.dependency_overrides[get_artifact_gateway] = lambda: FakeGateway()
    client = TestClient(app)
    session_id = str(uuid4())
    sha256 = "8" * 64
    assert client.post(
        "/v1/sessions", json=_registration_payload(session_id, sha256, 4096)
    ).status_code == 201
    object_key = f"sessions/{session_id}/packages/{sha256}.zip"
    assert client.post(
        f"/v1/sessions/{session_id}/uploaded", json={"object_key": object_key}
    ).status_code == 202

    completion = _processing_completion_v2(session_id)
    first = client.post(
        f"/v1/internal/sessions/{session_id}/processing-completion", json=completion
    )
    replay = client.post(
        f"/v1/internal/sessions/{session_id}/processing-completion", json=completion
    )
    assert first.status_code == replay.status_code == 200
    assert first.json()["schema_version"] == "1.0"
    assert first.json()["processing_output"]["schema_version"] == "2.0"
    assert first.json()["processing_completed_at"] == replay.json()["processing_completed_at"]
    timeline = client.get(f"/v1/sessions/{session_id}/timeline")
    assert timeline.status_code == 200
    assert timeline.json() == {
        key: value
        for key, value in completion.items()
        if key not in {"output_object_key", "idempotency_key"}
    }

    assert client.post(
        f"/v1/internal/sessions/{session_id}/processing-completion",
        json=_processing_completion(session_id),
    ).status_code == 409
    assert client.get(f"/v1/sessions/{session_id}/timeline").json() == timeline.json()


@pytest.mark.parametrize(
    "case",
    [
        "v1_with_operation_segments",
        "missing_operation_segments",
        "unknown_schema_version",
        "noncontiguous_sequence",
        "reversed_bounds",
        "unknown_evidence",
        "duplicate_timeline_id",
        "duplicate_evidence_within_segment",
        "evidence_reused_across_segments",
        "overlapping_segments",
        "nonfinite_bound",
        "bound_above_published_maximum",
        "arbitrary_wrong_output_key",
        "bad_digest",
    ],
)
def test_invalid_processing_completion_is_422_with_exact_session_zero_mutation(
    case: str,
) -> None:
    client = TestClient(app)
    session_id = _prepare_uploaded_http_session(client)
    before = _http_durable_snapshot(session_id)
    completion = _invalid_processing_completion(case, session_id)

    response = client.post(
        f"/v1/internal/sessions/{session_id}/processing-completion", json=completion
    )

    assert response.status_code == 422
    assert _http_durable_snapshot(session_id) == before


@pytest.mark.parametrize(
    "stored_output",
    ['{"schema_version":"3.0"}', '{"event_count":0}', "not-json"],
)
@pytest.mark.parametrize("endpoint", ["session", "list", "timeline"])
def test_malformed_historical_processing_output_is_exact_generic_503(
    stored_output: str, endpoint: str
) -> None:
    client = TestClient(app)
    session_id = str(uuid4())
    assert client.post(
        "/v1/sessions", json=_registration_payload(session_id, "7" * 64, 1024)
    ).status_code == 201
    assert CURRENT_STORE is not None
    with sqlite3.connect(CURRENT_STORE.database_path) as connection:
        connection.execute(
            "update legacy_sessions set processing_output_json = ? where session_id = ?",
            (stored_output, session_id),
        )

    path = {
        "session": f"/v1/sessions/{session_id}",
        "list": "/v1/sessions",
        "timeline": f"/v1/sessions/{session_id}/timeline",
    }[endpoint]
    response = client.get(path)
    assert response.status_code == 503
    assert response.json() == {"detail": "legacy session service unavailable"}


@pytest.mark.parametrize(
    ("ready_state", "stored_output"),
    [
        ("completed", '{"schema_version":"3.0"}'),
        ("uploaded", "not-json"),
    ],
)
def test_processing_completion_fails_closed_on_incompatible_persisted_output(
    ready_state: str, stored_output: str
) -> None:
    class FakeGateway:
        def verify_package_upload(self, authority, object_key, registration) -> None:
            assert authority == AUTHORITY

        def enqueue_processing(self, authority, session_id, object_key) -> None:
            assert authority == AUTHORITY

    app.dependency_overrides[get_artifact_gateway] = lambda: FakeGateway()
    client = TestClient(app)
    session_id = str(uuid4())
    sha256 = "6" * 64
    assert client.post(
        "/v1/sessions", json=_registration_payload(session_id, sha256, 1024)
    ).status_code == 201
    object_key = f"sessions/{session_id}/packages/{sha256}.zip"
    assert client.post(
        f"/v1/sessions/{session_id}/uploaded", json={"object_key": object_key}
    ).status_code == 202
    completion = (
        _processing_completion(session_id)
        if ready_state == "completed"
        else _processing_completion_v2(session_id)
    )
    completion_url = f"/v1/internal/sessions/{session_id}/processing-completion"
    if ready_state == "completed":
        assert client.post(completion_url, json=completion).status_code == 200
    assert CURRENT_STORE is not None
    with sqlite3.connect(CURRENT_STORE.database_path) as connection:
        connection.execute(
            "update legacy_sessions set processing_output_json = ? where session_id = ?",
            (stored_output, session_id),
        )
    before = _http_durable_snapshot(session_id)

    response = client.post(completion_url, json=completion)

    assert response.status_code == 503
    assert response.json() == {"detail": "legacy session service unavailable"}
    assert _http_durable_snapshot(session_id) == before


def test_processing_completion_fails_closed_outside_development() -> None:
    app.dependency_overrides.clear()
    production = Settings(environment="production")
    app.dependency_overrides[get_settings] = lambda: production
    try:
        client = TestClient(app)
        session_id = str(uuid4())
        completion = {
            "schema_version": "1.0",
            "session_id": session_id,
            "event_count": 0,
            "meaningful_event_count": 0,
            "timeline": [],
            "keyframes": [],
            "warnings": [],
            "output_object_key": f"sessions/{session_id}/timeline.json",
        }
        completion["idempotency_key"] = _idempotency_key(completion)
        response = client.post(
            f"/v1/internal/sessions/{session_id}/processing-completion",
            json=completion,
        )
        assert response.status_code == 503
    finally:
        app.dependency_overrides.clear()


def test_control_plane_fails_closed_outside_development() -> None:
    app.dependency_overrides.clear()
    production = Settings(environment="production")
    app.dependency_overrides[get_settings] = lambda: production
    try:
        client = TestClient(app)
        assert client.get("/v1/sessions").status_code == 503
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize("environment", ["development", "test", "production"])
def test_legacy_static_tokens_never_authenticate(environment: str) -> None:
    app.dependency_overrides.clear()
    app.dependency_overrides[get_settings] = lambda: Settings(environment=environment)
    client = TestClient(app)
    session_id = str(uuid4())
    headers = {
        "Authorization": "Bearer synthetic-legacy-static-token",
        "X-Workflow-Worker-Token": "synthetic-legacy-worker-token",
    }

    assert client.get("/v1/sessions", headers=headers).status_code == 503
    assert client.get(f"/v1/sessions/{session_id}", headers=headers).status_code == 503
    assert client.get(
        f"/v1/sessions/{session_id}/timeline", headers=headers
    ).status_code == 503
    assert client.post(
        "/v1/sessions",
        json=_registration_payload(session_id, "1" * 64, 100),
        headers=headers,
    ).status_code == 503
    assert client.post(
        f"/v1/sessions/{session_id}/upload-url", json={}, headers=headers
    ).status_code == 503
    assert client.post(
        f"/v1/sessions/{session_id}/uploaded",
        json={"object_key": "synthetic"},
        headers=headers,
    ).status_code == 503
    assert client.post(
        f"/v1/internal/sessions/{session_id}/processing-completion",
        json=_processing_completion(session_id),
        headers=headers,
    ).status_code == 503


def test_browser_and_workload_dependencies_are_transport_separated() -> None:
    client = TestClient(app)
    _install_authorization(workload_provider=object())
    assert client.post(
        "/v1/sessions", json=_registration_payload(str(uuid4()), "2" * 64, 100)
    ).status_code == 503

    app.dependency_overrides.clear()
    assert client.get("/v1/sessions").status_code == 503


def test_provider_failure_and_invalid_proof_precede_repository_and_gateway() -> None:
    class CountingGateway:
        calls = 0

        def create_package_upload(self, *args, **kwargs):
            self.calls += 1
            raise AssertionError("gateway must not be reached")

    class FailingProvider:
        def get_workload_context(self, **kwargs):
            raise RuntimeError("synthetic provider outage")

    assert CURRENT_STORE is not None
    store_calls = 0

    async def forbidden_create(*args, **kwargs):
        nonlocal store_calls
        store_calls += 1
        raise AssertionError("store must not be reached")

    CURRENT_STORE.create = forbidden_create  # type: ignore[method-assign]
    gateway = CountingGateway()
    app.dependency_overrides[get_artifact_gateway] = lambda: gateway
    _install_authorization(workload_provider=FailingProvider())
    client = TestClient(app)
    payload = _registration_payload(str(uuid4()), "3" * 64, 100)

    unavailable = client.post("/v1/sessions", json=payload)
    assert unavailable.status_code == 503
    assert store_calls == gateway.calls == 0

    invalid = HermeticWorkloadProvider(
        mutate=lambda context: dataclasses.replace(context, body_sha256="0" * 64)
    )
    _install_authorization(workload_provider=invalid)
    rejected = client.post("/v1/sessions", json=payload)
    assert rejected.status_code == 401
    assert rejected.json() == {"detail": "request authorization rejected"}
    assert store_calls == gateway.calls == 0


def test_scope_and_owner_isolation_is_generic_and_makes_zero_gateway_calls() -> None:
    class CountingGateway:
        presign_calls = 0
        verify_calls = 0
        queue_calls = 0

        def create_package_upload(self, *args, **kwargs):
            self.presign_calls += 1
            return "unused", "unused", {}

        def verify_package_upload(self, *args, **kwargs):
            self.verify_calls += 1

        def enqueue_processing(self, *args, **kwargs):
            self.queue_calls += 1

    gateway = CountingGateway()
    app.dependency_overrides[get_artifact_gateway] = lambda: gateway
    owner = _principal(
        ControlRole.CAPTURE_UPLOADER, subject="capture-owner-synthetic"
    )
    _install_authorization(capture_principal=owner)
    client = TestClient(app)
    session_id = str(uuid4())
    payload = _registration_payload(session_id, "4" * 64, 100)
    assert client.post("/v1/sessions", json=payload).status_code == 201

    other_owner = _principal(
        ControlRole.CAPTURE_UPLOADER, subject="capture-other-synthetic"
    )
    _install_authorization(capture_principal=other_owner)
    duplicate = client.post("/v1/sessions", json=payload)
    assert duplicate.status_code == 404
    assert duplicate.json() == {"detail": "session unavailable"}
    assert client.post(f"/v1/sessions/{session_id}/upload-url").status_code == 404
    assert client.post(
        f"/v1/sessions/{session_id}/uploaded",
        json={"object_key": f"sessions/{session_id}/packages/{'4' * 64}.zip"},
    ).status_code == 404
    assert gateway.presign_calls == gateway.verify_calls == gateway.queue_calls == 0

    other_reviewer = _principal(ControlRole.REVIEWER, scope=OTHER_SCOPE)
    other_worker = _principal(ControlRole.DETERMINISTIC_WORKER, scope=OTHER_SCOPE)
    _install_authorization(
        reviewer_principal=other_reviewer,
        worker_principal=other_worker,
    )
    assert client.get("/v1/sessions").json() == {"items": [], "count": 0}
    assert client.get(f"/v1/sessions/{session_id}").status_code == 404
    assert client.get(f"/v1/sessions/{session_id}/timeline").status_code == 404
    assert client.post(
        f"/v1/internal/sessions/{session_id}/processing-completion",
        json=_processing_completion(session_id),
    ).status_code == 404
    assert gateway.presign_calls == gateway.verify_calls == gateway.queue_calls == 0


def test_exact_role_matrix_rejects_cross_role_operations() -> None:
    client = TestClient(app)
    session_id = str(uuid4())
    payload = _registration_payload(session_id, "5" * 64, 100)

    reviewer = _principal(ControlRole.REVIEWER)
    _install_authorization(
        capture_principal=reviewer,
        worker_principal=reviewer,
        reviewer_principal=reviewer,
    )
    assert client.get("/v1/sessions").status_code == 200
    assert client.post("/v1/sessions", json=payload).status_code == 401
    assert client.post(f"/v1/sessions/{session_id}/upload-url").status_code == 401
    assert client.post(
        f"/v1/sessions/{session_id}/uploaded", json={"object_key": "synthetic"}
    ).status_code == 401
    assert client.post(
        f"/v1/internal/sessions/{session_id}/processing-completion",
        json=_processing_completion(session_id),
    ).status_code == 401

    capture = _principal(ControlRole.CAPTURE_UPLOADER)
    _install_authorization(
        capture_principal=capture,
        worker_principal=capture,
        reviewer_principal=capture,
    )
    assert client.get("/v1/sessions").status_code == 401
    assert client.get(f"/v1/sessions/{session_id}").status_code == 401
    assert client.get(f"/v1/sessions/{session_id}/timeline").status_code == 401
    assert client.post(
        f"/v1/internal/sessions/{session_id}/processing-completion",
        json=_processing_completion(session_id),
    ).status_code == 401

    worker = _principal(ControlRole.DETERMINISTIC_WORKER)
    _install_authorization(
        capture_principal=worker,
        worker_principal=worker,
        reviewer_principal=worker,
    )
    assert client.post("/v1/sessions", json=payload).status_code == 401
    assert client.post(f"/v1/sessions/{session_id}/upload-url").status_code == 401
    assert client.post(
        f"/v1/sessions/{session_id}/uploaded", json={"object_key": "synthetic"}
    ).status_code == 401
    assert client.get("/v1/sessions").status_code == 401


def test_security_caps_are_immutable() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Settings(max_package_size_bytes=512 * 1024 * 1024 + 1)
    with pytest.raises(ValidationError):
        Settings(presigned_url_ttl_seconds=901)


def test_s3_presign_uses_external_endpoint_and_signed_integrity_headers() -> None:
    class FakeClient:
        def __init__(self, endpoint_url: str | None) -> None:
            self.endpoint_url = endpoint_url
            self.presign_params = None

        def generate_presigned_url(self, operation, Params, ExpiresIn):
            self.presign_params = Params
            return f"{self.endpoint_url}/signed"

    clients: list[FakeClient] = []

    def fake_client(service, **options):
        client = FakeClient(options.get("endpoint_url"))
        clients.append(client)
        return client

    with patch("workflow_api.aws_clients.boto3.client", side_effect=fake_client):
        gateway = AwsGateway(
            Settings(
                aws_endpoint_url="http://localstack:4566",
                aws_s3_presigned_endpoint_url="http://localhost:4566",
            )
        )
    session_id = uuid4()
    sha256 = "d" * 64
    object_key, url, headers = gateway.create_package_upload(
        AUTHORITY, session_id, sha256, 1234
    )
    assert clients[0].endpoint_url == "http://localstack:4566"
    assert clients[2].endpoint_url == "http://localhost:4566"
    assert url.startswith("http://localhost:4566/")
    assert object_key == f"sessions/{session_id}/packages/{sha256}.zip"
    assert clients[2].presign_params["ContentLength"] == 1234
    assert clients[2].presign_params["IfNoneMatch"] == "*"
    assert headers["Content-Length"] == "1234"
    assert headers["x-amz-checksum-sha256"] == clients[2].presign_params["ChecksumSHA256"]


def test_sqs_client_failure_is_exposed_as_retryable_queue_error() -> None:
    class FailingSqs:
        def send_message(self, **kwargs) -> None:
            raise ClientError(
                {"Error": {"Code": "ServiceUnavailable", "Message": "synthetic outage"}},
                "SendMessage",
            )

    gateway = object.__new__(AwsGateway)
    gateway._settings = Settings(processing_queue_url="https://sqs.invalid/queue")
    gateway._sqs = FailingSqs()

    with pytest.raises(ProcessingQueueError, match="temporarily unavailable"):
        gateway.enqueue_processing(
            AUTHORITY, uuid4(), "sessions/synthetic/package.zip"
        )


def test_verification_streams_hash_and_binds_metadata_identity() -> None:
    session_id = uuid4()
    metadata = _package_metadata(session_id)
    package = _zip_with_metadata(metadata)
    sha256 = hashlib.sha256(package).hexdigest()
    record = SessionRecord.from_create(
        SessionCreate.model_validate(_registration_payload(str(session_id), sha256, len(package))),
        14,
    )

    class FakeBody(io.BytesIO):
        pass

    class FakeS3:
        def head_object(self, **kwargs):
            assert kwargs["ChecksumMode"] == "ENABLED"
            return {
                "Metadata": {"sha256": sha256},
                "ContentLength": len(package),
                "ChecksumSHA256": AwsGateway.checksum_sha256_header(sha256),
                "ETag": '"synthetic-etag"',
            }

        def get_object(self, **kwargs):
            assert kwargs["IfMatch"] == '"synthetic-etag"'
            return {"Body": FakeBody(package)}

    gateway = object.__new__(AwsGateway)
    gateway._settings = Settings(upload_stream_chunk_bytes=17, upload_spool_memory_bytes=32)
    gateway._s3 = FakeS3()
    gateway.verify_package_upload(
        AUTHORITY, f"sessions/{session_id}/packages/{sha256}.zip", record
    )

    wrong_metadata = {**metadata, "machine_id": "different-machine"}
    substituted = _zip_with_metadata(wrong_metadata)
    substituted_sha = hashlib.sha256(substituted).hexdigest()
    substituted_record = SessionRecord.from_create(
        SessionCreate.model_validate(
            _registration_payload(str(session_id), substituted_sha, len(substituted))
        ),
        14,
    )
    package = substituted
    sha256 = substituted_sha
    with pytest.raises(ValueError, match="metadata.json does not match registration"):
        gateway.verify_package_upload(
            AUTHORITY,
            f"sessions/{session_id}/packages/{substituted_sha}.zip",
            substituted_record,
        )


def test_package_cap_is_enforced_before_s3_read() -> None:
    record = SessionRecord.from_create(
        SessionCreate.model_validate(_registration_payload(str(uuid4()), "e" * 64, 101)),
        14,
    )
    gateway = object.__new__(AwsGateway)
    gateway._settings = Settings(max_package_size_bytes=100)
    gateway._s3 = object()
    with pytest.raises(ValueError, match="compressed size"):
        gateway.verify_package_upload(AUTHORITY, "unused", record)


def _registration_payload(session_id: str, sha256: str, size_bytes: int) -> dict:
    return {
        "schema_version": "1.0",
        "session_id": session_id,
        "machine_id": "machine-test-002",
        "project_id": "synthetic",
        "started_at": "2026-08-16T04:00:00Z",
        "ended_at": "2026-08-16T04:01:00Z",
        "active_duration_seconds": 60,
        "approved_process": "acad",
        "package_sha256": sha256,
        "package_size_bytes": size_bytes,
    }


def _http_durable_snapshot(
    session_id: str,
) -> tuple[tuple[object, ...], tuple[tuple[object, ...], ...], bytes | None]:
    assert CURRENT_STORE is not None
    with sqlite3.connect(CURRENT_STORE.database_path) as connection:
        session = connection.execute(
            "select * from legacy_sessions where session_id = ?", (session_id,)
        ).fetchone()
        events = connection.execute(
            "select * from legacy_session_events where session_id = ? order by sequence",
            (session_id,),
        ).fetchall()
        output_bytes_row = connection.execute(
            "select cast(processing_output_json as blob) from legacy_sessions "
            "where session_id = ?",
            (session_id,),
        ).fetchone()
    assert session is not None
    assert output_bytes_row is not None
    return tuple(session), tuple(tuple(event) for event in events), output_bytes_row[0]


def _prepare_uploaded_http_session(client: TestClient) -> str:
    class FakeGateway:
        def verify_package_upload(self, authority, object_key, registration) -> None:
            assert authority == AUTHORITY

        def enqueue_processing(self, authority, session_id, object_key) -> None:
            assert authority == AUTHORITY

    app.dependency_overrides[get_artifact_gateway] = lambda: FakeGateway()
    session_id = str(uuid4())
    sha256 = "5" * 64
    assert client.post(
        "/v1/sessions", json=_registration_payload(session_id, sha256, 1024)
    ).status_code == 201
    object_key = f"sessions/{session_id}/packages/{sha256}.zip"
    assert client.post(
        f"/v1/sessions/{session_id}/uploaded", json={"object_key": object_key}
    ).status_code == 202
    return session_id


def _invalid_processing_completion(case: str, session_id: str) -> dict:
    if case == "v1_with_operation_segments":
        completion = _processing_completion(session_id)
        completion["operation_segments"] = []
    else:
        completion = _processing_completion_v2(session_id)
        segment = completion["operation_segments"][0]
        source_event_id = completion["timeline"][0]["source_event_id"]
        if case == "missing_operation_segments":
            completion.pop("operation_segments")
        elif case == "unknown_schema_version":
            completion["schema_version"] = "3.0"
        elif case == "noncontiguous_sequence":
            segment["sequence"] = 2
        elif case == "reversed_bounds":
            segment["start_offset_seconds"] = 2.0
        elif case == "unknown_evidence":
            segment["source_event_ids"] = [str(uuid4())]
        elif case == "duplicate_timeline_id":
            completion["timeline"].append(dict(completion["timeline"][0]))
        elif case == "duplicate_evidence_within_segment":
            segment["source_event_ids"] = [source_event_id, source_event_id]
        elif case == "evidence_reused_across_segments":
            completion["operation_segments"].append(
                {**segment, "sequence": 2, "source_event_ids": [source_event_id]}
            )
        elif case == "overlapping_segments":
            second_source_event_id = str(uuid4())
            completion["timeline"].append(
                {
                    "offset_seconds": 1.5,
                    "event_type": "cad_command",
                    "summary": "Synthetic overlapping command",
                    "source_event_id": second_source_event_id,
                }
            )
            completion["operation_segments"].append(
                {
                    **segment,
                    "sequence": 2,
                    "start_offset_seconds": 0.5,
                    "end_offset_seconds": 1.5,
                    "source_event_ids": [second_source_event_id],
                }
            )
        elif case == "nonfinite_bound":
            segment["start_offset_seconds"] = "NaN"
        elif case == "bound_above_published_maximum":
            segment["end_offset_seconds"] = 604801.0
        elif case == "arbitrary_wrong_output_key":
            completion["output_object_key"] = "arbitrary/wrong-output.json"
        elif case == "bad_digest":
            completion["idempotency_key"] = "0" * 64
            return completion
        else:
            raise AssertionError(f"unknown invalid completion case: {case}")
    completion["idempotency_key"] = _idempotency_key(
        {key: value for key, value in completion.items() if key != "idempotency_key"}
    )
    return completion


def _package_metadata(session_id) -> dict:
    return {
        "schema_version": "1.0",
        "session_id": str(session_id),
        "machine_id": "machine-test-002",
        "project_id": "synthetic",
        "started_at": "2026-08-16T04:00:00Z",
        "ended_at": "2026-08-16T04:01:00Z",
        "active_duration_seconds": 60,
        "approved_process": "acad",
        "drawing_files": [],
        "input_artifacts": [],
        "output_artifacts": [],
        "recording": None,
        "cad_events": [],
        "idle_intervals": [],
        "processing_status": "local",
        "review_status": "not_ready",
        "labels": [],
        "skills": [],
        "raw_expires_at": None,
    }


def _zip_with_metadata(metadata: dict) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("metadata.json", json.dumps(metadata))
    return output.getvalue()


def _idempotency_key(payload: dict) -> str:
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _processing_completion(session_id: str) -> dict:
    completion = {
        "schema_version": "1.0",
        "session_id": session_id,
        "event_count": 0,
        "meaningful_event_count": 0,
        "timeline": [],
        "keyframes": [],
        "warnings": [],
        "output_object_key": f"sessions/{session_id}/timeline.json",
    }
    completion["idempotency_key"] = _idempotency_key(completion)
    return completion


def _processing_completion_v2(session_id: str) -> dict:
    source_event_id = str(uuid4())
    completion = {
        "schema_version": "2.0",
        "session_id": session_id,
        "event_count": 1,
        "meaningful_event_count": 1,
        "timeline": [
            {
                "offset_seconds": 1.0,
                "event_type": "cad_command",
                "summary": "Synthetic LINE command",
                "source_event_id": source_event_id,
            }
        ],
        "operation_segments": [
            {
                "sequence": 1,
                "start_offset_seconds": 1.0,
                "end_offset_seconds": 1.0,
                "command_names": ["LINE"],
                "drawing_ref": "synthetic-drawing-001",
                "summary": "Observed a synthetic line operation",
                "source_event_ids": [source_event_id],
            }
        ],
        "keyframes": [],
        "warnings": [],
        "output_object_key": f"sessions/{session_id}/timeline-v2.json",
    }
    completion["idempotency_key"] = _idempotency_key(completion)
    return completion
