import hashlib
import io
import json
import sqlite3
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from fastapi.testclient import TestClient
from workflow_api.artifact_gateway import ArtifactAuthority
from workflow_api.config import Settings
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
from workflow_api.legacy_session_store import SQLiteLegacySessionStore
from workflow_api.main import app
from workflow_api.session_security import SessionSecurityContext, SessionTransport
from workflow_worker.main import process_message_v2

PROJECT_ROOT = Path(__file__).parents[1]
SESSION_FIXTURE = PROJECT_ROOT / "contracts/examples/session.json"
RESULT_FIXTURE = PROJECT_ROOT / "contracts/examples/processing-result-v2.json"
COMPLETION_FIXTURE = PROJECT_ROOT / "contracts/examples/processing-completion-v2.json"


def _canonical_package() -> tuple[dict[str, object], bytes]:
    session = json.loads(SESSION_FIXTURE.read_text())
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("metadata.json", SESSION_FIXTURE.read_bytes())
        events = "\n".join(
            json.dumps(event, separators=(",", ":"))
            for event in session["cad_events"]
        )
        archive.writestr("events.jsonl", f"{events}\n".encode())
    return session, output.getvalue()


def test_canonical_synthetic_package_reaches_v2_timeline_and_completion(
    monkeypatch,
    tmp_path: Path,
) -> None:
    session_fixture, package = _canonical_package()
    session_id = UUID(session_fixture["session_id"])
    package_sha256 = hashlib.sha256(package).hexdigest()
    object_key = f"sessions/{session_id}/packages/{package_sha256}.zip"
    expected_result = json.loads(RESULT_FIXTURE.read_text())
    expected_completion = json.loads(COMPLETION_FIXTURE.read_text())
    queued_jobs: list[str] = []

    scope = TenantWorkspaceScope("tenant-synthetic", "workspace-synthetic")
    capture = AuthenticatedPrincipal(
        "capture-synthetic",
        frozenset({ControlRole.CAPTURE_UPLOADER}),
        scope,
    )
    worker = AuthenticatedPrincipal(
        "worker-synthetic",
        frozenset({ControlRole.DETERMINISTIC_WORKER}),
        scope,
    )
    reviewer = AuthenticatedPrincipal(
        "reviewer-synthetic",
        frozenset({ControlRole.REVIEWER}),
        scope,
    )

    class ApiGateway:
        def verify_package_upload(self, authority, key, registration) -> None:
            assert authority == ArtifactAuthority(scope, capture.subject)
            assert key == object_key
            assert registration.session_id == session_id

        def enqueue_processing(self, authority, queued_session_id, key) -> None:
            assert authority == ArtifactAuthority(scope, capture.subject)
            assert queued_session_id == session_id
            assert key == object_key
            queued_jobs.append(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "session_id": str(queued_session_id),
                        "object_key": key,
                    }
                )
            )

    class WorkerS3:
        def __init__(self) -> None:
            self.timeline_artifact: bytes | None = None

        def head_object(self, **kwargs):
            assert kwargs == {"Bucket": "raw", "Key": object_key}
            return {"ContentLength": len(package)}

        def get_object(self, **kwargs):
            assert kwargs == {"Bucket": "raw", "Key": object_key}
            return {"ContentLength": len(package), "Body": io.BytesIO(package)}

        def put_object(self, **kwargs):
            assert kwargs["Bucket"] == "processed"
            assert kwargs["Key"] == f"sessions/{session_id}/timeline-v2.json"
            self.timeline_artifact = kwargs["Body"]

    class WorkloadProvider:
        def get_workload_context(self, *, method, path, body_sha256, headers):
            internal = path.startswith("/v1/internal/")
            now = datetime.now(UTC)
            return LegacyWorkloadContext(
                principal=worker if internal else capture,
                audience=(
                    LegacySessionAudience.PROCESSING_COMPLETION
                    if internal
                    else LegacySessionAudience.CAPTURE_UPLOAD
                ),
                transport=(
                    LegacySessionTransport.WORKER_WORKLOAD
                    if internal
                    else LegacySessionTransport.CAPTURE_WORKLOAD
                ),
                method=method,
                path=path,
                body_sha256=body_sha256,
                proof_identifier_digest=hashlib.sha256(
                    f"{path}:{body_sha256}".encode()
                ).hexdigest(),
                issued_at=now - timedelta(seconds=1),
                expires_at=now + timedelta(minutes=1),
                generation=1,
                active_generation=1,
                revoked=False,
                replay_decision=ReplayDecision.ACCEPT,
            )

    class BrowserProvider:
        def get_session_security_context(self):
            now = datetime.now(UTC)
            return SessionSecurityContext(
                principal=reviewer,
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

    class ReviewerAuthenticator:
        def authenticate(self) -> VerifiedIdentityEvidence:
            return VerifiedIdentityEvidence(
                reviewer.subject,
                ("reviewers",),
                AuthenticationContext(
                    AuthenticationAssurance.MULTI_FACTOR,
                    (AuthenticationMethod.PASSWORD, AuthenticationMethod.TOTP),
                ),
                scope,
            )

    store = SQLiteLegacySessionStore(tmp_path / "vertical-slice.sqlite3")
    store.register_workload_principal(
        principal_subject=capture.subject,
        scope=scope,
        audience=LegacySessionAudience.CAPTURE_UPLOAD,
        role=ControlRole.CAPTURE_UPLOADER,
        transport=LegacySessionTransport.CAPTURE_WORKLOAD,
    )
    store.register_workload_principal(
        principal_subject=worker.subject,
        scope=scope,
        audience=LegacySessionAudience.PROCESSING_COMPLETION,
        role=ControlRole.DETERMINISTIC_WORKER,
        transport=LegacySessionTransport.WORKER_WORKLOAD,
    )
    composition = ProviderNeutralSecurityComposition(
        group_role_mapping=GroupRoleMapping(
            (GroupRoleBinding("reviewers", (ControlRole.REVIEWER,)),)
        ),
        subject_scope_policy=SubjectScopePolicy(
            (SubjectScopeBinding(reviewer.subject, scope),)
        ),
        authenticator_factory=lambda request: ReviewerAuthenticator(),
        browser_session_provider_factory=lambda request: BrowserProvider(),
        workload_credential_verifier_factory=lambda request: WorkloadProvider(),
        store=store,
    )

    app.dependency_overrides[get_artifact_gateway] = ApiGateway
    app.dependency_overrides[get_provider_neutral_security_composition] = lambda: composition
    app.dependency_overrides[get_runtime_settings] = lambda: Settings.model_construct(
        raw_retention_days=14,
        max_package_size_bytes=512 * 1024 * 1024,
    )
    monkeypatch.setenv("RAW_BUCKET", "raw")
    monkeypatch.setenv("PROCESSED_BUCKET", "processed")
    client = TestClient(app)
    worker_s3 = WorkerS3()
    try:
        registration = {
            **session_fixture,
            "package_sha256": package_sha256,
            "package_size_bytes": len(package),
        }
        assert client.post("/v1/sessions", json=registration).status_code == 201
        uploaded = client.post(
            f"/v1/sessions/{session_id}/uploaded",
            json={"object_key": object_key},
        )
        assert uploaded.status_code == 202, uploaded.text
        assert queued_jobs == [
            json.dumps(
                {
                    "schema_version": "1.0",
                        "session_id": str(session_id),
                    "object_key": object_key,
                }
            )
        ]

        def complete_api(completion) -> None:
            response = client.post(
                f"/v1/internal/sessions/{session_id}/processing-completion",
                json=completion.model_dump(mode="json"),
            )
            assert response.status_code == 200

        completion = process_message_v2(
            queued_jobs[0],
            s3=worker_s3,
            completion_callback=complete_api,
        )
        assert worker_s3.timeline_artifact is not None
        assert json.loads(worker_s3.timeline_artifact) == expected_result
        assert completion.model_dump(mode="json") == expected_completion

        session = client.get(f"/v1/sessions/{session_id}")
        assert session.status_code == 200
        assert session.json()["processing_status"] == "processed"
        timeline = client.get(f"/v1/sessions/{session_id}/timeline")
        assert timeline.status_code == 200
        assert timeline.json() == expected_result

        restarted_store = SQLiteLegacySessionStore(tmp_path / "vertical-slice.sqlite3")
        restarted_composition = ProviderNeutralSecurityComposition(
            group_role_mapping=GroupRoleMapping(
                (GroupRoleBinding("reviewers", (ControlRole.REVIEWER,)),)
            ),
            subject_scope_policy=SubjectScopePolicy(
                (SubjectScopeBinding(reviewer.subject, scope),)
            ),
            authenticator_factory=lambda request: ReviewerAuthenticator(),
            browser_session_provider_factory=lambda request: BrowserProvider(),
            workload_credential_verifier_factory=lambda request: WorkloadProvider(),
            store=restarted_store,
        )
        app.dependency_overrides[get_provider_neutral_security_composition] = (
            lambda: restarted_composition
        )
        durable_timeline = client.get(f"/v1/sessions/{session_id}/timeline")
        assert durable_timeline.status_code == 200
        assert durable_timeline.json() == expected_result
        with sqlite3.connect(restarted_store.database_path) as connection:
            state = connection.execute(
                "select processing_output_json from legacy_sessions where session_id = ?",
                (str(session_id),),
            ).fetchone()
        assert state is not None
        assert json.loads(state[0]) == expected_result
    finally:
        app.dependency_overrides.clear()
