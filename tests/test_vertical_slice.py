import hashlib
import io
import json
import sqlite3
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

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
from workflow_worker.main import process_message, process_message_v2


def _package(session_id) -> bytes:
    event_id = uuid4()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "metadata.json",
            json.dumps({"schema_version": "1.0", "session_id": str(session_id)}),
        )
        archive.writestr(
            "events.jsonl",
            json.dumps(
                {
                    "event_id": str(event_id),
                    "occurred_at": "2026-08-16T04:01:00Z",
                    "event_type": "session_ended",
                    "source": "agent",
                }
            ),
        )
    return output.getvalue()


def _package_v2(session_id) -> bytes:
    output = io.BytesIO()
    events = [
        {
            "event_id": str(uuid4()),
            "occurred_at": "2026-08-16T04:00:00Z",
            "event_type": "session_started",
            "source": "agent",
        },
        {
            "event_id": str(uuid4()),
            "occurred_at": "2026-08-16T04:00:30Z",
            "event_type": "cad_command",
            "source": "autocad",
            "command_name": "LINE",
            "drawing_ref": "synthetic-drawing-001",
        },
        {
            "event_id": str(uuid4()),
            "occurred_at": "2026-08-16T04:01:00Z",
            "event_type": "session_ended",
            "source": "agent",
        },
    ]
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "metadata.json",
            json.dumps({"schema_version": "1.0", "session_id": str(session_id)}),
        )
        archive.writestr("events.jsonl", "\n".join(json.dumps(event) for event in events))
    return output.getvalue()


def test_synthetic_upload_queue_worker_api_timeline_vertical_slice(
    monkeypatch,
    tmp_path: Path,
) -> None:
    session_id = uuid4()
    package = _package(session_id)
    package_sha256 = hashlib.sha256(package).hexdigest()
    object_key = f"sessions/{session_id}/packages/{package_sha256}.zip"
    queued_jobs: list[str] = []

    class ApiGateway:
        def verify_package_upload(self, authority, key, registration) -> None:
            assert authority == ArtifactAuthority(scope, capture.subject)
            assert key == (
                f"sessions/{registration.session_id}/packages/"
                f"{registration.package_sha256}.zip"
            )

        def enqueue_processing(self, authority, queued_session_id, key) -> None:
            assert authority == ArtifactAuthority(scope, capture.subject)
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
            assert kwargs["Key"] == f"sessions/{session_id}/timeline.json"
            self.timeline_artifact = kwargs["Body"]

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
            "schema_version": "1.0",
            "session_id": str(session_id),
            "machine_id": "machine-synthetic",
            "project_id": "synthetic",
            "started_at": "2026-08-16T04:00:00Z",
            "ended_at": "2026-08-16T04:01:00Z",
            "active_duration_seconds": 60,
            "approved_process": "acad",
            "package_sha256": package_sha256,
            "package_size_bytes": len(package),
        }
        assert client.post("/v1/sessions", json=registration).status_code == 201
        uploaded = client.post(
            f"/v1/sessions/{session_id}/uploaded",
            json={"object_key": object_key},
        )
        assert uploaded.status_code == 202
        assert len(queued_jobs) == 1

        def complete_api(completion) -> None:
            response = client.post(
                f"/v1/internal/sessions/{session_id}/processing-completion",
                json=completion.model_dump(mode="json"),
            )
            assert response.status_code == 200

        completion = process_message(
            queued_jobs[0],
            s3=worker_s3,
            completion_callback=complete_api,
        )
        assert worker_s3.timeline_artifact is not None
        session = client.get(f"/v1/sessions/{session_id}")
        assert session.status_code == 200
        assert session.json()["processing_status"] == "processed"
        timeline = client.get(f"/v1/sessions/{session_id}/timeline")
        assert timeline.status_code == 200
        expected_result = completion.model_dump(
            mode="json",
            exclude={"output_object_key", "idempotency_key"},
        )
        assert timeline.json() == expected_result
        assert timeline.json()["timeline"][0]["summary"] == "Approved CAD session ended"

        v2_session_id = uuid4()
        v2_package = _package_v2(v2_session_id)
        v2_package_sha256 = hashlib.sha256(v2_package).hexdigest()
        v2_object_key = (
            f"sessions/{v2_session_id}/packages/{v2_package_sha256}.zip"
        )
        v2_registration = {
            **registration,
            "session_id": str(v2_session_id),
            "package_sha256": v2_package_sha256,
            "package_size_bytes": len(v2_package),
        }
        assert client.post("/v1/sessions", json=v2_registration).status_code == 201
        assert client.post(
            f"/v1/sessions/{v2_session_id}/uploaded",
            json={"object_key": v2_object_key},
        ).status_code == 202
        assert len(queued_jobs) == 2

        class V2WorkerS3:
            timeline_artifact: bytes | None = None

            def head_object(self, **kwargs):
                assert kwargs == {"Bucket": "raw", "Key": v2_object_key}
                return {"ContentLength": len(v2_package)}

            def get_object(self, **kwargs):
                assert kwargs == {"Bucket": "raw", "Key": v2_object_key}
                return {
                    "ContentLength": len(v2_package),
                    "Body": io.BytesIO(v2_package),
                }

            def put_object(self, **kwargs):
                assert kwargs["Bucket"] == "processed"
                assert kwargs["Key"] == f"sessions/{v2_session_id}/timeline-v2.json"
                self.timeline_artifact = kwargs["Body"]

        v2_s3 = V2WorkerS3()

        def complete_v2_api(v2_completion) -> None:
            assert v2_s3.timeline_artifact is not None
            response = client.post(
                f"/v1/internal/sessions/{v2_session_id}/processing-completion",
                json=v2_completion.model_dump(mode="json"),
            )
            assert response.status_code == 200

        v2_completion = process_message_v2(
            queued_jobs[1],
            s3=v2_s3,
            completion_callback=complete_v2_api,
        )
        assert v2_s3.timeline_artifact is not None
        assert v2_completion.schema_version == "2.0"
        assert len(v2_completion.operation_segments) == 1

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
        restarted_timeline = client.get(f"/v1/sessions/{v2_session_id}/timeline")
        assert restarted_timeline.status_code == 200
        assert restarted_timeline.json() == v2_completion.as_result().model_dump(mode="json")

        with sqlite3.connect(restarted_store.database_path) as connection:
            before_conflict = connection.execute(
                "select processing_output_json, processing_completion_id, state_version "
                "from legacy_sessions where session_id = ?",
                (str(v2_session_id),),
            ).fetchone()
            before_events = connection.execute(
                "select count(*) from legacy_session_events where session_id = ?",
                (str(v2_session_id),),
            ).fetchone()
        v1_conflict = {
            "schema_version": "1.0",
            "session_id": str(v2_session_id),
            "event_count": 0,
            "meaningful_event_count": 0,
            "timeline": [],
            "keyframes": [],
            "warnings": [],
            "output_object_key": f"sessions/{v2_session_id}/timeline.json",
        }
        v1_conflict["idempotency_key"] = hashlib.sha256(
            json.dumps(
                v1_conflict,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()
        conflict = client.post(
            f"/v1/internal/sessions/{v2_session_id}/processing-completion",
            json=v1_conflict,
        )
        assert conflict.status_code == 409
        with sqlite3.connect(restarted_store.database_path) as connection:
            after_conflict = connection.execute(
                "select processing_output_json, processing_completion_id, state_version "
                "from legacy_sessions where session_id = ?",
                (str(v2_session_id),),
            ).fetchone()
            after_events = connection.execute(
                "select count(*) from legacy_session_events where session_id = ?",
                (str(v2_session_id),),
            ).fetchone()
        assert after_conflict == before_conflict
        assert after_events == before_events
        assert client.get(f"/v1/sessions/{v2_session_id}/timeline").json() == (
            restarted_timeline.json()
        )
    finally:
        app.dependency_overrides.clear()
