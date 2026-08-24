from __future__ import annotations

import base64
import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from fastapi.testclient import TestClient
from workflow_api.artifact_gateway import ArtifactAuthority
from workflow_api.config import Settings
from workflow_api.control_auth import AuthenticatedPrincipal, ControlRole
from workflow_api.control_scope import TenantWorkspaceScope
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
from workflow_api.in_process_runtime import create_in_process_no_network_bundle
from workflow_api.legacy_session_security import (
    LegacySessionAudience,
    LegacySessionTransport,
    LegacyWorkloadContext,
    ReplayDecision,
)
from workflow_api.main import create_app
from workflow_api.session_security import SessionSecurityContext, SessionTransport
from workflow_worker.main import process_message_v2

PROJECT_ROOT = Path(__file__).parents[1]
SESSION_FIXTURE = PROJECT_ROOT / "contracts/examples/session.json"
RESULT_FIXTURE = PROJECT_ROOT / "contracts/examples/processing-result-v2.json"
COMPLETION_FIXTURE = PROJECT_ROOT / "contracts/examples/processing-completion-v2.json"


def _canonical_package() -> tuple[dict[str, object], bytes]:
    session = json.loads(SESSION_FIXTURE.read_text(encoding="utf-8"))
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("metadata.json", SESSION_FIXTURE.read_bytes())
        events = "\n".join(
            json.dumps(event, separators=(",", ":"))
            for event in session["cad_events"]
        )
        archive.writestr("events.jsonl", f"{events}\n".encode())
    return session, output.getvalue()


def _synthetic_settings() -> Settings:
    return Settings(
        _env_file=None,
        environment="synthetic",
        log_level="INFO",
        cors_origins="https://review.synthetic.example",
        aws_region="region.synthetic.example",
        aws_endpoint_url=None,
        aws_s3_presigned_endpoint_url=None,
        raw_bucket="raw.synthetic.example",
        processed_bucket="processed.synthetic.example",
        processing_queue_url=None,
        raw_retention_days=14,
        presigned_url_ttl_seconds=900,
        max_package_size_bytes=512 * 1024 * 1024,
        max_metadata_size_bytes=1024 * 1024,
        upload_stream_chunk_bytes=1024 * 1024,
        upload_spool_memory_bytes=8 * 1024 * 1024,
    )


def test_canonical_synthetic_package_reaches_candidate_and_survives_restart(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("RAW_BUCKET", "raw")
    monkeypatch.setenv("PROCESSED_BUCKET", "processed")
    session_fixture, package = _canonical_package()
    session_id = UUID(session_fixture["session_id"])
    package_sha256 = hashlib.sha256(package).hexdigest()
    object_key = f"sessions/{session_id}/packages/{package_sha256}.zip"
    expected_result = json.loads(RESULT_FIXTURE.read_text(encoding="utf-8"))
    expected_completion = json.loads(COMPLETION_FIXTURE.read_text(encoding="utf-8"))
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
            del headers
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
                allowed_browser_origin="https://review.synthetic.example",
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

    workload_factory = lambda request: WorkloadProvider()
    authenticator_factory = lambda request: ReviewerAuthenticator()
    settings = _synthetic_settings()
    mapping = GroupRoleMapping(
        (GroupRoleBinding("reviewers", (ControlRole.REVIEWER,)),)
    )
    policy = SubjectScopePolicy((SubjectScopeBinding(reviewer.subject, scope),))
    data_dir = (tmp_path / "runtime").resolve()
    bundle = create_in_process_no_network_bundle(
        data_dir=data_dir,
        settings=settings,
        group_role_mapping=mapping,
        subject_scope_policy=policy,
        authenticator_factory=authenticator_factory,
        workload_credential_verifier_factory=workload_factory,
    )
    for principal, role, audience, transport in (
        (
            capture,
            ControlRole.CAPTURE_UPLOADER,
            LegacySessionAudience.CAPTURE_UPLOAD,
            LegacySessionTransport.CAPTURE_WORKLOAD,
        ),
        (
            worker,
            ControlRole.DETERMINISTIC_WORKER,
            LegacySessionAudience.PROCESSING_COMPLETION,
            LegacySessionTransport.WORKER_WORKLOAD,
        ),
    ):
        bundle.legacy_store.register_workload_principal(
            principal_subject=principal.subject,
            scope=scope,
            audience=audience,
            role=role,
            transport=transport,
        )

    browser_material = b"s" * 32
    browser_cookie = base64.urlsafe_b64encode(browser_material).decode("ascii").rstrip("=")
    now = datetime.now(UTC)
    bundle.browser_store.register_session(
        session_identifier_digest=hashlib.sha256(browser_material).hexdigest(),
        csrf_token_digest="b" * 64,
        principal=reviewer,
        allowed_browser_origin="https://review.synthetic.example",
        issued_at=now - timedelta(minutes=2),
        authenticated_at=now - timedelta(minutes=2),
        last_seen_at=now - timedelta(seconds=1),
        idle_expires_at=now + timedelta(minutes=10),
        absolute_expires_at=now + timedelta(hours=1),
        now=now,
    )

    application = create_app(bundle)
    client = TestClient(application)
    client.cookies.set("workflow_session", browser_cookie)
    registration = {
        **session_fixture,
        "package_sha256": package_sha256,
        "package_size_bytes": len(package),
    }
    assert client.post("/v1/sessions", json=registration).status_code == 201
    upload_url = client.post(f"/v1/sessions/{session_id}/upload-url")
    assert upload_url.status_code == 200, upload_url.text
    assert upload_url.json()["object_key"] == object_key
    bundle.artifact_gateway.record_receipt(
        authority=ArtifactAuthority(scope, capture.subject),
        object_key=object_key,
        package_sha256=package_sha256,
        package_size_bytes=len(package),
    )
    uploaded = client.post(
        f"/v1/sessions/{session_id}/uploaded",
        json={"object_key": object_key},
    )
    assert uploaded.status_code == 202, uploaded.text
    queued = bundle.artifact_gateway.queue_evidence
    assert len(queued) == 1
    queued_body = json.dumps(
        {
            "schema_version": "1.0",
            "session_id": str(queued[0].session_id),
            "object_key": queued[0].object_key,
        }
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

    worker_s3 = WorkerS3()
    callback_order: list[str] = []
    published_candidates: list[dict[str, object]] = []

    def complete_api(completion) -> None:
        callback_order.append("completion")
        response = client.post(
            f"/v1/internal/sessions/{session_id}/processing-completion",
            json=completion.model_dump(mode="json"),
        )
        assert response.status_code == 200, response.text

    def publish_candidate(evidence: dict[str, object]) -> None:
        callback_order.append("candidate")
        response = client.post(
            f"/v1/internal/sessions/{session_id}/candidate-publication",
            json=evidence,
        )
        assert response.status_code == 200, response.text
        published_candidates.append(response.json())

    completion = process_message_v2(
        queued_body,
        s3=worker_s3,
        completion_callback=complete_api,
        candidate_callback=publish_candidate,
    )
    assert callback_order == ["completion", "candidate"]
    assert len(published_candidates) == 1
    assert worker_s3.timeline_artifact is not None
    assert json.loads(worker_s3.timeline_artifact) == expected_result
    assert completion.model_dump(mode="json") == expected_completion
    assert client.get(f"/v1/sessions/{session_id}/timeline").json() == expected_result

    listing = client.get(
        "/v1/control/candidate-publications?correlation_id=vertical-slice"
    )
    assert listing.status_code == 200, listing.text
    assert listing.json()["count"] == 1
    assert listing.json()["items"][0]["session_id"] == str(session_id)
    assert listing.json()["items"][0]["state"] == "finalized"

    restarted_bundle = create_in_process_no_network_bundle(
        data_dir=data_dir,
        settings=settings,
        group_role_mapping=mapping,
        subject_scope_policy=policy,
        authenticator_factory=authenticator_factory,
        workload_credential_verifier_factory=workload_factory,
    )
    restarted_app = create_app(restarted_bundle)
    restarted_client = TestClient(restarted_app)
    restarted_client.cookies.set("workflow_session", browser_cookie)
    durable_timeline = restarted_client.get(f"/v1/sessions/{session_id}/timeline")
    assert durable_timeline.status_code == 200
    assert durable_timeline.json() == expected_result
    durable_candidates = restarted_client.get(
        "/v1/control/candidate-publications?correlation_id=vertical-slice-restart"
    )
    assert durable_candidates.status_code == 200
    assert durable_candidates.json()["count"] == 1
    assert durable_candidates.json()["items"] == listing.json()["items"]
