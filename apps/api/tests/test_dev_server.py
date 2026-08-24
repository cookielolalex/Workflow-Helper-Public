from __future__ import annotations

import base64
import hashlib
import sqlite3
from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

import workflow_api.main as main_module
from workflow_api import dev_server
from workflow_api.browser_session_store import SQLiteBrowserSessionStore
from workflow_api.candidate_discovery_service import CandidateDiscoveryService
from workflow_api.candidate_publication_service import (
    CandidatePublicationRequest,
    CandidatePublicationService,
)
from workflow_api.candidate_publication_store import (
    SQLiteCandidatePublicationStore,
    _restricted_jcs,
)
from workflow_api.control_scope import _qualify
from workflow_api.control_service import ControlService
from workflow_api.legacy_session_store import SQLiteLegacySessionStore
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
from workflow_api.runtime_bundle import SealedSyntheticRuntimeBundle
from workflow_api.safety_control import SafetyControlService

_PROOFS = {
    "capture": "capture-201-proof-abcdefghijklmnopqrstuvwxyz0123456789",
    "worker": "worker-201-proof-abcdefghijklmnopqrstuvwxyz0123456789",
    "reviewer": "reviewer-201-proof-abcdefghijklmnopqrstuvwxyz0123456789",
}
_SESSION = base64.urlsafe_b64encode(bytes(range(1, 33))).decode("ascii").rstrip("=")
_CSRF = base64.urlsafe_b64encode(bytes(range(33, 65))).decode("ascii").rstrip("=")
_JOB_ID = UUID("11111111-1111-4111-8111-111111111111")
_CANDIDATE_SESSION_ID = UUID("22222222-2222-4222-8222-222222222222")
_EVENT_IDS = (
    UUID("90000000-0000-4000-8000-000000000001"),
    UUID("90000000-0000-4000-8000-000000000002"),
)


def _configure(monkeypatch: pytest.MonkeyPatch, data_dir: Path) -> None:
    for name in dev_server._FORBIDDEN_PROVIDER_SOURCES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("WORKFLOW_DEV_DATA_DIR", str(data_dir))
    monkeypatch.setenv("WORKFLOW_DEV_CAPTURE_PROOF", _PROOFS["capture"])
    monkeypatch.setenv("WORKFLOW_DEV_WORKER_PROOF", _PROOFS["worker"])
    monkeypatch.setenv("WORKFLOW_DEV_REVIEWER_PROOF", _PROOFS["reviewer"])
    monkeypatch.setenv("WORKFLOW_DEV_REVIEWER_SESSION", _SESSION)
    monkeypatch.setenv("WORKFLOW_DEV_REVIEWER_CSRF", _CSRF)


def _session_payload() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "session_id": "00000000-0000-4000-8000-000000000201",
        "machine_id": "synthetic-machine-201",
        "project_id": "synthetic-project",
        "started_at": "2026-01-01T00:00:00Z",
        "ended_at": "2026-01-01T00:00:05Z",
        "active_duration_seconds": 5,
        "approved_process": "acad",
        "package_sha256": "a" * 64,
        "package_size_bytes": 1,
    }


def _publish_candidate(bundle: SealedSyntheticRuntimeBundle):
    job = ProcessingJobV2(
        schema_version="2.0",
        job_id=_JOB_ID,
        session_id=_CANDIDATE_SESSION_ID,
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
    timeline = [
        TimelineItem(
            offset_seconds=index,
            event_type=EventType.CAD_COMMAND,
            summary="observed command",
            source_event_id=event_id,
        )
        for index, event_id in enumerate(_EVENT_IDS, start=1)
    ]
    segments = [
        OperationSegment(
            sequence=index,
            start_offset_seconds=index,
            end_offset_seconds=index,
            command_names=["LINE"],
            drawing_ref="synthetic-drawing",
            summary="one synthetic command",
            source_event_ids=[event_id],
        )
        for index, event_id in enumerate(_EVENT_IDS, start=1)
    ]
    result = ProcessingResultV2(
        schema_version="2.0",
        session_id=_CANDIDATE_SESSION_ID,
        event_count=2,
        meaningful_event_count=2,
        timeline=timeline,
        operation_segments=segments,
        keyframes=[],
        warnings=[],
    )
    artifact = ArtifactRef(
        provider=ArtifactProvider.GOOGLE_DRIVE,
        file_id="timeline-synthetic",
        revision="timeline-revision-0001",
        sha256="b" * 64,
        size_bytes=128,
        mime_type="application/json",
        role=ArtifactRole.TIMELINE,
    ).model_dump(mode="json")
    manifest = {
        "schema_version": "1.0",
        "job_id": str(_JOB_ID),
        "session_id": str(_CANDIDATE_SESSION_ID),
        "payload_digest": processing_job_v2_payload_digest(job),
        "payload_digest_scheme": (
            "workflow-helper.processing-job-v2.payload.sha256-jcs.v1"
        ),
        "outputs": [
            {"store_namespace": "google-drive://synthetic", "artifact_ref": artifact}
        ],
    }
    manifest_jcs = _restricted_jcs(manifest).encode("utf-8")
    source_digest = hashlib.sha256(
        b"workflow-helper\0processing-job-v2\0result-digest\0sha256-jcs-v1\0"
        + manifest_jcs
    ).hexdigest()
    service = CandidatePublicationService(
        bundle.candidate_publication_store,
        bundle.control_service,
    )
    return service.publish(
        CandidatePublicationRequest(
            scope=dev_server._SCOPE,
            job=job,
            result=result,
            result_manifest={
                **manifest,
                "result_manifest_jcs": manifest_jcs.decode("utf-8"),
                "source_result_sha256": source_digest,
            },
            timeline_binding={
                "store_namespace": "google-drive://synthetic",
                "artifact_ref": artifact,
            },
            drawing_ref="synthetic-drawing",
            timeline_commands=[
                {
                    "event_id": str(event_id),
                    "command_name": "LINE",
                    "segment_sequence": index,
                }
                for index, event_id in enumerate(_EVENT_IDS, start=1)
            ],
            rejected_alternative_count=0,
            qualifying_run_length=2,
            reservation_owner_id="worker-synthetic",
            lease_duration_seconds=30,
            now=1_000_000,
        )
    )


def test_build_app_uses_exact_synthetic_bundle_and_six_stores(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "synthetic-runtime"
    _configure(monkeypatch, data_dir)

    application = dev_server.build_app()
    bundle = application.state.runtime_bundle

    assert type(bundle) is SealedSyntheticRuntimeBundle
    assert type(bundle.legacy_store) is SQLiteLegacySessionStore
    assert type(bundle.browser_store) is SQLiteBrowserSessionStore
    assert type(bundle.control_service) is ControlService
    assert type(bundle.candidate_publication_store) is SQLiteCandidatePublicationStore
    assert type(bundle.candidate_discovery_service) is CandidateDiscoveryService
    assert type(bundle.safety_control_service) is SafetyControlService
    assert bundle.settings.environment == "synthetic"
    assert bundle.settings.aws_endpoint_url is None
    assert bundle.settings.aws_s3_presigned_endpoint_url is None
    assert bundle.settings.processing_queue_url is None
    assert bundle.settings.model_fields_set == set(type(bundle.settings).model_fields)

    sqlite_names = {path.name for path in data_dir.glob("*.sqlite3")}
    assert sqlite_names == {
        "legacy.sqlite3",
        "browser.sqlite3",
        "control.sqlite3",
        "candidate-publications.sqlite3",
        "retention.sqlite3",
        "safety.sqlite3",
    }
    assert not any(path.is_dir() for path in data_dir.iterdir())
    for path in data_dir.iterdir():
        assert _PROOFS["capture"].encode() not in path.read_bytes()
        assert _PROOFS["worker"].encode() not in path.read_bytes()
        assert _PROOFS["reviewer"].encode() not in path.read_bytes()


def test_dev_runtime_authorizes_session_plane_and_denies_bad_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure(monkeypatch, tmp_path / "synthetic-runtime")
    client = TestClient(dev_server.build_app())

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json() == {
        "status": "ok",
        "service": "workflow-helper-api",
        "environment": "synthetic",
    }

    registration = client.post(
        "/v1/sessions",
        headers={"X-Workflow-Dev-Proof": _PROOFS["capture"]},
        json=_session_payload(),
    )
    assert registration.status_code == 201
    assert registration.json()["processing_status"] == "registered"

    reviewer_headers = {
        "Cookie": f"workflow_session={_SESSION}",
        "X-Workflow-Dev-Reviewer-Proof": _PROOFS["reviewer"],
    }
    listing = client.get("/v1/sessions", headers=reviewer_headers)
    assert listing.status_code == 200
    assert listing.json()["count"] == 1
    assert listing.json()["items"][0]["session_id"] == _session_payload()["session_id"]

    missing = client.post("/v1/sessions", json=_session_payload())
    assert missing.status_code == 401

    invalid = client.post(
        "/v1/sessions",
        headers={"X-Workflow-Dev-Proof": "invalid-proof"},
        json=_session_payload(),
    )
    assert invalid.status_code == 401


def test_dev_runtime_reviewer_records_durable_review_and_leaves_unreviewed_queue(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch, tmp_path / "synthetic-runtime")
    application = dev_server.build_app()
    bundle = application.state.runtime_bundle
    metadata = _publish_candidate(bundle)
    client = TestClient(application)
    safe_headers = {
        "Cookie": f"workflow_session={_SESSION}",
        "X-Workflow-Dev-Reviewer-Proof": _PROOFS["reviewer"],
    }
    unsafe_headers = {
        **safe_headers,
        "Origin": "https://review.synthetic.example",
        "X-CSRF-Token": _CSRF,
    }

    assert dev_server._REVIEWER_SUBJECT == "reviewer_synthetic"
    before = client.get(
        "/v1/control/candidate-publications?correlation_id=dev-review-before",
        headers=safe_headers,
    )
    assert before.status_code == 200
    assert before.json()["count"] == 1

    reviewed = client.post(
        f"/v1/control/candidate-publications/{metadata.publication_key}/review",
        headers=unsafe_headers,
        json={
            "review_target_id": metadata.review_target_id,
            "correlation_id": "dev-review-authorized",
            "idempotency_key": "dev-review-authorized-1",
            "status": "approved",
        },
    )

    assert reviewed.status_code == 200, reviewed.text
    assert reviewed.json() == {"status": "approved"}
    target = _qualify(dev_server._SCOPE, "review_target", metadata.review_target_id)
    events = bundle.control_service._store.list_candidate_review_events(
        target,
        after_sequence=0,
        limit=10,
    )
    assert len(events) == 1
    assert events[0].actor_id == "reviewer_synthetic"
    assert events[0].status == "approved"
    after = client.get(
        "/v1/control/candidate-publications?correlation_id=dev-review-after",
        headers=safe_headers,
    )
    assert after.status_code == 200
    assert after.json() == {"items": [], "count": 0, "next_cursor": None}

    reopened = TestClient(dev_server.open_existing_app())
    durable = reopened.get(
        "/v1/control/candidate-publications?correlation_id=dev-review-reopened",
        headers=safe_headers,
    )
    assert durable.status_code == 200
    assert durable.json() == {"items": [], "count": 0, "next_cursor": None}


def test_nonconforming_dev_reviewer_is_denied_before_publication_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch, tmp_path / "synthetic-runtime")
    monkeypatch.setattr(dev_server, "_REVIEWER_SUBJECT", "reviewer.synthetic")
    application = dev_server.build_app()
    bundle = application.state.runtime_bundle
    metadata = _publish_candidate(bundle)
    client = TestClient(application)
    looked_up = False
    original_get_finalized = SQLiteCandidatePublicationStore.get_finalized

    def forbidden_lookup(*_args: object, **_kwargs: object) -> object:
        nonlocal looked_up
        looked_up = True
        raise AssertionError("publication lookup occurred before reviewer denial")

    monkeypatch.setattr(
        SQLiteCandidatePublicationStore,
        "get_finalized",
        forbidden_lookup,
    )
    response = client.post(
        f"/v1/control/candidate-publications/{metadata.publication_key}/review",
        headers={
            "Cookie": f"workflow_session={_SESSION}",
            "Origin": "https://review.synthetic.example",
            "X-CSRF-Token": _CSRF,
            "X-Workflow-Dev-Reviewer-Proof": _PROOFS["reviewer"],
        },
        json={
            "review_target_id": metadata.review_target_id,
            "correlation_id": "dev-review-denied",
            "idempotency_key": "dev-review-denied-1",
            "status": "approved",
        },
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "action forbidden"}
    assert looked_up is False
    target = _qualify(dev_server._SCOPE, "review_target", metadata.review_target_id)
    assert bundle.control_service._store.list_candidate_review_events(
        target,
        after_sequence=0,
        limit=10,
    ) == []
    monkeypatch.setattr(
        SQLiteCandidatePublicationStore,
        "get_finalized",
        original_get_finalized,
    )
    remaining = client.get(
        "/v1/control/candidate-publications?correlation_id=dev-review-denied-after",
        headers={
            "Cookie": f"workflow_session={_SESSION}",
            "X-Workflow-Dev-Reviewer-Proof": _PROOFS["reviewer"],
        },
    )
    assert remaining.status_code == 200
    assert remaining.json()["count"] == 1


def test_outer_guard_rejects_non_dev_before_path_or_bundle_side_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "must-not-be-created"
    _configure(monkeypatch, data_dir)
    monkeypatch.setenv("ENVIRONMENT", "production")

    with pytest.raises(RuntimeError, match="dev-like ENVIRONMENT"):
        dev_server.build_app()

    assert not data_dir.exists()


def test_provider_source_is_rejected_before_data_dir_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "must-not-be-created"
    _configure(monkeypatch, data_dir)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "real-looking-access-key")

    with pytest.raises(RuntimeError, match="ambient provider source"):
        dev_server.build_app()

    assert not data_dir.exists()


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("WORKFLOW_DEV_CAPTURE_PROOF", ""),
        ("WORKFLOW_DEV_WORKER_PROOF", "test" * 16),
        ("WORKFLOW_DEV_REVIEWER_PROOF", "a" * 64),
        ("WORKFLOW_DEV_REVIEWER_SESSION", "A" * 43),
    ),
)
def test_missing_default_or_malformed_material_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: str,
) -> None:
    data_dir = tmp_path / "must-not-be-created"
    _configure(monkeypatch, data_dir)
    monkeypatch.setenv(name, value)

    with pytest.raises(RuntimeError, match="runtime-supplied|canonical"):
        dev_server.build_app()

    assert not data_dir.exists()


def test_ambiguous_proof_inputs_fail_before_data_dir_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "must-not-be-created"
    _configure(monkeypatch, data_dir)
    monkeypatch.setenv("WORKFLOW_DEV_WORKER_PROOF", _PROOFS["capture"])

    with pytest.raises(RuntimeError, match="distinct"):
        dev_server.build_app()

    assert not data_dir.exists()


def test_existing_nonempty_or_symlink_data_dir_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "runtime"
    data_dir.mkdir()
    (data_dir / "sentinel").write_text("synthetic", encoding="utf-8")
    _configure(monkeypatch, data_dir)

    with pytest.raises(RuntimeError, match="fresh and dedicated"):
        dev_server.build_app()

    link = tmp_path / "runtime-link"
    link.symlink_to(tmp_path, target_is_directory=True)
    monkeypatch.setenv("WORKFLOW_DEV_DATA_DIR", str(link))
    with pytest.raises(RuntimeError, match="absolute dedicated"):
        dev_server.build_app()


def test_default_module_app_remains_inert_after_dev_app_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure(monkeypatch, tmp_path / "synthetic-runtime")
    dev_server.build_app()

    assert main_module.app.state.runtime_bundle is None
    response = TestClient(main_module.create_app()).get("/health")
    assert response.status_code == 200
    assert response.json()["environment"] == "unconfigured"


def test_database_sidecars_contain_no_raw_proof_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure(monkeypatch, tmp_path / "synthetic-runtime")
    application = dev_server.build_app()
    bundle = application.state.runtime_bundle
    assert bundle is not None
    assert bundle.candidate_publication_store is not None

    database_paths = (
        bundle.legacy_store.database_path,
        bundle.browser_store.database_path,
        bundle.candidate_publication_store.database_path,
    )
    for database in sorted(Path(path).resolve() for path in database_paths):
        with sqlite3.connect(database) as connection:
            result = connection.execute("pragma integrity_check").fetchone()
            assert result == ("ok",)
        raw = database.read_bytes()
        assert all(proof.encode() not in raw for proof in _PROOFS.values())


def test_existing_runtime_opener_is_non_serving_and_does_not_mutate_or_register(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "synthetic-runtime"
    _configure(monkeypatch, data_dir)
    dev_server.build_app()
    before = dev_server._existing_runtime_snapshot(data_dir)
    opener_snapshots: list[dev_server._ExistingRuntimeSnapshot] = []
    construct_modes: list[bool] = []
    original_construct = dev_server._construct_bundle
    original_snapshot = dev_server._existing_runtime_snapshot

    def observed_construct(**kwargs):
        construct_modes.append(kwargs["create_directory"])
        return original_construct(**kwargs)

    def forbidden_registration(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("existing-runtime opener attempted durable registration")

    def observed_snapshot(data_dir: Path) -> dev_server._ExistingRuntimeSnapshot:
        snapshot = original_snapshot(data_dir)
        opener_snapshots.append(snapshot)
        return snapshot

    monkeypatch.setattr(dev_server, "_construct_bundle", observed_construct)
    monkeypatch.setattr(dev_server, "_existing_runtime_snapshot", observed_snapshot)
    monkeypatch.setattr(
        SQLiteLegacySessionStore,
        "register_workload_principal",
        forbidden_registration,
    )
    monkeypatch.setattr(
        SQLiteBrowserSessionStore,
        "register_session",
        forbidden_registration,
    )

    application = dev_server.open_existing_app()

    assert construct_modes == [False]
    assert len(opener_snapshots) == 2
    assert opener_snapshots[0] == opener_snapshots[1]
    after = original_snapshot(data_dir)
    assert after.directory == before.directory
    assert after.databases == before.databases
    assert type(application.state.runtime_bundle) is SealedSyntheticRuntimeBundle
    response = TestClient(application).get(
        "/v1/control/candidate-publications?correlation_id=existing-runtime",
        headers={
            "Cookie": f"workflow_session={_SESSION}",
            "X-Workflow-Dev-Reviewer-Proof": _PROOFS["reviewer"],
        },
    )
    assert response.status_code == 200
    assert response.json() == {"items": [], "count": 0, "next_cursor": None}


def test_existing_runtime_opener_rejects_extra_symlink_and_writable_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extra_dir = tmp_path / "extra-runtime"
    _configure(monkeypatch, extra_dir)
    dev_server.build_app()
    (extra_dir / "unexpected").write_text("synthetic", encoding="utf-8")
    with pytest.raises(RuntimeError, match="exactly six"):
        dev_server.open_existing_app()

    symlink_dir = tmp_path / "symlink-runtime"
    _configure(monkeypatch, symlink_dir)
    dev_server.build_app()
    database = symlink_dir / "legacy.sqlite3"
    held = tmp_path / "held-legacy.sqlite3"
    database.rename(held)
    database.symlink_to(held)
    with pytest.raises(RuntimeError, match="unsafe"):
        dev_server.open_existing_app()

    writable_dir = tmp_path / "writable-runtime"
    _configure(monkeypatch, writable_dir)
    dev_server.build_app()
    (writable_dir / "legacy.sqlite3").chmod(0o666)
    with pytest.raises(RuntimeError, match="unsafe"):
        dev_server.open_existing_app()


def test_existing_runtime_opener_rejects_constructor_time_schema_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "synthetic-runtime"
    _configure(monkeypatch, data_dir)
    dev_server.build_app()
    original_construct = dev_server._construct_bundle

    def mutating_construct(**kwargs):
        result = original_construct(**kwargs)
        with sqlite3.connect(data_dir / "legacy.sqlite3") as connection:
            connection.execute("create table forbidden_opener_mutation(value text)")
        return result

    monkeypatch.setattr(dev_server, "_construct_bundle", mutating_construct)

    with pytest.raises(RuntimeError, match="changed while opening"):
        dev_server.open_existing_app()


def test_database_digest_pins_one_read_snapshot_and_closes_deterministically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "snapshot.sqlite3"
    with sqlite3.connect(database) as connection:
        assert connection.execute("pragma journal_mode = wal").fetchone() == ("wal",)
        connection.execute("create table evidence(value text not null)")
        connection.execute("insert into evidence values ('before')")
    expected = dev_server._database_digest(database)
    original_connect = sqlite3.connect
    statements: list[str] = []
    rollbacks = 0
    closes = 0
    concurrent_write_done = False

    class ObservedConnection:
        def __init__(self, inner: sqlite3.Connection) -> None:
            self.inner = inner

        def execute(self, statement: str):
            nonlocal concurrent_write_done
            normalized = " ".join(statement.lower().split())
            statements.append(normalized)
            if normalized.startswith("select type, name") and not concurrent_write_done:
                with original_connect(database) as writer:
                    writer.execute("insert into evidence values ('after')")
                concurrent_write_done = True
            return self.inner.execute(statement)

        def rollback(self) -> None:
            nonlocal rollbacks
            rollbacks += 1
            self.inner.rollback()

        def close(self) -> None:
            nonlocal closes
            closes += 1
            self.inner.close()

    def observed_connect(*args: object, **kwargs: object) -> ObservedConnection:
        return ObservedConnection(original_connect(*args, **kwargs))

    monkeypatch.setattr(dev_server.sqlite3, "connect", observed_connect)
    observed = dev_server._database_digest(database)
    monkeypatch.setattr(dev_server.sqlite3, "connect", original_connect)

    assert statements[:3] == [
        "pragma query_only = on",
        "begin",
        "pragma integrity_check",
    ]
    assert concurrent_write_done is True
    assert observed == expected
    assert dev_server._database_digest(database) != expected
    assert rollbacks == 1
    assert closes == 1


def test_existing_runtime_opener_rejects_row_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir = tmp_path / "row-drift-runtime"
    _configure(monkeypatch, data_dir)
    dev_server.build_app()
    database = data_dir / "legacy.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("create table row_drift_probe(value text not null)")
        connection.execute("insert into row_drift_probe values ('before')")
    original_construct = dev_server._construct_bundle

    def mutating_construct(**kwargs):
        result = original_construct(**kwargs)
        with sqlite3.connect(database) as connection:
            connection.execute("insert into row_drift_probe values ('after')")
        return result

    monkeypatch.setattr(dev_server, "_construct_bundle", mutating_construct)

    with pytest.raises(RuntimeError, match="changed while opening"):
        dev_server.open_existing_app()


def test_existing_runtime_opener_rejects_missing_corrupt_and_unsafe_sidecars(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_dir = tmp_path / "missing-runtime"
    _configure(monkeypatch, missing_dir)
    dev_server.build_app()
    (missing_dir / "safety.sqlite3").unlink()
    with pytest.raises(RuntimeError, match="exactly six"):
        dev_server.open_existing_app()

    corrupt_dir = tmp_path / "corrupt-runtime"
    _configure(monkeypatch, corrupt_dir)
    dev_server.build_app()
    (corrupt_dir / "safety.sqlite3").write_bytes(b"not a sqlite database")
    with pytest.raises(RuntimeError, match="database is unavailable"):
        dev_server.open_existing_app()

    sidecar_dir = tmp_path / "sidecar-runtime"
    _configure(monkeypatch, sidecar_dir)
    dev_server.build_app()
    unsafe_sidecar = sidecar_dir / "safety.sqlite3-wal"
    unsafe_sidecar.symlink_to(sidecar_dir / "safety.sqlite3")
    with pytest.raises(RuntimeError, match="unsafe"):
        dev_server.open_existing_app()

    orphan_dir = tmp_path / "orphan-runtime"
    _configure(monkeypatch, orphan_dir)
    dev_server.build_app()
    (orphan_dir / "orphan.sqlite3-wal").write_bytes(b"synthetic")
    with pytest.raises(RuntimeError, match="exactly six"):
        dev_server.open_existing_app()
