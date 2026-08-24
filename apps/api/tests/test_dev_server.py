from __future__ import annotations

import base64
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import workflow_api.main as main_module
from workflow_api import dev_server
from workflow_api.browser_session_store import SQLiteBrowserSessionStore
from workflow_api.candidate_discovery_service import CandidateDiscoveryService
from workflow_api.candidate_publication_store import SQLiteCandidatePublicationStore
from workflow_api.control_service import ControlService
from workflow_api.legacy_session_store import SQLiteLegacySessionStore
from workflow_api.runtime_bundle import SealedSyntheticRuntimeBundle
from workflow_api.safety_control import SafetyControlService

_PROOFS = {
    "capture": "capture-201-proof-abcdefghijklmnopqrstuvwxyz0123456789",
    "worker": "worker-201-proof-abcdefghijklmnopqrstuvwxyz0123456789",
    "reviewer": "reviewer-201-proof-abcdefghijklmnopqrstuvwxyz0123456789",
}
_SESSION = base64.urlsafe_b64encode(bytes(range(1, 33))).decode("ascii").rstrip("=")
_CSRF = base64.urlsafe_b64encode(bytes(range(33, 65))).decode("ascii").rstrip("=")


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
