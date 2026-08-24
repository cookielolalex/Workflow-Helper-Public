import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from workflow_api.control_auth import AuthenticatedPrincipal, ControlRole
from workflow_api.control_scope import TenantWorkspaceScope, _qualify
from workflow_api.control_service import ControlService
from workflow_api.control_store import ControlConflictError, SQLiteControlStore
from workflow_api.dataset_approval import approve_dataset, read_dataset_approval_state
from workflow_api.dependencies import (
    get_authenticated_principal,
    get_control_service,
    get_session_security_context_provider,
)
from workflow_api.main import app
from workflow_api.session_security import (
    SessionSecurityContext,
    SessionTransport,
    csrf_token_digest,
)

SCOPE = TenantWorkspaceScope("tenant-synthetic", "workspace-synthetic")
SESSION_ORIGIN = "https://control.synthetic.test"
SESSION_TOKEN = base64.urlsafe_b64encode(b"d" * 32).decode("ascii").rstrip("=")


class _SessionProvider:
    def __init__(self, principal: AuthenticatedPrincipal):
        now = datetime.now(UTC)
        self.context = SessionSecurityContext(
            principal=principal,
            session_identifier_digest="5" * 64,
            session_generation=1,
            active_generation=1,
            issued_at=now - timedelta(minutes=10),
            authenticated_at=now - timedelta(minutes=9),
            last_seen_at=now - timedelta(minutes=1),
            idle_expires_at=now + timedelta(minutes=29),
            absolute_expires_at=now + timedelta(hours=7),
            revoked=False,
            transport=SessionTransport.BROWSER_COOKIE,
            allowed_browser_origin=SESSION_ORIGIN,
            csrf_token_digest=csrf_token_digest(SESSION_TOKEN),
        )

    def get_session_security_context(self) -> SessionSecurityContext:
        return self.context


def _service(tmp_path: Path) -> tuple[SQLiteControlStore, ControlService]:
    store = SQLiteControlStore(tmp_path / "control-plane.sqlite3")
    return store, ControlService(store)


def _reviewer(
    subject: str,
    scope: TenantWorkspaceScope = SCOPE,
) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        subject,
        frozenset({ControlRole.REVIEWER}),
        scope,
    )


def _manifest(*, revision: str = "revision-1", sha: str = "a" * 64) -> dict[str, str]:
    return {
        "source": "synthetic_manifest",
        "artifact_id": "dataset-manifest-synthetic",
        "revision": revision,
        "sha256": sha,
    }


def test_two_distinct_reviewers_are_required_and_state_survives_restart(
    tmp_path: Path,
) -> None:
    store, service = _service(tmp_path)
    reviewer_one = _reviewer("reviewer-one")
    reviewer_two = _reviewer("reviewer-two")

    first = approve_dataset(
        service,
        reviewer_one,
        dataset_id="dataset-synthetic",
        idempotency_key="dataset-approval-one",
        manifest=_manifest(),
        correlation_id="corr-approval-one",
    )
    assert first.status == "pending"
    assert first.approval_count == 1
    assert first.approvers == ("reviewer-one",)
    target_key = _qualify(SCOPE, "review_target", "dataset:dataset-synthetic")
    projection = store.get_review_projection(target_key)
    assert projection is not None
    assert projection.status == "pending"

    with pytest.raises(ControlConflictError, match="already approved this dataset manifest"):
        approve_dataset(
            service,
            reviewer_one,
            dataset_id="dataset-synthetic",
            idempotency_key="dataset-approval-one-again",
            manifest=_manifest(),
            correlation_id="corr-approval-one-again",
        )

    second = approve_dataset(
        service,
        reviewer_two,
        dataset_id="dataset-synthetic",
        idempotency_key="dataset-approval-two",
        manifest=_manifest(),
        correlation_id="corr-approval-two",
    )
    assert second.status == "approved"
    assert second.approval_count == 2
    assert second.approvers == ("reviewer-one", "reviewer-two")
    projection = store.get_review_projection(target_key)
    assert projection is not None
    assert projection.status == "approved"

    replay = approve_dataset(
        service,
        reviewer_one,
        dataset_id="dataset-synthetic",
        idempotency_key="dataset-approval-one",
        manifest=_manifest(),
        correlation_id="corr-approval-one-replay",
    )
    assert replay.status == "approved"
    assert replay.approvers == second.approvers

    restarted = ControlService(SQLiteControlStore(tmp_path / "control-plane.sqlite3"))
    readback = read_dataset_approval_state(
        restarted,
        reviewer_one,
        dataset_id="dataset-synthetic",
        correlation_id="corr-readback",
    )
    assert readback is not None
    assert readback.status == "approved"
    assert readback.approval_count == 2

    review_events = store.list_review_events(target_key)
    assert [event.detail["kind"] for event in review_events] == [
        "dataset_approval",
        "dataset_approval",
        "dataset_promotion",
    ]
    audit_events = store.list_audit_events(limit=100)
    assert [event.action for event in audit_events] == [
        "review.append",
        "review.append",
        "review.append",
    ]
    assert all(event.result == "accepted" for event in audit_events)


def test_manifest_mismatch_fails_closed_before_promotion(tmp_path: Path) -> None:
    store, service = _service(tmp_path)
    reviewer_one = _reviewer("reviewer-one")
    reviewer_two = _reviewer("reviewer-two")

    approve_dataset(
        service,
        reviewer_one,
        dataset_id="dataset-conflict",
        idempotency_key="dataset-conflict-one",
        manifest=_manifest(),
        correlation_id="corr-conflict-one",
    )

    with pytest.raises(ControlConflictError, match="manifest provenance"):
        approve_dataset(
            service,
            reviewer_two,
            dataset_id="dataset-conflict",
            idempotency_key="dataset-conflict-two",
            manifest=_manifest(revision="revision-2", sha="b" * 64),
            correlation_id="corr-conflict-two",
        )

    state = read_dataset_approval_state(
        service,
        reviewer_one,
        dataset_id="dataset-conflict",
        correlation_id="corr-conflict-read",
    )
    assert state is not None
    assert state.status == "pending"
    assert state.approval_count == 1
    projection = store.get_review_projection(
        _qualify(SCOPE, "review_target", "dataset:dataset-conflict")
    )
    assert projection is not None
    assert projection.status == "pending"


def test_unapproved_dataset_has_no_state(tmp_path: Path) -> None:
    _, service = _service(tmp_path)
    state = read_dataset_approval_state(
        service,
        _reviewer("reviewer-one"),
        dataset_id="dataset-missing",
        correlation_id="corr-missing",
    )
    assert state is None


def test_same_dataset_and_approval_idempotency_are_isolated_by_scope(
    tmp_path: Path,
) -> None:
    store, service = _service(tmp_path)
    scope_a = TenantWorkspaceScope("tenant-synthetic", "workspace-alpha")
    scope_b = TenantWorkspaceScope("tenant-synthetic", "workspace-beta")
    reviewer_a = _reviewer("reviewer-shared", scope_a)
    reviewer_b = _reviewer("reviewer-shared", scope_b)

    for reviewer in (reviewer_a, reviewer_b):
        state = approve_dataset(
            service,
            reviewer,
            dataset_id="same-dataset",
            idempotency_key="same-dataset-idempotency",
            manifest=_manifest(),
            correlation_id="corr-dataset-scoped",
        )
        assert state.dataset_id == "same-dataset"
        assert state.target_id == "dataset:same-dataset"
        assert state.approval_count == 1
        assert "whscope1" not in repr(state)

    assert len(
        store.list_review_events(
            _qualify(scope_a, "review_target", "dataset:same-dataset")
        )
    ) == 1
    assert len(
        store.list_review_events(
            _qualify(scope_b, "review_target", "dataset:same-dataset")
        )
    ) == 1


def test_dataset_route_uses_exact_session_and_csrf_evidence(tmp_path: Path) -> None:
    _, service = _service(tmp_path)
    principal = _reviewer("reviewer-route")
    provider = _SessionProvider(principal)
    app.dependency_overrides[get_authenticated_principal] = lambda: principal
    app.dependency_overrides[get_control_service] = lambda: service
    app.dependency_overrides[get_session_security_context_provider] = lambda: provider
    client = TestClient(
        app,
        headers={"Origin": SESSION_ORIGIN, "X-CSRF-Token": SESSION_TOKEN},
    )
    try:
        response = client.post(
            "/v1/control/datasets/dataset-route/approve",
            json={
                "correlation_id": "corr-dataset-route",
                "idempotency_key": "dataset-route-approval",
                "manifest": _manifest(),
            },
        )
        assert response.status_code == 201, response.text
        assert response.json()["dataset_id"] == "dataset-route"
        assert response.json()["approval_count"] == 1
    finally:
        app.dependency_overrides.clear()
