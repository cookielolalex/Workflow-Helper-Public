from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from workflow_api.control_auth import (
    AuthenticatedPrincipal,
    AuthorizationDeniedError,
    ControlAction,
    ControlRole,
)
from workflow_api.control_scope import TenantWorkspaceScope, _qualify
from workflow_api.control_service import ControlService
from workflow_api.control_store import AuditContext, ControlConflictError, SQLiteControlStore
from workflow_api.dependencies import (
    get_authenticated_principal,
    get_control_service,
    get_session_security_context_provider,
)
from workflow_api.main import app
from workflow_api.retention_store import DEFAULT_RAW_RETENTION_DAYS, RetentionLedger
from workflow_api.session_security import (
    SessionSecurityContext,
    SessionTransport,
    csrf_token_digest,
)

NOW = datetime(2026, 8, 17, 8, 0, tzinfo=UTC)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SCOPE = TenantWorkspaceScope("tenant-synthetic", "workspace-synthetic")
SESSION_ORIGIN = "https://control.synthetic.test"
SESSION_TOKEN = base64.urlsafe_b64encode(b"r" * 32).decode("ascii").rstrip("=")


class _SessionProvider:
    def __init__(self, principal: AuthenticatedPrincipal):
        now = datetime.now(UTC)
        self.context = SessionSecurityContext(
            principal=principal,
            session_identifier_digest="7" * 64,
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


def _steward(scope: TenantWorkspaceScope = SCOPE) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        "retention-steward-synthetic",
        frozenset({ControlRole.RETENTION_STEWARD}),
        scope,
    )


def _worker() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        "worker-synthetic",
        frozenset({ControlRole.DETERMINISTIC_WORKER}),
        SCOPE,
    )


def _copies() -> list[dict[str, str]]:
    return [
        {
            "copy_id": "raw-primary",
            "provider": "google_drive",
            "file_id": "drive-file-synthetic",
            "revision": "drive-revision-1",
            "sha256": SHA_A,
        },
        {
            "copy_id": "raw-rollback",
            "provider": "s3",
            "file_id": "s3-object-synthetic",
            "revision": "s3-version-1",
            "sha256": SHA_B,
        },
    ]


def _service(tmp_path: Path) -> tuple[SQLiteControlStore, RetentionLedger, ControlService]:
    path = tmp_path / "control.sqlite3"
    store = SQLiteControlStore(path)
    retention = RetentionLedger(path)
    return store, retention, ControlService(store, retention)


def test_legacy_audit_rows_survive_migration_with_sequence_continuity(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy.sqlite3"
    store = SQLiteControlStore(path)
    old = store.append_audit_event(
        AuditContext(
            correlation_id="corr-legacy",
            idempotency_key="legacy-idem",
            subject_id="reviewer-synthetic",
            roles=("reviewer",),
            action="review.append",
            target_id="artifact-legacy",
            result="accepted",
            occurred_at=NOW,
        )
    )
    assert old.sequence == 1

    retention = RetentionLedger(path)
    next_sequence = retention.append_audit_event(
        AuditContext(
            correlation_id="corr-retention",
            idempotency_key="retention-idem",
            subject_id="retention-steward-synthetic",
            roles=("retention_steward",),
            action="retention.register",
            target_id="retention-target",
            result="accepted",
            occurred_at=NOW + timedelta(seconds=1),
        )
    )
    assert next_sequence == 2
    events = store.list_audit_events(limit=100)
    assert [(event.sequence, event.action, event.subject_id) for event in events] == [
        (1, "review.append", "reviewer-synthetic"),
        (2, "retention.register", "retention-steward-synthetic"),
    ]


def test_registration_is_fixed_14_days_immutable_and_idempotent(tmp_path: Path) -> None:
    _, _, service = _service(tmp_path)
    steward = _steward()
    created = service.register_retention(
        steward,
        target_id="raw-session-1",
        copies=_copies(),
        correlation_id="corr-register",
        idempotency_key="retention-register-1",
        now=NOW,
    )
    assert created.created_by == steward.subject
    assert created.expires_at - created.created_at == timedelta(
        days=DEFAULT_RAW_RETENTION_DAYS
    )
    assert [copy.copy_id for copy in created.copies] == ["raw-primary", "raw-rollback"]
    assert {copy.state for copy in created.copies} == {"active"}

    replay = service.register_retention(
        steward,
        target_id="raw-session-1",
        copies=list(reversed(_copies())),
        correlation_id="corr-register-replay",
        idempotency_key="retention-register-1",
        now=NOW + timedelta(hours=1),
    )
    assert replay == created

    changed = _copies()
    changed[0] = {**changed[0], "revision": "drive-revision-2"}
    with pytest.raises(ControlConflictError, match="idempotency"):
        service.register_retention(
            steward,
            target_id="raw-session-1",
            copies=changed,
            correlation_id="corr-register-conflict",
            idempotency_key="retention-register-1",
            now=NOW,
        )
    with pytest.raises(ControlConflictError, match="already registered"):
        service.register_retention(
            steward,
            target_id="raw-session-1",
            copies=_copies(),
            correlation_id="corr-register-second-key",
            idempotency_key="retention-register-2",
            now=NOW,
        )


def test_hold_stage_attest_and_all_copy_completion_are_fail_closed(tmp_path: Path) -> None:
    _, retention, service = _service(tmp_path)
    steward = _steward()
    service.register_retention(
        steward,
        target_id="raw-session-2",
        copies=_copies(),
        correlation_id="corr-register",
        idempotency_key="register-2",
        now=NOW,
    )
    with pytest.raises(ControlConflictError, match="not reached"):
        service.stage_retention_trash(
            steward,
            target_id="raw-session-2",
            copy_id="raw-primary",
            correlation_id="corr-early",
            idempotency_key="stage-early",
            now=NOW + timedelta(days=13, hours=23),
        )

    service.set_retention_hold(
        steward,
        target_id="raw-session-2",
        hold=True,
        reason="synthetic legal hold",
        correlation_id="corr-hold",
        idempotency_key="hold-1",
        now=NOW + timedelta(days=13),
    )
    with pytest.raises(ControlConflictError, match="legal hold"):
        service.stage_retention_trash(
            steward,
            target_id="raw-session-2",
            copy_id="raw-primary",
            correlation_id="corr-held-stage",
            idempotency_key="stage-held",
            now=NOW + timedelta(days=14),
        )
    service.set_retention_hold(
        steward,
        target_id="raw-session-2",
        hold=False,
        reason=None,
        correlation_id="corr-release",
        idempotency_key="hold-release-1",
        now=NOW + timedelta(days=14),
    )
    staged = service.stage_retention_trash(
        steward,
        target_id="raw-session-2",
        copy_id="raw-primary",
        correlation_id="corr-stage-1",
        idempotency_key="stage-1",
        now=NOW + timedelta(days=14),
    )
    assert staged.copies[0].state == "trash_staged"

    service.set_retention_hold(
        steward,
        target_id="raw-session-2",
        hold=True,
        reason="second synthetic hold",
        correlation_id="corr-hold-2",
        idempotency_key="hold-2",
        now=NOW + timedelta(days=14, minutes=1),
    )
    with pytest.raises(ControlConflictError, match="legal hold"):
        service.attest_retention_delete(
            steward,
            target_id="raw-session-2",
            copy_id="raw-primary",
            deletion_receipt_sha256=SHA_C,
            correlation_id="corr-held-attest",
            idempotency_key="attest-held",
            now=NOW + timedelta(days=14, minutes=2),
        )
    service.set_retention_hold(
        steward,
        target_id="raw-session-2",
        hold=False,
        reason=None,
        correlation_id="corr-release-2",
        idempotency_key="hold-release-2",
        now=NOW + timedelta(days=14, minutes=3),
    )
    first = service.attest_retention_delete(
        steward,
        target_id="raw-session-2",
        copy_id="raw-primary",
        deletion_receipt_sha256=SHA_C,
        correlation_id="corr-attest-1",
        idempotency_key="attest-1",
        now=NOW + timedelta(days=14, minutes=4),
    )
    assert first.completed_at is None
    assert first.copies[0].state == "deleted"

    replay = service.attest_retention_delete(
        steward,
        target_id="raw-session-2",
        copy_id="raw-primary",
        deletion_receipt_sha256=SHA_C,
        correlation_id="corr-attest-replay",
        idempotency_key="attest-1",
        now=NOW + timedelta(days=15),
    )
    assert replay == first
    with pytest.raises(ControlConflictError, match="idempotency"):
        service.attest_retention_delete(
            steward,
            target_id="raw-session-2",
            copy_id="raw-primary",
            deletion_receipt_sha256=SHA_D,
            correlation_id="corr-attest-conflict",
            idempotency_key="attest-1",
            now=NOW + timedelta(days=15),
        )
    with pytest.raises(ControlConflictError, match="trash staged"):
        service.attest_retention_delete(
            steward,
            target_id="raw-session-2",
            copy_id="raw-rollback",
            deletion_receipt_sha256=SHA_D,
            correlation_id="corr-before-stage",
            idempotency_key="attest-before-stage",
            now=NOW + timedelta(days=15),
        )
    service.stage_retention_trash(
        steward,
        target_id="raw-session-2",
        copy_id="raw-rollback",
        correlation_id="corr-stage-2",
        idempotency_key="stage-2",
        now=NOW + timedelta(days=15),
    )
    completed = service.attest_retention_delete(
        steward,
        target_id="raw-session-2",
        copy_id="raw-rollback",
        deletion_receipt_sha256=SHA_D,
        correlation_id="corr-attest-2",
        idempotency_key="attest-2",
        now=NOW + timedelta(days=15, minutes=1),
    )
    assert completed.completed_at == NOW + timedelta(days=15, minutes=1)
    assert {copy.state for copy in completed.copies} == {"deleted"}
    restarted = ControlService(
        SQLiteControlStore(retention.database_path),
        RetentionLedger(retention.database_path),
    )
    assert (
        restarted.read_retention(
            steward,
            target_id="raw-session-2",
            correlation_id="corr-restart-read",
        )
        == completed
    )


def test_overdue_excludes_held_and_complete_targets(tmp_path: Path) -> None:
    _, _, service = _service(tmp_path)
    steward = _steward()
    created_at = NOW - timedelta(days=15)
    for target in ("overdue", "held", "complete"):
        service.register_retention(
            steward,
            target_id=target,
            copies=[_copies()[0]],
            correlation_id=f"corr-{target}",
            idempotency_key=f"{target}-register",
            now=created_at,
        )
    service.set_retention_hold(
        steward,
        target_id="held",
        hold=True,
        reason="synthetic hold",
        correlation_id="corr-held",
        idempotency_key="held-hold",
        now=NOW - timedelta(days=1),
    )
    service.stage_retention_trash(
        steward,
        target_id="complete",
        copy_id="raw-primary",
        correlation_id="corr-complete-stage",
        idempotency_key="complete-stage",
        now=NOW - timedelta(hours=2),
    )
    service.attest_retention_delete(
        steward,
        target_id="complete",
        copy_id="raw-primary",
        deletion_receipt_sha256=SHA_C,
        correlation_id="corr-complete-attest",
        idempotency_key="complete-attest",
        now=NOW - timedelta(hours=1),
    )
    overdue = service.list_overdue_retention(
        steward,
        correlation_id="corr-overdue-read",
        now=NOW,
    )
    assert [value.target_id for value in overdue] == ["overdue"]


def test_cross_role_denials_are_audited_without_state_mutation(tmp_path: Path) -> None:
    store, retention, service = _service(tmp_path)
    with pytest.raises(AuthorizationDeniedError, match="forbidden"):
        service.register_retention(
            _worker(),
            target_id="denied-target",
            copies=[_copies()[0]],
            correlation_id="corr-denied",
            idempotency_key="denied-register",
            now=NOW,
        )
    assert retention.get_target("denied-target") is None
    denied = store.list_audit_events(limit=100)[-1]
    assert denied.action == ControlAction.RETENTION_REGISTER.value
    assert denied.result == "denied"
    assert denied.roles == ("deterministic_worker",)

    with pytest.raises(AuthorizationDeniedError, match="forbidden"):
        service.register_job(
            _steward(),
            job_id="job-denied",
            payload_digest=SHA_A,
            correlation_id="corr-steward-job",
            idempotency_key=None,
        )
    denied = store.list_audit_events(limit=100)[-1]
    assert denied.action == ControlAction.JOB_REGISTER.value
    assert denied.roles == ("retention_steward",)


def test_routes_derive_steward_identity_and_reject_injected_actor(tmp_path: Path) -> None:
    _, retention, service = _service(tmp_path)
    app.dependency_overrides[get_control_service] = lambda: service
    principal = _steward()
    provider = _SessionProvider(principal)
    app.dependency_overrides[get_authenticated_principal] = lambda: principal
    app.dependency_overrides[get_session_security_context_provider] = lambda: provider
    client = TestClient(
        app,
        headers={"Origin": SESSION_ORIGIN, "X-CSRF-Token": SESSION_TOKEN},
    )
    try:
        payload = {
            "correlation_id": "corr-route",
            "idempotency_key": "route-register",
            "copies": [_copies()[0]],
        }
        injected = client.post(
            "/v1/control/retention/route-target",
            json={**payload, "actor_id": "attacker"},
        )
        assert injected.status_code == 422
        created = client.post("/v1/control/retention/route-target", json=payload)
        assert created.status_code == 201, created.text
        assert created.json()["created_by"] == "retention-steward-synthetic"
        readback = client.get(
            "/v1/control/retention/route-target?correlation_id=corr-route-read"
        )
        assert readback.status_code == 200
        assert (
            retention.get_target(_qualify(SCOPE, "retention_target", "route-target"))
            is not None
        )
    finally:
        app.dependency_overrides.clear()


def test_retention_ids_idempotency_and_overdue_reads_are_scope_isolated(
    tmp_path: Path,
) -> None:
    store, _, service = _service(tmp_path)
    scope_a = TenantWorkspaceScope("tenant-synthetic", "workspace-alpha")
    scope_b = TenantWorkspaceScope("tenant-synthetic", "workspace-beta")
    steward_a = _steward(scope_a)
    steward_b = _steward(scope_b)

    for steward in (steward_a, steward_b):
        state = service.register_retention(
            steward,
            target_id="same-target",
            copies=[_copies()[0]],
            correlation_id="corr-register-scoped",
            idempotency_key="same-retention-idempotency",
            now=NOW - timedelta(days=15),
        )
        assert state.target_id == "same-target"
        assert state.copies[0].copy_id == "raw-primary"
        assert "whscope1" not in repr(state)

    overdue_a = service.list_overdue_retention(
        steward_a,
        correlation_id="corr-overdue-a",
        now=NOW,
    )
    overdue_b = service.list_overdue_retention(
        steward_b,
        correlation_id="corr-overdue-b",
        now=NOW,
    )
    assert [state.target_id for state in overdue_a] == ["same-target"]
    assert [state.target_id for state in overdue_b] == ["same-target"]

    service.set_retention_hold(
        steward_a,
        target_id="same-target",
        hold=True,
        reason="synthetic scope-a hold",
        correlation_id="corr-hold-a",
        idempotency_key="same-hold-idempotency",
        now=NOW,
    )
    service.set_retention_hold(
        steward_b,
        target_id="same-target",
        hold=True,
        reason="synthetic scope-b hold",
        correlation_id="corr-hold-b",
        idempotency_key="same-hold-idempotency",
        now=NOW,
    )
    assert service.read_retention(
        steward_a, target_id="same-target", correlation_id="corr-read-a"
    ).hold_reason == "synthetic scope-a hold"
    assert service.read_retention(
        steward_b, target_id="same-target", correlation_id="corr-read-b"
    ).hold_reason == "synthetic scope-b hold"
    assert len(store.list_audit_events(limit=100)) >= 6
