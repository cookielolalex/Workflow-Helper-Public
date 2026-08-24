from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from workflow_api.control_auth import (
    AuthenticatedPrincipal,
    AuthorizationDeniedError,
    ControlRole,
)
from workflow_api.control_scope import TenantWorkspaceScope, _qualify
from workflow_api.control_service import ControlService
from workflow_api.control_store import LeaseUnavailableError, SQLiteControlStore
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

SHA_A = "a" * 64
SHA_B = "b" * 64
NOW = datetime(2026, 8, 17, 6, 0, tzinfo=UTC)
SCOPE = TenantWorkspaceScope("tenant-synthetic", "workspace-synthetic")
SESSION_ORIGIN = "https://control.synthetic.test"
SESSION_TOKEN = base64.urlsafe_b64encode(b"c" * 32).decode("ascii").rstrip("=")


class _SessionProvider:
    def __init__(self, principal: AuthenticatedPrincipal):
        now = datetime.now(UTC)
        self.context = SessionSecurityContext(
            principal=principal,
            session_identifier_digest="8" * 64,
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


def _principal(
    subject: str,
    *roles: ControlRole,
    scope: TenantWorkspaceScope = SCOPE,
) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(subject, frozenset(roles), scope)


@pytest.fixture
def control(tmp_path: Path):
    store = SQLiteControlStore(tmp_path / "control.sqlite3")
    service = ControlService(store)
    app.dependency_overrides[get_control_service] = lambda: service
    try:
        yield TestClient(
            app,
            headers={
                "Origin": SESSION_ORIGIN,
                "X-CSRF-Token": SESSION_TOKEN,
            },
        ), store
    finally:
        app.dependency_overrides.clear()


def _authenticate(principal: AuthenticatedPrincipal) -> None:
    provider = _SessionProvider(principal)
    app.dependency_overrides[get_authenticated_principal] = lambda: principal
    app.dependency_overrides[get_session_security_context_provider] = lambda: provider


def _register(client: TestClient, job_id: str, *, correlation: str) -> dict:
    response = client.post(
        "/v1/control/jobs",
        json={
            "job_id": job_id,
            "payload_digest": SHA_A,
            "correlation_id": correlation,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _acquire(
    client: TestClient, job_id: str, *, correlation: str, ttl_seconds: int = 1800
) -> dict:
    response = client.post(
        f"/v1/control/jobs/{job_id}/acquire",
        json={"correlation_id": correlation, "ttl_seconds": ttl_seconds},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _lease_payload(lease: dict, *, correlation: str, **extra) -> dict:
    return {
        "correlation_id": correlation,
        "fencing_token": lease["fencing_token"],
        "attempt": lease["attempt"],
        "acquired_at": lease["acquired_at"],
        "expires_at": lease["expires_at"],
        **extra,
    }


def _review_payload(*, correlation: str = "corr-review", status: str = "pending") -> dict:
    return {
        "target_id": "artifact-synthetic",
        "correlation_id": correlation,
        "idempotency_key": "review-idem-1",
        "status": status,
        "provenance": {
            "source": "synthetic_fixture",
            "artifact_id": "artifact-synthetic",
            "revision": "revision-1",
            "sha256": "9" * 64,
        },
        "detail": {"note": "synthetic-only"},
    }


def test_every_control_route_is_unavailable_without_installed_authentication() -> None:
    app.dependency_overrides.clear()
    client = TestClient(app)
    lease = {
        "correlation_id": "corr-default",
        "fencing_token": 1,
        "attempt": 1,
        "acquired_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=1)).isoformat(),
    }
    calls = [
        ("post", "/v1/control/jobs", {"job_id": "job-default", "payload_digest": SHA_A, "correlation_id": "corr-default"}),
        ("post", "/v1/control/jobs/job-default/acquire", {"correlation_id": "corr-default"}),
        ("post", "/v1/control/jobs/job-default/heartbeat", lease),
        ("post", "/v1/control/jobs/job-default/complete", {**lease, "idempotency_key": "completion-1", "result_digest": SHA_B}),
        ("post", "/v1/control/reviews", _review_payload()),
        ("get", "/v1/control/reviews/artifact-synthetic?correlation_id=corr-default", None),
        ("get", "/v1/control/reviews/artifact-synthetic/current?correlation_id=corr-default", None),
        ("get", "/v1/control/audit-events?correlation_id=corr-default", None),
        ("get", "/v1/control/audit-events/event-1?correlation_id=corr-default", None),
    ]

    for method, path, body in calls:
        response = client.request(method, path, json=body)
        assert response.status_code == 503, (method, path, response.text)
        assert response.json() == {"detail": "control authentication unavailable"}


def test_roleless_principal_is_denied_all_actions_and_denials_are_audited(control) -> None:
    client, store = control
    _authenticate(_principal("subject-roleless"))
    lease = {
        "correlation_id": "corr-roleless",
        "fencing_token": 1,
        "attempt": 1,
        "acquired_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(minutes=1)).isoformat(),
    }
    calls = [
        ("post", "/v1/control/jobs", {"job_id": "job-roleless", "payload_digest": SHA_A, "correlation_id": "corr-roleless"}),
        ("post", "/v1/control/jobs/job-roleless/acquire", {"correlation_id": "corr-roleless"}),
        ("post", "/v1/control/jobs/job-roleless/heartbeat", lease),
        ("post", "/v1/control/jobs/job-roleless/complete", {**lease, "idempotency_key": "complete-roleless", "result_digest": SHA_B}),
        ("post", "/v1/control/reviews", _review_payload(correlation="corr-roleless")),
        ("get", "/v1/control/reviews/artifact-synthetic?correlation_id=corr-roleless", None),
        ("get", "/v1/control/reviews/artifact-synthetic/current?correlation_id=corr-roleless", None),
        ("get", "/v1/control/audit-events?correlation_id=corr-roleless", None),
        ("get", "/v1/control/audit-events/event-1?correlation_id=corr-roleless", None),
    ]

    for method, path, body in calls:
        response = client.request(method, path, json=body)
        assert response.status_code == 403, (method, path, response.text)
        assert response.json() == {"detail": "action forbidden"}

    denied = store.list_audit_events(limit=100)
    assert len(denied) == len(calls)
    assert {event.result for event in denied} == {"denied"}
    assert {event.subject_id for event in denied} == {"subject-roleless"}
    assert {event.roles for event in denied} == {()}


def test_cross_role_access_is_denied_with_generic_errors(control) -> None:
    client, _ = control
    cases = [
        (
            _principal("worker-synthetic", ControlRole.DETERMINISTIC_WORKER),
            "post",
            "/v1/control/reviews",
            _review_payload(correlation="corr-worker-review"),
        ),
        (
            _principal("worker-synthetic", ControlRole.DETERMINISTIC_WORKER),
            "get",
            "/v1/control/audit-events?correlation_id=corr-worker-audit",
            None,
        ),
        (
            _principal("reviewer-synthetic", ControlRole.REVIEWER),
            "post",
            "/v1/control/jobs",
            {"job_id": "job-cross", "payload_digest": SHA_A, "correlation_id": "corr-reviewer-job"},
        ),
        (
            _principal("audit-synthetic", ControlRole.AUDIT_READER),
            "get",
            "/v1/control/reviews/artifact-synthetic?correlation_id=corr-audit-review",
            None,
        ),
    ]

    for principal, method, path, body in cases:
        _authenticate(principal)
        response = client.request(method, path, json=body)
        assert response.status_code == 403
        assert response.json() == {"detail": "action forbidden"}


def test_worker_identity_is_derived_and_cross_worker_lease_use_is_fenced(control) -> None:
    client, store = control
    worker_a = _principal("worker-synthetic-a", ControlRole.DETERMINISTIC_WORKER)
    worker_b = _principal("worker-synthetic-b", ControlRole.DETERMINISTIC_WORKER)
    _authenticate(worker_a)
    _register(client, "job-owned", correlation="corr-register")
    lease = _acquire(client, "job-owned", correlation="corr-acquire", ttl_seconds=60)

    for injected_field in ("owner_id", "actor_id", "subject"):
        response = client.post(
            "/v1/control/jobs/job-owned/heartbeat",
            json=_lease_payload(
                lease,
                correlation=f"corr-inject-{injected_field}",
                ttl_seconds=60,
                **{injected_field: "worker-synthetic-b"},
            ),
        )
        assert response.status_code == 422
        assert response.json() == {"detail": "invalid request"}

    _authenticate(worker_b)
    heartbeat = client.post(
        "/v1/control/jobs/job-owned/heartbeat",
        json=_lease_payload(lease, correlation="corr-cross-heartbeat", ttl_seconds=60),
    )
    completion = client.post(
        "/v1/control/jobs/job-owned/complete",
        json=_lease_payload(
            lease,
            correlation="corr-cross-complete",
            idempotency_key="completion-owned",
            result_digest=SHA_B,
        ),
    )
    assert heartbeat.status_code == 409
    assert completion.status_code == 409
    for response in (heartbeat, completion):
        body = response.text
        assert body == '{"detail":"request conflicts with current state"}'
        assert "worker-synthetic-a" not in body
        assert str(store._database_path) not in body

    _authenticate(worker_a)
    refreshed = client.post(
        "/v1/control/jobs/job-owned/heartbeat",
        json=_lease_payload(lease, correlation="corr-heartbeat", ttl_seconds=60),
    )
    assert refreshed.status_code == 200
    completed = client.post(
        "/v1/control/jobs/job-owned/complete",
        json=_lease_payload(
            refreshed.json(),
            correlation="corr-complete",
            idempotency_key="completion-owned",
            result_digest=SHA_B,
        ),
    )
    assert completed.status_code == 200


def test_worker_bounds_fencing_expiry_and_completion_idempotency(control) -> None:
    client, store = control
    worker = _principal("worker-synthetic", ControlRole.DETERMINISTIC_WORKER)
    _authenticate(worker)
    for index in range(4):
        _register(client, f"job-cap-{index}", correlation=f"corr-register-{index}")

    too_long = client.post(
        "/v1/control/jobs/job-cap-0/acquire",
        json={"correlation_id": "corr-too-long", "ttl_seconds": 1801},
    )
    assert too_long.status_code == 422
    expired = store.acquire(
        _qualify(SCOPE, "job", "job-cap-3"),
        "worker-synthetic",
        now=datetime.now(UTC) - timedelta(minutes=2),
        ttl_seconds=1,
    )
    leases = [
        _acquire(client, f"job-cap-{index}", correlation=f"corr-acquire-{index}", ttl_seconds=60)
        for index in range(3)
    ]
    fourth = client.post(
        "/v1/control/jobs/job-cap-3/acquire",
        json={"correlation_id": "corr-fourth", "ttl_seconds": 60},
    )
    assert fourth.status_code == 409

    wrong_token = client.post(
        "/v1/control/jobs/job-cap-0/complete",
        json=_lease_payload(
            {**leases[0], "fencing_token": leases[0]["fencing_token"] + 1},
            correlation="corr-wrong-token",
            idempotency_key="complete-cap-0",
            result_digest=SHA_B,
        ),
    )
    assert wrong_token.status_code == 409

    expired_response = client.post(
        "/v1/control/jobs/job-cap-3/complete",
        json={
            "correlation_id": "corr-expired",
            "fencing_token": expired.fencing_token,
            "attempt": expired.attempt,
            "acquired_at": expired.acquired_at.isoformat(),
            "expires_at": expired.expires_at.isoformat(),
            "idempotency_key": "complete-expired",
            "result_digest": SHA_B,
        },
    )
    assert expired_response.status_code == 409

    completed = client.post(
        "/v1/control/jobs/job-cap-0/complete",
        json=_lease_payload(
            leases[0],
            correlation="corr-complete-first",
            idempotency_key="complete-cap-0",
            result_digest=SHA_B,
        ),
    )
    assert completed.status_code == 200
    retry = client.post(
        "/v1/control/jobs/job-cap-0/complete",
        json=_lease_payload(
            leases[0],
            correlation="corr-complete-retry",
            idempotency_key="complete-cap-0",
            result_digest=SHA_B,
        ),
    )
    assert retry.status_code == 200
    assert retry.json() == completed.json()
    changed = client.post(
        "/v1/control/jobs/job-cap-0/complete",
        json=_lease_payload(
            leases[0],
            correlation="corr-complete-changed",
            idempotency_key="complete-cap-0",
            result_digest="c" * 64,
        ),
    )
    assert changed.status_code == 409


def test_reviewer_subject_provenance_idempotency_reads_and_audit_acl(control) -> None:
    client, _ = control
    reviewer = _principal("reviewer-synthetic", ControlRole.REVIEWER)
    _authenticate(reviewer)

    payload = _review_payload()
    created = client.post("/v1/control/reviews", json=payload)
    assert created.status_code == 201, created.text
    assert created.json()["actor_id"] == "reviewer-synthetic"
    assert client.post("/v1/control/reviews", json=payload).json() == created.json()
    changed = client.post(
        "/v1/control/reviews", json={**payload, "status": "approved"}
    )
    assert changed.status_code == 409

    listed = client.get(
        "/v1/control/reviews/artifact-synthetic?correlation_id=corr-review-list"
    )
    current = client.get(
        "/v1/control/reviews/artifact-synthetic/current?correlation_id=corr-review-read"
    )
    assert listed.status_code == 200
    assert listed.json()["count"] == 1
    assert current.status_code == 200
    assert current.json()["actor_id"] == "reviewer-synthetic"
    paged = client.get(
        "/v1/control/reviews/artifact-synthetic"
        f"?correlation_id=corr-review-page&after_sequence={created.json()['sequence']}&limit=1"
    )
    assert paged.status_code == 200
    assert paged.json() == {"items": [], "count": 0}
    invalid_page = client.get(
        "/v1/control/reviews/artifact-synthetic"
        "?correlation_id=corr-review-page-invalid&limit=101"
    )
    assert invalid_page.status_code == 422
    assert invalid_page.json() == {"detail": "invalid request"}

    for field in ("source", "artifact_id", "revision"):
        invalid = _review_payload(correlation=f"corr-missing-{field}")
        del invalid["provenance"][field]
        assert client.post("/v1/control/reviews", json=invalid).status_code == 422
    uppercase = _review_payload(correlation="corr-uppercase-sha")
    uppercase["provenance"]["sha256"] = "A" * 64
    assert client.post("/v1/control/reviews", json=uppercase).status_code == 422

    audit_denied = client.get(
        "/v1/control/audit-events?correlation_id=corr-reviewer-audit"
    )
    assert audit_denied.status_code == 403


def test_audit_reader_sees_complete_pseudonymous_evidence_and_can_read_one(control) -> None:
    client, _ = control
    worker = _principal("worker-audit-source", ControlRole.DETERMINISTIC_WORKER)
    _authenticate(worker)
    _register(client, "job-audit", correlation="corr-audit-register")
    _acquire(client, "job-audit", correlation="corr-audit-acquire", ttl_seconds=60)

    _authenticate(_principal("audit-reader-synthetic", ControlRole.AUDIT_READER))
    response = client.get(
        "/v1/control/audit-events?correlation_id=corr-audit-list&limit=100"
    )
    assert response.status_code == 200
    events = response.json()["items"]
    accepted = [event for event in events if event["result"] == "accepted"]
    assert [event["action"] for event in accepted] == ["job.register", "job.acquire"]
    assert {event["subject_id"] for event in accepted} == {"worker-audit-source"}
    assert {tuple(event["roles"]) for event in accepted} == {("deterministic_worker",)}
    assert {event["correlation_id"] for event in accepted} == {
        "corr-audit-register",
        "corr-audit-acquire",
    }
    assert all(event["target_id"] == "job-audit" for event in accepted)
    assert all(event["occurred_at"].endswith("Z") for event in accepted)

    event_id = accepted[0]["event_id"]
    one = client.get(
        f"/v1/control/audit-events/{event_id}?correlation_id=corr-audit-read-one"
    )
    assert one.status_code == 200
    assert one.json() == accepted[0]
    missing = client.get(
        "/v1/control/audit-events/missing-event?correlation_id=corr-audit-missing"
    )
    assert missing.status_code == 404


def test_unscoped_control_principal_fails_before_any_store_access(tmp_path: Path) -> None:
    store = SQLiteControlStore(tmp_path / "unscoped.sqlite3")
    service = ControlService(store)
    principal = AuthenticatedPrincipal(
        "worker-unscoped",
        frozenset({ControlRole.DETERMINISTIC_WORKER}),
    )

    with pytest.raises(AuthorizationDeniedError, match="forbidden"):
        service.register_job(
            principal,
            job_id="job-unscoped",
            payload_digest=SHA_A,
            correlation_id="corr-unscoped",
            idempotency_key=None,
        )
    assert store.list_audit_events() == []


def test_same_public_objects_and_idempotency_keys_are_isolated_by_scope(
    tmp_path: Path,
) -> None:
    store = SQLiteControlStore(tmp_path / "scoped.sqlite3")
    service = ControlService(store)
    scope_a = TenantWorkspaceScope("tenant-synthetic", "workspace-alpha")
    scope_b = TenantWorkspaceScope("tenant-synthetic", "workspace-beta")
    worker_a = _principal(
        "worker-alpha", ControlRole.DETERMINISTIC_WORKER, scope=scope_a
    )
    worker_b = _principal(
        "worker-beta", ControlRole.DETERMINISTIC_WORKER, scope=scope_b
    )

    for worker in (worker_a, worker_b):
        record = service.register_job(
            worker,
            job_id="same-job",
            payload_digest=SHA_A,
            correlation_id="corr-register",
            idempotency_key=None,
        )
        assert record.job_id == "same-job"
    assert store.get_job(_qualify(scope_a, "job", "same-job")).job_id != "same-job"
    assert store.get_job(_qualify(scope_b, "job", "same-job")).job_id != "same-job"

    reviewer_a = _principal("reviewer-alpha", ControlRole.REVIEWER, scope=scope_a)
    reviewer_b = _principal("reviewer-beta", ControlRole.REVIEWER, scope=scope_b)
    for reviewer in (reviewer_a, reviewer_b):
        event = service.append_review(
            reviewer,
            target_id="same-target",
            idempotency_key="same-review-idempotency",
            status="pending",
            provenance=_review_payload()["provenance"],
            detail={"synthetic": True},
            correlation_id="corr-review",
        )
        assert event.target_id == "same-target"
        assert event.idempotency_key == "same-review-idempotency"

    events_a = service.list_reviews(
        reviewer_a,
        target_id="same-target",
        correlation_id="corr-list-a",
        after_sequence=0,
        limit=100,
    )
    events_b = service.list_reviews(
        reviewer_b,
        target_id="same-target",
        correlation_id="corr-list-b",
        after_sequence=0,
        limit=100,
    )
    assert [event.sequence for event in events_a] == [1]
    assert [event.sequence for event in events_b] == [1]

    audit_a = service.list_audit_events(
        _principal("auditor-alpha", ControlRole.AUDIT_READER, scope=scope_a),
        correlation_id="corr-audit-a",
        after_sequence=0,
        limit=100,
    )
    audit_b = service.list_audit_events(
        _principal("auditor-beta", ControlRole.AUDIT_READER, scope=scope_b),
        correlation_id="corr-audit-b",
        after_sequence=0,
        limit=100,
    )
    assert {event.subject_id for event in audit_a} == {"worker-alpha", "reviewer-alpha"}
    assert {event.subject_id for event in audit_b} == {"worker-beta", "reviewer-beta"}
    assert [event.sequence for event in audit_a] == list(range(1, len(audit_a) + 1))
    assert [event.sequence for event in audit_b] == list(range(1, len(audit_b) + 1))
    assert all("whscope1" not in repr(event) for event in [*audit_a, *audit_b])
    assert (
        service.read_audit_event(
            _principal("auditor-beta", ControlRole.AUDIT_READER, scope=scope_b),
            event_id=audit_a[0].event_id,
            correlation_id="corr-cross-audit",
        )
        is None
    )


def test_global_lease_cap_is_shared_across_scopes_and_prefix_like_ids_are_opaque(
    tmp_path: Path,
) -> None:
    store = SQLiteControlStore(tmp_path / "global-cap.sqlite3")
    service = ControlService(store)
    workers = [
        _principal(
            f"worker-{index}",
            ControlRole.DETERMINISTIC_WORKER,
            scope=TenantWorkspaceScope("tenant-synthetic", f"workspace-{index}"),
        )
        for index in range(4)
    ]
    public_ids = [
        "same-job",
        "same-job",
        "same-job",
        "whscope1:16:tenant-synthetic:crafted",
    ]
    for worker, job_id in zip(workers, public_ids, strict=True):
        assert (
            service.register_job(
                worker,
                job_id=job_id,
                payload_digest=SHA_A,
                correlation_id="corr-register-cap",
                idempotency_key=None,
            ).job_id
            == job_id
        )
    for worker, job_id in zip(workers[:3], public_ids[:3], strict=True):
        service.acquire(
            worker,
            job_id=job_id,
            ttl_seconds=60,
            correlation_id="corr-acquire-cap",
            idempotency_key=None,
        )
    with pytest.raises(LeaseUnavailableError, match="active lease limit"):
        service.acquire(
            workers[3],
            job_id=public_ids[3],
            ttl_seconds=60,
            correlation_id="corr-fourth-cap",
            idempotency_key=None,
        )


def test_request_body_and_headers_cannot_select_trusted_scope(control) -> None:
    client, _ = control
    scope_a = TenantWorkspaceScope("tenant-synthetic", "workspace-alpha")
    scope_b = TenantWorkspaceScope("tenant-synthetic", "workspace-beta")
    worker_a = _principal(
        "worker-alpha", ControlRole.DETERMINISTIC_WORKER, scope=scope_a
    )
    worker_b = _principal(
        "worker-beta", ControlRole.DETERMINISTIC_WORKER, scope=scope_b
    )
    _authenticate(worker_a)

    injected = client.post(
        "/v1/control/jobs",
        json={
            "job_id": "job-body-scope",
            "payload_digest": SHA_A,
            "correlation_id": "corr-body-scope",
            "tenant_id": scope_b.tenant_id,
            "workspace_id": scope_b.workspace_id,
        },
    )
    assert injected.status_code == 422
    created = client.post(
        "/v1/control/jobs",
        headers={
            "x-tenant-id": scope_b.tenant_id,
            "x-workspace-id": scope_b.workspace_id,
        },
        json={
            "job_id": "job-header-scope",
            "payload_digest": SHA_A,
            "correlation_id": "corr-header-scope",
        },
    )
    assert created.status_code == 201
    assert "whscope1" not in created.text

    _authenticate(worker_b)
    absent = client.post(
        "/v1/control/jobs/job-header-scope/acquire",
        json={"correlation_id": "corr-cross-scope", "ttl_seconds": 60},
    )
    assert absent.status_code == 404
    assert absent.json() == {"detail": "resource not found"}
