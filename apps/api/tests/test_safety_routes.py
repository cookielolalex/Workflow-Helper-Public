from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from workflow_api.control_auth import AuthenticatedPrincipal, ControlRole
from workflow_api.control_scope import TenantWorkspaceScope
from workflow_api.dependencies import (
    get_authenticated_principal,
    get_safety_control_service,
    get_session_security_context_provider,
)
from workflow_api.main import app
from workflow_api.safety_control import SafetyControlService
from workflow_api.safety_switches import SafetyDomain, SafetySwitchLedger
from workflow_api.session_security import (
    SessionSecurityContext,
    SessionTransport,
    csrf_token_digest,
)

SCOPE = TenantWorkspaceScope("tenant-synthetic", "workspace-synthetic")
SESSION_ORIGIN = "https://control.synthetic.test"
SESSION_TOKEN = base64.urlsafe_b64encode(b"s" * 32).decode("ascii").rstrip("=")


class _SessionProvider:
    def __init__(self, principal: AuthenticatedPrincipal):
        now = datetime.now(UTC)
        self.context = SessionSecurityContext(
            principal=principal,
            session_identifier_digest="6" * 64,
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


def _principal(role: ControlRole, subject: str = "safety.steward") -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        subject=subject,
        roles=frozenset({role}),
        scope=SCOPE,
    )


def _install(tmp_path, principal: AuthenticatedPrincipal):
    ledger = SafetySwitchLedger(tmp_path / "safety-route.db")
    service = SafetyControlService(ledger)
    provider = _SessionProvider(principal)
    app.dependency_overrides[get_authenticated_principal] = lambda: principal
    app.dependency_overrides[get_safety_control_service] = lambda: service
    app.dependency_overrides[get_session_security_context_provider] = lambda: provider
    client = TestClient(
        app,
        headers={"Origin": SESSION_ORIGIN, "X-CSRF-Token": SESSION_TOKEN},
    )
    return ledger, client


def test_default_safety_route_fails_closed_without_installed_dependencies() -> None:
    app.dependency_overrides.clear()
    response = TestClient(app).get("/v1/control/safety/switches")

    assert response.status_code == 503
    assert response.json()["detail"] == "control authentication unavailable"


def test_safety_steward_reads_all_and_one_engaged_switch(tmp_path) -> None:
    _, client = _install(tmp_path, _principal(ControlRole.SAFETY_STEWARD))
    try:
        response = client.get("/v1/control/safety/switches")
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["count"] == len(SafetyDomain)
        assert [item["domain"] for item in body["items"]] == [
            domain.value for domain in SafetyDomain
        ]
        assert all(item["engaged"] is True for item in body["items"])

        single = client.get("/v1/control/safety/switches/analysis")
        assert single.status_code == 200
        assert single.json() == {"domain": "analysis", "engaged": True}
    finally:
        app.dependency_overrides.clear()


def test_engage_derives_actor_replays_and_conflicts_fail_closed(tmp_path) -> None:
    ledger, client = _install(
        tmp_path,
        _principal(ControlRole.SAFETY_STEWARD, "safety.operator"),
    )
    payload = {
        "correlation_id": "incident-1",
        "idempotency_key": "analysis-stop-1",
        "reason": "bounded synthetic incident drill",
    }
    try:
        injected = client.post(
            "/v1/control/safety/switches/analysis/engage",
            json={**payload, "actor_id": "attacker"},
        )
        assert injected.status_code == 422
        assert ledger.list_events() == []

        created = client.post(
            "/v1/control/safety/switches/analysis/engage",
            json=payload,
        )
        assert created.status_code == 201, created.text
        event = created.json()
        assert event["domain"] == "analysis"
        assert event["actor_id"] == "safety.operator"
        assert event["correlation_id"] == "incident-1"

        replay = client.post(
            "/v1/control/safety/switches/analysis/engage",
            json=payload,
        )
        assert replay.status_code == 201
        assert replay.json()["event_id"] == event["event_id"]
        assert len(ledger.list_events()) == 1

        conflict = client.post(
            "/v1/control/safety/switches/analysis/engage",
            json={**payload, "reason": "changed reason"},
        )
        assert conflict.status_code == 409
        assert len(ledger.list_events()) == 1

        events = client.get("/v1/control/safety/events?after_sequence=0&limit=1")
        assert events.status_code == 200
        assert events.json()["count"] == 1
        assert events.json()["items"][0]["event_id"] == event["event_id"]

        invalid_page = client.get("/v1/control/safety/events?limit=101")
        assert invalid_page.status_code == 422
    finally:
        app.dependency_overrides.clear()


def test_unrelated_role_is_denied_without_safety_evidence(tmp_path) -> None:
    ledger, client = _install(
        tmp_path,
        _principal(ControlRole.REVIEWER, "reviewer.synthetic"),
    )
    try:
        read = client.get("/v1/control/safety/switches")
        assert read.status_code == 403

        engage = client.post(
            "/v1/control/safety/switches/capture/engage",
            json={
                "correlation_id": "denied-1",
                "idempotency_key": "capture-stop-denied",
                "reason": "must not run",
            },
        )
        assert engage.status_code == 403
        assert ledger.list_events() == []
    finally:
        app.dependency_overrides.clear()


def test_http_surface_has_no_resume_disengage_or_generic_state_route(tmp_path) -> None:
    _, client = _install(tmp_path, _principal(ControlRole.SAFETY_STEWARD))
    try:
        forbidden_paths = (
            "/v1/control/safety/switches/analysis/resume",
            "/v1/control/safety/switches/analysis/disengage",
            "/v1/control/safety/switches/analysis/set-state",
        )
        for path in forbidden_paths:
            assert client.get(path).status_code == 404
            assert client.post(path, json={}).status_code == 404
    finally:
        app.dependency_overrides.clear()
