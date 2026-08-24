from __future__ import annotations

import pytest

from workflow_api.control_auth import (
    AuthenticatedPrincipal,
    AuthorizationDeniedError,
    ControlAction,
    ControlRole,
)
from workflow_api.safety_control import SafetyControlService
from workflow_api.safety_switches import SafetyDomain, SafetySwitchLedger


def _principal(role: ControlRole, subject: str = "safety.steward") -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(subject=subject, roles=frozenset({role}))


def _service(tmp_path) -> SafetyControlService:
    return SafetyControlService(SafetySwitchLedger(tmp_path / "control.db"))


def test_safety_steward_is_exclusive_and_exactly_scoped() -> None:
    principal = _principal(ControlRole.SAFETY_STEWARD)

    assert principal.allows(ControlAction.SAFETY_READ)
    assert principal.allows(ControlAction.SAFETY_ENGAGE)
    assert not principal.allows(ControlAction.JOB_ACQUIRE)
    assert not principal.allows(ControlAction.RETENTION_HOLD)

    with pytest.raises(ValueError, match="exclusive least-privilege"):
        AuthenticatedPrincipal(
            subject="mixed.safety",
            roles=frozenset(
                {ControlRole.SAFETY_STEWARD, ControlRole.AUDIT_READER}
            ),
        )


def test_non_safety_roles_cannot_read_or_engage(tmp_path) -> None:
    service = _service(tmp_path)
    reviewer = _principal(ControlRole.REVIEWER, "reviewer.one")

    with pytest.raises(AuthorizationDeniedError):
        service.read_all_switches(reviewer)
    with pytest.raises(AuthorizationDeniedError):
        service.engage(
            reviewer,
            domain=SafetyDomain.CAPTURE,
            idempotency_key="capture-stop",
            correlation_id="corr-1",
            reason="stop capture",
        )


def test_safety_steward_reads_engaged_defaults_and_events(tmp_path) -> None:
    service = _service(tmp_path)
    principal = _principal(ControlRole.SAFETY_STEWARD)

    states = service.read_all_switches(principal)
    assert tuple(state.domain for state in states) == tuple(SafetyDomain)
    assert all(state.engaged for state in states)
    assert service.list_events(principal) == []


def test_engage_derives_actor_from_authenticated_principal(tmp_path) -> None:
    service = _service(tmp_path)
    principal = _principal(ControlRole.SAFETY_STEWARD, "safety.operator")

    event = service.engage(
        principal,
        domain=SafetyDomain.ANALYSIS,
        idempotency_key="analysis-stop-1",
        correlation_id="incident-1",
        reason="bounded synthetic incident drill",
    )

    assert event.domain is SafetyDomain.ANALYSIS
    assert event.actor_id == "safety.operator"
    assert service.read_switch(principal, domain=SafetyDomain.ANALYSIS).engaged is True
    assert service.list_events(principal) == [event]


def test_boundary_has_no_resume_or_disengage_operation(tmp_path) -> None:
    service = _service(tmp_path)

    assert not hasattr(service, "resume")
    assert not hasattr(service, "disengage")
    assert not hasattr(service, "set_state")
