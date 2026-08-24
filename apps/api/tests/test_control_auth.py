from dataclasses import FrozenInstanceError

import pytest

from workflow_api.control_auth import (
    AuthenticatedPrincipal,
    AuthorizationDeniedError,
    ControlAction,
    ControlRole,
)
from workflow_api.control_scope import TenantWorkspaceScope


def _principal(*roles: ControlRole) -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal("subject-synthetic-1", frozenset(roles))


def test_principal_is_frozen_pseudonymous_and_supports_multiple_exact_roles() -> None:
    principal = _principal(ControlRole.REVIEWER, ControlRole.AUDIT_READER)

    assert principal.role_values == ("audit_reader", "reviewer")
    assert principal.allows(ControlAction.REVIEW_APPEND)
    assert principal.allows(ControlAction.REVIEW_READ)
    assert principal.allows(ControlAction.AUDIT_READ)
    assert not principal.allows(ControlAction.JOB_ACQUIRE)
    with pytest.raises(FrozenInstanceError):
        principal.subject = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    "invalid_roles",
    [
        frozenset({"*"}),
        frozenset({"review"}),
        frozenset({"reviewer_extra"}),
        frozenset({"Reviewer"}),
        frozenset({"REVIEWER"}),
    ],
)
def test_wildcard_substring_and_case_confused_roles_are_rejected(
    invalid_roles: frozenset[str],
) -> None:
    with pytest.raises(TypeError, match="exact ControlRole"):
        AuthenticatedPrincipal("subject-synthetic-1", invalid_roles)  # type: ignore[arg-type]


def test_role_container_and_subject_are_not_normalized_or_coerced() -> None:
    with pytest.raises(TypeError, match="frozenset"):
        AuthenticatedPrincipal("subject-synthetic-1", {ControlRole.REVIEWER})  # type: ignore[arg-type]
    for subject in ("Subject-Synthetic-1", " subject-synthetic-1", "a", "subject@synthetic"):
        with pytest.raises(ValueError, match="pseudonymous"):
            AuthenticatedPrincipal(subject, frozenset())


def test_retention_steward_uses_exclusive_least_privilege_identity() -> None:
    steward = _principal(ControlRole.RETENTION_STEWARD)
    assert steward.role_values == ("retention_steward",)
    for action in (
        ControlAction.RETENTION_REGISTER,
        ControlAction.RETENTION_READ,
        ControlAction.RETENTION_HOLD,
        ControlAction.RETENTION_STAGE_TRASH,
        ControlAction.RETENTION_ATTEST_DELETE,
    ):
        assert steward.allows(action)
    assert not steward.allows(ControlAction.REVIEW_APPEND)
    assert not steward.allows(ControlAction.JOB_REGISTER)

    with pytest.raises(ValueError, match="exclusive"):
        _principal(ControlRole.RETENTION_STEWARD, ControlRole.AUDIT_READER)


def test_roleless_principal_is_denied_every_action() -> None:
    principal = _principal()

    for action in ControlAction:
        assert not principal.allows(action)
        with pytest.raises(AuthorizationDeniedError, match="forbidden"):
            principal.require(action)


def test_each_single_role_has_only_its_enumerated_actions() -> None:
    expected = {
        ControlRole.CAPTURE_UPLOADER: {
            ControlAction.SESSION_REGISTER,
            ControlAction.SESSION_PRESIGN,
            ControlAction.SESSION_UPLOAD_COMPLETE,
        },
        ControlRole.DETERMINISTIC_WORKER: {
            ControlAction.SESSION_PROCESSING_COMPLETE,
            ControlAction.JOB_REGISTER,
            ControlAction.JOB_ACQUIRE,
            ControlAction.JOB_HEARTBEAT,
            ControlAction.JOB_COMPLETE,
        },
        ControlRole.REVIEWER: {
            ControlAction.SESSION_LIST,
            ControlAction.SESSION_READ,
            ControlAction.SESSION_TIMELINE_READ,
            ControlAction.REVIEW_APPEND,
            ControlAction.REVIEW_READ,
        },
        ControlRole.AUDIT_READER: {ControlAction.AUDIT_READ},
        ControlRole.RETENTION_STEWARD: {
            ControlAction.RETENTION_REGISTER,
            ControlAction.RETENTION_READ,
            ControlAction.RETENTION_HOLD,
            ControlAction.RETENTION_STAGE_TRASH,
            ControlAction.RETENTION_ATTEST_DELETE,
        },
    }

    for role, allowed in expected.items():
        principal = _principal(role)
        assert {action for action in ControlAction if principal.allows(action)} == allowed


def test_principal_scope_is_optional_immutable_and_exact() -> None:
    scope = TenantWorkspaceScope("tenant-synthetic", "workspace-synthetic")
    scoped = AuthenticatedPrincipal(
        "subject-synthetic-1",
        frozenset({ControlRole.REVIEWER}),
        scope,
    )
    assert scoped.scope == scope
    with pytest.raises(FrozenInstanceError):
        scoped.scope = None  # type: ignore[misc]

    unscoped_safety = AuthenticatedPrincipal(
        "safety-steward-synthetic",
        frozenset({ControlRole.SAFETY_STEWARD}),
    )
    assert unscoped_safety.scope is None
    assert unscoped_safety.allows(ControlAction.SAFETY_ENGAGE)
