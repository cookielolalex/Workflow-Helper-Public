from __future__ import annotations

from dataclasses import FrozenInstanceError, dataclass
from typing import cast

import pytest
from fastapi import HTTPException, status

from workflow_api.control_auth import ControlRole
from workflow_api.control_scope import TenantWorkspaceScope
from workflow_api.dependencies import get_authenticated_principal
from workflow_api.identity import (
    AuthenticationAssurance,
    AuthenticationContext,
    AuthenticationMethod,
    GroupRoleBinding,
    GroupRoleMapping,
    IdentityRejectedError,
    SubjectScopeBinding,
    SubjectScopePolicy,
    VerifiedIdentityEvidence,
    authenticate_principal,
)

SCOPE = TenantWorkspaceScope("tenant-synthetic", "workspace-synthetic")


@dataclass
class FakeAuthenticator:
    output: object

    def authenticate(self) -> VerifiedIdentityEvidence:
        return cast(VerifiedIdentityEvidence, self.output)


def _mfa() -> AuthenticationContext:
    return AuthenticationContext(
        AuthenticationAssurance.MULTI_FACTOR,
        (AuthenticationMethod.PASSWORD, AuthenticationMethod.TOTP),
    )


def _evidence(
    *groups: str,
    subject: str = "subject-synthetic-1",
    scope: TenantWorkspaceScope = SCOPE,
) -> VerifiedIdentityEvidence:
    return VerifiedIdentityEvidence(subject, groups, _mfa(), scope)


def _mapping(*bindings: GroupRoleBinding) -> GroupRoleMapping:
    return GroupRoleMapping(bindings)


def _binding(group: str, *roles: ControlRole) -> GroupRoleBinding:
    return GroupRoleBinding(group, roles)


def _scope_policy(
    subject: str = "subject-synthetic-1",
    scope: TenantWorkspaceScope = SCOPE,
) -> SubjectScopePolicy:
    return SubjectScopePolicy((SubjectScopeBinding(subject, scope),))


def test_exact_groups_map_to_only_existing_exact_control_roles() -> None:
    mapping = _mapping(
        _binding("workers", ControlRole.DETERMINISTIC_WORKER),
        _binding("auditors", ControlRole.AUDIT_READER),
    )

    principal = authenticate_principal(
        FakeAuthenticator(_evidence("workers", "auditors")),
        mapping,
        _scope_policy(),
    )

    assert principal.subject == "subject-synthetic-1"
    assert principal.roles == frozenset(
        {ControlRole.DETERMINISTIC_WORKER, ControlRole.AUDIT_READER}
    )
    assert principal.scope == SCOPE


def test_evidence_and_authentication_context_are_frozen() -> None:
    evidence = _evidence("reviewers")
    with pytest.raises(FrozenInstanceError):
        evidence.subject = "changed"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        evidence.authentication_context.methods = ()  # type: ignore[misc]


@pytest.mark.parametrize(
    "context",
    [
        (AuthenticationAssurance.SINGLE_FACTOR, (AuthenticationMethod.PASSWORD,)),
        (AuthenticationAssurance.MULTI_FACTOR, (AuthenticationMethod.PASSWORD,)),
        (
            AuthenticationAssurance.MULTI_FACTOR,
            (AuthenticationMethod.TOTP, AuthenticationMethod.SECURITY_KEY),
        ),
        (
            AuthenticationAssurance.MULTI_FACTOR,
            (AuthenticationMethod.PASSWORD, AuthenticationMethod.PASSWORD),
        ),
    ],
)
def test_missing_or_unsupported_mfa_context_is_rejected(context: tuple[object, object]) -> None:
    assurance, methods = context
    with pytest.raises((TypeError, ValueError)):
        AuthenticationContext(assurance, methods)  # type: ignore[arg-type]

    with pytest.raises((TypeError, ValueError), match="unsupported"):
        AuthenticationContext(
            AuthenticationAssurance.MULTI_FACTOR,
            (AuthenticationMethod.PASSWORD, "sms"),  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "subject",
    ["", "ab", " Subject", "Subject", "subject@example", "subject synthetic", "x" * 129],
)
def test_invalid_or_non_pseudonymous_subject_is_rejected(subject: str) -> None:
    with pytest.raises(ValueError, match="pseudonymous"):
        _evidence("reviewers", subject=subject)


def test_duplicate_unknown_case_changed_substring_and_wildcard_groups_fail_closed() -> None:
    mapping = _mapping(_binding("reviewers", ControlRole.REVIEWER))

    with pytest.raises(ValueError, match="duplicate"):
        _evidence("reviewers", "reviewers")
    for group in ("Reviewers", "review", "reviewers-extra"):
        with pytest.raises(IdentityRejectedError, match="identity rejected"):
            authenticate_principal(
                FakeAuthenticator(_evidence(group)), mapping, _scope_policy()
            )
    for group in ("*", "review*", "reviewers/*"):
        with pytest.raises(ValueError, match="exact bounded"):
            _evidence(group)


def test_empty_duplicate_ambiguous_and_zero_role_mappings_are_rejected() -> None:
    reviewer = _binding("reviewers", ControlRole.REVIEWER)
    with pytest.raises(ValueError, match="empty"):
        _mapping()
    with pytest.raises(ValueError, match="at least one role"):
        _binding("reviewers")
    with pytest.raises(ValueError, match="duplicate group"):
        _mapping(reviewer, reviewer)
    with pytest.raises(ValueError, match="duplicate role"):
        _binding("reviewers", ControlRole.REVIEWER, ControlRole.REVIEWER)
    for role in ("*", "review", "Reviewer"):
        with pytest.raises(TypeError, match="exact ControlRole"):
            GroupRoleBinding("reviewers", (role,))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "roles",
    [
        (ControlRole.RETENTION_STEWARD, ControlRole.AUDIT_READER),
        (ControlRole.SAFETY_STEWARD, ControlRole.AUDIT_READER),
    ],
)
def test_exclusive_steward_role_combinations_are_rejected(
    roles: tuple[ControlRole, ControlRole],
) -> None:
    with pytest.raises(ValueError, match="exclusive"):
        GroupRoleBinding("stewards", roles)

    mapping = _mapping(
        _binding("retention-stewards", ControlRole.RETENTION_STEWARD),
        _binding("auditors", ControlRole.AUDIT_READER),
    )
    with pytest.raises(IdentityRejectedError, match="identity rejected"):
        authenticate_principal(
            FakeAuthenticator(_evidence("retention-stewards", "auditors")),
            mapping,
            _scope_policy(),
        )


def test_authenticator_output_is_revalidated_and_cannot_bypass_frozen_constructor() -> None:
    forged = object.__new__(VerifiedIdentityEvidence)
    object.__setattr__(forged, "subject", "Subject-Not-Pseudonymous")
    object.__setattr__(forged, "groups", ("reviewers",))
    object.__setattr__(forged, "authentication_context", _mfa())
    object.__setattr__(forged, "scope", SCOPE)

    with pytest.raises(IdentityRejectedError, match="identity rejected"):
        authenticate_principal(
            FakeAuthenticator(forged),
            _mapping(_binding("reviewers", ControlRole.REVIEWER)),
            _scope_policy(),
        )


def test_unsupported_authenticator_output_and_authenticator_failure_fail_closed() -> None:
    mapping = _mapping(_binding("reviewers", ControlRole.REVIEWER))
    with pytest.raises(IdentityRejectedError, match="identity rejected"):
        authenticate_principal(FakeAuthenticator(object()), mapping, _scope_policy())

    class FailingAuthenticator:
        def authenticate(self) -> VerifiedIdentityEvidence:
            raise RuntimeError("provider detail must not escape")

    with pytest.raises(IdentityRejectedError, match="identity rejected") as caught:
        authenticate_principal(FailingAuthenticator(), mapping, _scope_policy())
    assert "provider detail" not in str(caught.value)


def test_scope_must_be_exact_lowercase_bounded_and_server_allowlisted() -> None:
    mapping = _mapping(_binding("reviewers", ControlRole.REVIEWER))
    other_scope = TenantWorkspaceScope("tenant-synthetic", "workspace-other")

    with pytest.raises(IdentityRejectedError, match="identity rejected"):
        authenticate_principal(
            FakeAuthenticator(_evidence("reviewers", scope=other_scope)),
            mapping,
            _scope_policy(),
        )
    with pytest.raises(IdentityRejectedError, match="identity rejected"):
        authenticate_principal(
            FakeAuthenticator(_evidence("reviewers", subject="subject-unknown")),
            mapping,
            _scope_policy(),
        )

    for value in ("Workspace-Synthetic", "workspace*", "ab", "x" * 65):
        with pytest.raises(ValueError, match="exact lowercase bounded"):
            TenantWorkspaceScope("tenant-synthetic", value)


def test_scope_policy_rejects_duplicate_or_ambiguous_subject_bindings() -> None:
    binding = SubjectScopeBinding("subject-synthetic-1", SCOPE)
    with pytest.raises(ValueError, match="empty"):
        SubjectScopePolicy(())
    with pytest.raises(ValueError, match="duplicate subject"):
        SubjectScopePolicy(
            (
                binding,
                SubjectScopeBinding(
                    "subject-synthetic-1",
                    TenantWorkspaceScope("tenant-synthetic", "workspace-other"),
                ),
            )
        )


def test_forged_scope_contract_is_revalidated_after_authentication() -> None:
    forged = object.__new__(TenantWorkspaceScope)
    object.__setattr__(forged, "tenant_id", "Tenant-Synthetic")
    object.__setattr__(forged, "workspace_id", "workspace-synthetic")
    evidence = object.__new__(VerifiedIdentityEvidence)
    object.__setattr__(evidence, "subject", "subject-synthetic-1")
    object.__setattr__(evidence, "groups", ("reviewers",))
    object.__setattr__(evidence, "authentication_context", _mfa())
    object.__setattr__(evidence, "scope", forged)

    with pytest.raises(IdentityRejectedError, match="identity rejected"):
        authenticate_principal(
            FakeAuthenticator(evidence),
            _mapping(_binding("reviewers", ControlRole.REVIEWER)),
            _scope_policy(),
        )


def test_default_runtime_dependency_remains_bounded_503() -> None:
    with pytest.raises(HTTPException) as caught:
        get_authenticated_principal()

    assert caught.value.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert caught.value.detail == "control authentication unavailable"
