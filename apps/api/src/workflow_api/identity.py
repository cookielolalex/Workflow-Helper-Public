"""Provider-neutral verified-identity boundary for server-side composition."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from .control_auth import AuthenticatedPrincipal, ControlRole
from .control_scope import TenantWorkspaceScope, _validate_scope

_SUBJECT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_GROUP_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_MAX_GROUPS = 32
_MAX_BINDINGS = 64
_MAX_METHODS = 4
_MAX_SCOPE_BINDINGS = 128


class AuthenticationAssurance(StrEnum):
    SINGLE_FACTOR = "single_factor"
    MULTI_FACTOR = "multi_factor"


class AuthenticationFactor(StrEnum):
    KNOWLEDGE = "knowledge"
    POSSESSION = "possession"
    INHERENCE = "inherence"


class AuthenticationMethod(StrEnum):
    PASSWORD = "password"
    TOTP = "totp"
    SECURITY_KEY = "security_key"
    PLATFORM_BIOMETRIC = "platform_biometric"


_METHOD_FACTORS: dict[AuthenticationMethod, AuthenticationFactor] = {
    AuthenticationMethod.PASSWORD: AuthenticationFactor.KNOWLEDGE,
    AuthenticationMethod.TOTP: AuthenticationFactor.POSSESSION,
    AuthenticationMethod.SECURITY_KEY: AuthenticationFactor.POSSESSION,
    AuthenticationMethod.PLATFORM_BIOMETRIC: AuthenticationFactor.INHERENCE,
}


class IdentityRejectedError(PermissionError):
    """Verified identity evidence was missing, unsupported, or ambiguous."""


@dataclass(frozen=True, slots=True)
class AuthenticationContext:
    """Typed evidence of independently verified authentication factors."""

    assurance: AuthenticationAssurance
    methods: tuple[AuthenticationMethod, ...]

    def __post_init__(self) -> None:
        _validate_authentication_context(self)


@dataclass(frozen=True, slots=True)
class VerifiedIdentityEvidence:
    """Bounded provider-neutral output from a trusted server authenticator."""

    subject: str
    groups: tuple[str, ...]
    authentication_context: AuthenticationContext
    scope: TenantWorkspaceScope

    def __post_init__(self) -> None:
        _validate_verified_evidence(self)


class Authenticator(Protocol):
    """Server-supplied authenticator; no request parsing is defined here."""

    def authenticate(self) -> VerifiedIdentityEvidence:
        """Return provider-neutral evidence after provider verification."""


@dataclass(frozen=True, slots=True)
class GroupRoleBinding:
    group: str
    roles: tuple[ControlRole, ...]

    def __post_init__(self) -> None:
        _validate_binding(self)


@dataclass(frozen=True, slots=True)
class GroupRoleMapping:
    """Exact, case-sensitive, server-owned group allowlist."""

    bindings: tuple[GroupRoleBinding, ...]

    def __post_init__(self) -> None:
        _validate_mapping(self)


@dataclass(frozen=True, slots=True)
class SubjectScopeBinding:
    """One exact server-approved scope for one exact pseudonymous subject."""

    subject: str
    scope: TenantWorkspaceScope

    def __post_init__(self) -> None:
        _validate_scope_binding(self)


@dataclass(frozen=True, slots=True)
class SubjectScopePolicy:
    """Exact server-owned subject-to-scope allowlist with no fallback."""

    bindings: tuple[SubjectScopeBinding, ...]

    def __post_init__(self) -> None:
        _validate_scope_policy(self)


def authenticate_principal(
    authenticator: Authenticator,
    group_role_mapping: GroupRoleMapping,
    subject_scope_policy: SubjectScopePolicy,
) -> AuthenticatedPrincipal:
    """Authenticate and derive only exact allowlisted roles, failing closed."""

    if (
        type(group_role_mapping) is not GroupRoleMapping
        or type(subject_scope_policy) is not SubjectScopePolicy
    ):
        raise IdentityRejectedError("identity rejected")
    try:
        _validate_mapping(group_role_mapping)
        _validate_scope_policy(subject_scope_policy)
        evidence = authenticator.authenticate()
        if type(evidence) is not VerifiedIdentityEvidence:
            raise TypeError("unsupported authenticator output")
        _validate_verified_evidence(evidence)

        roles_by_group = {binding.group: binding.roles for binding in group_role_mapping.bindings}
        resolved_roles: set[ControlRole] = set()
        for group in evidence.groups:
            roles = roles_by_group.get(group)
            if roles is None:
                raise ValueError("unknown group")
            resolved_roles.update(roles)
        if not resolved_roles:
            raise ValueError("identity resolves to zero roles")

        scopes_by_subject = {
            binding.subject: binding.scope for binding in subject_scope_policy.bindings
        }
        allowed_scope = scopes_by_subject.get(evidence.subject)
        if allowed_scope is None or allowed_scope != evidence.scope:
            raise ValueError("identity scope is not exactly allowlisted")

        return AuthenticatedPrincipal(
            evidence.subject,
            frozenset(resolved_roles),
            allowed_scope,
        )
    except IdentityRejectedError:
        raise
    except Exception as exc:
        raise IdentityRejectedError("identity rejected") from exc


def _validate_authentication_context(context: AuthenticationContext) -> None:
    if type(context) is not AuthenticationContext:
        raise TypeError("authentication context must use the exact contract type")
    if context.assurance is not AuthenticationAssurance.MULTI_FACTOR:
        raise ValueError("multi-factor authentication evidence is required")
    if not isinstance(context.methods, tuple):
        raise TypeError("authentication methods must be a tuple")
    if not 2 <= len(context.methods) <= _MAX_METHODS:
        raise ValueError("multi-factor authentication methods are missing or unbounded")
    if any(type(method) is not AuthenticationMethod for method in context.methods):
        raise TypeError("unsupported authentication method")
    if len(set(context.methods)) != len(context.methods):
        raise ValueError("duplicate authentication method")
    factors = {_METHOD_FACTORS[method] for method in context.methods}
    if len(factors) < 2:
        raise ValueError("independent authentication factors are required")


def _validate_verified_evidence(evidence: VerifiedIdentityEvidence) -> None:
    if type(evidence) is not VerifiedIdentityEvidence:
        raise TypeError("identity evidence must use the exact contract type")
    if not isinstance(evidence.subject, str) or not _SUBJECT_PATTERN.fullmatch(
        evidence.subject
    ):
        raise ValueError("subject must be a bounded pseudonymous identifier")
    if not isinstance(evidence.groups, tuple):
        raise TypeError("groups must be a tuple")
    if not 1 <= len(evidence.groups) <= _MAX_GROUPS:
        raise ValueError("groups are missing or unbounded")
    if any(
        not isinstance(group, str) or not _GROUP_PATTERN.fullmatch(group)
        for group in evidence.groups
    ):
        raise ValueError("group must be an exact bounded identifier")
    if len(set(evidence.groups)) != len(evidence.groups):
        raise ValueError("duplicate group is ambiguous")
    _validate_authentication_context(evidence.authentication_context)
    _validate_scope(evidence.scope)


def _validate_binding(binding: GroupRoleBinding) -> None:
    if type(binding) is not GroupRoleBinding:
        raise TypeError("binding must use the exact contract type")
    if not isinstance(binding.group, str) or not _GROUP_PATTERN.fullmatch(binding.group):
        raise ValueError("group must be an exact bounded identifier")
    if not isinstance(binding.roles, tuple):
        raise TypeError("roles must be a tuple")
    if not binding.roles:
        raise ValueError("group binding must map to at least one role")
    if any(type(role) is not ControlRole for role in binding.roles):
        raise TypeError("role must be an exact ControlRole")
    if len(set(binding.roles)) != len(binding.roles):
        raise ValueError("duplicate role is ambiguous")
    # Reuse the canonical role-combination invariant without accepting a roleless identity.
    AuthenticatedPrincipal("mapping-validation", frozenset(binding.roles))


def _validate_mapping(mapping: GroupRoleMapping) -> None:
    if type(mapping) is not GroupRoleMapping:
        raise TypeError("mapping must use the exact contract type")
    if not isinstance(mapping.bindings, tuple):
        raise TypeError("bindings must be a tuple")
    if not 1 <= len(mapping.bindings) <= _MAX_BINDINGS:
        raise ValueError("group mapping is empty or unbounded")
    groups: list[str] = []
    for binding in mapping.bindings:
        _validate_binding(binding)
        groups.append(binding.group)
    if len(set(groups)) != len(groups):
        raise ValueError("duplicate group mapping is ambiguous")


def _validate_scope_binding(binding: SubjectScopeBinding) -> None:
    if type(binding) is not SubjectScopeBinding:
        raise TypeError("scope binding must use the exact contract type")
    if not isinstance(binding.subject, str) or not _SUBJECT_PATTERN.fullmatch(
        binding.subject
    ):
        raise ValueError("subject must be a bounded pseudonymous identifier")
    _validate_scope(binding.scope)


def _validate_scope_policy(policy: SubjectScopePolicy) -> None:
    if type(policy) is not SubjectScopePolicy:
        raise TypeError("scope policy must use the exact contract type")
    if not isinstance(policy.bindings, tuple):
        raise TypeError("scope bindings must be a tuple")
    if not 1 <= len(policy.bindings) <= _MAX_SCOPE_BINDINGS:
        raise ValueError("scope policy is empty or unbounded")
    subjects: list[str] = []
    for binding in policy.bindings:
        _validate_scope_binding(binding)
        subjects.append(binding.subject)
    if len(set(subjects)) != len(subjects):
        raise ValueError("duplicate subject scope is ambiguous")
