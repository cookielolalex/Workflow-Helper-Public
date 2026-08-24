"""Synthetic authenticated-principal and exact authorization policy."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from .control_scope import TenantWorkspaceScope, _validate_scope

_SUBJECT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")


class ControlRole(StrEnum):
    CAPTURE_UPLOADER = "capture_uploader"
    DETERMINISTIC_WORKER = "deterministic_worker"
    REVIEWER = "reviewer"
    AUDIT_READER = "audit_reader"
    RETENTION_STEWARD = "retention_steward"
    SAFETY_STEWARD = "safety_steward"


class ControlAction(StrEnum):
    SESSION_REGISTER = "session.register"
    SESSION_PRESIGN = "session.presign"
    SESSION_UPLOAD_COMPLETE = "session.upload_complete"
    SESSION_LIST = "session.list"
    SESSION_READ = "session.read"
    SESSION_TIMELINE_READ = "session.timeline_read"
    SESSION_PROCESSING_COMPLETE = "session.processing_complete"
    JOB_REGISTER = "job.register"
    JOB_ACQUIRE = "job.acquire"
    JOB_HEARTBEAT = "job.heartbeat"
    JOB_COMPLETE = "job.complete"
    REVIEW_APPEND = "review.append"
    REVIEW_READ = "review.read"
    AUDIT_READ = "audit.read"
    RETENTION_REGISTER = "retention.register"
    RETENTION_READ = "retention.read"
    RETENTION_HOLD = "retention.hold"
    RETENTION_STAGE_TRASH = "retention.stage_trash"
    RETENTION_ATTEST_DELETE = "retention.attest_delete"
    SAFETY_READ = "safety.read"
    SAFETY_ENGAGE = "safety.engage"


_ROLE_ACTIONS: dict[ControlRole, frozenset[ControlAction]] = {
    ControlRole.CAPTURE_UPLOADER: frozenset(
        {
            ControlAction.SESSION_REGISTER,
            ControlAction.SESSION_PRESIGN,
            ControlAction.SESSION_UPLOAD_COMPLETE,
        }
    ),
    ControlRole.DETERMINISTIC_WORKER: frozenset(
        {
            ControlAction.SESSION_PROCESSING_COMPLETE,
            ControlAction.JOB_REGISTER,
            ControlAction.JOB_ACQUIRE,
            ControlAction.JOB_HEARTBEAT,
            ControlAction.JOB_COMPLETE,
        }
    ),
    ControlRole.REVIEWER: frozenset(
        {
            ControlAction.SESSION_LIST,
            ControlAction.SESSION_READ,
            ControlAction.SESSION_TIMELINE_READ,
            ControlAction.REVIEW_APPEND,
            ControlAction.REVIEW_READ,
        }
    ),
    ControlRole.AUDIT_READER: frozenset({ControlAction.AUDIT_READ}),
    ControlRole.RETENTION_STEWARD: frozenset(
        {
            ControlAction.RETENTION_REGISTER,
            ControlAction.RETENTION_READ,
            ControlAction.RETENTION_HOLD,
            ControlAction.RETENTION_STAGE_TRASH,
            ControlAction.RETENTION_ATTEST_DELETE,
        }
    ),
    ControlRole.SAFETY_STEWARD: frozenset(
        {ControlAction.SAFETY_READ, ControlAction.SAFETY_ENGAGE}
    ),
}

_EXCLUSIVE_ROLES = frozenset(
    {ControlRole.RETENTION_STEWARD, ControlRole.SAFETY_STEWARD}
)


class AuthorizationDeniedError(PermissionError):
    """The authenticated principal lacks the exact required action."""


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    """Immutable pseudonymous identity installed by a future authenticator."""

    subject: str
    roles: frozenset[ControlRole]
    scope: TenantWorkspaceScope | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.subject, str) or not _SUBJECT_PATTERN.fullmatch(self.subject):
            raise ValueError("subject must be a bounded pseudonymous identifier")
        if not isinstance(self.roles, frozenset):
            raise TypeError("roles must be a frozenset")
        for role in self.roles:
            if not isinstance(role, ControlRole):
                raise TypeError("role must be an exact ControlRole")
        if self.scope is not None:
            _validate_scope(self.scope)
        exclusive = self.roles.intersection(_EXCLUSIVE_ROLES)
        if exclusive and len(self.roles) != 1:
            role = next(iter(exclusive)).value
            raise ValueError(f"{role} must use an exclusive least-privilege identity")

    def allows(self, action: ControlAction) -> bool:
        if not isinstance(action, ControlAction):
            return False
        return any(action in _ROLE_ACTIONS[role] for role in self.roles)

    def require(self, action: ControlAction) -> None:
        if not self.allows(action):
            raise AuthorizationDeniedError("action forbidden")

    @property
    def role_values(self) -> tuple[str, ...]:
        return tuple(sorted(role.value for role in self.roles))
