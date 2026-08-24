"""Provider-neutral authorization policy for the legacy session/upload surface."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol

from starlette.datastructures import Headers

from .control_auth import AuthenticatedPrincipal, ControlAction, ControlRole
from .control_scope import TenantWorkspaceScope
from .session_security import (
    SessionSecurityContext,
    SessionSecurityRejectedError,
    validate_session_security,
)

_DIGEST_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_CANONICAL_PATH_PATTERN = re.compile(r"^/v1/(?:internal/)?sessions(?:/[a-f0-9-]+(?:/[a-z-]+)?)?$")
_MAX_WORKLOAD_LIFETIME = timedelta(minutes=5)
_MAX_CLOCK_SKEW = timedelta(seconds=60)
_MAX_GENERATION = 2**31 - 1


class LegacySessionAudience(StrEnum):
    CAPTURE_UPLOAD = "workflow-helper:capture-upload"
    PROCESSING_COMPLETION = "workflow-helper:processing-completion"


class LegacySessionTransport(StrEnum):
    CAPTURE_WORKLOAD = "capture_workload"
    WORKER_WORKLOAD = "worker_workload"


class ReplayDecision(StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"


class LegacySessionSecurityRejectedError(PermissionError):
    """The request failed the bounded generic legacy-session policy."""


@dataclass(frozen=True, slots=True)
class LegacyWorkloadContext:
    """Validated provider output; raw credentials are deliberately excluded."""

    principal: AuthenticatedPrincipal
    audience: LegacySessionAudience
    transport: LegacySessionTransport
    method: str
    path: str
    body_sha256: str
    proof_identifier_digest: str
    issued_at: datetime
    expires_at: datetime
    generation: int
    active_generation: int
    revoked: bool
    replay_decision: ReplayDecision

    def __post_init__(self) -> None:
        _validate_workload_shape(self)


class LegacySessionSecurityProvider(Protocol):
    """Request-scoped provider seam with no default implementation."""

    def get_workload_context(
        self,
        *,
        method: str,
        path: str,
        body_sha256: str,
        headers: Headers,
    ) -> LegacyWorkloadContext:
        """Authenticate provider-specific proof and return only validated context."""


@dataclass(frozen=True, slots=True)
class AuthorizedLegacySessionRequest:
    principal: AuthenticatedPrincipal

    @property
    def scope(self) -> TenantWorkspaceScope:
        scope = self.principal.scope
        if scope is None:  # Construction is private to validated authorization paths.
            raise RuntimeError("authorized request lost its scope")
        return scope


def raw_body_sha256(body: bytes) -> str:
    if type(body) is not bytes:
        raise TypeError("body must be exact bytes")
    return hashlib.sha256(body).hexdigest()


def authorize_browser_request(
    *,
    context: SessionSecurityContext,
    principal: AuthenticatedPrincipal,
    method: str,
    path: str,
    headers: Headers,
    action: ControlAction,
    now: datetime | None = None,
) -> AuthorizedLegacySessionRequest:
    """Reuse the verified-identity and PR35 browser-session validator for reads."""

    try:
        if action not in {
            ControlAction.SESSION_LIST,
            ControlAction.SESSION_READ,
            ControlAction.SESSION_TIMELINE_READ,
        }:
            raise ValueError("unsupported browser action")
        _validate_canonical_request(method=method, path=path, expected_method="GET")
        validate_session_security(
            context=context,
            route_principal=principal,
            method=method,
            headers=headers,
            now=now,
        )
        _validate_exact_principal(principal)
        principal.require(action)
        if principal.roles != frozenset({ControlRole.REVIEWER}):
            raise ValueError("browser role must be exact reviewer")
        return AuthorizedLegacySessionRequest(principal)
    except (LegacySessionSecurityRejectedError, SessionSecurityRejectedError):
        raise LegacySessionSecurityRejectedError("request authorization rejected")
    except Exception as exc:
        raise LegacySessionSecurityRejectedError("request authorization rejected") from exc


def authorize_workload_request(
    *,
    context: LegacyWorkloadContext,
    method: str,
    path: str,
    body: bytes,
    action: ControlAction,
    audience: LegacySessionAudience,
    transport: LegacySessionTransport,
    now: datetime | None = None,
) -> AuthorizedLegacySessionRequest:
    """Validate exact integrity, freshness, generation, role, and replay evidence."""

    try:
        evaluation_time = datetime.now(UTC) if now is None else now
        _validate_utc(evaluation_time)
        _validate_workload_shape(context)
        _validate_canonical_request(method=method, path=path, expected_method="POST")
        if context.method != method or context.path != path:
            raise ValueError("request binding mismatch")
        digest = raw_body_sha256(body)
        if not hmac.compare_digest(context.body_sha256, digest):
            raise ValueError("body binding mismatch")
        if context.audience is not audience or context.transport is not transport:
            raise ValueError("workload boundary mismatch")
        if context.revoked or context.replay_decision is not ReplayDecision.ACCEPT:
            raise ValueError("inactive proof")
        if context.generation != context.active_generation:
            raise ValueError("stale generation")
        if context.issued_at > evaluation_time + _MAX_CLOCK_SKEW:
            raise ValueError("future proof")
        if evaluation_time < context.issued_at - _MAX_CLOCK_SKEW:
            raise ValueError("future proof")
        if evaluation_time >= context.expires_at:
            raise ValueError("expired proof")
        principal = context.principal
        _validate_exact_principal(principal)
        principal.require(action)
        expected_role = (
            ControlRole.CAPTURE_UPLOADER
            if transport is LegacySessionTransport.CAPTURE_WORKLOAD
            else ControlRole.DETERMINISTIC_WORKER
        )
        if principal.roles != frozenset({expected_role}):
            raise ValueError("workload role must be exact")
        return AuthorizedLegacySessionRequest(principal)
    except LegacySessionSecurityRejectedError:
        raise
    except Exception as exc:
        raise LegacySessionSecurityRejectedError("request authorization rejected") from exc


def _validate_workload_shape(context: LegacyWorkloadContext) -> None:
    if type(context) is not LegacyWorkloadContext:
        raise TypeError("context must use the exact contract type")
    _validate_exact_principal(context.principal)
    if type(context.audience) is not LegacySessionAudience:
        raise TypeError("invalid audience")
    if type(context.transport) is not LegacySessionTransport:
        raise TypeError("invalid transport")
    _validate_canonical_request(method=context.method, path=context.path, expected_method="POST")
    for digest in (context.body_sha256, context.proof_identifier_digest):
        if not isinstance(digest, str) or not _DIGEST_PATTERN.fullmatch(digest):
            raise ValueError("invalid digest")
    _validate_utc(context.issued_at)
    _validate_utc(context.expires_at)
    if not context.issued_at < context.expires_at:
        raise ValueError("ill-ordered proof timestamps")
    if context.expires_at - context.issued_at > _MAX_WORKLOAD_LIFETIME:
        raise ValueError("proof lifetime exceeds cap")
    for generation in (context.generation, context.active_generation):
        if type(generation) is not int or not 1 <= generation <= _MAX_GENERATION:
            raise ValueError("invalid generation")
    if type(context.revoked) is not bool:
        raise TypeError("revocation decision must be exact bool")
    if type(context.replay_decision) is not ReplayDecision:
        raise TypeError("invalid replay decision")


def _validate_exact_principal(principal: AuthenticatedPrincipal) -> None:
    if type(principal) is not AuthenticatedPrincipal or principal.scope is None:
        raise TypeError("exact scoped principal required")
    if AuthenticatedPrincipal(principal.subject, principal.roles, principal.scope) != principal:
        raise ValueError("ambiguous principal")


def _validate_canonical_request(*, method: str, path: str, expected_method: str) -> None:
    if method != expected_method or method != method.upper():
        raise ValueError("method mismatch")
    if not isinstance(path, str) or not _CANONICAL_PATH_PATTERN.fullmatch(path):
        raise ValueError("non-canonical path")


def _validate_utc(value: datetime) -> None:
    if type(value) is not datetime or value.tzinfo is not UTC:
        raise ValueError("timestamp must be an exact UTC datetime")
