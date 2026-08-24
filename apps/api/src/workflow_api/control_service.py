"""Server-side authenticated boundary for the durable synthetic control store."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .control_auth import (
    AuthenticatedPrincipal,
    AuthorizationDeniedError,
    ControlAction,
    ControlRole,
)
from .control_scope import (
    TenantWorkspaceScope,
    _kind_prefix,
    _qualify,
    _unqualify,
    _validate_scope,
)
from .control_store import (
    _UNSET,
    AuditContext,
    AuditEvent,
    Completion,
    ControlConflictError,
    ControlStoreError,
    JobRecord,
    Lease,
    ReviewEvent,
    ReviewProjection,
    SQLiteControlStore,
    _is_candidate_review_target,
)
from .retention_store import (
    RetentionCopyState,
    RetentionLedger,
    RetentionTargetState,
)

_CANDIDATE_PUBLICATION_PATTERN = re.compile(
    r"^candidate-publication:1\.0:(?P<skill>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"
)
_CANDIDATE_REVIEW_TARGET_PATTERN = re.compile(
    r"^candidate-skill:1\.0:(?P<skill>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):sha256:(?P<content>[a-f0-9]{64})$"
)
_REVIEWER_SUBJECT_PATTERN = re.compile(r"^reviewer_[a-z0-9][a-z0-9_-]{2,63}$")
_CAPABILITY_SEAL = object()


@dataclass(frozen=True, slots=True, init=False)
class CandidateReviewCapability:
    """A short-lived, privately sealed review authorization.

    Instances are issued only by :class:`ControlService`.  The private seal
    and service identity are checked again at every consumer boundary, while
    the immutable public fields make the authorization's complete binding
    explicit for audit and adversarial tests.
    """

    principal: AuthenticatedPrincipal
    scope: TenantWorkspaceScope
    publication_key: str
    review_target_id: str
    correlation_id: str
    idempotency_key: str
    audit: AuditContext
    _control_service: ControlService = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    @classmethod
    def _issue(
        cls,
        *,
        principal: AuthenticatedPrincipal,
        scope: TenantWorkspaceScope,
        publication_key: str,
        review_target_id: str,
        correlation_id: str,
        idempotency_key: str,
        audit: AuditContext,
        control_service: ControlService,
    ) -> CandidateReviewCapability:
        value = object.__new__(cls)
        object.__setattr__(value, "principal", principal)
        object.__setattr__(value, "scope", scope)
        object.__setattr__(value, "publication_key", publication_key)
        object.__setattr__(value, "review_target_id", review_target_id)
        object.__setattr__(value, "correlation_id", correlation_id)
        object.__setattr__(value, "idempotency_key", idempotency_key)
        object.__setattr__(value, "audit", audit)
        object.__setattr__(value, "_control_service", control_service)
        # Keep a private immutable snapshot of every binding.  The snapshot
        # makes accidental or adversarial ``object.__setattr__`` tampering
        # fail closed even though Python's frozen dataclasses can be bypassed
        # by reflection.
        object.__setattr__(
            value,
            "_seal",
            (
                _CAPABILITY_SEAL,
                principal,
                scope,
                publication_key,
                review_target_id,
                correlation_id,
                idempotency_key,
                audit,
                control_service,
            ),
        )
        return value


class ControlService:
    """Authorize first, derive actor identity, then invoke transactional stores."""

    def __init__(
        self,
        store: SQLiteControlStore,
        retention: RetentionLedger | None = None,
    ) -> None:
        self._store = store
        self._retention = retention

    def register_job(
        self,
        principal: AuthenticatedPrincipal,
        *,
        job_id: str,
        payload_digest: str,
        correlation_id: str,
        idempotency_key: str | None,
    ) -> JobRecord:
        scope = self._require_scope(principal)
        audit = self._authorize(
            principal,
            ControlAction.JOB_REGISTER,
            job_id,
            correlation_id,
            idempotency_key,
        )
        record = self._store.register_job(
            _qualify(scope, "job", job_id),
            payload_digest,
            audit=audit,
        )
        return self._public_job(scope, record)

    def acquire(
        self,
        principal: AuthenticatedPrincipal,
        *,
        job_id: str,
        ttl_seconds: int,
        correlation_id: str,
        idempotency_key: str | None,
    ) -> Lease:
        scope = self._require_scope(principal)
        audit = self._authorize(
            principal,
            ControlAction.JOB_ACQUIRE,
            job_id,
            correlation_id,
            idempotency_key,
        )
        lease = self._store.acquire(
            _qualify(scope, "job", job_id),
            principal.subject,
            ttl_seconds=ttl_seconds,
            audit=audit,
        )
        return self._public_lease(scope, lease)

    def heartbeat(
        self,
        principal: AuthenticatedPrincipal,
        *,
        lease: Lease,
        ttl_seconds: int,
        correlation_id: str,
        idempotency_key: str | None,
    ) -> Lease:
        scope = self._require_scope(principal)
        owned_lease = self._owned_lease(principal, lease)
        audit = self._authorize(
            principal,
            ControlAction.JOB_HEARTBEAT,
            owned_lease.job_id,
            correlation_id,
            idempotency_key,
        )
        internal_lease = self._qualified_lease(scope, owned_lease)
        renewed = self._store.heartbeat(
            internal_lease,
            ttl_seconds=ttl_seconds,
            audit=audit,
        )
        return self._public_lease(scope, renewed)

    def complete(
        self,
        principal: AuthenticatedPrincipal,
        *,
        lease: Lease,
        idempotency_key: str,
        result_digest: str,
        correlation_id: str,
    ) -> Completion:
        scope = self._require_scope(principal)
        owned_lease = self._owned_lease(principal, lease)
        audit = self._authorize(
            principal,
            ControlAction.JOB_COMPLETE,
            owned_lease.job_id,
            correlation_id,
            idempotency_key,
        )
        completion = self._store.complete(
            self._qualified_lease(scope, owned_lease),
            idempotency_key=_qualify(scope, "completion_idempotency", idempotency_key),
            result_digest=result_digest,
            audit=audit,
        )
        return self._public_completion(scope, completion)

    def append_review(
        self,
        principal: AuthenticatedPrincipal,
        *,
        target_id: str,
        idempotency_key: str,
        status: str,
        provenance: Mapping[str, Any],
        detail: Mapping[str, Any] | None,
        correlation_id: str,
    ) -> ReviewEvent:
        if _is_candidate_review_target(target_id):
            raise ControlConflictError(
                "candidate review targets require the guarded candidate lifecycle operation"
            )
        scope = self._require_scope(principal)
        audit = self._authorize(
            principal,
            ControlAction.REVIEW_APPEND,
            target_id,
            correlation_id,
            idempotency_key,
        )
        event = self._store.append_review_event(
            target_id=_qualify(scope, "review_target", target_id),
            idempotency_key=_qualify(
                scope, "review_idempotency", idempotency_key
            ),
            actor_id=principal.subject,
            status=status,
            provenance=provenance,
            detail=detail,
            audit=audit,
        )
        return self._public_review_event(scope, event)

    def authorize_candidate_review(
        self,
        principal: AuthenticatedPrincipal,
        *,
        publication_key: str,
        review_target_id: str,
        correlation_id: str,
        idempotency_key: str,
    ) -> CandidateReviewCapability:
        """Authorize one candidate review before any publication lookup.

        The returned capability contains the exact scope, public publication
        identity, review target, request correlation/idempotency bindings, and
        the accepted audit context that must be consumed by the later atomic
        control mutation.  No publication store is consulted here.
        """

        scope = self._require_scope(principal)
        if not isinstance(correlation_id, str) or not correlation_id.strip():
            raise ValueError("correlation_id is required")
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise ValueError("idempotency_key is required")
        audit = self._authorize(
            principal,
            ControlAction.REVIEW_APPEND,
            review_target_id,
            correlation_id,
            idempotency_key,
            _validate_reviewer_subject=True,
        )
        # Authorization, including a durable denial audit, must precede any
        # cross-identity or target-shape validation.  A caller without
        # review.append therefore cannot use a mismatched-but-well-formed
        # publication/target pair to distinguish target validation from
        # authorization.  Accepted callers still receive the exact binding
        # checks before a capability is issued.
        _validate_candidate_review_identity(publication_key, review_target_id)
        return CandidateReviewCapability._issue(
            principal=principal,
            scope=scope,
            publication_key=publication_key,
            review_target_id=review_target_id,
            correlation_id=correlation_id,
            idempotency_key=idempotency_key,
            audit=audit,
            control_service=self,
        )

    # Keep descriptive spellings on this one authorization seam.
    authorize_candidate_review_append = authorize_candidate_review
    authorize_review_append = authorize_candidate_review

    def validate_candidate_review_capability(
        self,
        capability: CandidateReviewCapability,
        principal: AuthenticatedPrincipal,
        *,
        publication_key: str,
        review_target_id: str,
        correlation_id: str,
        idempotency_key: str,
    ) -> AuditContext:
        """Validate every immutable capability binding without re-authorizing."""

        if type(capability) is not CandidateReviewCapability:
            raise ControlConflictError("candidate review capability is invalid")
        seal = capability._seal
        if type(seal) is not tuple or len(seal) != 9 or seal[0] is not _CAPABILITY_SEAL:
            raise ControlConflictError("candidate review capability is invalid")
        if (
            seal[1] != capability.principal
            or seal[2] != capability.scope
            or seal[3] != capability.publication_key
            or seal[4] != capability.review_target_id
            or seal[5] != capability.correlation_id
            or seal[6] != capability.idempotency_key
            or seal[7] != capability.audit
            or seal[8] is not capability._control_service
        ):
            raise ControlConflictError("candidate review capability is invalid")
        if capability._control_service is not self:
            raise ControlConflictError("candidate review capability authority conflicts")
        if type(principal) is not AuthenticatedPrincipal:
            raise ControlConflictError("candidate review principal is invalid")
        if principal != capability.principal:
            raise ControlConflictError("candidate review principal conflicts")
        scope = self._require_scope(principal)
        if capability.scope != scope:
            raise ControlConflictError("candidate review scope conflicts")
        _validate_candidate_review_identity(publication_key, review_target_id)
        if (
            capability.publication_key != publication_key
            or capability.review_target_id != review_target_id
            or capability.correlation_id != correlation_id
            or capability.idempotency_key != idempotency_key
        ):
            raise ControlConflictError("candidate review capability binding conflicts")
        _validate_reviewer_subject(principal.subject)

        audit = capability.audit
        if type(audit) is not AuditContext:
            raise ControlConflictError("candidate review audit binding is invalid")
        expected_target = _qualify(scope, "audit_target", review_target_id)
        expected_idempotency = _qualify(
            scope, "audit_idempotency", idempotency_key
        )
        if (
            audit.correlation_id != correlation_id
            or audit.idempotency_key != expected_idempotency
            or audit.subject_id != principal.subject
            or audit.roles != principal.role_values
            or audit.action != ControlAction.REVIEW_APPEND.value
            or audit.target_id != expected_target
            or audit.result != "accepted"
            or type(audit.occurred_at) is not datetime
            or audit.occurred_at.tzinfo is not UTC
        ):
            raise ControlConflictError("candidate review audit binding conflicts")
        return audit

    def append_candidate_review(
        self,
        principal: AuthenticatedPrincipal,
        *,
        publication_key: str | None = None,
        publication: Any | None = None,
        review_target_id: str | None = None,
        target_id: str | None = None,
        idempotency_key: str,
        status: str | None = None,
        destination_status: str | None = None,
        schema_version: str = "1.0",
        candidate_id: str | None = None,
        skill_id: str | None = None,
        content_sha256: str | None = None,
        full_sha256: str | None = None,
        source_result_sha256: str | None = None,
        reason: str | None | object = _UNSET,
        evidence: Any = _UNSET,
        expected_prior_state: object = _UNSET,
        expected_prior_version: object = _UNSET,
        expected_prior_event_id: object = _UNSET,
        occurred_at: datetime | None = None,
        now: datetime | None = None,
        correlation_id: str,
        capability: CandidateReviewCapability | None = None,
        legacy_provenance: Mapping[str, Any] | None = None,
        legacy_detail: Mapping[str, Any] | None = None,
    ) -> ReviewEvent:
        """Apply one authenticated candidate publication review transition.

        All caller-visible candidate identities are unqualified.  This method
        derives the authenticated scope and reviewer from ``principal`` and
        delegates the sole mutation to ``SQLiteControlStore``'s guarded
        candidate operation.  ``publication`` is an optional metadata object
        accepted for convenience; it is copied only for its digest/identity
        fields and never exposes its BLOBs.
        """

        publication_fields = _publication_review_fields(publication)
        publication_key = _coalesce_review_field(
            publication_key, publication_fields, "publication_key"
        )
        review_target_id = _coalesce_review_field(
            review_target_id if review_target_id is not None else target_id,
            publication_fields,
            "review_target_id",
        )
        if target_id is not None and review_target_id != target_id:
            raise ControlConflictError("candidate review target conflicts")
        content_sha256 = _coalesce_review_field(
            content_sha256, publication_fields, "content_sha256"
        )
        full_sha256 = _coalesce_review_field(full_sha256, publication_fields, "full_sha256")
        source_result_sha256 = _coalesce_review_field(
            source_result_sha256, publication_fields, "source_result_sha256"
        )
        if publication_key is None or review_target_id is None:
            raise ValueError("candidate publication and review target are required")
        if content_sha256 is None or full_sha256 is None or source_result_sha256 is None:
            raise ValueError("candidate publication digests are required")
        scope = self._require_scope(principal)
        if not _is_candidate_review_target(review_target_id):
            raise ControlConflictError("candidate review target syntax is invalid")
        if capability is None:
            audit = self._authorize(
                principal,
                ControlAction.REVIEW_APPEND,
                review_target_id,
                correlation_id,
                idempotency_key,
            )
        else:
            if legacy_provenance is not None or legacy_detail is not None:
                raise ControlConflictError(
                    "legacy candidate review payload cannot use a capability"
                )
            audit = self.validate_candidate_review_capability(
                capability,
                principal,
                publication_key=publication_key,
                review_target_id=review_target_id,
                correlation_id=correlation_id,
                idempotency_key=idempotency_key,
            )
        event = self._store.append_candidate_review_event(
            scope=scope,
            publication_key=publication_key,
            review_target_id=review_target_id,
            idempotency_key=idempotency_key,
            actor_id=principal.subject,
            status=status,
            destination_status=destination_status,
            schema_version=schema_version,
            candidate_id=candidate_id,
            skill_id=skill_id,
            content_sha256=content_sha256,
            full_sha256=full_sha256,
            source_result_sha256=source_result_sha256,
            reason=reason,
            evidence=evidence,
            expected_prior_state=expected_prior_state,
            expected_prior_version=expected_prior_version,
            expected_prior_event_id=expected_prior_event_id,
            occurred_at=occurred_at,
            now=now,
            audit=audit,
            legacy_provenance=legacy_provenance,
            legacy_detail=legacy_detail,
        )
        return self._public_review_event(scope, event)

    # Every spelling resolves to the same guarded operation.
    append_candidate_review_event = append_candidate_review
    transition_candidate_review = append_candidate_review
    review_candidate = append_candidate_review

    def read_candidate_review(
        self,
        principal: AuthenticatedPrincipal,
        *,
        review_target_id: str | None = None,
        target_id: str | None = None,
        correlation_id: str,
    ) -> ReviewProjection | None:
        """Read a candidate projection only after independent event validation."""

        selected_target = review_target_id if review_target_id is not None else target_id
        if review_target_id is not None and target_id is not None and review_target_id != target_id:
            raise ControlConflictError("candidate review target conflicts")
        if selected_target is None or not _is_candidate_review_target(selected_target):
            raise ControlConflictError("candidate review target syntax is invalid")
        scope = self._require_scope(principal)
        self._authorize(
            principal, ControlAction.REVIEW_READ, selected_target, correlation_id, None
        )
        projection = self._store.get_candidate_review_projection(
            _qualify(scope, "review_target", selected_target)
        )
        return None if projection is None else self._public_review_projection(scope, projection)

    def list_reviews(
        self,
        principal: AuthenticatedPrincipal,
        *,
        target_id: str,
        correlation_id: str,
        after_sequence: int,
        limit: int,
    ) -> list[ReviewEvent]:
        if _is_candidate_review_target(target_id):
            scope = self._require_scope(principal)
            self._authorize(
                principal, ControlAction.REVIEW_READ, target_id, correlation_id, None
            )
            events = self._store.list_candidate_review_events(
                _qualify(scope, "review_target", target_id),
                after_sequence=after_sequence,
                limit=limit,
            )
            return [self._public_review_event(scope, event) for event in events]
        scope = self._require_scope(principal)
        self._authorize(
            principal, ControlAction.REVIEW_READ, target_id, correlation_id, None
        )
        events = self._store.list_scoped_review_events(
            _qualify(scope, "review_target", target_id),
            after_sequence=after_sequence,
            limit=limit,
        )
        return [self._public_review_event(scope, event) for event in events]

    def read_review(
        self,
        principal: AuthenticatedPrincipal,
        *,
        target_id: str,
        correlation_id: str,
    ) -> ReviewProjection | None:
        if _is_candidate_review_target(target_id):
            return self.read_candidate_review(
                principal,
                review_target_id=target_id,
                correlation_id=correlation_id,
            )
        scope = self._require_scope(principal)
        self._authorize(
            principal, ControlAction.REVIEW_READ, target_id, correlation_id, None
        )
        projection = self._store.get_review_projection(
            _qualify(scope, "review_target", target_id)
        )
        return (
            None
            if projection is None
            else self._public_review_projection(scope, projection)
        )

    def list_audit_events(
        self,
        principal: AuthenticatedPrincipal,
        *,
        correlation_id: str,
        after_sequence: int,
        limit: int,
    ) -> list[AuditEvent]:
        scope = self._require_scope(principal)
        self._authorize(
            principal, ControlAction.AUDIT_READ, "audit-events", correlation_id, None
        )
        events = self._store.list_scoped_audit_events(
            _kind_prefix(scope, "audit_target"),
            after_sequence=after_sequence,
            limit=limit,
        )
        return [self._public_audit_event(scope, event) for event in events]

    def read_audit_event(
        self,
        principal: AuthenticatedPrincipal,
        *,
        event_id: str,
        correlation_id: str,
    ) -> AuditEvent | None:
        scope = self._require_scope(principal)
        self._authorize(
            principal, ControlAction.AUDIT_READ, event_id, correlation_id, None
        )
        event = self._store.get_scoped_audit_event(
            event_id,
            scope_prefix=_kind_prefix(scope, "audit_target"),
        )
        return None if event is None else self._public_audit_event(scope, event)

    def register_retention(
        self,
        principal: AuthenticatedPrincipal,
        *,
        target_id: str,
        copies: Sequence[Mapping[str, str]],
        correlation_id: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> RetentionTargetState:
        scope = self._require_scope(principal)
        ledger = self._require_retention()
        audit = self._authorize_retention(
            principal,
            ControlAction.RETENTION_REGISTER,
            target_id,
            correlation_id,
            idempotency_key,
        )
        qualified_copies = [
            {
                **dict(copy),
                "copy_id": _qualify(scope, "retention_copy", copy.get("copy_id", "")),
            }
            for copy in copies
        ]
        state = ledger.register_target(
            target_id=_qualify(scope, "retention_target", target_id),
            copies=qualified_copies,
            idempotency_key=_qualify(
                scope, "retention_idempotency", idempotency_key
            ),
            actor_id=principal.subject,
            now=now,
            audit=audit,
        )
        return self._public_retention_state(scope, state)

    def read_retention(
        self,
        principal: AuthenticatedPrincipal,
        *,
        target_id: str,
        correlation_id: str,
    ) -> RetentionTargetState | None:
        scope = self._require_scope(principal)
        ledger = self._require_retention()
        audit = self._authorize_retention(
            principal,
            ControlAction.RETENTION_READ,
            target_id,
            correlation_id,
            None,
        )
        state = ledger.get_target(
            _qualify(scope, "retention_target", target_id),
            audit=audit,
        )
        return None if state is None else self._public_retention_state(scope, state)

    def set_retention_hold(
        self,
        principal: AuthenticatedPrincipal,
        *,
        target_id: str,
        hold: bool,
        reason: str | None,
        correlation_id: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> RetentionTargetState:
        scope = self._require_scope(principal)
        ledger = self._require_retention()
        audit = self._authorize_retention(
            principal,
            ControlAction.RETENTION_HOLD,
            target_id,
            correlation_id,
            idempotency_key,
        )
        state = ledger.set_legal_hold(
            target_id=_qualify(scope, "retention_target", target_id),
            hold=hold,
            reason=reason,
            idempotency_key=_qualify(
                scope, "retention_idempotency", idempotency_key
            ),
            actor_id=principal.subject,
            now=now,
            audit=audit,
        )
        return self._public_retention_state(scope, state)

    def stage_retention_trash(
        self,
        principal: AuthenticatedPrincipal,
        *,
        target_id: str,
        copy_id: str,
        correlation_id: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> RetentionTargetState:
        scope = self._require_scope(principal)
        ledger = self._require_retention()
        audit = self._authorize_retention(
            principal,
            ControlAction.RETENTION_STAGE_TRASH,
            target_id,
            correlation_id,
            idempotency_key,
        )
        state = ledger.stage_trash(
            target_id=_qualify(scope, "retention_target", target_id),
            copy_id=_qualify(scope, "retention_copy", copy_id),
            idempotency_key=_qualify(
                scope, "retention_idempotency", idempotency_key
            ),
            actor_id=principal.subject,
            now=now,
            audit=audit,
        )
        return self._public_retention_state(scope, state)

    def attest_retention_delete(
        self,
        principal: AuthenticatedPrincipal,
        *,
        target_id: str,
        copy_id: str,
        deletion_receipt_sha256: str,
        correlation_id: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> RetentionTargetState:
        scope = self._require_scope(principal)
        ledger = self._require_retention()
        audit = self._authorize_retention(
            principal,
            ControlAction.RETENTION_ATTEST_DELETE,
            target_id,
            correlation_id,
            idempotency_key,
        )
        state = ledger.attest_deleted(
            target_id=_qualify(scope, "retention_target", target_id),
            copy_id=_qualify(scope, "retention_copy", copy_id),
            deletion_receipt_sha256=deletion_receipt_sha256,
            idempotency_key=_qualify(
                scope, "retention_idempotency", idempotency_key
            ),
            actor_id=principal.subject,
            now=now,
            audit=audit,
        )
        return self._public_retention_state(scope, state)

    def list_overdue_retention(
        self,
        principal: AuthenticatedPrincipal,
        *,
        correlation_id: str,
        now: datetime | None = None,
    ) -> list[RetentionTargetState]:
        scope = self._require_scope(principal)
        ledger = self._require_retention()
        audit = self._authorize_retention(
            principal,
            ControlAction.RETENTION_READ,
            "retention-overdue",
            correlation_id,
            None,
        )
        states = ledger.list_scoped_overdue(
            _kind_prefix(scope, "retention_target"),
            now=now,
            audit=audit,
        )
        return [self._public_retention_state(scope, state) for state in states]

    def _authorize(
        self,
        principal: AuthenticatedPrincipal,
        action: ControlAction,
        target_id: str,
        correlation_id: str,
        idempotency_key: str | None,
        *,
        _validate_reviewer_subject: bool = False,
    ) -> AuditContext:
        scope = self._require_scope(principal)
        occurred_at = datetime.now(UTC)
        try:
            principal.require(action)
            if _validate_reviewer_subject:
                _validate_reviewer_subject_value(principal.subject)
        except AuthorizationDeniedError:
            audit = self._audit_context(
                scope,
                principal,
                action,
                target_id,
                correlation_id,
                idempotency_key,
                result="denied",
                occurred_at=occurred_at,
            )
            if (
                self._retention is not None
                and ControlRole.RETENTION_STEWARD in principal.roles
            ):
                self._retention.append_audit_event(audit)
            else:
                self._store.append_audit_event(audit)
            raise
        return self._audit_context(
            scope,
            principal,
            action,
            target_id,
            correlation_id,
            idempotency_key,
            result="accepted",
            occurred_at=occurred_at,
        )

    def _authorize_retention(
        self,
        principal: AuthenticatedPrincipal,
        action: ControlAction,
        target_id: str,
        correlation_id: str,
        idempotency_key: str | None,
    ) -> AuditContext:
        ledger = self._require_retention()
        scope = self._require_scope(principal)
        occurred_at = datetime.now(UTC)
        try:
            principal.require(action)
        except AuthorizationDeniedError:
            ledger.append_audit_event(
                self._audit_context(
                    scope,
                    principal,
                    action,
                    target_id,
                    correlation_id,
                    idempotency_key,
                    result="denied",
                    occurred_at=occurred_at,
                )
            )
            raise
        return self._audit_context(
            scope,
            principal,
            action,
            target_id,
            correlation_id,
            idempotency_key,
            result="accepted",
            occurred_at=occurred_at,
        )

    def _require_retention(self) -> RetentionLedger:
        if self._retention is None:
            raise ControlStoreError("retention ledger unavailable")
        return self._retention

    @staticmethod
    def _require_scope(principal: AuthenticatedPrincipal) -> TenantWorkspaceScope:
        if type(principal) is not AuthenticatedPrincipal or principal.scope is None:
            raise AuthorizationDeniedError("action forbidden")
        try:
            _validate_scope(principal.scope)
        except (TypeError, ValueError) as exc:
            raise AuthorizationDeniedError("action forbidden") from exc
        return principal.scope

    @staticmethod
    def _audit_context(
        scope: TenantWorkspaceScope,
        principal: AuthenticatedPrincipal,
        action: ControlAction,
        target_id: str,
        correlation_id: str,
        idempotency_key: str | None,
        *,
        result: str,
        occurred_at: datetime,
    ) -> AuditContext:
        return AuditContext(
            correlation_id=correlation_id,
            idempotency_key=(
                None
                if idempotency_key is None
                else _qualify(scope, "audit_idempotency", idempotency_key)
            ),
            subject_id=principal.subject,
            roles=principal.role_values,
            action=action.value,
            target_id=_qualify(scope, "audit_target", target_id),
            result=result,
            occurred_at=occurred_at,
        )

    @staticmethod
    def _owned_lease(principal: AuthenticatedPrincipal, lease: Lease) -> Lease:
        return Lease(
            job_id=lease.job_id,
            owner_id=principal.subject,
            fencing_token=lease.fencing_token,
            attempt=lease.attempt,
            acquired_at=lease.acquired_at,
            expires_at=lease.expires_at,
        )

    @staticmethod
    def _qualified_lease(scope: TenantWorkspaceScope, lease: Lease) -> Lease:
        return Lease(
            job_id=_qualify(scope, "job", lease.job_id),
            owner_id=lease.owner_id,
            fencing_token=lease.fencing_token,
            attempt=lease.attempt,
            acquired_at=lease.acquired_at,
            expires_at=lease.expires_at,
        )

    @staticmethod
    def _public_job(scope: TenantWorkspaceScope, value: JobRecord) -> JobRecord:
        return JobRecord(
            job_id=_unqualify(scope, "job", value.job_id),
            payload_digest=value.payload_digest,
            state=value.state,
            created_at=value.created_at,
            updated_at=value.updated_at,
        )

    @staticmethod
    def _public_lease(scope: TenantWorkspaceScope, value: Lease) -> Lease:
        return Lease(
            job_id=_unqualify(scope, "job", value.job_id),
            owner_id=value.owner_id,
            fencing_token=value.fencing_token,
            attempt=value.attempt,
            acquired_at=value.acquired_at,
            expires_at=value.expires_at,
        )

    @staticmethod
    def _public_completion(
        scope: TenantWorkspaceScope,
        value: Completion,
    ) -> Completion:
        return Completion(
            job_id=_unqualify(scope, "job", value.job_id),
            idempotency_key=_unqualify(
                scope, "completion_idempotency", value.idempotency_key
            ),
            result_digest=value.result_digest,
            fencing_token=value.fencing_token,
            completed_at=value.completed_at,
        )

    @staticmethod
    def _public_review_event(
        scope: TenantWorkspaceScope,
        value: ReviewEvent,
    ) -> ReviewEvent:
        target_id = _unqualify(scope, "review_target", value.target_id)
        return ReviewEvent(
            sequence=value.sequence,
            event_id=value.event_id,
            target_id=target_id,
            idempotency_key=_unqualify(
                scope, "review_idempotency", value.idempotency_key
            ),
            actor_id=value.actor_id,
            status=value.status,
            provenance=(
                _public_candidate_json(value.provenance)
                if _is_candidate_review_target(target_id)
                else value.provenance
            ),
            detail=(
                _public_candidate_json(value.detail)
                if _is_candidate_review_target(target_id)
                else value.detail
            ),
            occurred_at=value.occurred_at,
            _content_digest=value.content_digest,
        )

    @staticmethod
    def _public_review_projection(
        scope: TenantWorkspaceScope,
        value: ReviewProjection,
    ) -> ReviewProjection:
        target_id = _unqualify(scope, "review_target", value.target_id)
        return ReviewProjection(
            target_id=target_id,
            status=value.status,
            version=value.version,
            last_event_id=value.last_event_id,
            actor_id=value.actor_id,
            provenance=(
                _public_candidate_json(value.provenance)
                if _is_candidate_review_target(target_id)
                else value.provenance
            ),
            detail=(
                _public_candidate_json(value.detail)
                if _is_candidate_review_target(target_id)
                else value.detail
            ),
            occurred_at=value.occurred_at,
            _content_digest=value.content_digest,
        )

    @staticmethod
    def _public_audit_event(
        scope: TenantWorkspaceScope,
        value: AuditEvent,
    ) -> AuditEvent:
        return AuditEvent(
            sequence=value.sequence,
            event_id=value.event_id,
            correlation_id=value.correlation_id,
            idempotency_key=(
                None
                if value.idempotency_key is None
                else _unqualify(scope, "audit_idempotency", value.idempotency_key)
            ),
            subject_id=value.subject_id,
            roles=value.roles,
            action=value.action,
            target_id=_unqualify(scope, "audit_target", value.target_id),
            result=value.result,
            occurred_at=value.occurred_at,
        )

    @staticmethod
    def _public_retention_state(
        scope: TenantWorkspaceScope,
        value: RetentionTargetState,
    ) -> RetentionTargetState:
        copies = tuple(
            RetentionCopyState(
                copy_id=_unqualify(scope, "retention_copy", copy.copy_id),
                provider=copy.provider,
                file_id=copy.file_id,
                revision=copy.revision,
                sha256=copy.sha256,
                state=copy.state,
                trash_staged_at=copy.trash_staged_at,
                deletion_attested_at=copy.deletion_attested_at,
                deletion_receipt_sha256=copy.deletion_receipt_sha256,
            )
            for copy in value.copies
        )
        return RetentionTargetState(
            target_id=_unqualify(scope, "retention_target", value.target_id),
            created_by=value.created_by,
            created_at=value.created_at,
            expires_at=value.expires_at,
            legal_hold=value.legal_hold,
            hold_reason=value.hold_reason,
            completed_at=value.completed_at,
            copies=copies,
        )


def _validate_reviewer_subject_value(subject: str) -> None:
    if not isinstance(subject, str) or _REVIEWER_SUBJECT_PATTERN.fullmatch(subject) is None:
        raise AuthorizationDeniedError("action forbidden")


def _validate_reviewer_subject(subject: str) -> None:
    """Validate a reviewer identity for capability consumers."""

    _validate_reviewer_subject_value(subject)


def _validate_candidate_review_identity(
    publication_key: str,
    review_target_id: str,
) -> None:
    if not isinstance(publication_key, str):
        raise TypeError("candidate publication key is invalid")
    publication_match = _CANDIDATE_PUBLICATION_PATTERN.fullmatch(publication_key)
    if publication_match is None:
        raise ValueError("candidate publication key is invalid")
    if not isinstance(review_target_id, str):
        raise TypeError("candidate review target is invalid")
    target_match = _CANDIDATE_REVIEW_TARGET_PATTERN.fullmatch(review_target_id)
    if target_match is None:
        raise ValueError("candidate review target is invalid")
    if publication_match.group("skill") != target_match.group("skill"):
        raise ControlConflictError("candidate publication and target identities conflict")


def _publication_review_fields(publication: Any) -> dict[str, Any]:
    if publication is None:
        return {}
    if isinstance(publication, Mapping):
        source = publication
    else:
        source = {
            name: getattr(publication, name, None)
            for name in (
                "publication_key",
                "review_target_id",
                "content_sha256",
                "full_sha256",
                "source_result_sha256",
                "schema_version",
                "job_id",
                "skill_id",
            )
        }
    return {
        key: source[key]
        for key in (
            "publication_key",
            "review_target_id",
            "content_sha256",
            "full_sha256",
            "source_result_sha256",
            "schema_version",
            "job_id",
            "skill_id",
        )
        if key in source and source[key] is not None
    }


def _coalesce_review_field(
    value: Any,
    publication: Mapping[str, Any],
    name: str,
) -> Any:
    if value is not None and name in publication and value != publication[name]:
        raise ControlConflictError(f"candidate publication {name} conflicts")
    return value if value is not None else publication.get(name)


def _public_candidate_json(value: Mapping[str, Any]) -> dict[str, Any]:
    """Remove server-only scope/idempotency bindings from public review JSON."""

    hidden = {
        "scope",
        "qualified_idempotency_key",
        "qualified_review_target_id",
        "server_scope",
    }
    lifecycle = "lifecycle_schema_version" in value or "publication_key" in value
    sensitive_exact = {
        "authorization",
        "canonical_bytes",
        "credential",
        "credentials",
        "derivation_evidence_jcs",
        "password",
        "raw_artifact",
        "reservation_epoch",
        "reservation_expires_at_us",
        "reservation_owner_id",
        "secret",
        "signed_url",
        "token",
        "url",
        "uri",
    }

    def clean(item: Any) -> Any:
        if isinstance(item, Mapping):
            return {
                str(key): clean(child)
                for key, child in item.items()
                if key not in hidden
                and not (
                    lifecycle
                    and (
                        str(key).lower() in sensitive_exact
                        or str(key).lower().endswith(("_url", "_uri", "_token"))
                    )
                )
            }
        if isinstance(item, list):
            return [clean(child) for child in item]
        if isinstance(item, tuple):
            return [clean(child) for child in item]
        if isinstance(item, str):
            if item.startswith("whscope1|"):
                return None
            if lifecycle and item.lower().startswith(("http://", "https://", "file://", "s3://", "gs://")):
                return None
        return item

    cleaned = clean(value)
    assert isinstance(cleaned, dict)
    return cleaned
