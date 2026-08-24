"""Dormant application boundary for one complete candidate publication.

The service is intentionally small.  It accepts evidence that an upstream
caller has already verified, asks the publication domain to prepare the exact
canonical bytes before any durable operation, and delegates reservation and
finalization to :mod:`candidate_publication_store`.  It does not discover
providers, read artifacts, consult configuration, or open a database while
being imported or constructed.

Only the store's metadata projection crosses this boundary.  In particular,
the derivation-evidence and canonical-byte BLOBs held by a store record are
never returned by this service.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .candidate_authority import verify_candidate_authority
from .candidate_publication_store import (
    CandidatePublicationError,
    CandidatePublicationMetadata,
    CandidatePublicationRecord,
    CandidatePublicationValidationError,
    SQLiteCandidatePublicationStore,
    canonical_candidate_publication_bytes,
)
from .control_auth import AuthenticatedPrincipal
from .control_scope import TenantWorkspaceScope
from .control_service import CandidateReviewCapability, ControlService
from .control_store import _UNSET, ControlConflictError
from .models import ProcessingJobV2, ProcessingResultV2

# Public aliases keep the application boundary's failure vocabulary stable
# while the immutable store remains the authority for domain-specific errors.
CandidatePublicationServiceError = CandidatePublicationError
CandidatePublicationServiceValidationError = CandidatePublicationValidationError


@dataclass(frozen=True, slots=True)
class CandidatePublicationRequest:
    """Complete, explicit input for one reserve/finalize attempt.

    ``timeline_commands`` is the caller-supplied occurrence evidence expected
    by the publication domain.  It is deliberately not derived here from the
    result.  The two counts are explicit as well: a caller that does not hold
    complete evidence must fail before the store can mutate.
    """

    scope: TenantWorkspaceScope
    job: ProcessingJobV2
    result: ProcessingResultV2
    result_manifest: Mapping[str, Any]
    timeline_binding: Mapping[str, Any]
    drawing_ref: str
    timeline_commands: Sequence[Mapping[str, Any]]
    rejected_alternative_count: int
    qualifying_run_length: int
    reservation_owner_id: str
    lease_duration_seconds: int
    now: int | datetime | None = None
    envelope_version: str = "1.0"


# The metadata projection is the service response contract: no canonical or
# evidence bytes, raw artifact values, provider state, or qualified key are
# present in it.  Keeping an alias also makes the relationship to the public
# store type obvious to callers.
CandidatePublicationResponse = CandidatePublicationMetadata
CandidatePublicationResult = CandidatePublicationMetadata
_MISSING = object()


class CandidatePublicationService:
    """Coordinate one complete immutable publication through the public store."""

    def __init__(
        self,
        store: SQLiteCandidatePublicationStore,
        control_service: ControlService | None = None,
    ) -> None:
        # Do not inspect paths or otherwise touch the store here.  The store is
        # injected already constructed; service construction itself is inert.
        if type(store) is not SQLiteCandidatePublicationStore:
            raise TypeError("store must use the exact SQLiteCandidatePublicationStore type")
        if control_service is not None and type(control_service) is not ControlService:
            raise TypeError("control_service must use the exact ControlService type")
        self._store = store
        self._control_service = control_service

    def publish(
        self,
        request: CandidatePublicationRequest | None = None,
        *,
        scope: TenantWorkspaceScope | object = _MISSING,
        job: ProcessingJobV2 | object = _MISSING,
        result: ProcessingResultV2 | object = _MISSING,
        result_manifest: Mapping[str, Any] | object = _MISSING,
        timeline_binding: Mapping[str, Any] | object = _MISSING,
        drawing_ref: str | object = _MISSING,
        timeline_commands: Sequence[Mapping[str, Any]] | object = _MISSING,
        rejected_alternative_count: int | object = _MISSING,
        qualifying_run_length: int | object = _MISSING,
        reservation_owner_id: str | object = _MISSING,
        lease_duration_seconds: int | object = _MISSING,
        now: int | datetime | None = None,
        envelope_version: str = "1.0",
    ) -> CandidatePublicationMetadata:
        """Reserve and finalize one complete evidence envelope.

        Preparation through the public canonicalization seam happens before
        ``reserve``.  A finalized reservation is an independently verified
        replay and is returned directly; otherwise the exact prepared bytes
        are passed to the store's fenced finalizer.
        """

        if request is None:
            missing = [
                name
                for name, value in (
                    ("scope", scope),
                    ("job", job),
                    ("result", result),
                    ("result_manifest", result_manifest),
                    ("timeline_binding", timeline_binding),
                    ("drawing_ref", drawing_ref),
                    ("timeline_commands", timeline_commands),
                    ("rejected_alternative_count", rejected_alternative_count),
                    ("qualifying_run_length", qualifying_run_length),
                    ("reservation_owner_id", reservation_owner_id),
                    ("lease_duration_seconds", lease_duration_seconds),
                )
                if value is _MISSING
            ]
            if missing:
                raise CandidatePublicationValidationError(
                    "complete publication inputs are required"
                )
            request = CandidatePublicationRequest(
                scope=scope,
                job=job,
                result=result,
                result_manifest=result_manifest,
                timeline_binding=timeline_binding,
                drawing_ref=drawing_ref,
                timeline_commands=timeline_commands,
                rejected_alternative_count=rejected_alternative_count,
                qualifying_run_length=qualifying_run_length,
                reservation_owner_id=reservation_owner_id,
                lease_duration_seconds=lease_duration_seconds,
                now=now,
                envelope_version=envelope_version,
            )
        elif any(
            value is not _MISSING
            for value in (
                scope,
                job,
                result,
                result_manifest,
                timeline_binding,
                drawing_ref,
                timeline_commands,
                rejected_alternative_count,
                qualifying_run_length,
                reservation_owner_id,
                lease_duration_seconds,
            )
        ):
            raise CandidatePublicationValidationError(
                "request cannot be combined with explicit publication inputs"
            )
        return self._publish_request(request)

    def publish_request(self, request: CandidatePublicationRequest) -> CandidatePublicationMetadata:
        """Publish one already assembled request object."""

        return self._publish_request(request)

    def _publish_request(
        self, request: CandidatePublicationRequest
    ) -> CandidatePublicationMetadata:
        if type(request) is not CandidatePublicationRequest:
            raise CandidatePublicationValidationError(
                "request must use the exact CandidatePublicationRequest type"
            )
        envelope = _evidence_envelope(request)

        # This is the only service-side preparation.  Canonicalization,
        # admission, digest, identity, and candidate-shape logic remain owned
        # by the publication domain's public helper.
        canonical_bytes = canonical_candidate_publication_bytes(envelope)

        reserved = self._store.reserve(
            request.scope,
            envelope,
            reservation_owner_id=request.reservation_owner_id,
            lease_duration_seconds=request.lease_duration_seconds,
            now=request.now,
        )
        if reserved.state == "finalized":
            return _response_metadata(reserved)
        if reserved.state != "reserved":
            # The store currently admits only these states.  Keep this guard
            # stable if a future store implementation returns an unknown one.
            raise CandidatePublicationError("candidate publication state is invalid")

        finalized = self._store.finalize(
            request.scope,
            reserved.publication_key,
            reservation_owner_id=request.reservation_owner_id,
            reservation_epoch=reserved.reservation_epoch,
            canonical_bytes=canonical_bytes,
            now=request.now,
        )
        return _response_metadata(finalized)

    # The explicit names are useful to an adapter while retaining exactly the
    # same operation and validation semantics.
    publish_candidate = publish
    publish_publication = publish

    def review_candidate(
        self,
        principal: AuthenticatedPrincipal | ControlService | None = None,
        control_service: ControlService | AuthenticatedPrincipal | None = None,
        *,
        publication: CandidatePublicationRecord | CandidatePublicationMetadata | Mapping[str, Any] | None = None,
        scope: TenantWorkspaceScope | None = None,
        publication_key: str | None = None,
        review_target_id: str | None = None,
        target_id: str | None = None,
        idempotency_key: str,
        status: str | None = None,
        destination_status: str | None = None,
        reason: str | None | object = _UNSET,
        evidence: Any = _UNSET,
        expected_prior_state: object = _UNSET,
        expected_prior_version: object = _UNSET,
        expected_prior_event_id: object = _UNSET,
        correlation_id: str,
        now: int | datetime | None = None,
        capability: CandidateReviewCapability | None = None,
    ):
        """Review one independently verified finalized publication.

        Publication storage remains responsible for immutable bytes and the
        control service remains the sole review authority.  This boundary only
        joins their already-public metadata projections; it never returns a
        publication BLOB or writes a second review record.
        """

        # Accept both adapter conventions: principal-first (matching
        # ControlService) and the explicit control-service-first form used by
        # the functional wrapper.  Both resolve to the same injected control
        # authority before any publication read occurs.
        if type(principal) is ControlService:
            if type(control_service) is not AuthenticatedPrincipal:
                raise TypeError("principal must use the exact AuthenticatedPrincipal type")
            principal, control_service = control_service, principal
        control_service = control_service or self._control_service
        if type(control_service) is not ControlService:
            raise TypeError("control_service must use the exact ControlService type")
        if self._control_service is not None and control_service is not self._control_service:
            raise ControlConflictError("candidate control authority conflicts")
        if type(principal) is not AuthenticatedPrincipal:
            raise TypeError("principal must use the exact AuthenticatedPrincipal type")
        publication_fields = _publication_fields(publication)
        selected_key = publication_key or publication_fields.get("publication_key")
        selected_target = review_target_id if review_target_id is not None else target_id
        if review_target_id is not None and target_id is not None and review_target_id != target_id:
            raise CandidatePublicationValidationError("review target identifiers conflict")
        if selected_target is None:
            selected_target = publication_fields.get("review_target_id")
        if selected_key is None:
            raise CandidatePublicationValidationError("publication_key is required")
        if selected_target is None:
            raise CandidatePublicationValidationError("review_target_id is required")

        # Authorization is deliberately completed before the authority check
        # and before the first publication-store read.  The route supplies the
        # capability; direct legacy callers receive the same pre-read
        # authorization from this adapter.
        if capability is None:
            publication_scope = _publication_scope(publication)
            if (
                scope is not None
                and publication_scope is not None
                and scope != publication_scope
            ):
                raise CandidatePublicationValidationError(
                    "publication scope identifiers conflict"
                )
            selected_scope = scope or publication_scope
            if type(selected_scope) is not TenantWorkspaceScope:
                raise CandidatePublicationValidationError(
                    "scope must use the exact TenantWorkspaceScope type"
                )
            capability = control_service.authorize_candidate_review(
                principal,
                publication_key=selected_key,
                review_target_id=selected_target,
                correlation_id=correlation_id,
                idempotency_key=idempotency_key,
            )
            if selected_scope != capability.scope:
                raise ControlConflictError("candidate review scope conflicts")
        else:
            # Treat capabilities as opaque until the control authority has
            # checked their exact type, private seal, service identity, and
            # every request binding.  In particular, do not dereference
            # ``capability.scope`` before validation: forged objects must be
            # rejected as a controlled conflict before any publication read.
            control_service.validate_candidate_review_capability(
                capability,
                principal,
                publication_key=selected_key,
                review_target_id=selected_target,
                correlation_id=correlation_id,
                idempotency_key=idempotency_key,
            )
            if scope is not None and scope != capability.scope:
                raise ControlConflictError("candidate review scope conflicts")
            publication_scope = _publication_scope(publication)
            if publication_scope is not None and publication_scope != capability.scope:
                raise ControlConflictError("candidate review scope conflicts")
            selected_scope = capability.scope

        # Reuse the discovery service's exact path/inode/schema authority
        # proof.  This must stay immediately before get_finalized so an
        # unavailable or cross-bound authority cannot become an existence
        # oracle.
        verify_candidate_authority(self._store, control_service)
        record = self._store.get_finalized(selected_scope, selected_key)
        # Compare any caller-supplied metadata against the independently
        # verified row before entering the control mutation boundary.
        for field in (
            "publication_key",
            "review_target_id",
            "content_sha256",
            "full_sha256",
            "source_result_sha256",
        ):
            supplied = publication_fields.get(field)
            if supplied is not None and supplied != getattr(record, field):
                raise CandidatePublicationError(
                    f"candidate publication {field} conflicts with stored identity"
                )
        if selected_target != record.review_target_id:
            raise CandidatePublicationError("candidate publication review target conflicts")
        # ``None`` means the caller did not override the store's expected
        # initial state.  The ControlService/ControlStore pair will resolve
        # the current projection atomically; explicit values can still be
        # supplied through the same keyword fields.
        return control_service.append_candidate_review(
            principal,
            publication=record,
            idempotency_key=idempotency_key,
            status=status,
            destination_status=destination_status,
            reason=reason,
            evidence=evidence,
            expected_prior_state=expected_prior_state,
            expected_prior_version=expected_prior_version,
            expected_prior_event_id=expected_prior_event_id,
            correlation_id=correlation_id,
            now=(_datetime_from_value(now) if now is not None else None),
            capability=capability,
        )

    review_publication = review_candidate
    transition_candidate_review = review_candidate

    def review(
        self,
        principal: AuthenticatedPrincipal,
        control_service: ControlService | None = None,
        **inputs: Any,
    ):
        """Principal-first spelling for adapters that inject the control service."""

        return self.review_candidate(principal, control_service, **inputs)


def publish_candidate(
    service: CandidatePublicationService,
    request: CandidatePublicationRequest | None = None,
    **inputs: Any,
) -> CandidatePublicationMetadata:
    """Functional spelling of :meth:`CandidatePublicationService.publish`."""

    if type(service) is not CandidatePublicationService:
        raise TypeError("service must use the exact CandidatePublicationService type")
    return service.publish(request, **inputs)


def review_candidate_publication(
    service: CandidatePublicationService,
    control_service: ControlService,
    principal: AuthenticatedPrincipal,
    **inputs: Any,
):
    if type(service) is not CandidatePublicationService:
        raise TypeError("service must use the exact CandidatePublicationService type")
    return service.review_candidate(principal, control_service, **inputs)


def _publication_fields(publication: Any) -> dict[str, Any]:
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
            )
        }
    return {
        field: source[field]
        for field in (
            "publication_key",
            "review_target_id",
            "content_sha256",
            "full_sha256",
            "source_result_sha256",
        )
        if field in source and source[field] is not None
    }


def _publication_scope(publication: Any) -> TenantWorkspaceScope | None:
    if publication is None:
        return None
    value = getattr(publication, "scope", None)
    if isinstance(value, TenantWorkspaceScope):
        return value
    tenant = getattr(publication, "tenant_id", None)
    workspace = getattr(publication, "workspace_id", None)
    if tenant is not None and workspace is not None:
        return TenantWorkspaceScope(tenant, workspace)
    if isinstance(publication, Mapping):
        tenant = publication.get("tenant_id")
        workspace = publication.get("workspace_id")
        if tenant is not None and workspace is not None:
            return TenantWorkspaceScope(tenant, workspace)
    return None


def _datetime_from_value(value: int | datetime) -> datetime:
    if isinstance(value, datetime):
        return value
    if type(value) is int:
        return datetime.fromtimestamp(value / 1_000_000, tz=UTC)
    raise CandidatePublicationValidationError("review timestamp must be integer micros or datetime")


def _evidence_envelope(request: CandidatePublicationRequest) -> dict[str, Any]:
    """Validate request shape and form the complete store envelope.

    This function copies only caller-provided containers.  It never fills in
    missing occurrences, manifest values, drawing identity, or lease data.
    Fixed contract values are accepted only when supplied explicitly through
    the request's fields/defaulted schema version.
    """

    if type(request.scope) is not TenantWorkspaceScope:
        raise CandidatePublicationValidationError(
            "scope must use the exact TenantWorkspaceScope type"
        )
    if type(request.job) is not ProcessingJobV2:
        raise CandidatePublicationValidationError(
            "job must use the exact ProcessingJobV2 type"
        )
    if type(request.result) is not ProcessingResultV2:
        raise CandidatePublicationValidationError(
            "result must use the exact ProcessingResultV2 type"
        )
    if not isinstance(request.result_manifest, Mapping):
        raise CandidatePublicationValidationError("result_manifest must be an object")
    if not isinstance(request.timeline_binding, Mapping):
        raise CandidatePublicationValidationError("timeline_binding must be an object")
    if type(request.drawing_ref) is not str:
        raise CandidatePublicationValidationError("drawing_ref must be text")
    if type(request.timeline_commands) is not list:
        raise CandidatePublicationValidationError("timeline_commands must be an array")
    if any(not isinstance(item, Mapping) for item in request.timeline_commands):
        raise CandidatePublicationValidationError(
            "timeline_commands must contain objects"
        )
    if type(request.rejected_alternative_count) is not int:
        raise CandidatePublicationValidationError(
            "rejected_alternative_count must be an integer"
        )
    if type(request.qualifying_run_length) is not int:
        raise CandidatePublicationValidationError(
            "qualifying_run_length must be an integer"
        )
    if type(request.envelope_version) is not str:
        raise CandidatePublicationValidationError("envelope_version must be text")
    if type(request.reservation_owner_id) is not str:
        raise CandidatePublicationValidationError(
            "reservation_owner_id must be text"
        )
    if type(request.lease_duration_seconds) is not int:
        raise CandidatePublicationValidationError(
            "lease_duration_seconds must be an integer"
        )

    # The service does not reinterpret or normalize evidence.  The store's
    # public admission seam remains responsible for all nested validation.
    return {
        "envelope_version": request.envelope_version,
        "job": request.job,
        "result": request.result,
        "result_manifest": dict(request.result_manifest),
        "timeline_binding": dict(request.timeline_binding),
        "drawing_ref": request.drawing_ref,
        "occurrences": list(request.timeline_commands),
        "rejected_alternative_count": request.rejected_alternative_count,
        "qualifying_run_length": request.qualifying_run_length,
    }


def _response_metadata(record: CandidatePublicationRecord) -> CandidatePublicationMetadata:
    """Return only the store's BLOB-free public projection."""

    if type(record) is not CandidatePublicationRecord:
        raise CandidatePublicationError("candidate publication record type is invalid")
    return record.without_bytes()


__all__ = [
    "CandidatePublicationRequest",
    "CandidatePublicationResponse",
    "CandidatePublicationResult",
    "CandidatePublicationService",
    "CandidatePublicationServiceError",
    "CandidatePublicationServiceValidationError",
    "publish_candidate",
    "review_candidate_publication",
]
