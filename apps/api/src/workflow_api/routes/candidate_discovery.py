"""Guarded authenticated candidate-publication discovery route.

The router is absent from the module-global/default application and is
registered only when :mod:`workflow_api.main` receives an exact sealed
candidate runtime bundle.  The default service dependency fails closed; it
never discovers or constructs a publication store, control service, or
alternate authority.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..candidate_discovery_service import (
    CandidateDiscoveryError,
    CandidateDiscoveryService,
    CandidateDiscoveryUnavailableError,
    CandidateDiscoveryValidationError,
    CandidateReviewOutcomeRecord,
    CandidateReviewQueueRecord,
)
from ..candidate_publication_service import CandidatePublicationService
from ..candidate_publication_store import (
    CandidatePublicationError,
    CandidatePublicationMetadata,
    CandidatePublicationValidationError,
)
from ..control_auth import AuthenticatedPrincipal, AuthorizationDeniedError
from ..control_service import ControlService
from ..control_store import _UNSET, ControlConflictError, ControlStoreError
from ..dependencies import get_authenticated_principal, get_control_service

MAX_DISCOVERY_LIMIT = 100

CorrelationId = Annotated[
    str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
]

PrincipalDependency = Annotated[
    AuthenticatedPrincipal, Depends(get_authenticated_principal)
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CandidatePublicationItem(StrictModel):
    """The deliberately narrow, BLOB-free public item projection."""

    publication_key: str
    schema_version: str
    job_id: str
    session_id: str
    source_result_sha256: str
    derivation_evidence_sha256: str
    review_target_id: str
    content_sha256: str
    full_sha256: str
    publication_identity: str
    byte_length: int
    state: str
    finalized_at_us: int

    @classmethod
    def from_metadata(cls, value: CandidatePublicationMetadata) -> CandidatePublicationItem:
        if type(value) is not CandidatePublicationMetadata:
            raise CandidateDiscoveryUnavailableError(
                "candidate discovery returned invalid publication metadata"
            )
        try:
            # Explicit field selection is intentional.  It prevents storage
            # fields such as scope, reservation state, writer epochs, or any
            # future internal fields from crossing this response boundary.
            if value.state != "finalized" or type(value.finalized_at_us) is not int:
                raise ValueError("candidate publication is not finalized")
            return cls(
                publication_key=value.publication_key,
                schema_version=value.schema_version,
                job_id=value.job_id,
                session_id=value.session_id,
                source_result_sha256=value.source_result_sha256,
                derivation_evidence_sha256=value.derivation_evidence_sha256,
                review_target_id=value.review_target_id,
                content_sha256=value.content_sha256,
                full_sha256=value.full_sha256,
                publication_identity=value.publication_identity,
                byte_length=value.byte_length,
                state=value.state,
                finalized_at_us=value.finalized_at_us,
            )
        except (AttributeError, TypeError, ValueError, ValidationError) as exc:
            raise CandidateDiscoveryUnavailableError(
                "candidate discovery returned invalid publication metadata"
            ) from exc


class CandidatePublicationListResponse(StrictModel):
    items: tuple[CandidatePublicationItem, ...]
    count: int
    next_cursor: str | None


_PUBLICATION_KEY_PATTERN = (
    r"^candidate-publication:1\.0:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_REVIEW_TARGET_PATTERN = (
    r"^candidate-skill:1\.0:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:sha256:[a-f0-9]{64}$"
)
CandidatePublicationKey = Annotated[
    str, Field(min_length=1, max_length=128, pattern=_PUBLICATION_KEY_PATTERN)
]
CandidateReviewTarget = Annotated[
    str, Field(min_length=1, max_length=256, pattern=_REVIEW_TARGET_PATTERN)
]


class CandidateReviewQueueItem(StrictModel):
    """Server-only review binding plus bounded informed display evidence."""

    publication_key: CandidatePublicationKey
    review_target_id: CandidateReviewTarget
    command_sequence: tuple[Annotated[str, Field(min_length=1, max_length=128)], ...]
    occurrence_count: Annotated[int, Field(ge=2, le=64)]
    provenance: Literal["observed"]
    review_status: Literal["unreviewed", "pending"]
    finalized_at_us: Annotated[int, Field(gt=0)]

    @classmethod
    def from_record(cls, value: CandidateReviewQueueRecord) -> CandidateReviewQueueItem:
        if type(value) is not CandidateReviewQueueRecord:
            raise CandidateDiscoveryUnavailableError(
                "candidate review queue returned invalid evidence"
            )
        try:
            return cls(
                publication_key=value.publication_key,
                review_target_id=value.review_target_id,
                command_sequence=value.command_sequence,
                occurrence_count=value.occurrence_count,
                provenance=value.provenance,
                review_status=value.review_status,
                finalized_at_us=value.finalized_at_us,
            )
        except (AttributeError, TypeError, ValueError, ValidationError) as exc:
            raise CandidateDiscoveryUnavailableError(
                "candidate review queue returned invalid evidence"
            ) from exc


class CandidateReviewQueueResponse(StrictModel):
    items: tuple[CandidateReviewQueueItem, ...]
    count: int


class CandidateReviewOutcomeItem(StrictModel):
    """Identifier-free, bounded terminal review result."""

    command_sequence: tuple[Annotated[str, Field(min_length=1, max_length=128)], ...]
    occurrence_count: Annotated[int, Field(ge=2, le=64)]
    provenance: Literal["observed"]
    review_status: Literal["approved", "rejected", "needs_changes"]
    decided_at_us: Annotated[int, Field(gt=0)]

    @classmethod
    def from_record(cls, value: CandidateReviewOutcomeRecord) -> CandidateReviewOutcomeItem:
        if type(value) is not CandidateReviewOutcomeRecord:
            raise CandidateDiscoveryUnavailableError(
                "candidate review outcomes returned invalid evidence"
            )
        try:
            return cls(
                command_sequence=value.command_sequence,
                occurrence_count=value.occurrence_count,
                provenance=value.provenance,
                review_status=value.review_status,
                decided_at_us=value.decided_at_us,
            )
        except (AttributeError, TypeError, ValueError, ValidationError) as exc:
            raise CandidateDiscoveryUnavailableError(
                "candidate review outcomes returned invalid evidence"
            ) from exc


class CandidateReviewOutcomesResponse(StrictModel):
    items: tuple[CandidateReviewOutcomeItem, ...]
    count: int


ReviewStatus = Literal["pending", "approved", "rejected", "needs_changes"]
ReviewEvidenceText = Annotated[str, Field(max_length=512)]
ReviewEvidenceValue = ReviewEvidenceText | int | float | bool | None


class CandidateReviewRequest(StrictModel):
    """Only public request evidence needed for one review transition."""

    review_target_id: CandidateReviewTarget
    correlation_id: CorrelationId
    idempotency_key: Annotated[
        str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    ]
    status: ReviewStatus
    reason: str | None = Field(default=None, max_length=512)
    evidence: dict[
        Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")],
        ReviewEvidenceValue,
    ] | None = Field(default=None, max_length=20)


class CandidateReviewResponse(StrictModel):
    """Display-safe result; event/publication/internal identifiers stay server-side."""

    status: ReviewStatus


ControlServiceDependency = Annotated[
    ControlService, Depends(get_control_service)
]


def get_candidate_publication_service() -> CandidatePublicationService:
    """Provide no default publication authority outside explicit synthetic wiring."""

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="candidate publication unavailable",
    )


PublicationServiceDependency = Annotated[
    CandidatePublicationService, Depends(get_candidate_publication_service)
]


def get_candidate_discovery_service() -> CandidateDiscoveryService:
    """Provide no default authority; isolated callers must install one."""

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="candidate discovery unavailable",
    )


ServiceDependency = Annotated[
    CandidateDiscoveryService, Depends(get_candidate_discovery_service)
]


class BoundedValidationRoute(APIRoute):
    """Keep request-validation failures generic and content-independent."""

    def get_route_handler(self):
        original = super().get_route_handler()

        async def bounded_handler(request: Request):
            try:
                return await original(request)
            except RequestValidationError as exc:
                raise HTTPException(status_code=422, detail="invalid request") from exc

        return bounded_handler


router = APIRouter(
    prefix="/v1/control",
    tags=["control"],
    route_class=BoundedValidationRoute,
)


@router.get(
    "/candidate-publications",
    response_model=CandidatePublicationListResponse,
)
def list_candidate_publications(
    correlation_id: Annotated[CorrelationId, Query()],
    principal: PrincipalDependency,
    service: ServiceDependency,
    limit: Annotated[int, Query(ge=1, le=MAX_DISCOVERY_LIMIT)] = MAX_DISCOVERY_LIMIT,
    cursor: Annotated[str | None, Query()] = None,
) -> CandidatePublicationListResponse:
    """List only authenticated, finalized, currently unreviewed metadata."""

    return _call(
        lambda: _list_candidate_publications(
            principal,
            service,
            correlation_id=correlation_id,
            limit=limit,
            cursor=cursor,
        )
    )


def _list_candidate_publications(
    principal: AuthenticatedPrincipal,
    service: CandidateDiscoveryService,
    *,
    correlation_id: str,
    limit: int,
    cursor: str | None,
) -> CandidatePublicationListResponse:
    if type(principal) is not AuthenticatedPrincipal:
        raise CandidateDiscoveryUnavailableError("candidate authentication unavailable")
    if type(service) is not CandidateDiscoveryService:
        raise CandidateDiscoveryUnavailableError("candidate discovery unavailable")

    rows = service.list_finalized_unreviewed(
        principal,
        correlation_id=correlation_id,
        limit=limit,
        cursor=cursor,
    )
    if type(rows) is not list:
        raise CandidateDiscoveryUnavailableError(
            "candidate discovery returned an invalid result"
        )
    if len(rows) > limit:
        raise CandidateDiscoveryUnavailableError(
            "candidate discovery returned an unbounded result"
        )

    try:
        items = tuple(CandidatePublicationItem.from_metadata(row) for row in rows)
    except CandidateDiscoveryUnavailableError:
        raise
    except (AttributeError, TypeError, ValueError, ValidationError) as exc:
        raise CandidateDiscoveryUnavailableError(
            "candidate discovery returned invalid publication metadata"
        ) from exc

    next_cursor = _next_cursor(rows, limit)
    return CandidatePublicationListResponse(
        items=items,
        count=len(items),
        next_cursor=next_cursor,
    )


def _next_cursor(rows: list[CandidatePublicationMetadata], limit: int) -> str | None:
    """Expose continuation only for a full page; the cursor stays opaque."""

    if not rows or len(rows) < limit:
        return None
    try:
        cursor = rows[-1].cursor
        if cursor is None:
            raise ValueError("finalized metadata has no cursor")
        return cursor.encode()
    except (AttributeError, TypeError, ValueError, CandidatePublicationError) as exc:
        raise CandidateDiscoveryUnavailableError(
            "candidate discovery returned invalid cursor metadata"
        ) from exc


@router.get(
    "/candidate-publications/review-queue",
    response_model=CandidateReviewQueueResponse,
)
def list_candidate_review_queue(
    principal: PrincipalDependency,
    service: ServiceDependency,
) -> CandidateReviewQueueResponse:
    """Return fixed, bounded informed evidence for the sealed synthetic reviewer."""

    return _call(lambda: _list_candidate_review_queue(principal, service))


def _list_candidate_review_queue(
    principal: AuthenticatedPrincipal,
    service: CandidateDiscoveryService,
) -> CandidateReviewQueueResponse:
    if type(principal) is not AuthenticatedPrincipal:
        raise CandidateDiscoveryUnavailableError("candidate authentication unavailable")
    if type(service) is not CandidateDiscoveryService:
        raise CandidateDiscoveryUnavailableError("candidate discovery unavailable")
    rows = service.list_review_queue(
        principal,
        correlation_id="candidate-review-queue",
    )
    if type(rows) is not list or len(rows) > MAX_DISCOVERY_LIMIT:
        raise CandidateDiscoveryUnavailableError(
            "candidate review queue returned an invalid result"
        )
    try:
        items = tuple(CandidateReviewQueueItem.from_record(row) for row in rows)
    except CandidateDiscoveryUnavailableError:
        raise
    except (AttributeError, TypeError, ValueError, ValidationError) as exc:
        raise CandidateDiscoveryUnavailableError(
            "candidate review queue returned invalid evidence"
        ) from exc
    return CandidateReviewQueueResponse(items=items, count=len(items))


@router.get(
    "/candidate-publications/review-outcomes",
    response_model=CandidateReviewOutcomesResponse,
)
def list_candidate_review_outcomes(
    principal: PrincipalDependency,
    service: ServiceDependency,
) -> CandidateReviewOutcomesResponse:
    """Return fixed, bounded terminal evidence for the sealed synthetic reviewer."""

    return _call(lambda: _list_candidate_review_outcomes(principal, service))


def _list_candidate_review_outcomes(
    principal: AuthenticatedPrincipal,
    service: CandidateDiscoveryService,
) -> CandidateReviewOutcomesResponse:
    if type(principal) is not AuthenticatedPrincipal:
        raise CandidateDiscoveryUnavailableError("candidate authentication unavailable")
    if type(service) is not CandidateDiscoveryService:
        raise CandidateDiscoveryUnavailableError("candidate discovery unavailable")
    rows = service.list_review_outcomes(
        principal,
        correlation_id="candidate-review-outcomes",
    )
    if type(rows) is not list or len(rows) > MAX_DISCOVERY_LIMIT:
        raise CandidateDiscoveryUnavailableError(
            "candidate review outcomes returned an invalid result"
        )
    try:
        items = tuple(CandidateReviewOutcomeItem.from_record(row) for row in rows)
    except CandidateDiscoveryUnavailableError:
        raise
    except (AttributeError, TypeError, ValueError, ValidationError) as exc:
        raise CandidateDiscoveryUnavailableError(
            "candidate review outcomes returned invalid evidence"
        ) from exc
    return CandidateReviewOutcomesResponse(items=items, count=len(items))


@router.post(
    "/candidate-publications/{publication_key}/review",
    response_model=CandidateReviewResponse,
)
def review_candidate_publication(
    publication_key: Annotated[
        str, Path(min_length=1, max_length=128, pattern=_PUBLICATION_KEY_PATTERN)
    ],
    payload: CandidateReviewRequest,
    principal: PrincipalDependency,
    control_service: ControlServiceDependency,
    service: PublicationServiceDependency,
) -> CandidateReviewResponse:
    """Authorize, bind, and append one synthetic candidate review decision."""

    return _call(
        lambda: _review_candidate_publication(
            publication_key,
            payload,
            principal,
            control_service,
            service,
        )
    )


def _review_candidate_publication(
    publication_key: str,
    payload: CandidateReviewRequest,
    principal: AuthenticatedPrincipal,
    control_service: ControlService,
    service: CandidatePublicationService,
) -> CandidateReviewResponse:
    if type(principal) is not AuthenticatedPrincipal:
        raise CandidateDiscoveryUnavailableError("candidate authentication unavailable")
    if type(control_service) is not ControlService:
        raise CandidateDiscoveryUnavailableError("candidate control service unavailable")
    if type(service) is not CandidatePublicationService:
        raise CandidateDiscoveryUnavailableError("candidate publication unavailable")

    # The capability is issued before the publication authority is checked or
    # read.  Review target identity is public caller evidence; publication
    # metadata remains independently verified by the service below.
    capability = control_service.authorize_candidate_review(
        principal,
        publication_key=publication_key,
        review_target_id=payload.review_target_id,
        correlation_id=payload.correlation_id,
        idempotency_key=payload.idempotency_key,
    )
    evidence = (
        payload.evidence
        if "evidence" in payload.model_fields_set
        else _UNSET
    )
    event = service.review_candidate(
        principal,
        control_service,
        publication_key=publication_key,
        review_target_id=payload.review_target_id,
        idempotency_key=payload.idempotency_key,
        status=payload.status,
        reason=(payload.reason if "reason" in payload.model_fields_set else _UNSET),
        evidence=evidence,
        correlation_id=payload.correlation_id,
        capability=capability,
    )
    try:
        return CandidateReviewResponse(status=event.status)
    except (AttributeError, TypeError, ValueError, ValidationError) as exc:
        raise CandidateDiscoveryUnavailableError(
            "candidate review returned invalid result"
        ) from exc


def _call[T](operation: Callable[[], T]) -> T:
    try:
        return operation()
    except AuthorizationDeniedError as exc:
        raise HTTPException(status_code=403, detail="action forbidden") from exc
    except CandidateDiscoveryValidationError as exc:
        raise HTTPException(status_code=422, detail="invalid request") from exc
    except CandidatePublicationValidationError as exc:
        raise HTTPException(status_code=422, detail="invalid request") from exc
    except ControlConflictError as exc:
        raise HTTPException(
            status_code=409, detail="request conflicts with current state"
        ) from exc
    except CandidatePublicationError as exc:
        raise HTTPException(
            status_code=503, detail="candidate discovery unavailable"
        ) from exc
    except CandidateDiscoveryUnavailableError as exc:
        raise HTTPException(
            status_code=503, detail="candidate discovery unavailable"
        ) from exc
    except CandidateDiscoveryError as exc:
        raise HTTPException(
            status_code=503, detail="candidate discovery unavailable"
        ) from exc
    except (ControlStoreError, sqlite3.Error, OSError, RuntimeError) as exc:
        raise HTTPException(
            status_code=503, detail="candidate discovery unavailable"
        ) from exc
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="invalid request") from exc
    except Exception as exc:
        # Fail closed for an unexpected authority or schema failure.  Never
        # expose raw exception text at this boundary.
        raise HTTPException(
            status_code=503, detail="candidate discovery unavailable"
        ) from exc


__all__ = [
    "BoundedValidationRoute",
    "CandidatePublicationItem",
    "CandidatePublicationListResponse",
    "CandidateReviewQueueItem",
    "CandidateReviewQueueResponse",
    "CandidateReviewRequest",
    "CandidateReviewResponse",
    "get_candidate_discovery_service",
    "get_candidate_publication_service",
    "list_candidate_publications",
    "list_candidate_review_queue",
    "review_candidate_publication",
    "router",
]
