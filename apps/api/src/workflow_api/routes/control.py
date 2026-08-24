"""Bounded, synthetic-only authenticated control-service routes."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from ..control_auth import AuthenticatedPrincipal, AuthorizationDeniedError
from ..control_service import ControlService
from ..control_store import (
    AuditEvent,
    Completion,
    ControlConflictError,
    ControlStoreError,
    JobNotFoundError,
    JobRecord,
    Lease,
    LeaseUnavailableError,
    ReviewEvent,
    ReviewProjection,
    StaleLeaseError,
)
from ..dependencies import get_authenticated_principal, get_control_service

Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")]
CorrelationId = Annotated[
    str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
]
Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
ShortText = Annotated[str, Field(min_length=1, max_length=128)]
DetailText = Annotated[str, Field(max_length=512)]
DetailValue = DetailText | int | float | bool | None

PrincipalDependency = Annotated[
    AuthenticatedPrincipal, Depends(get_authenticated_principal)
]
ServiceDependency = Annotated[ControlService, Depends(get_control_service)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RequestEvidence(StrictModel):
    correlation_id: CorrelationId
    idempotency_key: Identifier | None = None


class RegisterJobRequest(RequestEvidence):
    job_id: Identifier
    payload_digest: Digest


class AcquireRequest(RequestEvidence):
    ttl_seconds: int = Field(default=1800, ge=1, le=1800)


class LeaseRequest(RequestEvidence):
    fencing_token: int = Field(gt=0)
    attempt: int = Field(gt=0)
    acquired_at: AwareDatetime
    expires_at: AwareDatetime

    def as_lease(self, job_id: str) -> Lease:
        return Lease(
            job_id=job_id,
            owner_id="derived-by-service",
            fencing_token=self.fencing_token,
            attempt=self.attempt,
            acquired_at=self.acquired_at,
            expires_at=self.expires_at,
        )


class HeartbeatRequest(LeaseRequest):
    ttl_seconds: int = Field(default=1800, ge=1, le=1800)


class CompleteRequest(LeaseRequest):
    idempotency_key: Identifier
    result_digest: Digest


class ReviewProvenance(StrictModel):
    source: ShortText
    artifact_id: Identifier
    revision: ShortText
    sha256: Digest


class AppendReviewRequest(StrictModel):
    target_id: Identifier
    correlation_id: CorrelationId
    idempotency_key: Identifier
    status: Literal["pending", "approved", "rejected", "needs_changes"]
    provenance: ReviewProvenance
    detail: dict[Identifier, DetailValue] = Field(default_factory=dict, max_length=20)


class JobResponse(StrictModel):
    job_id: str
    payload_digest: str
    state: str
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_record(cls, value: JobRecord) -> JobResponse:
        return cls.model_validate(value, from_attributes=True)


class LeaseResponse(StrictModel):
    job_id: str
    fencing_token: int
    attempt: int
    acquired_at: datetime
    expires_at: datetime

    @classmethod
    def from_lease(cls, value: Lease) -> LeaseResponse:
        return cls.model_validate(value, from_attributes=True)


class CompletionResponse(StrictModel):
    job_id: str
    idempotency_key: str
    result_digest: str
    fencing_token: int
    completed_at: datetime

    @classmethod
    def from_completion(cls, value: Completion) -> CompletionResponse:
        return cls.model_validate(value, from_attributes=True)


class ReviewEventResponse(StrictModel):
    sequence: int
    event_id: str
    target_id: str
    idempotency_key: str
    actor_id: str
    status: str
    provenance: dict[str, object]
    detail: dict[str, object]
    occurred_at: datetime

    @classmethod
    def from_event(cls, value: ReviewEvent) -> ReviewEventResponse:
        return cls.model_validate(value, from_attributes=True)


class ReviewListResponse(StrictModel):
    items: list[ReviewEventResponse]
    count: int


class ReviewProjectionResponse(StrictModel):
    target_id: str
    status: str
    version: int
    last_event_id: str
    actor_id: str
    provenance: dict[str, object]
    detail: dict[str, object]
    occurred_at: datetime

    @classmethod
    def from_projection(cls, value: ReviewProjection) -> ReviewProjectionResponse:
        return cls.model_validate(value, from_attributes=True)


class AuditEventResponse(StrictModel):
    sequence: int
    event_id: str
    correlation_id: str
    idempotency_key: str | None
    subject_id: str
    roles: tuple[str, ...]
    action: str
    target_id: str
    result: str
    occurred_at: datetime

    @classmethod
    def from_event(cls, value: AuditEvent) -> AuditEventResponse:
        return cls.model_validate(value, from_attributes=True)


class AuditListResponse(StrictModel):
    items: list[AuditEventResponse]
    count: int


class BoundedValidationRoute(APIRoute):
    """Keep validation responses generic and independent of submitted content."""

    def get_route_handler(self):
        original = super().get_route_handler()

        async def bounded_handler(request: Request):
            try:
                return await original(request)
            except RequestValidationError as exc:
                raise HTTPException(status_code=422, detail="invalid request") from exc

        return bounded_handler


router = APIRouter(
    prefix="/v1/control", tags=["control"], route_class=BoundedValidationRoute
)


@router.post("/jobs", response_model=JobResponse, status_code=status.HTTP_201_CREATED)
def register_job(
    payload: RegisterJobRequest,
    principal: PrincipalDependency,
    service: ServiceDependency,
) -> JobResponse:
    record = _call(
        lambda: service.register_job(
            principal,
            job_id=payload.job_id,
            payload_digest=payload.payload_digest,
            correlation_id=payload.correlation_id,
            idempotency_key=payload.idempotency_key,
        )
    )
    return JobResponse.from_record(record)


@router.post("/jobs/{job_id}/acquire", response_model=LeaseResponse)
def acquire_job(
    job_id: Identifier,
    payload: AcquireRequest,
    principal: PrincipalDependency,
    service: ServiceDependency,
) -> LeaseResponse:
    lease = _call(
        lambda: service.acquire(
            principal,
            job_id=job_id,
            ttl_seconds=payload.ttl_seconds,
            correlation_id=payload.correlation_id,
            idempotency_key=payload.idempotency_key,
        )
    )
    return LeaseResponse.from_lease(lease)


@router.post("/jobs/{job_id}/heartbeat", response_model=LeaseResponse)
def heartbeat_job(
    job_id: Identifier,
    payload: HeartbeatRequest,
    principal: PrincipalDependency,
    service: ServiceDependency,
) -> LeaseResponse:
    lease = _call(
        lambda: service.heartbeat(
            principal,
            lease=payload.as_lease(job_id),
            ttl_seconds=payload.ttl_seconds,
            correlation_id=payload.correlation_id,
            idempotency_key=payload.idempotency_key,
        )
    )
    return LeaseResponse.from_lease(lease)


@router.post("/jobs/{job_id}/complete", response_model=CompletionResponse)
def complete_job(
    job_id: Identifier,
    payload: CompleteRequest,
    principal: PrincipalDependency,
    service: ServiceDependency,
) -> CompletionResponse:
    completion = _call(
        lambda: service.complete(
            principal,
            lease=payload.as_lease(job_id),
            idempotency_key=payload.idempotency_key,
            result_digest=payload.result_digest,
            correlation_id=payload.correlation_id,
        )
    )
    return CompletionResponse.from_completion(completion)


@router.post(
    "/reviews", response_model=ReviewEventResponse, status_code=status.HTTP_201_CREATED
)
def append_review(
    payload: AppendReviewRequest,
    principal: PrincipalDependency,
    service: ServiceDependency,
) -> ReviewEventResponse:
    event = _call(
        lambda: service.append_review(
            principal,
            target_id=payload.target_id,
            idempotency_key=payload.idempotency_key,
            status=payload.status,
            provenance=payload.provenance.model_dump(),
            detail=payload.detail,
            correlation_id=payload.correlation_id,
        )
    )
    return ReviewEventResponse.from_event(event)


@router.get("/reviews/{target_id}", response_model=ReviewListResponse)
def list_reviews(
    target_id: Identifier,
    correlation_id: Annotated[CorrelationId, Query()],
    principal: PrincipalDependency,
    service: ServiceDependency,
    after_sequence: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> ReviewListResponse:
    events = _call(
        lambda: service.list_reviews(
            principal,
            target_id=target_id,
            correlation_id=correlation_id,
            after_sequence=after_sequence,
            limit=limit,
        )
    )
    items = [ReviewEventResponse.from_event(event) for event in events]
    return ReviewListResponse(items=items, count=len(items))


@router.get("/reviews/{target_id}/current", response_model=ReviewProjectionResponse)
def read_review(
    target_id: Identifier,
    correlation_id: Annotated[CorrelationId, Query()],
    principal: PrincipalDependency,
    service: ServiceDependency,
) -> ReviewProjectionResponse:
    projection = _call(
        lambda: service.read_review(
            principal,
            target_id=target_id,
            correlation_id=correlation_id,
        )
    )
    if projection is None:
        raise HTTPException(status_code=404, detail="resource not found")
    return ReviewProjectionResponse.from_projection(projection)


@router.get("/audit-events", response_model=AuditListResponse)
def list_audit_events(
    correlation_id: Annotated[CorrelationId, Query()],
    principal: PrincipalDependency,
    service: ServiceDependency,
    after_sequence: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> AuditListResponse:
    events = _call(
        lambda: service.list_audit_events(
            principal,
            correlation_id=correlation_id,
            after_sequence=after_sequence,
            limit=limit,
        )
    )
    items = [AuditEventResponse.from_event(event) for event in events]
    return AuditListResponse(items=items, count=len(items))


@router.get("/audit-events/{event_id}", response_model=AuditEventResponse)
def read_audit_event(
    event_id: Identifier,
    correlation_id: Annotated[CorrelationId, Query()],
    principal: PrincipalDependency,
    service: ServiceDependency,
) -> AuditEventResponse:
    event = _call(
        lambda: service.read_audit_event(
            principal,
            event_id=event_id,
            correlation_id=correlation_id,
        )
    )
    if event is None:
        raise HTTPException(status_code=404, detail="resource not found")
    return AuditEventResponse.from_event(event)


def _call(operation):
    try:
        return operation()
    except AuthorizationDeniedError as exc:
        raise HTTPException(status_code=403, detail="action forbidden") from exc
    except JobNotFoundError as exc:
        raise HTTPException(status_code=404, detail="resource not found") from exc
    except (ControlConflictError, LeaseUnavailableError, StaleLeaseError) as exc:
        raise HTTPException(
            status_code=409, detail="request conflicts with current state"
        ) from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail="invalid request") from exc
    except (sqlite3.Error, ControlStoreError) as exc:
        raise HTTPException(status_code=503, detail="control service unavailable") from exc
