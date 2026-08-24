"""Authenticated synthetic retention-state routes; no provider operations."""

from __future__ import annotations

import sqlite3
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from ..control_auth import AuthenticatedPrincipal, AuthorizationDeniedError
from ..control_service import ControlService
from ..control_store import ControlConflictError, ControlStoreError
from ..dependencies import get_authenticated_principal, get_control_service
from ..retention_store import RetentionTargetState

Identifier = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")]
CorrelationId = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")]
Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
ShortText = Annotated[str, Field(min_length=1, max_length=256)]

PrincipalDependency = Annotated[
    AuthenticatedPrincipal, Depends(get_authenticated_principal)
]
ServiceDependency = Annotated[ControlService, Depends(get_control_service)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RetentionCopyRequest(StrictModel):
    copy_id: Identifier
    provider: Literal["google_drive", "s3"]
    file_id: ShortText
    revision: ShortText
    sha256: Digest


class RetentionRegisterRequest(StrictModel):
    correlation_id: CorrelationId
    idempotency_key: Identifier
    copies: Annotated[tuple[RetentionCopyRequest, ...], Field(min_length=1, max_length=32)]


class RetentionHoldRequest(StrictModel):
    correlation_id: CorrelationId
    idempotency_key: Identifier
    hold: bool
    reason: str | None = Field(default=None, max_length=256)


class RetentionMutationRequest(StrictModel):
    correlation_id: CorrelationId
    idempotency_key: Identifier


class RetentionDeletionAttestationRequest(RetentionMutationRequest):
    deletion_receipt_sha256: Digest


class RetentionCopyResponse(StrictModel):
    copy_id: str
    provider: str
    file_id: str
    revision: str
    sha256: str
    state: str
    trash_staged_at: str | None
    deletion_attested_at: str | None
    deletion_receipt_sha256: str | None


class RetentionTargetResponse(StrictModel):
    target_id: str
    created_by: str
    created_at: str
    expires_at: str
    legal_hold: bool
    hold_reason: str | None
    completed_at: str | None
    copies: tuple[RetentionCopyResponse, ...]

    @classmethod
    def from_state(cls, value: RetentionTargetState) -> RetentionTargetResponse:
        return cls(
            target_id=value.target_id,
            created_by=value.created_by,
            created_at=value.created_at.isoformat(),
            expires_at=value.expires_at.isoformat(),
            legal_hold=value.legal_hold,
            hold_reason=value.hold_reason,
            completed_at=(
                None if value.completed_at is None else value.completed_at.isoformat()
            ),
            copies=tuple(
                RetentionCopyResponse(
                    copy_id=copy.copy_id,
                    provider=copy.provider,
                    file_id=copy.file_id,
                    revision=copy.revision,
                    sha256=copy.sha256,
                    state=copy.state,
                    trash_staged_at=(
                        None
                        if copy.trash_staged_at is None
                        else copy.trash_staged_at.isoformat()
                    ),
                    deletion_attested_at=(
                        None
                        if copy.deletion_attested_at is None
                        else copy.deletion_attested_at.isoformat()
                    ),
                    deletion_receipt_sha256=copy.deletion_receipt_sha256,
                )
                for copy in value.copies
            ),
        )


class RetentionListResponse(StrictModel):
    items: tuple[RetentionTargetResponse, ...]
    count: int


router = APIRouter(prefix="/v1/control/retention", tags=["control"])


@router.get("/overdue", response_model=RetentionListResponse)
def list_overdue(
    correlation_id: Annotated[CorrelationId, Query()],
    principal: PrincipalDependency,
    service: ServiceDependency,
) -> RetentionListResponse:
    values = _call(
        lambda: service.list_overdue_retention(
            principal,
            correlation_id=correlation_id,
        )
    )
    items = tuple(RetentionTargetResponse.from_state(value) for value in values)
    return RetentionListResponse(items=items, count=len(items))


@router.post("/{target_id}", response_model=RetentionTargetResponse, status_code=201)
def register_retention(
    target_id: Identifier,
    payload: RetentionRegisterRequest,
    principal: PrincipalDependency,
    service: ServiceDependency,
) -> RetentionTargetResponse:
    state = _call(
        lambda: service.register_retention(
            principal,
            target_id=target_id,
            copies=[copy.model_dump() for copy in payload.copies],
            correlation_id=payload.correlation_id,
            idempotency_key=payload.idempotency_key,
        )
    )
    return RetentionTargetResponse.from_state(state)


@router.get("/{target_id}", response_model=RetentionTargetResponse)
def read_retention(
    target_id: Identifier,
    correlation_id: Annotated[CorrelationId, Query()],
    principal: PrincipalDependency,
    service: ServiceDependency,
) -> RetentionTargetResponse:
    state = _call(
        lambda: service.read_retention(
            principal,
            target_id=target_id,
            correlation_id=correlation_id,
        )
    )
    if state is None:
        raise HTTPException(status_code=404, detail="resource not found")
    return RetentionTargetResponse.from_state(state)


@router.post("/{target_id}/hold", response_model=RetentionTargetResponse)
def set_retention_hold(
    target_id: Identifier,
    payload: RetentionHoldRequest,
    principal: PrincipalDependency,
    service: ServiceDependency,
) -> RetentionTargetResponse:
    state = _call(
        lambda: service.set_retention_hold(
            principal,
            target_id=target_id,
            hold=payload.hold,
            reason=payload.reason,
            correlation_id=payload.correlation_id,
            idempotency_key=payload.idempotency_key,
        )
    )
    return RetentionTargetResponse.from_state(state)


@router.post(
    "/{target_id}/copies/{copy_id}/stage-trash",
    response_model=RetentionTargetResponse,
)
def stage_retention_trash(
    target_id: Identifier,
    copy_id: Identifier,
    payload: RetentionMutationRequest,
    principal: PrincipalDependency,
    service: ServiceDependency,
) -> RetentionTargetResponse:
    state = _call(
        lambda: service.stage_retention_trash(
            principal,
            target_id=target_id,
            copy_id=copy_id,
            correlation_id=payload.correlation_id,
            idempotency_key=payload.idempotency_key,
        )
    )
    return RetentionTargetResponse.from_state(state)


@router.post(
    "/{target_id}/copies/{copy_id}/attest-deleted",
    response_model=RetentionTargetResponse,
)
def attest_retention_delete(
    target_id: Identifier,
    copy_id: Identifier,
    payload: RetentionDeletionAttestationRequest,
    principal: PrincipalDependency,
    service: ServiceDependency,
) -> RetentionTargetResponse:
    state = _call(
        lambda: service.attest_retention_delete(
            principal,
            target_id=target_id,
            copy_id=copy_id,
            deletion_receipt_sha256=payload.deletion_receipt_sha256,
            correlation_id=payload.correlation_id,
            idempotency_key=payload.idempotency_key,
        )
    )
    return RetentionTargetResponse.from_state(state)


def _call(operation):
    try:
        return operation()
    except AuthorizationDeniedError as exc:
        raise HTTPException(status_code=403, detail="action forbidden") from exc
    except ControlConflictError as exc:
        raise HTTPException(status_code=409, detail="state conflict") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="request rejected") from exc
    except (ControlStoreError, sqlite3.Error, RuntimeError, OSError) as exc:
        raise HTTPException(status_code=503, detail="control service unavailable") from exc
