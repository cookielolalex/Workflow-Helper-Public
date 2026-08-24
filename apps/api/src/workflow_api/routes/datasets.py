"""Authenticated synthetic-only dual-human dataset approval routes."""

from __future__ import annotations

import sqlite3
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from ..control_auth import AuthenticatedPrincipal, AuthorizationDeniedError
from ..control_service import ControlService
from ..control_store import ControlConflictError, ControlStoreError
from ..dataset_approval import (
    DatasetApprovalState,
    approve_dataset,
    read_dataset_approval_state,
)
from ..dependencies import get_authenticated_principal, get_control_service

Identifier = Annotated[str, Field(min_length=1, max_length=96, pattern=r"^[A-Za-z0-9._:-]+$")]
CorrelationId = Annotated[
    str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
]
Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
ShortText = Annotated[str, Field(min_length=1, max_length=128)]

PrincipalDependency = Annotated[
    AuthenticatedPrincipal, Depends(get_authenticated_principal)
]
ServiceDependency = Annotated[ControlService, Depends(get_control_service)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ManifestProvenance(StrictModel):
    source: ShortText
    artifact_id: Identifier
    revision: ShortText
    sha256: Digest


class DatasetApprovalRequest(StrictModel):
    correlation_id: CorrelationId
    idempotency_key: Identifier
    manifest: ManifestProvenance


class DatasetApprovalResponse(StrictModel):
    dataset_id: str
    target_id: str
    status: str
    approval_count: int
    approvers: tuple[str, ...]
    manifest: ManifestProvenance
    last_event_id: str

    @classmethod
    def from_state(cls, value: DatasetApprovalState) -> DatasetApprovalResponse:
        return cls(
            dataset_id=value.dataset_id,
            target_id=value.target_id,
            status=value.status,
            approval_count=value.approval_count,
            approvers=value.approvers,
            manifest=ManifestProvenance.model_validate(value.manifest),
            last_event_id=value.last_event_id,
        )


router = APIRouter(prefix="/v1/control/datasets", tags=["control"])


@router.post(
    "/{dataset_id}/approve",
    response_model=DatasetApprovalResponse,
    status_code=status.HTTP_201_CREATED,
)
def approve_dataset_manifest(
    dataset_id: Identifier,
    payload: DatasetApprovalRequest,
    principal: PrincipalDependency,
    service: ServiceDependency,
) -> DatasetApprovalResponse:
    state = _call(
        lambda: approve_dataset(
            service,
            principal,
            dataset_id=dataset_id,
            idempotency_key=payload.idempotency_key,
            manifest=payload.manifest.model_dump(),
            correlation_id=payload.correlation_id,
        )
    )
    return DatasetApprovalResponse.from_state(state)


@router.get("/{dataset_id}/approval", response_model=DatasetApprovalResponse)
def get_dataset_approval(
    dataset_id: Identifier,
    correlation_id: Annotated[CorrelationId, Query()],
    principal: PrincipalDependency,
    service: ServiceDependency,
) -> DatasetApprovalResponse:
    state = _call(
        lambda: read_dataset_approval_state(
            service,
            principal,
            dataset_id=dataset_id,
            correlation_id=correlation_id,
        )
    )
    if state is None:
        raise HTTPException(status_code=404, detail="resource not found")
    return DatasetApprovalResponse.from_state(state)


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
