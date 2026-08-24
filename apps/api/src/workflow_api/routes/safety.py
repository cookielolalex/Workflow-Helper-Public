"""Authenticated one-way synthetic safety routes; no live-system wiring."""

from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from ..control_auth import AuthenticatedPrincipal, AuthorizationDeniedError
from ..control_store import ControlConflictError, ControlStoreError
from ..dependencies import get_authenticated_principal, get_safety_control_service
from ..safety_control import SafetyControlService
from ..safety_switches import SafetyDomain, SafetySwitchEvent, SafetySwitchState

Identifier = Annotated[
    str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
]
CorrelationId = Annotated[
    str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
]
Reason = Annotated[str, Field(min_length=1, max_length=256)]

PrincipalDependency = Annotated[
    AuthenticatedPrincipal, Depends(get_authenticated_principal)
]
SafetyServiceDependency = Annotated[
    SafetyControlService, Depends(get_safety_control_service)
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SafetyEngageRequest(StrictModel):
    correlation_id: CorrelationId
    idempotency_key: Identifier
    reason: Reason


class SafetySwitchResponse(StrictModel):
    domain: SafetyDomain
    engaged: bool

    @classmethod
    def from_state(cls, value: SafetySwitchState) -> SafetySwitchResponse:
        return cls.model_validate(value, from_attributes=True)


class SafetySwitchListResponse(StrictModel):
    items: tuple[SafetySwitchResponse, ...]
    count: int


class SafetyEventResponse(StrictModel):
    sequence: int
    event_id: str
    domain: SafetyDomain
    idempotency_key: str
    actor_id: str
    correlation_id: str
    reason: str
    occurred_at: datetime

    @classmethod
    def from_event(cls, value: SafetySwitchEvent) -> SafetyEventResponse:
        return cls.model_validate(value, from_attributes=True)


class SafetyEventListResponse(StrictModel):
    items: tuple[SafetyEventResponse, ...]
    count: int


router = APIRouter(prefix="/v1/control/safety", tags=["control"])


@router.get("/switches", response_model=SafetySwitchListResponse)
def read_all_switches(
    principal: PrincipalDependency,
    service: SafetyServiceDependency,
) -> SafetySwitchListResponse:
    states = _call(lambda: service.read_all_switches(principal))
    items = tuple(SafetySwitchResponse.from_state(value) for value in states)
    return SafetySwitchListResponse(items=items, count=len(items))


@router.get("/switches/{domain}", response_model=SafetySwitchResponse)
def read_switch(
    domain: SafetyDomain,
    principal: PrincipalDependency,
    service: SafetyServiceDependency,
) -> SafetySwitchResponse:
    state_value = _call(lambda: service.read_switch(principal, domain=domain))
    return SafetySwitchResponse.from_state(state_value)


@router.get("/events", response_model=SafetyEventListResponse)
def list_events(
    principal: PrincipalDependency,
    service: SafetyServiceDependency,
    after_sequence: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 100,
) -> SafetyEventListResponse:
    events = _call(
        lambda: service.list_events(
            principal,
            after_sequence=after_sequence,
            limit=limit,
        )
    )
    items = tuple(SafetyEventResponse.from_event(value) for value in events)
    return SafetyEventListResponse(items=items, count=len(items))


@router.post(
    "/switches/{domain}/engage",
    response_model=SafetyEventResponse,
    status_code=status.HTTP_201_CREATED,
)
def engage_switch(
    domain: SafetyDomain,
    payload: SafetyEngageRequest,
    principal: PrincipalDependency,
    service: SafetyServiceDependency,
) -> SafetyEventResponse:
    event = _call(
        lambda: service.engage(
            principal,
            domain=domain,
            idempotency_key=payload.idempotency_key,
            correlation_id=payload.correlation_id,
            reason=payload.reason,
        )
    )
    return SafetyEventResponse.from_event(event)


def _call(operation):
    try:
        return operation()
    except AuthorizationDeniedError as exc:
        raise HTTPException(status_code=403, detail="action forbidden") from exc
    except ControlConflictError as exc:
        raise HTTPException(
            status_code=409, detail="request conflicts with current state"
        ) from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail="invalid request") from exc
    except (sqlite3.Error, ControlStoreError) as exc:
        raise HTTPException(status_code=503, detail="safety control unavailable") from exc
