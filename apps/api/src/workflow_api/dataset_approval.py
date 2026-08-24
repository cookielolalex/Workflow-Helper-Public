"""Dual-human dataset approval built on append-only authenticated review evidence."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .control_auth import AuthenticatedPrincipal
from .control_service import ControlService
from .control_store import ControlConflictError, ReviewEvent

_APPROVAL_KIND = "dataset_approval"
_PROMOTION_KIND = "dataset_promotion"


@dataclass(frozen=True, slots=True)
class DatasetApprovalState:
    dataset_id: str
    target_id: str
    status: str
    approval_count: int
    approvers: tuple[str, ...]
    manifest: dict[str, Any]
    last_event_id: str


def approve_dataset(
    service: ControlService,
    principal: AuthenticatedPrincipal,
    *,
    dataset_id: str,
    idempotency_key: str,
    manifest: Mapping[str, Any],
    correlation_id: str,
) -> DatasetApprovalState:
    """Record one reviewer approval and promote only after a distinct second reviewer."""

    if not dataset_id.strip():
        raise ValueError("dataset_id is required")
    manifest_value = dict(manifest)
    target_id = _target_id(dataset_id)
    events = _all_events(service, principal, target_id, correlation_id)
    current = _state_from_events(dataset_id, target_id, events)

    if current is not None:
        _require_same_manifest(current.manifest, manifest_value)
        actor_events = [
            event
            for event in _approval_events(events)
            if event.actor_id == principal.subject
        ]
        replay = next(
            (event for event in actor_events if event.idempotency_key == idempotency_key),
            None,
        )
        if replay is not None:
            return current
        if current.status == "approved":
            raise ControlConflictError("dataset is already approved")
        if actor_events:
            raise ControlConflictError("reviewer already approved this dataset manifest")

    service.append_review(
        principal,
        target_id=target_id,
        idempotency_key=idempotency_key,
        status="pending",
        provenance=manifest_value,
        detail={"kind": _APPROVAL_KIND, "decision": "approve"},
        correlation_id=correlation_id,
    )

    events = _all_events(service, principal, target_id, correlation_id)
    state = _state_from_events(dataset_id, target_id, events)
    assert state is not None
    if state.status == "approved" or state.approval_count < 2:
        return state

    promotion_key = _promotion_idempotency_key(
        dataset_id,
        manifest_value,
        state.approvers,
        principal.subject,
    )
    service.append_review(
        principal,
        target_id=target_id,
        idempotency_key=promotion_key,
        status="approved",
        provenance=manifest_value,
        detail={
            "kind": _PROMOTION_KIND,
            "approval_count": state.approval_count,
            "approvers": list(state.approvers),
        },
        correlation_id=correlation_id,
    )
    events = _all_events(service, principal, target_id, correlation_id)
    promoted = _state_from_events(dataset_id, target_id, events)
    assert promoted is not None
    if promoted.status != "approved":
        raise ControlConflictError("dataset promotion did not reach approved state")
    return promoted


def read_dataset_approval_state(
    service: ControlService,
    principal: AuthenticatedPrincipal,
    *,
    dataset_id: str,
    correlation_id: str,
) -> DatasetApprovalState | None:
    if not dataset_id.strip():
        raise ValueError("dataset_id is required")
    target_id = _target_id(dataset_id)
    events = _all_events(service, principal, target_id, correlation_id)
    return _state_from_events(dataset_id, target_id, events)


def _all_events(
    service: ControlService,
    principal: AuthenticatedPrincipal,
    target_id: str,
    correlation_id: str,
) -> list[ReviewEvent]:
    events: list[ReviewEvent] = []
    after_sequence = 0
    while True:
        batch = service.list_reviews(
            principal,
            target_id=target_id,
            correlation_id=correlation_id,
            after_sequence=after_sequence,
            limit=100,
        )
        if not batch:
            return events
        events.extend(batch)
        after_sequence = batch[-1].sequence
        if len(batch) < 100:
            return events


def _state_from_events(
    dataset_id: str,
    target_id: str,
    events: list[ReviewEvent],
) -> DatasetApprovalState | None:
    approvals = _approval_events(events)
    promotions = [event for event in events if event.detail.get("kind") == _PROMOTION_KIND]
    if not approvals and not promotions:
        return None

    reference = approvals[0].provenance if approvals else promotions[0].provenance
    for event in [*approvals, *promotions]:
        _require_same_manifest(reference, event.provenance)

    approvers = tuple(sorted({event.actor_id for event in approvals}))
    if promotions and len(approvers) < 2:
        raise ControlConflictError("approved dataset lacks two distinct reviewer approvals")
    status = "approved" if promotions else "pending"
    last_event = max([*approvals, *promotions], key=lambda event: event.sequence)
    return DatasetApprovalState(
        dataset_id=dataset_id,
        target_id=target_id,
        status=status,
        approval_count=len(approvers),
        approvers=approvers,
        manifest=dict(reference),
        last_event_id=last_event.event_id,
    )


def _approval_events(events: list[ReviewEvent]) -> list[ReviewEvent]:
    return [
        event
        for event in events
        if event.detail.get("kind") == _APPROVAL_KIND
        and event.detail.get("decision") == "approve"
    ]


def _require_same_manifest(
    expected: Mapping[str, Any], actual: Mapping[str, Any]
) -> None:
    if _canonical_json(expected) != _canonical_json(actual):
        raise ControlConflictError("dataset manifest provenance does not match prior approval")


def _target_id(dataset_id: str) -> str:
    return f"dataset:{dataset_id}"


def _promotion_idempotency_key(
    dataset_id: str,
    manifest: Mapping[str, Any],
    approvers: tuple[str, ...],
    actor_id: str,
) -> str:
    payload = _canonical_json(
        {
            "dataset_id": dataset_id,
            "manifest": dict(manifest),
            "approvers": list(approvers),
            "actor_id": actor_id,
        }
    )
    return "dataset-promotion-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _canonical_json(value: Mapping[str, Any] | dict[str, Any]) -> str:
    try:
        return json.dumps(
            dict(value),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("manifest provenance must be JSON serializable") from exc
