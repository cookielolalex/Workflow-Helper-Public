"""Authenticated one-way control boundary for synthetic safety switches."""

from __future__ import annotations

from .control_auth import AuthenticatedPrincipal, ControlAction
from .safety_switches import (
    SafetyDomain,
    SafetySwitchEvent,
    SafetySwitchLedger,
    SafetySwitchState,
)


class SafetyControlService:
    """Authorize exact safety actions, derive actor identity, never resume a switch."""

    def __init__(self, ledger: SafetySwitchLedger) -> None:
        self._ledger = ledger

    def read_switch(
        self,
        principal: AuthenticatedPrincipal,
        *,
        domain: SafetyDomain | str,
    ) -> SafetySwitchState:
        principal.require(ControlAction.SAFETY_READ)
        return self._ledger.read(domain)

    def read_all_switches(
        self,
        principal: AuthenticatedPrincipal,
    ) -> tuple[SafetySwitchState, ...]:
        principal.require(ControlAction.SAFETY_READ)
        return self._ledger.read_all()

    def list_events(
        self,
        principal: AuthenticatedPrincipal,
        *,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> list[SafetySwitchEvent]:
        principal.require(ControlAction.SAFETY_READ)
        return self._ledger.list_events(
            after_sequence=after_sequence,
            limit=limit,
        )

    def engage(
        self,
        principal: AuthenticatedPrincipal,
        *,
        domain: SafetyDomain | str,
        idempotency_key: str,
        correlation_id: str,
        reason: str,
    ) -> SafetySwitchEvent:
        principal.require(ControlAction.SAFETY_ENGAGE)
        return self._ledger.engage(
            domain,
            idempotency_key=idempotency_key,
            actor_id=principal.subject,
            correlation_id=correlation_id,
            reason=reason,
        )
