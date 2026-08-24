from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

import pytest

from workflow_api.control_store import ControlConflictError
from workflow_api.safety_switches import SafetyDomain, SafetySwitchLedger


def _ledger(tmp_path) -> SafetySwitchLedger:
    return SafetySwitchLedger(tmp_path / "control.db")


def test_all_six_domains_start_engaged_and_survive_restart(tmp_path) -> None:
    ledger = _ledger(tmp_path)

    states = ledger.read_all()

    assert tuple(state.domain for state in states) == tuple(SafetyDomain)
    assert all(state.engaged for state in states)
    restarted = _ledger(tmp_path)
    assert restarted.read_all() == states


def test_engagement_evidence_is_append_only_and_idempotent(tmp_path) -> None:
    ledger = _ledger(tmp_path)
    occurred_at = datetime(2026, 8, 17, 8, 30, tzinfo=UTC)

    first = ledger.engage(
        SafetyDomain.CAPTURE,
        idempotency_key="engage-capture-1",
        actor_id="safety.steward",
        correlation_id="corr-1",
        reason="synthetic emergency stop evidence",
        now=occurred_at,
    )
    replay = ledger.engage(
        SafetyDomain.CAPTURE,
        idempotency_key="engage-capture-1",
        actor_id="safety.steward",
        correlation_id="corr-1",
        reason="synthetic emergency stop evidence",
        now=occurred_at,
    )

    assert replay == first
    assert ledger.read(SafetyDomain.CAPTURE).engaged is True
    assert ledger.list_events() == [first]

    with pytest.raises(ControlConflictError):
        ledger.engage(
            SafetyDomain.INGEST,
            idempotency_key="engage-capture-1",
            actor_id="safety.steward",
            correlation_id="corr-2",
            reason="different evidence",
            now=occurred_at,
        )


def test_unknown_domain_and_bad_inputs_fail_closed(tmp_path) -> None:
    ledger = _ledger(tmp_path)

    with pytest.raises(ValueError, match="unknown safety domain"):
        ledger.read("unknown")
    with pytest.raises(ValueError, match="reason"):
        ledger.engage(
            SafetyDomain.ANALYSIS,
            idempotency_key="key",
            actor_id="safety.steward",
            correlation_id="corr",
            reason="",
        )
    with pytest.raises(ValueError, match="pagination"):
        ledger.list_events(limit=101)


def test_database_rejects_disengage_or_evidence_mutation(tmp_path) -> None:
    ledger = _ledger(tmp_path)
    event = ledger.engage(
        SafetyDomain.RETENTION,
        idempotency_key="retention-stop",
        actor_id="safety.steward",
        correlation_id="corr-retention",
        reason="keep retention stopped",
    )

    connection = sqlite3.connect(ledger.database_path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="fail-safe"):
            connection.execute(
                "update safety_switches set engaged = 0 where domain = ?",
                (SafetyDomain.RETENTION.value,),
            )
        connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "update safety_switch_events set reason = 'changed' where event_id = ?",
                (event.event_id,),
            )
        connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "delete from safety_switch_events where event_id = ?",
                (event.event_id,),
            )
    finally:
        connection.close()


def test_each_domain_accepts_separate_stop_evidence(tmp_path) -> None:
    ledger = _ledger(tmp_path)

    for index, domain in enumerate(SafetyDomain, start=1):
        event = ledger.engage(
            domain,
            idempotency_key=f"stop-{index}",
            actor_id="safety.steward",
            correlation_id=f"corr-{index}",
            reason=f"stop {domain.value}",
        )
        assert event.domain is domain
        assert ledger.read(domain).engaged is True

    assert len(ledger.list_events()) == len(SafetyDomain)
