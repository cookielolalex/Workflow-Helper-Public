"""Durable synthetic emergency-stop state and evidence.

This module is intentionally state-only. It never calls a capture agent, queue,
model provider, artifact store, retention provider, or dataset publisher. Every
switch starts engaged and there is deliberately no disengage/resume operation in
this package; live wiring and any release path remain gated by later R3 controls.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from uuid import uuid4

from .control_store import ControlConflictError, ControlStoreError

_MAX_TEXT = 256


class SafetyDomain(StrEnum):
    CAPTURE = "capture"
    INGEST = "ingest"
    DETERMINISTIC_PROCESSING = "deterministic_processing"
    ANALYSIS = "analysis"
    RETENTION = "retention"
    DATASET_PROMOTION = "dataset_promotion"


@dataclass(frozen=True, slots=True)
class SafetySwitchState:
    domain: SafetyDomain
    engaged: bool


@dataclass(frozen=True, slots=True)
class SafetySwitchEvent:
    sequence: int
    event_id: str
    domain: SafetyDomain
    idempotency_key: str
    actor_id: str
    correlation_id: str
    reason: str
    occurred_at: datetime


_SCHEMA = (
    """
    create table if not exists safety_switches (
        domain text primary key check (
            domain in (
                'capture', 'ingest', 'deterministic_processing',
                'analysis', 'retention', 'dataset_promotion'
            )
        ),
        engaged integer not null check (engaged = 1)
    )
    """,
    """
    create trigger if not exists safety_switches_no_update
    before update on safety_switches
    begin
        select raise(abort, 'safety switch state is fail-safe and immutable');
    end
    """,
    """
    create trigger if not exists safety_switches_no_delete
    before delete on safety_switches
    begin
        select raise(abort, 'safety switch state is fail-safe and immutable');
    end
    """,
    """
    create table if not exists safety_switch_events (
        sequence integer primary key autoincrement,
        event_id text not null unique,
        domain text not null references safety_switches(domain),
        idempotency_key text not null unique,
        content_digest text not null,
        actor_id text not null,
        correlation_id text not null,
        reason text not null,
        occurred_at integer not null
    )
    """,
    """
    create trigger if not exists safety_switch_events_no_update
    before update on safety_switch_events
    begin
        select raise(abort, 'safety switch events are immutable');
    end
    """,
    """
    create trigger if not exists safety_switch_events_no_delete
    before delete on safety_switch_events
    begin
        select raise(abort, 'safety switch events are immutable');
    end
    """,
)


class SafetySwitchLedger:
    """Persistent fail-safe switch state with append-only engagement evidence."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        if busy_timeout_seconds <= 0:
            raise ValueError("busy_timeout_seconds must be positive")
        if str(database_path) == ":memory:":
            raise ValueError("a filesystem path is required for a durable safety ledger")
        self._database_path = str(Path(database_path))
        self._busy_timeout_ms = int(busy_timeout_seconds * 1000)
        Path(self._database_path).parent.mkdir(parents=True, exist_ok=True)
        with self._transaction() as connection:
            for statement in _SCHEMA:
                connection.execute(statement)
            for domain in SafetyDomain:
                connection.execute(
                    "insert or ignore into safety_switches (domain, engaged) values (?, 1)",
                    (domain.value,),
                )

    @property
    def database_path(self) -> str:
        return self._database_path

    def read(self, domain: SafetyDomain | str) -> SafetySwitchState:
        normalized = _domain(domain)
        with self._connection() as connection:
            row = connection.execute(
                "select domain, engaged from safety_switches where domain = ?",
                (normalized.value,),
            ).fetchone()
        if row is None:
            raise ControlStoreError("safety switch is missing")
        return SafetySwitchState(
            domain=SafetyDomain(row["domain"]),
            engaged=bool(row["engaged"]),
        )

    def read_all(self) -> tuple[SafetySwitchState, ...]:
        return tuple(self.read(domain) for domain in SafetyDomain)

    def engage(
        self,
        domain: SafetyDomain | str,
        *,
        idempotency_key: str,
        actor_id: str,
        correlation_id: str,
        reason: str,
        now: datetime | None = None,
    ) -> SafetySwitchEvent:
        normalized = _domain(domain)
        normalized_key = _bounded_text(idempotency_key, "idempotency_key")
        normalized_actor = _bounded_text(actor_id, "actor_id")
        normalized_correlation = _bounded_text(correlation_id, "correlation_id")
        normalized_reason = _bounded_text(reason, "reason")
        detail = {
            "domain": normalized.value,
            "actor_id": normalized_actor,
            "correlation_id": normalized_correlation,
            "reason": normalized_reason,
            "operation": "engage",
            "provider_call": False,
        }
        digest = hashlib.sha256(
            json.dumps(detail, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        occurred_at = now or datetime.now(UTC)
        occurred_us = _to_micros(occurred_at)

        with self._transaction() as connection:
            existing = connection.execute(
                """
                select sequence, event_id, domain, idempotency_key, content_digest,
                       actor_id, correlation_id, reason, occurred_at
                from safety_switch_events where idempotency_key = ?
                """,
                (normalized_key,),
            ).fetchone()
            if existing is not None:
                if existing["content_digest"] != digest:
                    raise ControlConflictError(
                        "idempotency key was already used for different safety evidence"
                    )
                return _event(existing)

            state = connection.execute(
                "select engaged from safety_switches where domain = ?",
                (normalized.value,),
            ).fetchone()
            if state is None or state["engaged"] != 1:
                raise ControlStoreError("safety switch is not in fail-safe engaged state")

            event_id = str(uuid4())
            connection.execute(
                """
                insert into safety_switch_events (
                    event_id, domain, idempotency_key, content_digest, actor_id,
                    correlation_id, reason, occurred_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    normalized.value,
                    normalized_key,
                    digest,
                    normalized_actor,
                    normalized_correlation,
                    normalized_reason,
                    occurred_us,
                ),
            )
            row = connection.execute(
                """
                select sequence, event_id, domain, idempotency_key, content_digest,
                       actor_id, correlation_id, reason, occurred_at
                from safety_switch_events where event_id = ?
                """,
                (event_id,),
            ).fetchone()
            if row is None:
                raise ControlStoreError("safety evidence write could not be read back")
            return _event(row)

    def list_events(
        self,
        *,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> list[SafetySwitchEvent]:
        if after_sequence < 0 or limit < 1 or limit > 100:
            raise ValueError("safety event pagination is out of bounds")
        with self._connection() as connection:
            rows = connection.execute(
                """
                select sequence, event_id, domain, idempotency_key, content_digest,
                       actor_id, correlation_id, reason, occurred_at
                from safety_switch_events
                where sequence > ? order by sequence asc limit ?
                """,
                (after_sequence, limit),
            ).fetchall()
        return [_event(row) for row in rows]

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(
            self._database_path,
            timeout=self._busy_timeout_ms / 1000,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"pragma busy_timeout = {self._busy_timeout_ms}")
        connection.execute("pragma foreign_keys = on")
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self):
        with self._connection() as connection:
            connection.execute("begin immediate")
            try:
                yield connection
            except Exception:
                connection.rollback()
                raise
            else:
                connection.commit()


def _domain(value: SafetyDomain | str) -> SafetyDomain:
    if isinstance(value, SafetyDomain):
        return value
    try:
        return SafetyDomain(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("unknown safety domain") from exc


def _bounded_text(value: str, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be text")
    normalized = value.strip()
    if not normalized or len(normalized) > _MAX_TEXT:
        raise ValueError(f"{field} must contain 1-{_MAX_TEXT} characters")
    return normalized


def _to_micros(value: datetime) -> int:
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return int(value.astimezone(UTC).timestamp() * 1_000_000)


def _from_micros(value: int) -> datetime:
    return datetime.fromtimestamp(value / 1_000_000, tz=UTC)


def _event(row: sqlite3.Row) -> SafetySwitchEvent:
    return SafetySwitchEvent(
        sequence=row["sequence"],
        event_id=row["event_id"],
        domain=SafetyDomain(row["domain"]),
        idempotency_key=row["idempotency_key"],
        actor_id=row["actor_id"],
        correlation_id=row["correlation_id"],
        reason=row["reason"],
        occurred_at=_from_micros(row["occurred_at"]),
    )
