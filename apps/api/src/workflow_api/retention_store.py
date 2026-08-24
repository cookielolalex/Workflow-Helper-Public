"""Durable synthetic retention state and evidence on the shared SQLite control plane."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from .audit_schema import (
    SHARED_AUDIT_ACTIONS,
    SHARED_AUDIT_ROLES,
    ensure_shared_audit_schema,
)
from .control_store import AuditContext, ControlConflictError, ControlStoreError

DEFAULT_RAW_RETENTION_DAYS = 14
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_ALLOWED_PROVIDERS = {"google_drive", "s3"}


@dataclass(frozen=True, slots=True)
class RetentionCopyState:
    copy_id: str
    provider: str
    file_id: str
    revision: str
    sha256: str
    state: str
    trash_staged_at: datetime | None
    deletion_attested_at: datetime | None
    deletion_receipt_sha256: str | None


@dataclass(frozen=True, slots=True)
class RetentionTargetState:
    target_id: str
    created_by: str
    created_at: datetime
    expires_at: datetime
    legal_hold: bool
    hold_reason: str | None
    completed_at: datetime | None
    copies: tuple[RetentionCopyState, ...]


@dataclass(frozen=True, slots=True)
class RetentionEvent:
    sequence: int
    event_id: str
    target_id: str
    copy_id: str | None
    idempotency_key: str
    actor_id: str
    event_type: str
    detail: dict[str, Any]
    occurred_at: datetime


_RETENTION_SCHEMA = (
    """
    create table if not exists retention_targets (
        target_id text primary key,
        created_by text not null,
        created_at integer not null,
        expires_at integer not null,
        legal_hold integer not null default 0 check (legal_hold in (0, 1)),
        hold_reason text,
        completed_at integer,
        updated_at integer not null,
        check (expires_at > created_at)
    )
    """,
    """
    create table if not exists retention_copies (
        target_id text not null references retention_targets(target_id),
        copy_id text not null,
        provider text not null check (provider in ('google_drive', 's3')),
        file_id text not null,
        revision text not null,
        sha256 text not null,
        state text not null check (state in ('active', 'trash_staged', 'deleted')),
        trash_staged_at integer,
        deletion_attested_at integer,
        deletion_receipt_sha256 text,
        primary key (target_id, copy_id)
    )
    """,
    """
    create trigger if not exists retention_copies_identity_immutable
    before update of copy_id, provider, file_id, revision, sha256 on retention_copies
    begin
        select raise(abort, 'retention copy identity is immutable');
    end
    """,
    """
    create table if not exists retention_events (
        sequence integer primary key autoincrement,
        event_id text not null unique,
        target_id text not null references retention_targets(target_id),
        copy_id text,
        idempotency_key text not null unique,
        content_digest text not null,
        actor_id text not null,
        event_type text not null check (
            event_type in (
                'registered', 'hold_placed', 'hold_released',
                'trash_staged', 'deletion_attested'
            )
        ),
        detail_json text not null,
        occurred_at integer not null
    )
    """,
    """
    create trigger if not exists retention_events_no_update
    before update on retention_events
    begin
        select raise(abort, 'retention events are immutable');
    end
    """,
    """
    create trigger if not exists retention_events_no_delete
    before delete on retention_events
    begin
        select raise(abort, 'retention events are immutable');
    end
    """,
    """
    create index if not exists retention_targets_due_idx
        on retention_targets (legal_hold, completed_at, expires_at)
    """,
)


class RetentionLedger:
    """Retention intent/evidence only; this class never calls an artifact provider."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        if busy_timeout_seconds <= 0:
            raise ValueError("busy_timeout_seconds must be positive")
        if str(database_path) == ":memory:":
            raise ValueError("a filesystem path is required for a durable retention ledger")
        self._database_path = str(Path(database_path))
        self._busy_timeout_ms = int(busy_timeout_seconds * 1000)
        Path(self._database_path).parent.mkdir(parents=True, exist_ok=True)
        with self._transaction() as connection:
            ensure_shared_audit_schema(
                connection,
                allow_legacy_control_schema=False,
            )
            for statement in _RETENTION_SCHEMA:
                connection.execute(statement)

    @property
    def database_path(self) -> str:
        return self._database_path

    def register_target(
        self,
        *,
        target_id: str,
        copies: Sequence[Mapping[str, str]],
        idempotency_key: str,
        actor_id: str,
        now: datetime | None = None,
        audit: AuditContext | None = None,
    ) -> RetentionTargetState:
        _require_text(target_id, "target_id")
        _require_text(idempotency_key, "idempotency_key")
        _require_text(actor_id, "actor_id")
        canonical_copies = _canonicalize_copies(copies)
        occurred_at = now or datetime.now(UTC)
        created_us = _to_micros(occurred_at)
        expires_at = occurred_at + timedelta(days=DEFAULT_RAW_RETENTION_DAYS)
        detail = {"copies": canonical_copies, "retention_days": DEFAULT_RAW_RETENTION_DAYS}
        digest = _content_digest(target_id, None, actor_id, "registered", detail)

        with self._transaction() as connection:
            replay = self._idempotent_replay(
                connection, idempotency_key=idempotency_key, content_digest=digest
            )
            if replay is not None:
                self._append_audit_event(connection, audit)
                return self._target_state(connection, target_id)

            existing = connection.execute(
                "select target_id from retention_targets where target_id = ?", (target_id,)
            ).fetchone()
            if existing is not None:
                raise ControlConflictError("retention target is already registered")

            connection.execute(
                """
                insert into retention_targets (
                    target_id, created_by, created_at, expires_at, legal_hold,
                    hold_reason, completed_at, updated_at
                ) values (?, ?, ?, ?, 0, null, null, ?)
                """,
                (target_id, actor_id, created_us, _to_micros(expires_at), created_us),
            )
            for copy in canonical_copies:
                connection.execute(
                    """
                    insert into retention_copies (
                        target_id, copy_id, provider, file_id, revision, sha256, state,
                        trash_staged_at, deletion_attested_at, deletion_receipt_sha256
                    ) values (?, ?, ?, ?, ?, ?, 'active', null, null, null)
                    """,
                    (
                        target_id,
                        copy["copy_id"],
                        copy["provider"],
                        copy["file_id"],
                        copy["revision"],
                        copy["sha256"],
                    ),
                )
            self._append_retention_event(
                connection,
                target_id=target_id,
                copy_id=None,
                idempotency_key=idempotency_key,
                content_digest=digest,
                actor_id=actor_id,
                event_type="registered",
                detail=detail,
                occurred_at=created_us,
            )
            self._append_audit_event(connection, audit)
            return self._target_state(connection, target_id)

    def set_legal_hold(
        self,
        *,
        target_id: str,
        hold: bool,
        reason: str | None,
        idempotency_key: str,
        actor_id: str,
        now: datetime | None = None,
        audit: AuditContext | None = None,
    ) -> RetentionTargetState:
        _require_text(target_id, "target_id")
        _require_text(idempotency_key, "idempotency_key")
        _require_text(actor_id, "actor_id")
        if hold:
            _require_text(reason or "", "reason")
            normalized_reason = reason.strip() if reason is not None else None
            event_type = "hold_placed"
        else:
            if reason is not None:
                raise ValueError("reason must be omitted when releasing a legal hold")
            normalized_reason = None
            event_type = "hold_released"
        detail = {"hold": hold, "reason": normalized_reason}
        digest = _content_digest(target_id, None, actor_id, event_type, detail)
        occurred_at = now or datetime.now(UTC)
        occurred_us = _to_micros(occurred_at)

        with self._transaction() as connection:
            replay = self._idempotent_replay(
                connection, idempotency_key=idempotency_key, content_digest=digest
            )
            if replay is not None:
                self._append_audit_event(connection, audit)
                return self._target_state(connection, target_id)
            target = self._target_row(connection, target_id)
            if target["completed_at"] is not None:
                raise ControlConflictError("completed retention target cannot change legal hold")
            current = bool(target["legal_hold"])
            if current == hold:
                raise ControlConflictError("legal hold already has the requested state")
            connection.execute(
                """
                update retention_targets
                set legal_hold = ?, hold_reason = ?, updated_at = ?
                where target_id = ?
                """,
                (1 if hold else 0, normalized_reason, occurred_us, target_id),
            )
            self._append_retention_event(
                connection,
                target_id=target_id,
                copy_id=None,
                idempotency_key=idempotency_key,
                content_digest=digest,
                actor_id=actor_id,
                event_type=event_type,
                detail=detail,
                occurred_at=occurred_us,
            )
            self._append_audit_event(connection, audit)
            return self._target_state(connection, target_id)

    def stage_trash(
        self,
        *,
        target_id: str,
        copy_id: str,
        idempotency_key: str,
        actor_id: str,
        now: datetime | None = None,
        audit: AuditContext | None = None,
    ) -> RetentionTargetState:
        _require_text(target_id, "target_id")
        _require_text(copy_id, "copy_id")
        _require_text(idempotency_key, "idempotency_key")
        _require_text(actor_id, "actor_id")
        detail = {"copy_id": copy_id, "provider_call": False}
        digest = _content_digest(target_id, copy_id, actor_id, "trash_staged", detail)
        occurred_at = now or datetime.now(UTC)
        occurred_us = _to_micros(occurred_at)
        with self._transaction() as connection:
            replay = self._idempotent_replay(
                connection, idempotency_key=idempotency_key, content_digest=digest
            )
            if replay is not None:
                self._append_audit_event(connection, audit)
                return self._target_state(connection, target_id)
            target = self._target_row(connection, target_id)
            self._require_not_held_or_completed(target)
            if occurred_us < target["expires_at"]:
                raise ControlConflictError("retention target has not reached its expiry")
            copy = self._copy_row(connection, target_id, copy_id)
            if copy["state"] != "active":
                raise ControlConflictError("retention copy is not eligible for trash staging")
            connection.execute(
                """
                update retention_copies
                set state = 'trash_staged', trash_staged_at = ?
                where target_id = ? and copy_id = ?
                """,
                (occurred_us, target_id, copy_id),
            )
            connection.execute(
                "update retention_targets set updated_at = ? where target_id = ?",
                (occurred_us, target_id),
            )
            self._append_retention_event(
                connection,
                target_id=target_id,
                copy_id=copy_id,
                idempotency_key=idempotency_key,
                content_digest=digest,
                actor_id=actor_id,
                event_type="trash_staged",
                detail=detail,
                occurred_at=occurred_us,
            )
            self._append_audit_event(connection, audit)
            return self._target_state(connection, target_id)

    def attest_deleted(
        self,
        *,
        target_id: str,
        copy_id: str,
        deletion_receipt_sha256: str,
        idempotency_key: str,
        actor_id: str,
        now: datetime | None = None,
        audit: AuditContext | None = None,
    ) -> RetentionTargetState:
        _require_text(target_id, "target_id")
        _require_text(copy_id, "copy_id")
        _require_text(idempotency_key, "idempotency_key")
        _require_text(actor_id, "actor_id")
        _require_sha256(deletion_receipt_sha256, "deletion_receipt_sha256")
        detail = {
            "copy_id": copy_id,
            "deletion_receipt_sha256": deletion_receipt_sha256,
            "provider_call": False,
        }
        digest = _content_digest(target_id, copy_id, actor_id, "deletion_attested", detail)
        occurred_at = now or datetime.now(UTC)
        occurred_us = _to_micros(occurred_at)
        with self._transaction() as connection:
            replay = self._idempotent_replay(
                connection, idempotency_key=idempotency_key, content_digest=digest
            )
            if replay is not None:
                self._append_audit_event(connection, audit)
                return self._target_state(connection, target_id)
            target = self._target_row(connection, target_id)
            self._require_not_held_or_completed(target)
            copy = self._copy_row(connection, target_id, copy_id)
            if copy["state"] != "trash_staged":
                raise ControlConflictError("retention copy must be trash staged before attestation")
            connection.execute(
                """
                update retention_copies
                set state = 'deleted', deletion_attested_at = ?,
                    deletion_receipt_sha256 = ?
                where target_id = ? and copy_id = ?
                """,
                (occurred_us, deletion_receipt_sha256, target_id, copy_id),
            )
            remaining = connection.execute(
                """
                select count(*) from retention_copies
                where target_id = ? and state != 'deleted'
                """,
                (target_id,),
            ).fetchone()[0]
            completed_at = occurred_us if remaining == 0 else None
            connection.execute(
                """
                update retention_targets
                set completed_at = coalesce(completed_at, ?), updated_at = ?
                where target_id = ?
                """,
                (completed_at, occurred_us, target_id),
            )
            self._append_retention_event(
                connection,
                target_id=target_id,
                copy_id=copy_id,
                idempotency_key=idempotency_key,
                content_digest=digest,
                actor_id=actor_id,
                event_type="deletion_attested",
                detail=detail,
                occurred_at=occurred_us,
            )
            self._append_audit_event(connection, audit)
            return self._target_state(connection, target_id)

    def get_target(
        self,
        target_id: str,
        *,
        audit: AuditContext | None = None,
    ) -> RetentionTargetState | None:
        _require_text(target_id, "target_id")
        with self._transaction() as connection:
            row = connection.execute(
                "select target_id from retention_targets where target_id = ?", (target_id,)
            ).fetchone()
            self._append_audit_event(connection, audit)
            if row is None:
                return None
            return self._target_state(connection, target_id)

    def list_overdue(
        self,
        *,
        now: datetime | None = None,
        audit: AuditContext | None = None,
    ) -> list[RetentionTargetState]:
        now_us = _to_micros(now or datetime.now(UTC))
        with self._transaction() as connection:
            rows = connection.execute(
                """
                select target_id from retention_targets
                where expires_at <= ? and legal_hold = 0 and completed_at is null
                order by expires_at, target_id
                """,
                (now_us,),
            ).fetchall()
            self._append_audit_event(connection, audit)
            return [self._target_state(connection, row["target_id"]) for row in rows]

    def list_scoped_overdue(
        self,
        scope_prefix: str,
        *,
        now: datetime | None = None,
        audit: AuditContext | None = None,
    ) -> list[RetentionTargetState]:
        """Select one exact scope in SQL before loading any overdue target state."""

        _require_text(scope_prefix, "scope_prefix")
        now_us = _to_micros(now or datetime.now(UTC))
        with self._transaction() as connection:
            rows = connection.execute(
                """
                select target_id from retention_targets
                where substr(target_id, 1, length(?)) = ?
                  and expires_at <= ? and legal_hold = 0 and completed_at is null
                order by expires_at, target_id
                """,
                (scope_prefix, scope_prefix, now_us),
            ).fetchall()
            self._append_audit_event(connection, audit)
            return [self._target_state(connection, row["target_id"]) for row in rows]

    def list_events(self, target_id: str) -> list[RetentionEvent]:
        _require_text(target_id, "target_id")
        with self._connect() as connection:
            rows = connection.execute(
                "select * from retention_events where target_id = ? order by sequence",
                (target_id,),
            ).fetchall()
        return [_retention_event_from_row(row) for row in rows]

    def append_audit_event(self, audit: AuditContext) -> int:
        with self._transaction() as connection:
            sequence = self._append_audit_event(connection, audit)
            assert sequence is not None
            return sequence

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("begin immediate")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._database_path,
            timeout=self._busy_timeout_ms / 1000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("pragma foreign_keys = on")
        connection.execute(f"pragma busy_timeout = {self._busy_timeout_ms}")
        return connection

    def _append_audit_event(
        self, connection: sqlite3.Connection, audit: AuditContext | None
    ) -> int | None:
        if audit is None:
            return None
        _validate_audit_context(audit)
        cursor = connection.execute(
            """
            insert into audit_events (
                event_id, correlation_id, idempotency_key, subject_id, roles_json,
                action, target_id, result, occurred_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid4()),
                audit.correlation_id,
                audit.idempotency_key,
                audit.subject_id,
                _canonical_json(list(audit.roles)),
                audit.action,
                audit.target_id,
                audit.result,
                _to_micros(audit.occurred_at),
            ),
        )
        assert cursor.lastrowid is not None
        return cursor.lastrowid

    @staticmethod
    def _append_retention_event(
        connection: sqlite3.Connection,
        *,
        target_id: str,
        copy_id: str | None,
        idempotency_key: str,
        content_digest: str,
        actor_id: str,
        event_type: str,
        detail: Mapping[str, Any],
        occurred_at: int,
    ) -> None:
        connection.execute(
            """
            insert into retention_events (
                event_id, target_id, copy_id, idempotency_key, content_digest,
                actor_id, event_type, detail_json, occurred_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid4()),
                target_id,
                copy_id,
                idempotency_key,
                content_digest,
                actor_id,
                event_type,
                _canonical_json(dict(detail)),
                occurred_at,
            ),
        )

    @staticmethod
    def _idempotent_replay(
        connection: sqlite3.Connection,
        *,
        idempotency_key: str,
        content_digest: str,
    ) -> sqlite3.Row | None:
        row = connection.execute(
            "select * from retention_events where idempotency_key = ?",
            (idempotency_key,),
        ).fetchone()
        if row is not None and row["content_digest"] != content_digest:
            raise ControlConflictError(
                "retention idempotency key conflicts with stored content"
            )
        return row

    @staticmethod
    def _target_row(connection: sqlite3.Connection, target_id: str) -> sqlite3.Row:
        row = connection.execute(
            "select * from retention_targets where target_id = ?", (target_id,)
        ).fetchone()
        if row is None:
            raise ControlStoreError("retention target not found")
        return row

    @staticmethod
    def _copy_row(
        connection: sqlite3.Connection, target_id: str, copy_id: str
    ) -> sqlite3.Row:
        row = connection.execute(
            "select * from retention_copies where target_id = ? and copy_id = ?",
            (target_id, copy_id),
        ).fetchone()
        if row is None:
            raise ControlStoreError("retention copy not found")
        return row

    @staticmethod
    def _require_not_held_or_completed(target: sqlite3.Row) -> None:
        if target["legal_hold"]:
            raise ControlConflictError("legal hold blocks retention mutation")
        if target["completed_at"] is not None:
            raise ControlConflictError("retention target is already complete")

    @staticmethod
    def _target_state(
        connection: sqlite3.Connection, target_id: str
    ) -> RetentionTargetState:
        target = RetentionLedger._target_row(connection, target_id)
        copies = connection.execute(
            """
            select * from retention_copies
            where target_id = ? order by copy_id
            """,
            (target_id,),
        ).fetchall()
        return RetentionTargetState(
            target_id=target["target_id"],
            created_by=target["created_by"],
            created_at=_from_micros(target["created_at"]),
            expires_at=_from_micros(target["expires_at"]),
            legal_hold=bool(target["legal_hold"]),
            hold_reason=target["hold_reason"],
            completed_at=(
                None
                if target["completed_at"] is None
                else _from_micros(target["completed_at"])
            ),
            copies=tuple(_copy_state_from_row(copy) for copy in copies),
        )


def _canonicalize_copies(
    copies: Sequence[Mapping[str, str]],
) -> list[dict[str, str]]:
    if not copies:
        raise ValueError("at least one retention copy is required")
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw in copies:
        copy_id = raw.get("copy_id")
        provider = raw.get("provider")
        file_id = raw.get("file_id")
        revision = raw.get("revision")
        sha256 = raw.get("sha256")
        for value, name in (
            (copy_id, "copy_id"),
            (provider, "provider"),
            (file_id, "file_id"),
            (revision, "revision"),
        ):
            _require_text(value or "", name)
        assert copy_id is not None
        assert provider is not None
        assert file_id is not None
        assert revision is not None
        if copy_id in seen:
            raise ValueError("copy_id values must be unique")
        if provider not in _ALLOWED_PROVIDERS:
            raise ValueError("unsupported retention copy provider")
        _require_sha256(sha256 or "", "sha256")
        assert sha256 is not None
        seen.add(copy_id)
        normalized.append(
            {
                "copy_id": copy_id,
                "provider": provider,
                "file_id": file_id,
                "revision": revision,
                "sha256": sha256,
            }
        )
    return sorted(normalized, key=lambda value: value["copy_id"])


def _content_digest(
    target_id: str,
    copy_id: str | None,
    actor_id: str,
    event_type: str,
    detail: Mapping[str, Any],
) -> str:
    payload = _canonical_json(
        {
            "target_id": target_id,
            "copy_id": copy_id,
            "actor_id": actor_id,
            "event_type": event_type,
            "detail": dict(detail),
        }
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _copy_state_from_row(row: sqlite3.Row) -> RetentionCopyState:
    return RetentionCopyState(
        copy_id=row["copy_id"],
        provider=row["provider"],
        file_id=row["file_id"],
        revision=row["revision"],
        sha256=row["sha256"],
        state=row["state"],
        trash_staged_at=(
            None if row["trash_staged_at"] is None else _from_micros(row["trash_staged_at"])
        ),
        deletion_attested_at=(
            None
            if row["deletion_attested_at"] is None
            else _from_micros(row["deletion_attested_at"])
        ),
        deletion_receipt_sha256=row["deletion_receipt_sha256"],
    )


def _retention_event_from_row(row: sqlite3.Row) -> RetentionEvent:
    return RetentionEvent(
        sequence=row["sequence"],
        event_id=row["event_id"],
        target_id=row["target_id"],
        copy_id=row["copy_id"],
        idempotency_key=row["idempotency_key"],
        actor_id=row["actor_id"],
        event_type=row["event_type"],
        detail=json.loads(row["detail_json"]),
        occurred_at=_from_micros(row["occurred_at"]),
    )


def _require_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if len(value) > 512:
        raise ValueError(f"{name} must not exceed 512 characters")


def _require_sha256(value: str, name: str) -> None:
    if not isinstance(value, str) or not _SHA256_PATTERN.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


def _validate_audit_context(audit: AuditContext) -> None:
    if audit.action not in SHARED_AUDIT_ACTIONS:
        raise ValueError("unsupported audit action")
    if audit.result not in {"accepted", "denied"}:
        raise ValueError("unsupported audit result")
    if tuple(sorted(set(audit.roles))) != audit.roles:
        raise ValueError("roles must be a sorted unique tuple")
    for role in audit.roles:
        if role not in SHARED_AUDIT_ROLES:
            raise ValueError("unsupported audit role")
    for value, name in (
        (audit.correlation_id, "correlation_id"),
        (audit.subject_id, "subject_id"),
        (audit.target_id, "target_id"),
    ):
        _require_text(value, name)
    if audit.idempotency_key is not None:
        _require_text(audit.idempotency_key, "idempotency_key")
    _to_micros(audit.occurred_at)


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("retention content must be JSON serializable") from exc


def _to_micros(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return int(value.astimezone(UTC).timestamp() * 1_000_000)


def _from_micros(value: int) -> datetime:
    return datetime.fromtimestamp(value / 1_000_000, tz=UTC)
