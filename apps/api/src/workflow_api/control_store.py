"""Durable, provider-neutral control-plane primitives backed by SQLite.

This module intentionally has no API routes or cloud adapters.  It provides a
small transactional boundary for synthetic development and for a later
authenticated service layer to call.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from .audit_schema import (
    CONTROL_AUDIT_ACTIONS,
    CONTROL_AUDIT_ROLES,
    ensure_shared_audit_schema,
)

MAX_ACTIVE_LEASES = 3
MAX_LEASE_SECONDS = 30 * 60
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_CANDIDATE_TARGET_PATTERN = re.compile(
    r"^candidate-skill:1\.0:(?P<skill>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):sha256:(?P<content>[a-f0-9]{64})$"
)
_PUBLICATION_KEY_PATTERN = re.compile(
    r"^candidate-publication:1\.0:(?P<skill>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"
)
_REVIEWER_ID_PATTERN = re.compile(r"^reviewer_[a-z0-9][a-z0-9_-]{2,63}$")
_MAX_REVIEW_REASON = 512
_MAX_REVIEW_EVIDENCE_BYTES = 16 * 1024
_CANDIDATE_LIFECYCLE_VERSION = "138.1"
_UNSET = object()


class ControlStoreError(RuntimeError):
    """Base error for persistent control-plane operations."""


class ControlConflictError(ControlStoreError):
    """An idempotency key or immutable result conflicts with stored state."""


class JobNotFoundError(ControlStoreError):
    """The requested job is not registered."""


class LeaseUnavailableError(ControlStoreError):
    """The job or global bounded-worker capacity is currently unavailable."""


class StaleLeaseError(ControlStoreError):
    """The caller no longer owns the current, unexpired fencing token."""


@dataclass(frozen=True, slots=True)
class JobRecord:
    job_id: str
    payload_digest: str
    state: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class Lease:
    job_id: str
    owner_id: str
    fencing_token: int
    attempt: int
    acquired_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class Completion:
    job_id: str
    idempotency_key: str
    result_digest: str
    fencing_token: int
    completed_at: datetime


@dataclass(frozen=True, slots=True)
class ReviewEvent:
    sequence: int
    event_id: str
    target_id: str
    idempotency_key: str
    actor_id: str
    status: str
    provenance: dict[str, Any]
    detail: dict[str, Any]
    occurred_at: datetime
    _content_digest: str | None = field(default=None, repr=False, compare=False)

    @property
    def content_digest(self) -> str:
        """Recompute the immutable semantic digest from the public fields."""

        if self._content_digest is not None:
            return self._content_digest
        return _review_content_digest(
            self.target_id,
            self.actor_id,
            self.status,
            self.provenance,
            self.detail,
        )


@dataclass(frozen=True, slots=True)
class ReviewProjection:
    target_id: str
    status: str
    version: int
    last_event_id: str
    actor_id: str
    provenance: dict[str, Any]
    detail: dict[str, Any]
    occurred_at: datetime
    _content_digest: str | None = field(default=None, repr=False, compare=False)

    @property
    def content_digest(self) -> str:
        """Recompute the digest represented by the projection's last event."""

        if self._content_digest is not None:
            return self._content_digest
        return _review_content_digest(
            self.target_id,
            self.actor_id,
            self.status,
            self.provenance,
            self.detail,
        )


@dataclass(frozen=True, slots=True)
class AuditContext:
    """Authenticated request evidence to append with a store mutation."""

    correlation_id: str
    idempotency_key: str | None
    subject_id: str
    roles: tuple[str, ...]
    action: str
    target_id: str
    result: str
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class AuditEvent:
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


_SCHEMA = """
create table if not exists control_jobs (
    job_id text primary key,
    payload_digest text not null,
    state text not null check (state in ('queued', 'leased', 'completed')),
    current_owner_id text,
    current_fencing_token integer not null default 0,
    current_attempt integer not null default 0,
    lease_acquired_at integer,
    lease_expires_at integer,
    heartbeat_at integer,
    completion_idempotency_key text,
    completion_result_digest text,
    completed_at integer,
    created_at integer not null,
    updated_at integer not null,
    check (
        (state = 'leased' and current_owner_id is not null and lease_expires_at is not null)
        or state != 'leased'
    ),
    check (
        (state = 'completed' and completion_idempotency_key is not null
            and completion_result_digest is not null and completed_at is not null)
        or state != 'completed'
    )
);

create index if not exists control_jobs_active_lease_idx
    on control_jobs (state, lease_expires_at);

create table if not exists lease_events (
    sequence integer primary key autoincrement,
    event_id text not null unique,
    job_id text not null references control_jobs(job_id),
    event_type text not null check (
        event_type in ('acquired', 'reacquired', 'heartbeat', 'completed')
    ),
    owner_id text not null,
    fencing_token integer not null check (fencing_token > 0),
    attempt integer not null check (attempt > 0),
    occurred_at integer not null,
    lease_expires_at integer,
    result_digest text
);

create trigger if not exists lease_events_no_update
before update on lease_events
begin
    select raise(abort, 'lease events are immutable');
end;

create trigger if not exists lease_events_no_delete
before delete on lease_events
begin
    select raise(abort, 'lease events are immutable');
end;

create table if not exists review_events (
    sequence integer primary key autoincrement,
    event_id text not null unique,
    target_id text not null,
    idempotency_key text not null,
    content_digest text not null,
    actor_id text not null,
    status text not null check (
        status in ('pending', 'approved', 'rejected', 'needs_changes')
    ),
    provenance_json text not null,
    detail_json text not null,
    occurred_at integer not null,
    unique (idempotency_key)
);

create trigger if not exists review_events_no_update
before update on review_events
begin
    select raise(abort, 'review events are immutable');
end;

create trigger if not exists review_events_no_delete
before delete on review_events
begin
    select raise(abort, 'review events are immutable');
end;

create table if not exists review_projection (
    target_id text primary key,
    status text not null,
    version integer not null check (version > 0),
    last_event_id text not null references review_events(event_id),
    actor_id text not null,
    provenance_json text not null,
    detail_json text not null,
    occurred_at integer not null
);

"""


class SQLiteControlStore:
    """Transactional job leasing and append-only review state.

    A connection is opened for each operation so independent processes and
    threads coordinate through SQLite locking rather than Python object state.
    """

    def __init__(
        self,
        database_path: str | Path,
        *,
        max_active_leases: int = MAX_ACTIVE_LEASES,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        if max_active_leases < 1 or max_active_leases > MAX_ACTIVE_LEASES:
            raise ValueError(f"max_active_leases must be between 1 and {MAX_ACTIVE_LEASES}")
        if busy_timeout_seconds <= 0:
            raise ValueError("busy_timeout_seconds must be positive")
        if str(database_path) == ":memory:":
            raise ValueError("a filesystem path is required for a durable control store")
        self._database_path = str(Path(database_path))
        self._max_active_leases = max_active_leases
        self._busy_timeout_ms = int(busy_timeout_seconds * 1000)
        Path(self._database_path).parent.mkdir(parents=True, exist_ok=True)
        with self._transaction() as connection:
            ensure_shared_audit_schema(
                connection,
                allow_legacy_control_schema=True,
            )
            for statement in _schema_statements(_SCHEMA):
                connection.execute(statement)
        with self._connect() as connection:
            connection.execute("pragma journal_mode = wal")
            connection.execute("pragma synchronous = full")

    def register_job(
        self,
        job_id: str,
        payload_digest: str,
        *,
        now: datetime | None = None,
        audit: AuditContext | None = None,
    ) -> JobRecord:
        _require_text(job_id, "job_id")
        _require_sha256(payload_digest, "payload_digest")
        now_us = _to_micros(now or datetime.now(UTC))
        with self._transaction() as connection:
            row = connection.execute(
                "select * from control_jobs where job_id = ?", (job_id,)
            ).fetchone()
            if row is not None:
                if row["payload_digest"] != payload_digest:
                    raise ControlConflictError("job_id already has a different payload digest")
                self._append_audit_event(connection, audit)
                return _job_from_row(row)
            connection.execute(
                """
                insert into control_jobs (
                    job_id, payload_digest, state, created_at, updated_at
                ) values (?, ?, 'queued', ?, ?)
                """,
                (job_id, payload_digest, now_us, now_us),
            )
            row = connection.execute(
                "select * from control_jobs where job_id = ?", (job_id,)
            ).fetchone()
            assert row is not None
            self._append_audit_event(connection, audit)
            return _job_from_row(row)

    def get_job(self, job_id: str) -> JobRecord:
        with self._connect() as connection:
            row = connection.execute(
                "select * from control_jobs where job_id = ?", (job_id,)
            ).fetchone()
        if row is None:
            raise JobNotFoundError(job_id)
        return _job_from_row(row)

    def acquire(
        self,
        job_id: str,
        owner_id: str,
        *,
        now: datetime | None = None,
        ttl_seconds: int = MAX_LEASE_SECONDS,
        audit: AuditContext | None = None,
    ) -> Lease:
        _require_text(job_id, "job_id")
        _require_text(owner_id, "owner_id")
        _require_ttl(ttl_seconds)
        acquired_at = now or datetime.now(UTC)
        now_us = _to_micros(acquired_at)
        expires_us = _to_micros(acquired_at + timedelta(seconds=ttl_seconds))
        with self._transaction() as connection:
            row = self._job_row(connection, job_id)
            if row["state"] == "completed":
                raise LeaseUnavailableError("job is already completed")
            if row["state"] == "leased" and row["lease_expires_at"] > now_us:
                if row["current_owner_id"] == owner_id:
                    self._append_audit_event(connection, audit)
                    return _lease_from_row(row)
                raise LeaseUnavailableError("job has an unexpired lease")
            active_count = connection.execute(
                """
                select count(*) from control_jobs
                where state = 'leased' and lease_expires_at > ?
                """,
                (now_us,),
            ).fetchone()[0]
            if active_count >= self._max_active_leases:
                raise LeaseUnavailableError("active lease limit reached")
            fencing_token = row["current_fencing_token"] + 1
            attempt = row["current_attempt"] + 1
            event_type = "acquired" if fencing_token == 1 else "reacquired"
            connection.execute(
                """
                update control_jobs
                set state = 'leased', current_owner_id = ?, current_fencing_token = ?,
                    current_attempt = ?, lease_acquired_at = ?, lease_expires_at = ?,
                    heartbeat_at = ?, updated_at = ?
                where job_id = ?
                """,
                (
                    owner_id,
                    fencing_token,
                    attempt,
                    now_us,
                    expires_us,
                    now_us,
                    now_us,
                    job_id,
                ),
            )
            self._append_lease_event(
                connection,
                job_id=job_id,
                event_type=event_type,
                owner_id=owner_id,
                fencing_token=fencing_token,
                attempt=attempt,
                occurred_at=now_us,
                lease_expires_at=expires_us,
            )
            row = self._job_row(connection, job_id)
            self._append_audit_event(connection, audit)
            return _lease_from_row(row)

    def heartbeat(
        self,
        lease: Lease,
        *,
        now: datetime | None = None,
        ttl_seconds: int = MAX_LEASE_SECONDS,
        audit: AuditContext | None = None,
    ) -> Lease:
        _require_ttl(ttl_seconds)
        heartbeat_at = now or datetime.now(UTC)
        now_us = _to_micros(heartbeat_at)
        expires_us = _to_micros(heartbeat_at + timedelta(seconds=ttl_seconds))
        with self._transaction() as connection:
            row = self._job_row(connection, lease.job_id)
            self._require_current_lease(row, lease, now_us)
            connection.execute(
                """
                update control_jobs
                set lease_expires_at = ?, heartbeat_at = ?, updated_at = ?
                where job_id = ?
                """,
                (expires_us, now_us, now_us, lease.job_id),
            )
            self._append_lease_event(
                connection,
                job_id=lease.job_id,
                event_type="heartbeat",
                owner_id=lease.owner_id,
                fencing_token=lease.fencing_token,
                attempt=lease.attempt,
                occurred_at=now_us,
                lease_expires_at=expires_us,
            )
            self._append_audit_event(connection, audit)
            return _lease_from_row(self._job_row(connection, lease.job_id))

    def complete(
        self,
        lease: Lease,
        *,
        idempotency_key: str,
        result_digest: str,
        now: datetime | None = None,
        audit: AuditContext | None = None,
    ) -> Completion:
        _require_text(idempotency_key, "idempotency_key")
        _require_sha256(result_digest, "result_digest")
        completed_at = now or datetime.now(UTC)
        now_us = _to_micros(completed_at)
        with self._transaction() as connection:
            row = self._job_row(connection, lease.job_id)
            if row["state"] == "completed":
                if (
                    row["current_owner_id"] != lease.owner_id
                    or row["current_fencing_token"] != lease.fencing_token
                    or row["current_attempt"] != lease.attempt
                ):
                    raise StaleLeaseError("completion replay is not from the completing lease")
                if (
                    row["completion_idempotency_key"] == idempotency_key
                    and row["completion_result_digest"] == result_digest
                ):
                    self._append_audit_event(connection, audit)
                    return _completion_from_row(row)
                raise ControlConflictError("completion conflicts with the immutable result")
            self._require_current_lease(row, lease, now_us)
            connection.execute(
                """
                update control_jobs
                set state = 'completed', completion_idempotency_key = ?,
                    completion_result_digest = ?, completed_at = ?, updated_at = ?
                where job_id = ?
                """,
                (idempotency_key, result_digest, now_us, now_us, lease.job_id),
            )
            self._append_lease_event(
                connection,
                job_id=lease.job_id,
                event_type="completed",
                owner_id=lease.owner_id,
                fencing_token=lease.fencing_token,
                attempt=lease.attempt,
                occurred_at=now_us,
                result_digest=result_digest,
            )
            self._append_audit_event(connection, audit)
            return _completion_from_row(self._job_row(connection, lease.job_id))

    def append_review_event(
        self,
        *,
        target_id: str,
        idempotency_key: str,
        actor_id: str,
        status: str,
        provenance: Mapping[str, Any],
        detail: Mapping[str, Any] | None = None,
        occurred_at: datetime | None = None,
        audit: AuditContext | None = None,
    ) -> ReviewEvent:
        _require_text(target_id, "target_id")
        _require_text(idempotency_key, "idempotency_key")
        _require_text(actor_id, "actor_id")
        if _is_candidate_review_target(target_id):
            raise ControlConflictError(
                "candidate review targets require the guarded candidate lifecycle operation"
            )
        if status not in {"pending", "approved", "rejected", "needs_changes"}:
            raise ValueError("unsupported review status")
        source = provenance.get("source")
        if not isinstance(source, str) or not source.strip():
            raise ValueError("provenance.source is required")
        artifact_id = provenance.get("artifact_id")
        if not isinstance(artifact_id, str) or not artifact_id.strip():
            raise ValueError("provenance.artifact_id is required")
        revision = provenance.get("revision")
        if not isinstance(revision, str) or not revision.strip():
            raise ValueError("provenance.revision is required")
        artifact_sha256 = provenance.get("sha256")
        if not isinstance(artifact_sha256, str) or not _SHA256_PATTERN.fullmatch(
            artifact_sha256
        ):
            raise ValueError("provenance.sha256 must be a lowercase SHA-256 digest")
        provenance_json = _canonical_json(dict(provenance))
        detail_json = _canonical_json(dict(detail or {}))
        content_digest = _review_content_digest(
            target_id,
            actor_id,
            status,
            json.loads(provenance_json),
            json.loads(detail_json),
        )
        occurred_us = _to_micros(occurred_at or datetime.now(UTC))
        with self._transaction() as connection:
            existing = connection.execute(
                """
                select * from review_events
                where idempotency_key = ?
                """,
                (idempotency_key,),
            ).fetchone()
            if existing is not None:
                if existing["content_digest"] != content_digest:
                    raise ControlConflictError(
                        "review idempotency key conflicts with stored content"
                    )
                self._append_audit_event(connection, audit)
                return _review_event_from_row(existing)
            event_id = str(uuid4())
            cursor = connection.execute(
                """
                insert into review_events (
                    event_id, target_id, idempotency_key, content_digest, actor_id,
                    status, provenance_json, detail_json, occurred_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    target_id,
                    idempotency_key,
                    content_digest,
                    actor_id,
                    status,
                    provenance_json,
                    detail_json,
                    occurred_us,
                ),
            )
            prior = connection.execute(
                "select version from review_projection where target_id = ?", (target_id,)
            ).fetchone()
            version = 1 if prior is None else prior["version"] + 1
            connection.execute(
                """
                insert into review_projection (
                    target_id, status, version, last_event_id, actor_id,
                    provenance_json, detail_json, occurred_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?)
                on conflict(target_id) do update set
                    status = excluded.status,
                    version = excluded.version,
                    last_event_id = excluded.last_event_id,
                    actor_id = excluded.actor_id,
                    provenance_json = excluded.provenance_json,
                    detail_json = excluded.detail_json,
                    occurred_at = excluded.occurred_at
                """,
                (
                    target_id,
                    status,
                    version,
                    event_id,
                    actor_id,
                    provenance_json,
                    detail_json,
                    occurred_us,
                ),
            )
            row = connection.execute(
                "select * from review_events where sequence = ?", (cursor.lastrowid,)
            ).fetchone()
            assert row is not None
            self._append_audit_event(connection, audit)
            return _review_event_from_row(row)

    def append_candidate_review_event(
        self,
        *,
        scope: Any | None = None,
        server_scope: Any | None = None,
        publication_key: str,
        review_target_id: str | None = None,
        target_id: str | None = None,
        idempotency_key: str | None = None,
        qualified_idempotency_key: str | None = None,
        actor_id: str,
        status: str | None = None,
        destination_status: str | None = None,
        schema_version: str = "1.0",
        candidate_id: str | None = None,
        skill_id: str | None = None,
        content_sha256: str,
        full_sha256: str,
        source_result_sha256: str,
        reason: str | None | object = _UNSET,
        evidence: Any = _UNSET,
        expected_prior_state: str | object = _UNSET,
        expected_prior_version: int | object = _UNSET,
        expected_prior_event_id: str | None | object = _UNSET,
        occurred_at: datetime | None = None,
        now: datetime | None = None,
        audit: AuditContext | None = None,
        legacy_provenance: Mapping[str, Any] | None = None,
        legacy_detail: Mapping[str, Any] | None = None,
    ) -> ReviewEvent:
        """Atomically apply one candidate publication review transition.

        Candidate reviews intentionally share ``review_events`` and
        ``review_projection`` with ordinary reviews.  This method is the one
        candidate writer: it validates the candidate identity, checks the
        expected projection under the same SQLite write transaction as the
        append, and appends the audit evidence only for a newly accepted
        transition.  A retry for the exact qualified idempotency payload is a
        read-only replay.

        ``legacy_provenance``/``legacy_detail`` are a narrow compatibility
        seam for the pre-publication candidate-skill approval wrapper.  That
        wrapper still enters this guarded operation; the seam only preserves
        its established public event shape for existing callers.
        """

        scope_value = scope if scope is not None else server_scope
        scope_key = _scope_key(scope_value)
        if scope is not None and server_scope is not None and _scope_key(server_scope) != scope_key:
            raise ControlConflictError("candidate review scope conflicts")
        _require_candidate_publication_key(publication_key)
        selected_target = review_target_id if review_target_id is not None else target_id
        if review_target_id is not None and target_id is not None and review_target_id != target_id:
            raise ControlConflictError("candidate review target conflicts")
        _require_text(selected_target, "review_target_id")
        target_match = _CANDIDATE_TARGET_PATTERN.fullmatch(selected_target)
        if target_match is None:
            raise ControlConflictError("candidate review target syntax is invalid")
        publication_match = _PUBLICATION_KEY_PATTERN.fullmatch(publication_key)
        assert publication_match is not None  # _require_candidate_publication_key
        target_skill_id = target_match.group("skill")
        if publication_match.group("skill") != target_skill_id:
            raise ControlConflictError("candidate publication and target identities conflict")

        selected_skill_id = skill_id if skill_id is not None else candidate_id
        if skill_id is not None and candidate_id is not None and skill_id != candidate_id:
            raise ControlConflictError("candidate and skill identities conflict")
        if selected_skill_id is None:
            selected_skill_id = target_skill_id
        if selected_skill_id != target_skill_id or not _UUID_PATTERN.fullmatch(selected_skill_id):
            raise ControlConflictError("candidate skill identity is invalid")
        if schema_version != "1.0":
            raise ValueError('schema_version must be exactly "1.0"')
        for digest, name in (
            (content_sha256, "content_sha256"),
            (full_sha256, "full_sha256"),
            (source_result_sha256, "source_result_sha256"),
        ):
            _require_sha256(digest, name)
        if target_match.group("content") != content_sha256:
            raise ControlConflictError("candidate target content digest conflicts")
        selected_status = status if status is not None else destination_status
        if status is not None and destination_status is not None and status != destination_status:
            raise ControlConflictError("candidate destination status conflicts")
        if selected_status not in {"pending", "approved", "rejected", "needs_changes"}:
            raise ValueError("unsupported candidate review status")
        _require_text(actor_id, "actor_id")
        if _REVIEWER_ID_PATTERN.fullmatch(actor_id) is None:
            raise ControlConflictError("candidate reviewer identity is invalid")

        qualified_target = _qualify_scope_key(scope_key, "review_target", selected_target)
        qualified_key = _candidate_idempotency_key(
            scope_key,
            idempotency_key=idempotency_key,
            qualified_idempotency_key=qualified_idempotency_key,
        )
        legacy = legacy_provenance is not None or legacy_detail is not None
        if legacy and (legacy_provenance is None or legacy_detail is None):
            raise ValueError("legacy candidate event requires both JSON objects")
        if legacy:
            assert legacy_provenance is not None and legacy_detail is not None
            provenance_input = _bounded_review_mapping(legacy_provenance, "provenance")
            detail_input = _bounded_review_mapping(legacy_detail, "detail")
            # Keep the old approval seam bound to the exact candidate target.
            _validate_review_provenance(provenance_input)
        else:
            provenance_input = None
            detail_input = None
        if reason is not _UNSET and reason is not None and (
            type(reason) is not str or not reason.strip() or len(reason) > _MAX_REVIEW_REASON
        ):
            raise ValueError("candidate review reason is outside the bound")
        evidence_provided = evidence is not _UNSET
        evidence_value = (
            None if not evidence_provided else _bounded_review_value(evidence, "evidence")
        )

        explicit_time = occurred_at if occurred_at is not None else now
        if (
            occurred_at is not None
            and now is not None
            and _to_micros(occurred_at) != _to_micros(now)
        ):
            raise ValueError("occurred_at and now conflict")

        with self._transaction() as connection:
            existing = connection.execute(
                "select * from review_events where idempotency_key = ?",
                (qualified_key,),
            ).fetchone()
            if existing is not None:
                # Replays use the persisted server timestamp when the caller
                # did not supply one.  This keeps a normal service retry exact
                # while an explicitly changed bound timestamp still conflicts.
                replay_time = (
                    _from_micros(existing["occurred_at"])
                    if explicit_time is None
                    else explicit_time
                )
                if not legacy:
                    try:
                        stored_detail = json.loads(existing["detail_json"])
                    except (TypeError, ValueError, json.JSONDecodeError) as exc:
                        raise ControlConflictError("candidate review JSON is corrupt") from exc
                    if not isinstance(stored_detail, dict):
                        raise ControlConflictError("candidate review JSON is corrupt")
                    if expected_prior_state is _UNSET:
                        expected_prior_state = stored_detail.get("expected_prior_state", _UNSET)
                    if expected_prior_version is _UNSET:
                        expected_prior_version = stored_detail.get("expected_prior_version", _UNSET)
                    if expected_prior_event_id is _UNSET:
                        expected_prior_event_id = stored_detail.get("expected_prior_event_id", _UNSET)
                    if reason is _UNSET and "reason" in stored_detail:
                        reason = stored_detail["reason"]
                    if not evidence_provided and "evidence" in stored_detail:
                        evidence_value = stored_detail["evidence"]
                if reason is _UNSET:
                    reason = None
                expected_digest, _provenance, _detail = _candidate_event_payload(
                    scope_key=scope_key,
                    qualified_target=qualified_target,
                    qualified_idempotency_key=qualified_key,
                    publication_key=publication_key,
                    review_target_id=selected_target,
                    schema_version=schema_version,
                    skill_id=selected_skill_id,
                    content_sha256=content_sha256,
                    full_sha256=full_sha256,
                    source_result_sha256=source_result_sha256,
                    status=selected_status,
                    reason=reason,
                    evidence=evidence_value,
                    expected_prior_state=expected_prior_state,
                    expected_prior_version=expected_prior_version,
                    expected_prior_event_id=expected_prior_event_id,
                    actor_id=actor_id,
                    occurred_at=replay_time,
                    legacy_provenance=provenance_input,
                    legacy_detail=detail_input,
                )
                if existing["content_digest"] != expected_digest:
                    raise ControlConflictError(
                        "candidate review idempotency key conflicts with stored content"
                    )
                projection = connection.execute(
                    "select * from review_projection where target_id = ?",
                    (existing["target_id"],),
                ).fetchone()
                history = connection.execute(
                    "select * from review_events where target_id = ? order by sequence",
                    (existing["target_id"],),
                ).fetchall()
                if projection is None or not any(
                    row["event_id"] == existing["event_id"] for row in history
                ):
                    raise ControlConflictError("candidate review authority is ambiguous")
                _validate_candidate_projection(connection, projection, history)
                return _review_event_from_row(existing)

            if reason is _UNSET:
                reason = None
            projection = connection.execute(
                "select * from review_projection where target_id = ?",
                (qualified_target,),
            ).fetchone()
            prior_events = connection.execute(
                "select * from review_events where target_id = ? order by sequence",
                (qualified_target,),
            ).fetchall()
            if projection is None:
                if prior_events:
                    raise ControlConflictError("candidate review authority is ambiguous")
                current_state = "unreviewed"
                current_version = 0
                current_event_id = None
            else:
                if not prior_events or len(prior_events) != 1 and projection["status"] == "unreviewed":
                    raise ControlConflictError("candidate review projection is corrupt")
                _validate_candidate_projection(connection, projection, prior_events)
                current_state = projection["status"]
                current_version = projection["version"]
                current_event_id = projection["last_event_id"]

            resolved_prior_state = (
                current_state if expected_prior_state is _UNSET else expected_prior_state
            )
            resolved_prior_version = (
                current_version if expected_prior_version is _UNSET else expected_prior_version
            )
            resolved_prior_event = (
                current_event_id
                if expected_prior_event_id is _UNSET
                else expected_prior_event_id
            )
            _validate_expected_prior(
                current_state,
                current_version,
                current_event_id,
                resolved_prior_state,
                resolved_prior_version,
                resolved_prior_event,
            )
            if not _legal_candidate_transition(current_state, selected_status):
                raise ControlConflictError(
                    f"candidate review transition {current_state}->{selected_status} is not legal"
                )
            event_time = _resolve_review_time(explicit_time)
            content_digest, provenance_json, detail_json = _candidate_event_payload(
                scope_key=scope_key,
                qualified_target=qualified_target,
                qualified_idempotency_key=qualified_key,
                publication_key=publication_key,
                review_target_id=selected_target,
                schema_version=schema_version,
                skill_id=selected_skill_id,
                content_sha256=content_sha256,
                full_sha256=full_sha256,
                source_result_sha256=source_result_sha256,
                status=selected_status,
                reason=reason,
                evidence=evidence_value,
                expected_prior_state=resolved_prior_state,
                expected_prior_version=resolved_prior_version,
                expected_prior_event_id=resolved_prior_event,
                actor_id=actor_id,
                occurred_at=event_time,
                legacy_provenance=provenance_input,
                legacy_detail=detail_input,
            )
            event_id = str(uuid4())
            cursor = connection.execute(
                """
                insert into review_events (
                    event_id, target_id, idempotency_key, content_digest, actor_id,
                    status, provenance_json, detail_json, occurred_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    qualified_target,
                    qualified_key,
                    content_digest,
                    actor_id,
                    selected_status,
                    provenance_json,
                    detail_json,
                    _to_micros(event_time),
                ),
            )
            next_version = current_version + 1
            connection.execute(
                """
                insert into review_projection (
                    target_id, status, version, last_event_id, actor_id,
                    provenance_json, detail_json, occurred_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?)
                on conflict(target_id) do update set
                    status = excluded.status,
                    version = excluded.version,
                    last_event_id = excluded.last_event_id,
                    actor_id = excluded.actor_id,
                    provenance_json = excluded.provenance_json,
                    detail_json = excluded.detail_json,
                    occurred_at = excluded.occurred_at
                """,
                (
                    qualified_target,
                    selected_status,
                    next_version,
                    event_id,
                    actor_id,
                    provenance_json,
                    detail_json,
                    _to_micros(event_time),
                ),
            )
            self._append_audit_event(connection, audit)
            row = connection.execute(
                "select * from review_events where sequence = ?", (cursor.lastrowid,)
            ).fetchone()
            assert row is not None
            return _review_event_from_row(row)

    # Keep several descriptive spellings on the same guarded writer.  These
    # aliases do not introduce additional authorities or mutation paths.
    append_candidate_review = append_candidate_review_event
    transition_candidate_review = append_candidate_review_event
    review_candidate = append_candidate_review_event

    def get_review_projection(self, target_id: str) -> ReviewProjection | None:
        if _is_candidate_review_target(target_id):
            return self.get_candidate_review_projection(target_id)
        with self._connect() as connection:
            row = connection.execute(
                "select * from review_projection where target_id = ?", (target_id,)
            ).fetchone()
        return None if row is None else _review_projection_from_row(row)

    def get_candidate_review_projection(
        self, target_id: str
    ) -> ReviewProjection | None:
        """Read a candidate projection only after event/projection integrity checks."""

        if not _is_candidate_review_target(target_id):
            raise ControlConflictError("candidate review target syntax is invalid")
        with self._connect() as connection:
            projection = connection.execute(
                "select * from review_projection where target_id = ?", (target_id,)
            ).fetchone()
            if projection is None:
                events = connection.execute(
                    "select * from review_events where target_id = ? order by sequence",
                    (target_id,),
                ).fetchall()
                if events:
                    raise ControlConflictError("candidate review authority is ambiguous")
                return None
            events = connection.execute(
                "select * from review_events where target_id = ? order by sequence",
                (target_id,),
            ).fetchall()
            _validate_candidate_projection(connection, projection, events)
            return _review_projection_from_row(projection)

    def list_candidate_review_events(
        self,
        target_id: str,
        *,
        after_sequence: int,
        limit: int,
    ) -> list[ReviewEvent]:
        """List candidate events after validating the complete projection chain."""

        if not _is_candidate_review_target(target_id):
            raise ControlConflictError("candidate review target syntax is invalid")
        _require_pagination(after_sequence, limit)
        with self._connect() as connection:
            projection = connection.execute(
                "select * from review_projection where target_id = ?", (target_id,)
            ).fetchone()
            rows = connection.execute(
                "select * from review_events where target_id = ? order by sequence",
                (target_id,),
            ).fetchall()
            if projection is None:
                if rows:
                    raise ControlConflictError("candidate review authority is ambiguous")
                return []
            _validate_candidate_projection(connection, projection, rows)
            return [
                ReviewEvent(
                    sequence=index + 1,
                    event_id=event.event_id,
                    target_id=event.target_id,
                    idempotency_key=event.idempotency_key,
                    actor_id=event.actor_id,
                    status=event.status,
                    provenance=event.provenance,
                    detail=event.detail,
                    occurred_at=event.occurred_at,
                    _content_digest=event.content_digest,
                )
                for index, event in enumerate(
                    [_review_event_from_row(row) for row in rows],
                )
                if after_sequence < index + 1 <= after_sequence + limit
            ]

    def list_review_events(self, target_id: str) -> list[ReviewEvent]:
        if _is_candidate_review_target(target_id):
            return self.list_candidate_review_events(
                target_id,
                after_sequence=0,
                limit=100,
            )
        with self._connect() as connection:
            rows = connection.execute(
                "select * from review_events where target_id = ? order by sequence",
                (target_id,),
            ).fetchall()
        return [_review_event_from_row(row) for row in rows]

    def list_scoped_review_events(
        self,
        target_id: str,
        *,
        after_sequence: int,
        limit: int,
    ) -> list[ReviewEvent]:
        """Page one qualified target and expose only target-local sequence numbers."""

        _require_text(target_id, "target_id")
        _require_pagination(after_sequence, limit)
        if _is_candidate_review_target(target_id):
            return self.list_candidate_review_events(
                target_id,
                after_sequence=after_sequence,
                limit=limit,
            )
        with self._connect() as connection:
            rows = connection.execute(
                """
                with scoped as (
                    select row_number() over (order by sequence) as sequence,
                           event_id, target_id, idempotency_key, content_digest, actor_id, status,
                           provenance_json, detail_json, occurred_at
                    from review_events where target_id = ?
                )
                select * from scoped
                where sequence > ? order by sequence limit ?
                """,
                (target_id, after_sequence, limit),
            ).fetchall()
        return [_review_event_from_row(row) for row in rows]

    def append_audit_event(self, audit: AuditContext) -> AuditEvent:
        """Append standalone evidence, used for authenticated authorization denial."""

        with self._transaction() as connection:
            sequence = self._append_audit_event(connection, audit)
            assert sequence is not None
            row = connection.execute(
                "select * from audit_events where sequence = ?", (sequence,)
            ).fetchone()
            assert row is not None
            return _audit_event_from_row(row)

    def list_audit_events(
        self, *, after_sequence: int = 0, limit: int = 100
    ) -> list[AuditEvent]:
        if not isinstance(after_sequence, int) or isinstance(after_sequence, bool):
            raise TypeError("after_sequence must be an integer")
        if after_sequence < 0:
            raise ValueError("after_sequence must not be negative")
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise TypeError("limit must be an integer")
        if limit < 1 or limit > 100:
            raise ValueError("limit must be between 1 and 100")
        with self._connect() as connection:
            rows = connection.execute(
                """
                select * from audit_events
                where sequence > ? order by sequence limit ?
                """,
                (after_sequence, limit),
            ).fetchall()
        return [_audit_event_from_row(row) for row in rows]

    def get_audit_event(self, event_id: str) -> AuditEvent | None:
        _require_text(event_id, "event_id")
        with self._connect() as connection:
            row = connection.execute(
                "select * from audit_events where event_id = ?", (event_id,)
            ).fetchone()
        return None if row is None else _audit_event_from_row(row)

    def list_scoped_audit_events(
        self,
        scope_prefix: str,
        *,
        after_sequence: int = 0,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Apply exact scope selection in SQL before numbering and pagination."""

        _require_text(scope_prefix, "scope_prefix")
        _require_pagination(after_sequence, limit)
        with self._connect() as connection:
            rows = connection.execute(
                """
                with scoped as (
                    select row_number() over (order by sequence) as sequence,
                           event_id, correlation_id, idempotency_key, subject_id,
                           roles_json, action, target_id, result, occurred_at
                    from audit_events
                    where substr(target_id, 1, length(?)) = ?
                )
                select * from scoped
                where sequence > ? order by sequence limit ?
                """,
                (scope_prefix, scope_prefix, after_sequence, limit),
            ).fetchall()
        return [_audit_event_from_row(row) for row in rows]

    def get_scoped_audit_event(
        self,
        event_id: str,
        *,
        scope_prefix: str,
    ) -> AuditEvent | None:
        """Read one event only when its qualified target is in the exact scope."""

        _require_text(event_id, "event_id")
        _require_text(scope_prefix, "scope_prefix")
        with self._connect() as connection:
            row = connection.execute(
                """
                select (
                           select count(*) from audit_events prior
                           where substr(prior.target_id, 1, length(?)) = ?
                             and prior.sequence <= current.sequence
                       ) as sequence,
                       current.event_id, current.correlation_id,
                       current.idempotency_key, current.subject_id,
                       current.roles_json, current.action, current.target_id,
                       current.result, current.occurred_at
                from audit_events current
                where current.event_id = ?
                  and substr(current.target_id, 1, length(?)) = ?
                """,
                (
                    scope_prefix,
                    scope_prefix,
                    event_id,
                    scope_prefix,
                    scope_prefix,
                ),
            ).fetchone()
        return None if row is None else _audit_event_from_row(row)

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

    @staticmethod
    def _job_row(connection: sqlite3.Connection, job_id: str) -> sqlite3.Row:
        row = connection.execute(
            "select * from control_jobs where job_id = ?", (job_id,)
        ).fetchone()
        if row is None:
            raise JobNotFoundError(job_id)
        return row

    @staticmethod
    def _require_current_lease(row: sqlite3.Row, lease: Lease, now_us: int) -> None:
        if (
            row["state"] != "leased"
            or row["current_owner_id"] != lease.owner_id
            or row["current_fencing_token"] != lease.fencing_token
            or row["current_attempt"] != lease.attempt
            or row["lease_expires_at"] <= now_us
        ):
            raise StaleLeaseError("lease is expired, superseded, or not current")

    @staticmethod
    def _append_lease_event(
        connection: sqlite3.Connection,
        *,
        job_id: str,
        event_type: str,
        owner_id: str,
        fencing_token: int,
        attempt: int,
        occurred_at: int,
        lease_expires_at: int | None = None,
        result_digest: str | None = None,
    ) -> None:
        connection.execute(
            """
            insert into lease_events (
                event_id, job_id, event_type, owner_id, fencing_token, attempt,
                occurred_at, lease_expires_at, result_digest
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid4()),
                job_id,
                event_type,
                owner_id,
                fencing_token,
                attempt,
                occurred_at,
                lease_expires_at,
                result_digest,
            ),
        )

    @staticmethod
    def _append_audit_event(
        connection: sqlite3.Connection, audit: AuditContext | None
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


def _require_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _schema_statements(script: str) -> tuple[str, ...]:
    """Split the fixed control DDL without losing trigger bodies."""

    statements: list[str] = []
    pending = ""
    for line in script.splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            statements.append(pending.strip())
            pending = ""
    if pending.strip():  # pragma: no cover - fixed module constant guard
        raise RuntimeError("incomplete control schema statement")
    return tuple(statements)


def _require_sha256(value: str, name: str) -> None:
    if not _SHA256_PATTERN.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


def _require_ttl(ttl_seconds: int) -> None:
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool):
        raise TypeError("ttl_seconds must be an integer")
    if ttl_seconds < 1 or ttl_seconds > MAX_LEASE_SECONDS:
        raise ValueError(f"ttl_seconds must be between 1 and {MAX_LEASE_SECONDS}")


def _require_pagination(after_sequence: int, limit: int) -> None:
    if not isinstance(after_sequence, int) or isinstance(after_sequence, bool):
        raise TypeError("after_sequence must be an integer")
    if after_sequence < 0:
        raise ValueError("after_sequence must not be negative")
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise TypeError("limit must be an integer")
    if limit < 1 or limit > 100:
        raise ValueError("limit must be between 1 and 100")


def _validate_audit_context(audit: AuditContext) -> None:
    if audit.action not in CONTROL_AUDIT_ACTIONS:
        raise ValueError("unsupported audit action")
    for value, name in (
        (audit.correlation_id, "correlation_id"),
        (audit.subject_id, "subject_id"),
        (audit.action, "action"),
        (audit.target_id, "target_id"),
        (audit.result, "result"),
    ):
        _require_text(value, name)
        if len(value) > 512:
            raise ValueError(f"{name} must not exceed 512 characters")
    if audit.idempotency_key is not None:
        _require_text(audit.idempotency_key, "idempotency_key")
        if len(audit.idempotency_key) > 512:
            raise ValueError("idempotency_key must not exceed 512 characters")
    if not isinstance(audit.roles, tuple):
        raise TypeError("roles must be a tuple")
    if len(audit.roles) > 3 or tuple(sorted(set(audit.roles))) != audit.roles:
        raise ValueError("roles must be a sorted unique tuple")
    for role in audit.roles:
        _require_text(role, "role")
        if role not in CONTROL_AUDIT_ROLES:
            raise ValueError("unsupported audit role")
    if audit.result not in {"accepted", "denied"}:
        raise ValueError("unsupported audit result")
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
        raise ValueError("review content must be JSON serializable") from exc


def _review_content_digest(
    target_id: str,
    actor_id: str,
    status: str,
    provenance: Mapping[str, Any],
    detail: Mapping[str, Any],
) -> str:
    semantic_content = _canonical_json(
        {
            "target_id": target_id,
            "actor_id": actor_id,
            "status": status,
            "provenance": dict(provenance),
            "detail": dict(detail),
        }
    )
    return hashlib.sha256(semantic_content.encode("utf-8")).hexdigest()


def _is_candidate_review_target(value: str) -> bool:
    if _CANDIDATE_TARGET_PATTERN.fullmatch(value):
        return True
    # Qualified targets are deliberately rejected too.  The exact scope
    # prefix is opaque here, so a bounded search is safer than accepting a
    # candidate-looking suffix from an unrelated key shape.
    return "candidate-skill:1.0:" in value and bool(
        re.search(
            r"candidate-skill:1\.0:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:sha256:[a-f0-9]{64}$",
            value,
        )
    )


def _scope_key(value: Any) -> str:
    if value is None:
        raise ValueError("candidate review scope is required")
    if isinstance(value, str):
        if not _valid_scope_key(value):
            raise ValueError("candidate review scope is invalid")
        return value
    try:
        from .control_scope import _scope_prefix

        result = _scope_prefix(value)
    except (ImportError, TypeError, ValueError) as exc:
        raise ValueError("candidate review scope is invalid") from exc
    if not _valid_scope_key(result):
        raise ValueError("candidate review scope is invalid")
    return result


def _valid_scope_key(value: str) -> bool:
    if not value.startswith("whscope1|"):
        return False
    try:
        from .control_scope import _SCOPE_ID_PATTERN

        offset = len("whscope1|")
        for _ in range(2):
            separator = value.find(":", offset)
            if separator <= offset or not value[offset:separator].isdigit():
                return False
            length = int(value[offset:separator])
            start = separator + 1
            end = start + length
            if length < 3 or length > 64 or end > len(value):
                return False
            if value[offset:separator] != str(length):
                return False
            if _SCOPE_ID_PATTERN.fullmatch(value[start:end]) is None:
                return False
            offset = end
        return offset == len(value)
    except (ImportError, TypeError, ValueError):
        return False


def _qualify_scope_key(scope_key: str, object_kind: str, public_id: str) -> str:
    if not isinstance(public_id, str) or not public_id.strip():
        raise ValueError("candidate review identifier is invalid")
    return f"{scope_key}{len(object_kind)}:{object_kind}{len(public_id)}:{public_id}"


def _candidate_idempotency_key(
    scope_key: str,
    *,
    idempotency_key: str | None,
    qualified_idempotency_key: str | None,
) -> str:
    if (
        idempotency_key is not None
        and qualified_idempotency_key is not None
        and idempotency_key != qualified_idempotency_key
    ):
        raise ControlConflictError("candidate idempotency keys conflict")
    selected = qualified_idempotency_key or idempotency_key
    if not isinstance(selected, str) or not selected.strip() or len(selected) > 512:
        raise ValueError("candidate idempotency key is invalid")
    prefix = f"{scope_key}{len('review_idempotency')}:review_idempotency"
    if selected.startswith(prefix):
        # Ensure this is a complete qualified segment, not a key with a
        # candidate-looking prefix followed by an ambiguous suffix.
        public = selected[len(prefix) :]
        if not public:
            raise ValueError("candidate qualified idempotency key is invalid")
        separator = public.find(":")
        if separator <= 0 or not public[:separator].isdigit():
            raise ValueError("candidate qualified idempotency key is invalid")
        length = int(public[:separator])
        value = public[separator + 1 :]
        if length < 1 or length > 512 or len(value) != length:
            raise ValueError("candidate qualified idempotency key is invalid")
        return selected
    if qualified_idempotency_key is not None:
        raise ControlConflictError("candidate idempotency key is outside the server scope")
    return f"{prefix}{len(selected)}:{selected}"


def _require_candidate_publication_key(value: Any) -> None:
    if not isinstance(value, str) or _PUBLICATION_KEY_PATTERN.fullmatch(value) is None:
        raise ValueError("candidate publication key is invalid")


def _bounded_review_value(value: Any, name: str) -> Any:
    if value is None:
        return None
    try:
        normalized = json.loads(_canonical_json(value))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"candidate review {name} must be canonical JSON") from exc
    if len(_canonical_json(normalized).encode("utf-8")) > _MAX_REVIEW_EVIDENCE_BYTES:
        raise ValueError(f"candidate review {name} exceeds the byte limit")
    return normalized


def _bounded_review_mapping(value: Mapping[str, Any], name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"candidate review {name} must be an object")
    normalized = _bounded_review_value(dict(value), name)
    if not isinstance(normalized, dict):
        raise TypeError(f"candidate review {name} must be an object")
    return normalized


def _validate_review_provenance(provenance: Mapping[str, Any]) -> None:
    for name in ("source", "artifact_id", "revision"):
        if not isinstance(provenance.get(name), str) or not provenance[name].strip():
            raise ValueError(f"provenance.{name} is required")
    _require_sha256(provenance.get("sha256"), "provenance.sha256")


def _resolve_review_time(value: datetime | None) -> datetime:
    resolved = value or datetime.now(UTC)
    if resolved.tzinfo is None or resolved.utcoffset() is None:
        raise ValueError("candidate review timestamp must be timezone-aware")
    return _from_micros(_to_micros(resolved))


def _candidate_event_payload(
    *,
    scope_key: str,
    qualified_target: str,
    qualified_idempotency_key: str,
    publication_key: str,
    review_target_id: str,
    schema_version: str,
    skill_id: str,
    content_sha256: str,
    full_sha256: str,
    source_result_sha256: str,
    status: str,
    reason: str | None,
    evidence: Any,
    expected_prior_state: str | object,
    expected_prior_version: int | object,
    expected_prior_event_id: str | None | object,
    actor_id: str,
    occurred_at: datetime,
    legacy_provenance: Mapping[str, Any] | None,
    legacy_detail: Mapping[str, Any] | None,
) -> tuple[str, str, str]:
    if legacy_provenance is not None or legacy_detail is not None:
        if legacy_provenance is None or legacy_detail is None:
            raise ValueError("legacy candidate event requires both JSON objects")
        provenance = dict(legacy_provenance)
        detail = dict(legacy_detail)
    else:
        if expected_prior_state is _UNSET:
            expected_prior_state = "unreviewed"
        if expected_prior_version is _UNSET:
            expected_prior_version = 0
        if expected_prior_event_id is _UNSET:
            expected_prior_event_id = None
        if expected_prior_state not in {
            "unreviewed",
            "pending",
            "approved",
            "rejected",
            "needs_changes",
        }:
            raise ValueError("expected_prior_state is invalid")
        if type(expected_prior_version) is not int or not 0 <= expected_prior_version <= 2**63 - 1:
            raise ValueError("expected_prior_version is invalid")
        if expected_prior_event_id is not None and (
            type(expected_prior_event_id) is not str
            or _UUID_PATTERN.fullmatch(expected_prior_event_id) is None
        ):
            raise ValueError("expected_prior_event_id is invalid")
        server_time = occurred_at.astimezone(UTC).isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        )
        provenance = {
            "source": "candidate_publication_review",
            "artifact_id": publication_key,
            "revision": schema_version,
            "sha256": content_sha256,
            "scope": scope_key,
            "publication_key": publication_key,
            "review_target_id": review_target_id,
            "schema_version": schema_version,
            "candidate_id": skill_id,
            "skill_id": skill_id,
            "content_sha256": content_sha256,
            "full_sha256": full_sha256,
            "source_result_sha256": source_result_sha256,
            "destination_status": status,
            "expected_prior_state": expected_prior_state,
            "expected_prior_version": expected_prior_version,
            "expected_prior_event_id": expected_prior_event_id,
            "reviewer_id": actor_id,
            "server_reviewer_id": actor_id,
            "server_utc_time": server_time,
            "qualified_idempotency_key": qualified_idempotency_key,
        }
        detail = {
            "lifecycle_schema_version": _CANDIDATE_LIFECYCLE_VERSION,
            "scope": scope_key,
            "publication_key": publication_key,
            "review_target_id": review_target_id,
            "schema_version": schema_version,
            "candidate_id": skill_id,
            "skill_id": skill_id,
            "content_sha256": content_sha256,
            "full_sha256": full_sha256,
            "source_result_sha256": source_result_sha256,
            "destination_status": status,
            "status": status,
            "reason": reason,
            "evidence": evidence,
            "expected_prior_state": expected_prior_state,
            "expected_prior_version": expected_prior_version,
            "expected_prior_event_id": expected_prior_event_id,
            "reviewer_id": actor_id,
            "server_reviewer_id": actor_id,
            "server_utc_time": server_time,
            "qualified_idempotency_key": qualified_idempotency_key,
        }
    _validate_review_provenance(provenance)
    provenance_json = _canonical_json(provenance)
    detail_json = _canonical_json(detail)
    return (
        _review_content_digest(qualified_target, actor_id, status, provenance, detail),
        provenance_json,
        detail_json,
    )


def _validate_expected_prior(
    current_state: str,
    current_version: int,
    current_event_id: str | None,
    expected_state: object,
    expected_version: object,
    expected_event_id: object,
) -> None:
    if expected_state != current_state:
        raise ControlConflictError("candidate review expected prior state conflicts")
    if expected_version != current_version:
        raise ControlConflictError("candidate review expected prior version conflicts")
    if expected_event_id != current_event_id:
        raise ControlConflictError("candidate review expected prior event conflicts")


def _legal_candidate_transition(current_state: str, destination: str) -> bool:
    return destination in {
        "unreviewed": {"pending", "approved"},
        "pending": {"approved", "rejected", "needs_changes"},
        "approved": set(),
        "rejected": set(),
        "needs_changes": set(),
    }.get(current_state, set())


def _validate_candidate_projection(
    connection: sqlite3.Connection,
    projection: sqlite3.Row,
    events: list[sqlite3.Row],
) -> None:
    if not events:
        raise ControlConflictError("candidate review event history is missing")
    if not _is_candidate_review_target(projection["target_id"]):
        raise ControlConflictError("candidate review target is corrupt")
    if projection["status"] not in {"pending", "approved", "rejected", "needs_changes"}:
        raise ControlConflictError("candidate review projection status is invalid")
    if type(projection["version"]) is not int or projection["version"] != len(events):
        raise ControlConflictError("candidate review projection version is corrupt")
    current_state = "unreviewed"
    current_event_id: str | None = None
    for index, event_row in enumerate(events):
        if event_row["target_id"] != projection["target_id"]:
            raise ControlConflictError("candidate review event target is corrupt")
        if (
            not isinstance(event_row["event_id"], str)
            or _UUID_PATTERN.fullmatch(event_row["event_id"]) is None
        ):
            raise ControlConflictError("candidate review event id is corrupt")
        try:
            event_provenance = json.loads(event_row["provenance_json"])
            event_detail = json.loads(event_row["detail_json"])
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ControlConflictError("candidate review JSON is corrupt") from exc
        if not isinstance(event_provenance, dict) or not isinstance(event_detail, dict):
            raise ControlConflictError("candidate review JSON is corrupt")
        if event_row["content_digest"] != _review_content_digest(
            event_row["target_id"],
            event_row["actor_id"],
            event_row["status"],
            event_provenance,
            event_detail,
        ):
            raise ControlConflictError("candidate review event digest is corrupt")
        if not _legal_candidate_transition(current_state, event_row["status"]):
            raise ControlConflictError("candidate review event transition is corrupt")
        lifecycle_markers = {
            "lifecycle_schema_version",
            "publication_key",
            "review_target_id",
            "destination_status",
            "expected_prior_state",
            "expected_prior_version",
            "expected_prior_event_id",
            "qualified_idempotency_key",
        }
        if any(marker in event_detail or marker in event_provenance for marker in lifecycle_markers):
            _validate_candidate_lifecycle_event(
                event_row,
                event_provenance,
                event_detail,
                current_state=current_state,
                current_version=index,
                current_event_id=current_event_id,
            )
        elif (
            index != 0
            or event_row["status"] != "approved"
            or not _validate_legacy_candidate_event(event_row, event_provenance, event_detail)
        ):
            # The old candidate-skill approval event shape remains readable as
            # one initial approval only.  Any subsequent or non-approval
            # legacy-looking event is ambiguous rather than a new authority.
            raise ControlConflictError("candidate review event lifecycle is corrupt")
        current_state = event_row["status"]
        current_event_id = event_row["event_id"]
    event = connection.execute(
        "select * from review_events where event_id = ?", (projection["last_event_id"],)
    ).fetchone()
    if event is None or event["event_id"] != events[-1]["event_id"]:
        raise ControlConflictError("candidate review projection event is corrupt")
    _validate_candidate_rows(event, projection)
    if event["content_digest"] != _review_content_digest(
        event["target_id"],
        event["actor_id"],
        event["status"],
        json.loads(event["provenance_json"]),
        json.loads(event["detail_json"]),
    ):
        raise ControlConflictError("candidate review event digest is corrupt")


def _validate_candidate_lifecycle_event(
    event: sqlite3.Row,
    provenance: Mapping[str, Any],
    detail: Mapping[str, Any],
    *,
    current_state: str,
    current_version: int,
    current_event_id: str | None,
) -> None:
    """Validate every Decision-138 binding on one persisted lifecycle event."""

    required = (
        "scope",
        "publication_key",
        "review_target_id",
        "schema_version",
        "candidate_id",
        "skill_id",
        "content_sha256",
        "full_sha256",
        "source_result_sha256",
        "destination_status",
        "expected_prior_state",
        "expected_prior_version",
        "expected_prior_event_id",
        "reviewer_id",
        "server_reviewer_id",
        "server_utc_time",
        "qualified_idempotency_key",
    )
    if detail.get("lifecycle_schema_version") != _CANDIDATE_LIFECYCLE_VERSION:
        raise ControlConflictError("candidate review lifecycle schema is corrupt")
    if any(name not in provenance or name not in detail for name in required):
        raise ControlConflictError("candidate review lifecycle binding is incomplete")
    if "reason" not in detail or "evidence" not in detail:
        raise ControlConflictError("candidate review reason/evidence binding is incomplete")
    if detail.get("status") != event["status"]:
        raise ControlConflictError("candidate review destination status is corrupt")
    if any(provenance.get(name) != detail.get(name) for name in required):
        raise ControlConflictError("candidate review lifecycle binding conflicts")
    try:
        _validate_review_provenance(provenance)
    except (TypeError, ValueError) as exc:
        raise ControlConflictError("candidate review provenance is corrupt") from exc
    if (
        provenance.get("source") != "candidate_publication_review"
        or provenance.get("artifact_id") != detail["publication_key"]
        or provenance.get("revision") != detail["schema_version"]
        or provenance.get("sha256") != detail["content_sha256"]
    ):
        raise ControlConflictError("candidate review provenance binding conflicts")
    scope_key = detail["scope"]
    review_target_id = detail["review_target_id"]
    publication_key = detail["publication_key"]
    schema_version = detail["schema_version"]
    skill_id = detail["skill_id"]
    if not isinstance(scope_key, str) or not _valid_scope_key(scope_key):
        raise ControlConflictError("candidate review scope binding is corrupt")
    if not isinstance(review_target_id, str):
        raise ControlConflictError("candidate review target binding is corrupt")
    target_match = _CANDIDATE_TARGET_PATTERN.fullmatch(review_target_id)
    if target_match is None:
        raise ControlConflictError("candidate review target binding is corrupt")
    if _qualify_scope_key(scope_key, "review_target", review_target_id) != event["target_id"]:
        raise ControlConflictError("candidate review scope binding conflicts")
    if not isinstance(publication_key, str) or _PUBLICATION_KEY_PATTERN.fullmatch(publication_key) is None:
        raise ControlConflictError("candidate publication binding is corrupt")
    if publication_key != f"candidate-publication:1.0:{target_match.group('skill')}":
        raise ControlConflictError("candidate publication binding conflicts")
    if (
        schema_version != "1.0"
        or detail["candidate_id"] != target_match.group("skill")
        or skill_id != target_match.group("skill")
    ):
        raise ControlConflictError("candidate schema binding conflicts")
    for name in ("content_sha256", "full_sha256", "source_result_sha256"):
        if not isinstance(detail[name], str) or _SHA256_PATTERN.fullmatch(detail[name]) is None:
            raise ControlConflictError("candidate digest binding is corrupt")
    if detail["content_sha256"] != target_match.group("content"):
        raise ControlConflictError("candidate content binding conflicts")
    if detail["destination_status"] != event["status"]:
        raise ControlConflictError("candidate destination binding conflicts")
    if detail["expected_prior_state"] != current_state:
        raise ControlConflictError("candidate prior state binding conflicts")
    if detail["expected_prior_version"] != current_version:
        raise ControlConflictError("candidate prior version binding conflicts")
    if detail["expected_prior_event_id"] != current_event_id:
        raise ControlConflictError("candidate prior event binding conflicts")
    if detail["reviewer_id"] != event["actor_id"] or detail["server_reviewer_id"] != event["actor_id"]:
        raise ControlConflictError("candidate reviewer binding conflicts")
    if _REVIEWER_ID_PATTERN.fullmatch(event["actor_id"]) is None:
        raise ControlConflictError("candidate reviewer identity is corrupt")
    server_time = detail["server_utc_time"]
    if not isinstance(server_time, str) or not server_time.endswith("Z"):
        raise ControlConflictError("candidate review server time is corrupt")
    try:
        parsed_time = datetime.fromisoformat(server_time)
        parsed_us = _to_micros(parsed_time)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ControlConflictError("candidate review server time is corrupt") from exc
    if parsed_us != event["occurred_at"]:
        raise ControlConflictError("candidate review server time conflicts")
    expected_server_time = (
        _from_micros(event["occurred_at"])
        .astimezone(UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    if server_time != expected_server_time:
        raise ControlConflictError("candidate review server time is not canonical")
    if _candidate_idempotency_key(
        scope_key,
        idempotency_key=event["idempotency_key"],
        qualified_idempotency_key=detail["qualified_idempotency_key"],
    ) != event["idempotency_key"]:
        raise ControlConflictError("candidate idempotency binding conflicts")
    if detail["qualified_idempotency_key"] != provenance["qualified_idempotency_key"]:
        raise ControlConflictError("candidate idempotency binding conflicts")
    reason = detail.get("reason")
    if reason is not None and (
        type(reason) is not str or not reason.strip() or len(reason) > _MAX_REVIEW_REASON
    ):
        raise ControlConflictError("candidate review reason is corrupt")
    try:
        if _bounded_review_value(detail.get("evidence"), "evidence") != detail.get("evidence"):
            raise ControlConflictError("candidate review evidence is not canonical")
    except (TypeError, ValueError) as exc:
        raise ControlConflictError("candidate review evidence is corrupt") from exc


def _validate_legacy_candidate_event(
    event: sqlite3.Row,
    provenance: Mapping[str, Any],
    detail: Mapping[str, Any],
) -> bool:
    """Recognize only the exact pre-publication approval compatibility shape."""

    if set(provenance) != {"source", "artifact_id", "revision", "sha256"}:
        return False
    if set(detail) != {
        "kind",
        "decision",
        "schema_version",
        "skill_id",
        "content_sha256",
        "approval_basis",
    }:
        return False
    if not _is_candidate_review_target(event["target_id"]):
        return False
    target = re.search(
        r"candidate-skill:1\.0:(?P<skill>[0-9a-f-]{36}):sha256:(?P<content>[a-f0-9]{64})$",
        event["target_id"],
    )
    if target is None:
        return False
    skill_id = target.group("skill")
    content_sha256 = target.group("content")
    return (
        provenance["source"] == "candidate_skill_canonical_sha256"
        and provenance["artifact_id"] == skill_id
        and provenance["revision"] == "1.0"
        and provenance["sha256"] == content_sha256
        and detail["kind"] == "candidate_skill_approval"
        and detail["decision"] == "approve"
        and detail["schema_version"] == "1.0"
        and detail["skill_id"] == skill_id
        and detail["content_sha256"] == content_sha256
        and isinstance(detail["approval_basis"], str)
        and bool(detail["approval_basis"].strip())
        and _REVIEWER_ID_PATTERN.fullmatch(event["actor_id"]) is not None
    )


def _validate_candidate_rows(
    event: sqlite3.Row,
    projection: sqlite3.Row | None,
) -> None:
    if projection is None:
        raise ControlConflictError("candidate review projection is missing")
    try:
        provenance = json.loads(event["provenance_json"])
        detail = json.loads(event["detail_json"])
        projection_provenance = json.loads(projection["provenance_json"])
        projection_detail = json.loads(projection["detail_json"])
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ControlConflictError("candidate review JSON is corrupt") from exc
    if not all(isinstance(value, dict) for value in (
        provenance, detail, projection_provenance, projection_detail
    )):
        raise ControlConflictError("candidate review JSON is corrupt")
    if event["target_id"] != projection["target_id"]:
        raise ControlConflictError("candidate review target projection is corrupt")
    if event["status"] != projection["status"] or event["actor_id"] != projection["actor_id"]:
        raise ControlConflictError("candidate review projection does not match event")
    if event["event_id"] != projection["last_event_id"]:
        raise ControlConflictError("candidate review projection event is corrupt")
    if event["occurred_at"] != projection["occurred_at"]:
        raise ControlConflictError("candidate review projection time is corrupt")
    if provenance != projection_provenance or detail != projection_detail:
        raise ControlConflictError("candidate review projection JSON is corrupt")
    if event["content_digest"] != _review_content_digest(
        event["target_id"], event["actor_id"], event["status"], provenance, detail
    ):
        raise ControlConflictError("candidate review content digest is corrupt")


def _to_micros(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return int(value.astimezone(UTC).timestamp() * 1_000_000)


def _from_micros(value: int) -> datetime:
    return datetime.fromtimestamp(value / 1_000_000, tz=UTC)


def _job_from_row(row: sqlite3.Row) -> JobRecord:
    return JobRecord(
        job_id=row["job_id"],
        payload_digest=row["payload_digest"],
        state=row["state"],
        created_at=_from_micros(row["created_at"]),
        updated_at=_from_micros(row["updated_at"]),
    )


def _lease_from_row(row: sqlite3.Row) -> Lease:
    return Lease(
        job_id=row["job_id"],
        owner_id=row["current_owner_id"],
        fencing_token=row["current_fencing_token"],
        attempt=row["current_attempt"],
        acquired_at=_from_micros(row["lease_acquired_at"]),
        expires_at=_from_micros(row["lease_expires_at"]),
    )


def _completion_from_row(row: sqlite3.Row) -> Completion:
    return Completion(
        job_id=row["job_id"],
        idempotency_key=row["completion_idempotency_key"],
        result_digest=row["completion_result_digest"],
        fencing_token=row["current_fencing_token"],
        completed_at=_from_micros(row["completed_at"]),
    )


def _review_event_from_row(row: sqlite3.Row) -> ReviewEvent:
    try:
        provenance = json.loads(row["provenance_json"])
        detail = json.loads(row["detail_json"])
        if not isinstance(provenance, dict) or not isinstance(detail, dict):
            raise TypeError("review JSON is not an object")
        expected_digest = _review_content_digest(
            row["target_id"],
            row["actor_id"],
            row["status"],
            provenance,
            detail,
        )
        if row["content_digest"] != expected_digest:
            raise ControlStoreError("stored review event content digest is invalid")
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ControlStoreError("stored review event JSON is invalid") from exc
    return ReviewEvent(
        sequence=row["sequence"],
        event_id=row["event_id"],
        target_id=row["target_id"],
        idempotency_key=row["idempotency_key"],
        actor_id=row["actor_id"],
        status=row["status"],
        provenance=json.loads(row["provenance_json"]),
        detail=json.loads(row["detail_json"]),
        occurred_at=_from_micros(row["occurred_at"]),
        _content_digest=row["content_digest"],
    )


def _review_projection_from_row(row: sqlite3.Row) -> ReviewProjection:
    return ReviewProjection(
        target_id=row["target_id"],
        status=row["status"],
        version=row["version"],
        last_event_id=row["last_event_id"],
        actor_id=row["actor_id"],
        provenance=json.loads(row["provenance_json"]),
        detail=json.loads(row["detail_json"]),
        occurred_at=_from_micros(row["occurred_at"]),
        _content_digest=_review_content_digest(
            row["target_id"],
            row["actor_id"],
            row["status"],
            json.loads(row["provenance_json"]),
            json.loads(row["detail_json"]),
        ),
    )


def _audit_event_from_row(row: sqlite3.Row) -> AuditEvent:
    roles = json.loads(row["roles_json"])
    if not isinstance(roles, list) or not all(isinstance(role, str) for role in roles):
        raise ControlStoreError("invalid stored audit roles")
    return AuditEvent(
        sequence=row["sequence"],
        event_id=row["event_id"],
        correlation_id=row["correlation_id"],
        idempotency_key=row["idempotency_key"],
        subject_id=row["subject_id"],
        roles=tuple(roles),
        action=row["action"],
        target_id=row["target_id"],
        result=row["result"],
        occurred_at=_from_micros(row["occurred_at"]),
    )
