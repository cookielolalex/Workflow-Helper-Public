"""Durable synthetic legacy-session and workload-proof state.

This component is deliberately not wired into routes or providers.  It is the
hermetic SQLite implementation of ADR 0009 and owns only the five tables whose
shape is defined by :mod:`workflow_api.legacy_session_schema`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from pydantic import TypeAdapter, ValidationError

from .artifact_gateway import ArtifactAuthority
from .control_auth import AuthenticatedPrincipal, ControlAction, ControlRole
from .control_scope import TenantWorkspaceScope, _validate_scope
from .legacy_session_schema import (
    LEGACY_SESSION_RECORD_CONTRACT_VERSION,
    initialize_legacy_session_schema,
)
from .legacy_session_security import (
    AuthorizedLegacySessionRequest,
    LegacySessionAudience,
    LegacySessionSecurityRejectedError,
    LegacySessionTransport,
    LegacyWorkloadContext,
    _validate_canonical_request,
    _validate_workload_shape,
    raw_body_sha256,
)
from .models import (
    ProcessingCompletion,
    ProcessingCompletionPayload,
    ProcessingCompletionV2,
    ProcessingResultPayload,
    ProcessingStatus,
    ReviewStatus,
    SessionCreate,
    SessionRecord,
)
from .repository import SessionConflictError, SessionNotFoundError

_MAX_LIST_LIMIT = 1_000
_MAX_GENERATION = 2**31 - 1
_MAX_CLOCK_SKEW = timedelta(seconds=60)
_MIN_CLAIM_RETENTION = timedelta(seconds=60)
_PROCESSING_RESULT_ADAPTER = TypeAdapter(ProcessingResultPayload)

_SESSION_COLUMNS = """
session_id, tenant_id, workspace_id, capture_owner_subject,
record_contract_version, machine_id, project_id, started_at_us, ended_at_us,
active_duration_seconds, approved_process, package_sha256, package_size_bytes,
processing_status, review_status, raw_object_key, processed_prefix,
processing_output_json, processing_completion_id, processing_completed_at_us,
raw_expires_at_us, state_version, created_at_us, updated_at_us
"""


class LegacyWorkloadPrincipalNotFoundError(KeyError):
    """An exact workload-principal key was absent."""


class LegacyWorkloadPrincipalConflictError(ValueError):
    """A workload-principal mutation conflicted with durable state."""


@dataclass(frozen=True, slots=True)
class LegacySessionEvent:
    sequence: int
    event_id: str
    session_id: UUID
    scope: TenantWorkspaceScope
    capture_owner_subject: str
    event_type: str
    from_state: str | None
    to_state: str
    state_version: int
    actor_subject: str
    actor_role: str
    idempotency_key: str | None
    request_digest: str
    detail: dict[str, object]
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class LegacyWorkloadPrincipalState:
    principal_subject: str
    scope: TenantWorkspaceScope
    audience: LegacySessionAudience
    role: ControlRole
    transport: LegacySessionTransport
    active_generation: int
    revoked_at: datetime | None
    state_version: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class ResolvedSessionCaptureAuthority:
    """Stored capture authority bound to one exact legacy session UUID."""

    session_id: UUID
    authority: ArtifactAuthority

    def __post_init__(self) -> None:
        _validate_session_id(self.session_id)
        if type(self.authority) is not ArtifactAuthority:
            raise TypeError("authority must use the exact artifact contract type")


class SQLiteLegacySessionStore:
    """Connection-per-transaction SQLite reference store for ADR 0009."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        busy_timeout_seconds: float = 5.0,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if busy_timeout_seconds <= 0:
            raise ValueError("busy_timeout_seconds must be positive")
        if str(database_path) == ":memory:":
            raise ValueError("a filesystem path is required for a durable legacy store")
        self._database_path = str(Path(database_path))
        self._busy_timeout_ms = max(1, int(busy_timeout_seconds * 1_000))
        self._clock = clock or (lambda: datetime.now(UTC))
        Path(self._database_path).parent.mkdir(parents=True, exist_ok=True)

        with closing(self._connect()) as connection:
            initialize_legacy_session_schema(
                connection,
                installed_at_us=_to_micros(self._now()),
            )
            # Journal-mode changes cannot run inside the atomic schema transaction.
            # Apply WAL only after exact validation so an incompatible file is not
            # mutated before the constructor fails closed.
            mode = connection.execute("pragma journal_mode = wal").fetchone()
            if mode is None or str(mode[0]).casefold() != "wal":
                raise RuntimeError("SQLite WAL mode is required")

    @property
    def database_path(self) -> str:
        return self._database_path

    async def create(
        self,
        value: SessionCreate,
        retention_days: int,
        *,
        scope: TenantWorkspaceScope,
        owner_subject: str,
        actor_subject: str | None = None,
        actor_role: str = ControlRole.CAPTURE_UPLOADER.value,
        request_digest: str | None = None,
    ) -> SessionRecord:
        _validate_scope(scope)
        _require_text(owner_subject, "owner_subject")
        _require_exact_type(value, SessionCreate, "value")
        if type(retention_days) is not int or retention_days < 1:
            raise ValueError("retention_days must be a positive integer")
        actor = owner_subject if actor_subject is None else actor_subject
        _require_text(actor, "actor_subject")
        _require_text(actor_role, "actor_role")
        if actor_role != ControlRole.CAPTURE_UPLOADER.value:
            raise ValueError("registration actor role must be capture_uploader")
        digest = request_digest or _digest_json(value.model_dump(mode="json"))
        _require_sha256(digest, "request_digest")
        now = self._now()
        now_us = _to_micros(now)
        expires_us = _to_micros(now + timedelta(days=retention_days))
        session_id = str(value.session_id)

        try:
            with self._transaction() as connection:
                connection.execute(
                    """
                    insert into legacy_sessions (
                        session_id, tenant_id, workspace_id, capture_owner_subject,
                        record_contract_version, machine_id, project_id, started_at_us,
                        ended_at_us, active_duration_seconds, approved_process,
                        package_sha256, package_size_bytes, processing_status,
                        review_status, raw_object_key, processed_prefix,
                        processing_output_json, processing_completion_id,
                        processing_completed_at_us, raw_expires_at_us, state_version,
                        created_at_us, updated_at_us
                    ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'registered',
                              'not_ready', null, null, null, null, null, ?, 1, ?, ?)
                    """,
                    (
                        session_id,
                        scope.tenant_id,
                        scope.workspace_id,
                        owner_subject,
                        LEGACY_SESSION_RECORD_CONTRACT_VERSION,
                        value.machine_id,
                        value.project_id,
                        _to_micros(value.started_at),
                        _to_micros(value.ended_at),
                        value.active_duration_seconds,
                        value.approved_process,
                        value.package_sha256,
                        value.package_size_bytes,
                        expires_us,
                        now_us,
                        now_us,
                    ),
                )
                self._append_event(
                    connection,
                    session_id=session_id,
                    scope=scope,
                    owner_subject=owner_subject,
                    event_type="registered",
                    from_state=None,
                    to_state=ProcessingStatus.REGISTERED.value,
                    state_version=1,
                    actor_subject=actor,
                    actor_role=actor_role,
                    idempotency_key=None,
                    request_digest=digest,
                    detail={},
                    occurred_at_us=now_us,
                )
                row = self._select_session(
                    connection,
                    value.session_id,
                    scope=scope,
                    owner_subject=owner_subject,
                )
                assert row is not None
                return _session_from_row(row)
        except sqlite3.IntegrityError as exc:
            with closing(self._connect()) as connection:
                same_scope = self._select_session(
                    connection,
                    value.session_id,
                    scope=scope,
                    owner_subject=owner_subject,
                )
            if same_scope is None:
                raise SessionNotFoundError("session unavailable") from exc
            raise SessionConflictError(str(value.session_id)) from exc

    async def list(
        self,
        *,
        scope: TenantWorkspaceScope,
        limit: int = _MAX_LIST_LIMIT,
    ) -> list[SessionRecord]:
        _validate_scope(scope)
        _require_limit(limit)
        with closing(self._connect()) as connection:
            rows = connection.execute(
                f"""
                select {_SESSION_COLUMNS}
                from legacy_sessions
                where tenant_id = ? and workspace_id = ?
                order by started_at_us desc, session_id
                limit ?
                """,
                (scope.tenant_id, scope.workspace_id, limit),
            ).fetchall()
        return [_session_from_row(row) for row in rows]

    async def get(
        self,
        session_id: UUID,
        *,
        scope: TenantWorkspaceScope,
        owner_subject: str | None = None,
    ) -> SessionRecord:
        _validate_session_id(session_id)
        _validate_scope(scope)
        if owner_subject is not None:
            _require_text(owner_subject, "owner_subject")
        with closing(self._connect()) as connection:
            row = self._select_session(
                connection,
                session_id,
                scope=scope,
                owner_subject=owner_subject,
            )
        if row is None:
            raise SessionNotFoundError(str(session_id))
        return _session_from_row(row)

    async def resolve_session_capture_authority(
        self,
        session_id: UUID,
        *,
        scope: TenantWorkspaceScope,
    ) -> ResolvedSessionCaptureAuthority:
        """Resolve only the capture authority stored for one exact scoped session."""

        try:
            _validate_session_id(session_id)
            _validate_scope(scope)
        except (TypeError, ValueError):
            raise SessionNotFoundError("session unavailable") from None

        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                select session.session_id, session.tenant_id, session.workspace_id,
                       session.capture_owner_subject, session.record_contract_version
                from legacy_sessions as session
                join legacy_session_events as registration
                  on registration.session_id = session.session_id
                 and registration.tenant_id = session.tenant_id
                 and registration.workspace_id = session.workspace_id
                 and registration.capture_owner_subject = session.capture_owner_subject
                 and registration.event_type = 'registered'
                 and registration.from_state is null
                 and registration.to_state = 'registered'
                 and registration.state_version = 1
                where session.session_id = ?
                  and session.tenant_id = ?
                  and session.workspace_id = ?
                """,
                (str(session_id), scope.tenant_id, scope.workspace_id),
            ).fetchone()
        if row is None:
            raise SessionNotFoundError("session unavailable")

        try:
            if (
                type(row["session_id"]) is not str
                or row["session_id"] != str(session_id)
                or type(row["tenant_id"]) is not str
                or type(row["workspace_id"]) is not str
                or row["record_contract_version"] != LEGACY_SESSION_RECORD_CONTRACT_VERSION
            ):
                raise ValueError("stored session provenance is incompatible")
            stored_scope = TenantWorkspaceScope(row["tenant_id"], row["workspace_id"])
            if stored_scope != scope:
                raise ValueError("stored session provenance is incompatible")
            authority = ArtifactAuthority(stored_scope, row["capture_owner_subject"])
            return ResolvedSessionCaptureAuthority(session_id, authority)
        except (IndexError, KeyError, TypeError, ValueError):
            raise SessionNotFoundError("session unavailable") from None

    async def mark_uploaded(
        self,
        session_id: UUID,
        object_key: str,
        *,
        scope: TenantWorkspaceScope,
        owner_subject: str,
        expected_state_version: int | None = None,
        actor_subject: str | None = None,
        actor_role: str = ControlRole.CAPTURE_UPLOADER.value,
        request_digest: str | None = None,
    ) -> tuple[SessionRecord, bool]:
        _validate_session_id(session_id)
        _validate_scope(scope)
        _require_text(owner_subject, "owner_subject")
        _require_text(object_key, "object_key", maximum=1_024)
        _require_optional_version(expected_state_version)
        actor = owner_subject if actor_subject is None else actor_subject
        _require_text(actor, "actor_subject")
        _require_text(actor_role, "actor_role")
        if actor_role != ControlRole.CAPTURE_UPLOADER.value:
            raise ValueError("upload actor role must be capture_uploader")
        digest = request_digest or hashlib.sha256(object_key.encode("utf-8")).hexdigest()
        _require_sha256(digest, "request_digest")

        with self._transaction() as connection:
            row = self._select_session(
                connection,
                session_id,
                scope=scope,
                owner_subject=owner_subject,
            )
            if row is None:
                raise SessionNotFoundError(str(session_id))
            if row["raw_object_key"] is not None and row["raw_object_key"] != object_key:
                raise SessionConflictError("session already references another raw object")
            if row["processing_status"] == ProcessingStatus.UPLOADED.value:
                return _session_from_row(row), True
            if (
                expected_state_version is not None
                and row["state_version"] != expected_state_version
            ):
                raise SessionConflictError("session state version conflicts")
            if row["processing_status"] != ProcessingStatus.REGISTERED.value:
                return _session_from_row(row), False

            now_us = _to_micros(self._now())
            old_version = row["state_version"]
            try:
                cursor = connection.execute(
                    """
                    update legacy_sessions
                    set processing_status = ?, raw_object_key = ?, state_version = ?,
                        updated_at_us = ?
                    where session_id = ? and tenant_id = ? and workspace_id = ?
                      and capture_owner_subject = ? and state_version = ?
                    """,
                    (
                        ProcessingStatus.UPLOADED.value,
                        object_key,
                        old_version + 1,
                        now_us,
                        str(session_id),
                        scope.tenant_id,
                        scope.workspace_id,
                        owner_subject,
                        old_version,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                if "unique constraint failed" in str(exc).casefold():
                    raise SessionConflictError("session state conflicts") from exc
                raise
            if cursor.rowcount != 1:
                raise SessionConflictError("session state version conflicts")
            self._append_event(
                connection,
                session_id=str(session_id),
                scope=scope,
                owner_subject=owner_subject,
                event_type="uploaded",
                from_state=ProcessingStatus.REGISTERED.value,
                to_state=ProcessingStatus.UPLOADED.value,
                state_version=old_version + 1,
                actor_subject=actor,
                actor_role=actor_role,
                idempotency_key=None,
                request_digest=digest,
                detail={"object_key": object_key},
                occurred_at_us=now_us,
            )
            updated = self._select_session(
                connection,
                session_id,
                scope=scope,
                owner_subject=owner_subject,
            )
            assert updated is not None
            return _session_from_row(updated), True

    async def complete_processing(
        self,
        session_id: UUID,
        completion: ProcessingCompletionPayload,
        *,
        scope: TenantWorkspaceScope,
        expected_state_version: int | None = None,
        actor_subject: str = "deterministic-worker",
        actor_role: str = ControlRole.DETERMINISTIC_WORKER.value,
        request_digest: str | None = None,
    ) -> SessionRecord:
        _validate_session_id(session_id)
        _validate_scope(scope)
        if type(completion) not in {ProcessingCompletion, ProcessingCompletionV2}:
            raise TypeError("completion must use an exact processing completion contract type")
        if completion.session_id != session_id:
            raise ValueError("completion session_id does not match")
        _require_optional_version(expected_state_version)
        _require_text(actor_subject, "actor_subject")
        _require_text(actor_role, "actor_role")
        if actor_role != ControlRole.DETERMINISTIC_WORKER.value:
            raise ValueError("completion actor role must be deterministic_worker")
        digest = request_digest or completion.idempotency_key
        _require_sha256(digest, "request_digest")
        result = completion.as_result()
        output_json = _canonical_json(result.model_dump(mode="json"))
        processed_prefix = completion.output_object_key.rsplit("/", 1)[0] + "/"

        with self._transaction() as connection:
            row = self._select_session(connection, session_id, scope=scope)
            if row is None:
                raise SessionNotFoundError(str(session_id))
            _session_from_row(row)
            if row["processing_completion_id"] is not None:
                if (
                    row["processing_completion_id"] == completion.idempotency_key
                    and row["processing_output_json"] == output_json
                    and row["processed_prefix"] == processed_prefix
                ):
                    return _session_from_row(row)
                raise SessionConflictError("processing completion conflicts with persisted result")
            if (
                expected_state_version is not None
                and row["state_version"] != expected_state_version
            ):
                raise SessionConflictError("session state version conflicts")
            if row["processing_status"] not in {
                ProcessingStatus.UPLOADED.value,
                ProcessingStatus.PROCESSING.value,
            }:
                raise SessionConflictError("session is not ready for processing completion")

            now_us = _to_micros(self._now())
            old_version = row["state_version"]
            try:
                cursor = connection.execute(
                    """
                    update legacy_sessions
                    set processing_status = ?, review_status = ?, processed_prefix = ?,
                        processing_output_json = ?, processing_completion_id = ?,
                        processing_completed_at_us = ?, state_version = ?, updated_at_us = ?
                    where session_id = ? and tenant_id = ? and workspace_id = ?
                      and state_version = ?
                    """,
                    (
                        ProcessingStatus.PROCESSED.value,
                        ReviewStatus.PENDING.value,
                        processed_prefix,
                        output_json,
                        completion.idempotency_key,
                        now_us,
                        old_version + 1,
                        now_us,
                        str(session_id),
                        scope.tenant_id,
                        scope.workspace_id,
                        old_version,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                if "unique constraint failed" in str(exc).casefold():
                    raise SessionConflictError("processing completion conflicts") from exc
                raise
            if cursor.rowcount != 1:
                raise SessionConflictError("session state version conflicts")
            self._append_event(
                connection,
                session_id=str(session_id),
                scope=scope,
                owner_subject=row["capture_owner_subject"],
                event_type="processing_completed",
                from_state=row["processing_status"],
                to_state=ProcessingStatus.PROCESSED.value,
                state_version=old_version + 1,
                actor_subject=actor_subject,
                actor_role=actor_role,
                idempotency_key=completion.idempotency_key,
                request_digest=digest,
                detail={"output_object_key": completion.output_object_key},
                occurred_at_us=now_us,
            )
            updated = self._select_session(connection, session_id, scope=scope)
            assert updated is not None
            return _session_from_row(updated)

    async def get_timeline(
        self,
        session_id: UUID,
        *,
        scope: TenantWorkspaceScope,
    ) -> ProcessingResultPayload:
        value = await self.get(session_id, scope=scope)
        if value.processing_output is None:
            raise SessionNotFoundError(f"timeline for {session_id}")
        return value.processing_output.model_copy(deep=True)

    async def list_events(
        self,
        session_id: UUID,
        *,
        scope: TenantWorkspaceScope,
        owner_subject: str | None = None,
        limit: int = _MAX_LIST_LIMIT,
    ) -> list[LegacySessionEvent]:
        _validate_session_id(session_id)
        _validate_scope(scope)
        _require_limit(limit)
        parameters: list[object] = [str(session_id), scope.tenant_id, scope.workspace_id]
        owner_clause = ""
        if owner_subject is not None:
            _require_text(owner_subject, "owner_subject")
            owner_clause = " and capture_owner_subject = ?"
            parameters.append(owner_subject)
        parameters.append(limit)
        with closing(self._connect()) as connection:
            rows = connection.execute(
                f"""
                select sequence, event_id, session_id, tenant_id, workspace_id,
                       capture_owner_subject, event_type, from_state, to_state,
                       state_version, actor_subject, actor_role, idempotency_key,
                       request_digest, detail_json, occurred_at_us
                from legacy_session_events
                where session_id = ? and tenant_id = ? and workspace_id = ?
                {owner_clause}
                order by sequence
                limit ?
                """,
                tuple(parameters),
            ).fetchall()
        if not rows:
            # Apply the same generic absence contract to an unknown or unauthorized UUID.
            await self.get(session_id, scope=scope, owner_subject=owner_subject)
        return [_event_from_row(row) for row in rows]

    def register_workload_principal(
        self,
        *,
        principal_subject: str,
        scope: TenantWorkspaceScope,
        audience: LegacySessionAudience,
        role: ControlRole,
        transport: LegacySessionTransport,
        active_generation: int = 1,
        now: datetime | None = None,
    ) -> LegacyWorkloadPrincipalState:
        _validate_principal_fields(
            principal_subject, scope, audience, role, transport, active_generation
        )
        occurred_us = _to_micros(self._now() if now is None else _require_utc(now))
        try:
            with self._transaction() as connection:
                connection.execute(
                    """
                    insert into legacy_workload_principals (
                        principal_subject, tenant_id, workspace_id, audience, role,
                        transport, active_generation, revoked_at_us, state_version,
                        created_at_us, updated_at_us
                    ) values (?, ?, ?, ?, ?, ?, ?, null, 1, ?, ?)
                    """,
                    (
                        principal_subject,
                        scope.tenant_id,
                        scope.workspace_id,
                        audience.value,
                        role.value,
                        transport.value,
                        active_generation,
                        occurred_us,
                        occurred_us,
                    ),
                )
                row = self._select_principal(connection, principal_subject, scope, audience)
                assert row is not None
                return _principal_from_row(row)
        except sqlite3.IntegrityError as exc:
            raise LegacyWorkloadPrincipalConflictError(
                "workload principal is already registered"
            ) from exc

    def get_workload_principal(
        self,
        *,
        principal_subject: str,
        scope: TenantWorkspaceScope,
        audience: LegacySessionAudience,
    ) -> LegacyWorkloadPrincipalState:
        _require_text(principal_subject, "principal_subject")
        _validate_scope(scope)
        _require_exact_type(audience, LegacySessionAudience, "audience")
        with closing(self._connect()) as connection:
            row = self._select_principal(connection, principal_subject, scope, audience)
        if row is None:
            raise LegacyWorkloadPrincipalNotFoundError("workload principal unavailable")
        return _principal_from_row(row)

    def rotate_workload_generation(
        self,
        *,
        principal_subject: str,
        scope: TenantWorkspaceScope,
        audience: LegacySessionAudience,
        expected_state_version: int,
        new_generation: int,
        now: datetime | None = None,
    ) -> LegacyWorkloadPrincipalState:
        _require_optional_version(expected_state_version, required=True)
        _require_generation(new_generation)
        occurred_us = _to_micros(self._now() if now is None else _require_utc(now))
        with self._transaction() as connection:
            row = self._select_principal(connection, principal_subject, scope, audience)
            if row is None:
                raise LegacyWorkloadPrincipalNotFoundError("workload principal unavailable")
            if row["state_version"] != expected_state_version or row["revoked_at_us"] is not None:
                raise LegacyWorkloadPrincipalConflictError("workload principal state conflicts")
            if new_generation <= row["active_generation"]:
                raise LegacyWorkloadPrincipalConflictError("generation must increase")
            cursor = connection.execute(
                """
                update legacy_workload_principals
                set active_generation = ?, state_version = ?, updated_at_us = ?
                where principal_subject = ? and tenant_id = ? and workspace_id = ?
                  and audience = ? and state_version = ? and revoked_at_us is null
                """,
                (
                    new_generation,
                    expected_state_version + 1,
                    occurred_us,
                    principal_subject,
                    scope.tenant_id,
                    scope.workspace_id,
                    audience.value,
                    expected_state_version,
                ),
            )
            if cursor.rowcount != 1:
                raise LegacyWorkloadPrincipalConflictError("workload principal state conflicts")
            updated = self._select_principal(connection, principal_subject, scope, audience)
            assert updated is not None
            return _principal_from_row(updated)

    def revoke_workload_principal(
        self,
        *,
        principal_subject: str,
        scope: TenantWorkspaceScope,
        audience: LegacySessionAudience,
        expected_state_version: int,
        now: datetime | None = None,
    ) -> LegacyWorkloadPrincipalState:
        _require_optional_version(expected_state_version, required=True)
        occurred_us = _to_micros(self._now() if now is None else _require_utc(now))
        with self._transaction() as connection:
            row = self._select_principal(connection, principal_subject, scope, audience)
            if row is None:
                raise LegacyWorkloadPrincipalNotFoundError("workload principal unavailable")
            if row["state_version"] != expected_state_version or row["revoked_at_us"] is not None:
                raise LegacyWorkloadPrincipalConflictError("workload principal state conflicts")
            cursor = connection.execute(
                """
                update legacy_workload_principals
                set revoked_at_us = ?, state_version = ?, updated_at_us = ?
                where principal_subject = ? and tenant_id = ? and workspace_id = ?
                  and audience = ? and state_version = ? and revoked_at_us is null
                """,
                (
                    occurred_us,
                    expected_state_version + 1,
                    occurred_us,
                    principal_subject,
                    scope.tenant_id,
                    scope.workspace_id,
                    audience.value,
                    expected_state_version,
                ),
            )
            if cursor.rowcount != 1:
                raise LegacyWorkloadPrincipalConflictError("workload principal state conflicts")
            updated = self._select_principal(connection, principal_subject, scope, audience)
            assert updated is not None
            return _principal_from_row(updated)

    def claim_workload_proof(
        self,
        *,
        context: LegacyWorkloadContext,
        method: str,
        path: str,
        body: bytes,
        action: ControlAction,
        audience: LegacySessionAudience,
        transport: LegacySessionTransport,
        now: datetime | None = None,
    ) -> AuthorizedLegacySessionRequest:
        """Validate and atomically claim one provider-authenticated workload proof.

        Provider-supplied generation, revocation, and replay decisions are not
        consulted.  Their durable counterparts are checked under the same
        ``BEGIN IMMEDIATE`` serialization as the claim insert.
        """

        try:
            evaluation_time = self._now() if now is None else _require_utc(now)
            _validate_workload_shape(context)
            _validate_canonical_request(method=method, path=path, expected_method="POST")
            if context.method != method or context.path != path:
                raise ValueError("request binding mismatch")
            if not hmac.compare_digest(context.body_sha256, raw_body_sha256(body)):
                raise ValueError("body binding mismatch")
            if context.audience is not audience or context.transport is not transport:
                raise ValueError("workload boundary mismatch")
            expected_role = _expected_role(audience, transport)
            principal = context.principal
            if principal.roles != frozenset({expected_role}) or principal.scope is None:
                raise ValueError("workload role mismatch")
            principal.require(action)
            if context.issued_at > evaluation_time + _MAX_CLOCK_SKEW:
                raise ValueError("future proof")
            if evaluation_time < context.issued_at - _MAX_CLOCK_SKEW:
                raise ValueError("future proof")
            if evaluation_time >= context.expires_at:
                raise ValueError("expired proof")

            claimed_at_us = _to_micros(evaluation_time)
            retain_until_us = _to_micros(context.expires_at + _MIN_CLAIM_RETENTION)
            scope = principal.scope
            with self._transaction() as connection:
                row = self._select_principal(
                    connection,
                    principal.subject,
                    scope,
                    audience,
                )
                if (
                    row is None
                    or row["role"] != expected_role.value
                    or row["transport"] != transport.value
                    or row["revoked_at_us"] is not None
                    or row["active_generation"] != context.generation
                ):
                    raise ValueError("inactive workload principal")
                connection.execute(
                    """
                    insert into legacy_workload_proof_claims (
                        proof_identifier_digest, principal_subject, tenant_id,
                        workspace_id, audience, role, transport, generation, method,
                        canonical_path, body_sha256, issued_at_us, expires_at_us,
                        claimed_at_us, retain_until_us
                    ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        context.proof_identifier_digest,
                        principal.subject,
                        scope.tenant_id,
                        scope.workspace_id,
                        audience.value,
                        expected_role.value,
                        transport.value,
                        context.generation,
                        method,
                        path,
                        context.body_sha256,
                        _to_micros(context.issued_at),
                        _to_micros(context.expires_at),
                        claimed_at_us,
                        retain_until_us,
                    ),
                )
            return AuthorizedLegacySessionRequest(principal)
        except LegacySessionSecurityRejectedError:
            raise
        except Exception as exc:
            raise LegacySessionSecurityRejectedError("request authorization rejected") from exc

    def _now(self) -> datetime:
        return _require_utc(self._clock())

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
            timeout=self._busy_timeout_ms / 1_000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("pragma foreign_keys = on")
        connection.execute(f"pragma busy_timeout = {self._busy_timeout_ms}")
        connection.execute("pragma synchronous = full")
        if connection.execute("pragma foreign_keys").fetchone()[0] != 1:
            connection.close()
            raise RuntimeError("SQLite foreign-key enforcement is required")
        return connection

    @staticmethod
    def _select_session(
        connection: sqlite3.Connection,
        session_id: UUID,
        *,
        scope: TenantWorkspaceScope,
        owner_subject: str | None = None,
    ) -> sqlite3.Row | None:
        if owner_subject is None:
            return connection.execute(
                f"""
                select {_SESSION_COLUMNS}
                from legacy_sessions
                where session_id = ? and tenant_id = ? and workspace_id = ?
                """,
                (str(session_id), scope.tenant_id, scope.workspace_id),
            ).fetchone()
        return connection.execute(
            f"""
            select {_SESSION_COLUMNS}
            from legacy_sessions
            where session_id = ? and tenant_id = ? and workspace_id = ?
              and capture_owner_subject = ?
            """,
            (str(session_id), scope.tenant_id, scope.workspace_id, owner_subject),
        ).fetchone()

    @staticmethod
    def _select_principal(
        connection: sqlite3.Connection,
        principal_subject: str,
        scope: TenantWorkspaceScope,
        audience: LegacySessionAudience,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            select principal_subject, tenant_id, workspace_id, audience, role,
                   transport, active_generation, revoked_at_us, state_version,
                   created_at_us, updated_at_us
            from legacy_workload_principals
            where principal_subject = ? and tenant_id = ? and workspace_id = ?
              and audience = ?
            """,
            (
                principal_subject,
                scope.tenant_id,
                scope.workspace_id,
                audience.value,
            ),
        ).fetchone()

    @staticmethod
    def _append_event(
        connection: sqlite3.Connection,
        *,
        session_id: str,
        scope: TenantWorkspaceScope,
        owner_subject: str,
        event_type: str,
        from_state: str | None,
        to_state: str,
        state_version: int,
        actor_subject: str,
        actor_role: str,
        idempotency_key: str | None,
        request_digest: str,
        detail: dict[str, object],
        occurred_at_us: int,
    ) -> None:
        connection.execute(
            """
            insert into legacy_session_events (
                event_id, session_id, tenant_id, workspace_id,
                capture_owner_subject, event_type, from_state, to_state,
                state_version, actor_subject, actor_role, idempotency_key,
                request_digest, detail_json, occurred_at_us
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid4()),
                session_id,
                scope.tenant_id,
                scope.workspace_id,
                owner_subject,
                event_type,
                from_state,
                to_state,
                state_version,
                actor_subject,
                actor_role,
                idempotency_key,
                request_digest,
                _canonical_json(detail),
                occurred_at_us,
            ),
        )


def _session_from_row(row: sqlite3.Row) -> SessionRecord:
    if row["record_contract_version"] != LEGACY_SESSION_RECORD_CONTRACT_VERSION:
        raise RuntimeError("stored legacy session contract version is incompatible")
    try:
        processing_output = (
            None
            if row["processing_output_json"] is None
            else _PROCESSING_RESULT_ADAPTER.validate_json(row["processing_output_json"])
        )
    except ValidationError as exc:
        raise RuntimeError("stored processing output is incompatible") from exc
    return SessionRecord(
        schema_version=row["record_contract_version"],
        session_id=UUID(row["session_id"]),
        machine_id=row["machine_id"],
        project_id=row["project_id"],
        started_at=_from_micros(row["started_at_us"]),
        ended_at=_from_micros(row["ended_at_us"]),
        active_duration_seconds=row["active_duration_seconds"],
        approved_process=row["approved_process"],
        package_sha256=row["package_sha256"],
        package_size_bytes=row["package_size_bytes"],
        processing_status=ProcessingStatus(row["processing_status"]),
        review_status=ReviewStatus(row["review_status"]),
        raw_object_key=row["raw_object_key"],
        processed_prefix=row["processed_prefix"],
        processing_output=processing_output,
        processing_completion_id=row["processing_completion_id"],
        processing_completed_at=(
            None
            if row["processing_completed_at_us"] is None
            else _from_micros(row["processing_completed_at_us"])
        ),
        raw_expires_at=_from_micros(row["raw_expires_at_us"]),
        created_at=_from_micros(row["created_at_us"]),
        updated_at=_from_micros(row["updated_at_us"]),
    )


def _event_from_row(row: sqlite3.Row) -> LegacySessionEvent:
    detail = json.loads(row["detail_json"])
    if not isinstance(detail, dict):
        raise TypeError("stored legacy event detail is invalid")
    return LegacySessionEvent(
        sequence=row["sequence"],
        event_id=row["event_id"],
        session_id=UUID(row["session_id"]),
        scope=TenantWorkspaceScope(row["tenant_id"], row["workspace_id"]),
        capture_owner_subject=row["capture_owner_subject"],
        event_type=row["event_type"],
        from_state=row["from_state"],
        to_state=row["to_state"],
        state_version=row["state_version"],
        actor_subject=row["actor_subject"],
        actor_role=row["actor_role"],
        idempotency_key=row["idempotency_key"],
        request_digest=row["request_digest"],
        detail=detail,
        occurred_at=_from_micros(row["occurred_at_us"]),
    )


def _principal_from_row(row: sqlite3.Row) -> LegacyWorkloadPrincipalState:
    return LegacyWorkloadPrincipalState(
        principal_subject=row["principal_subject"],
        scope=TenantWorkspaceScope(row["tenant_id"], row["workspace_id"]),
        audience=LegacySessionAudience(row["audience"]),
        role=ControlRole(row["role"]),
        transport=LegacySessionTransport(row["transport"]),
        active_generation=row["active_generation"],
        revoked_at=(None if row["revoked_at_us"] is None else _from_micros(row["revoked_at_us"])),
        state_version=row["state_version"],
        created_at=_from_micros(row["created_at_us"]),
        updated_at=_from_micros(row["updated_at_us"]),
    )


def _expected_role(
    audience: LegacySessionAudience,
    transport: LegacySessionTransport,
) -> ControlRole:
    _require_exact_type(audience, LegacySessionAudience, "audience")
    _require_exact_type(transport, LegacySessionTransport, "transport")
    pairings = {
        (
            LegacySessionAudience.CAPTURE_UPLOAD,
            LegacySessionTransport.CAPTURE_WORKLOAD,
        ): ControlRole.CAPTURE_UPLOADER,
        (
            LegacySessionAudience.PROCESSING_COMPLETION,
            LegacySessionTransport.WORKER_WORKLOAD,
        ): ControlRole.DETERMINISTIC_WORKER,
    }
    try:
        return pairings[(audience, transport)]
    except KeyError as exc:
        raise ValueError("unsupported workload audience and transport pairing") from exc


def _validate_principal_fields(
    principal_subject: str,
    scope: TenantWorkspaceScope,
    audience: LegacySessionAudience,
    role: ControlRole,
    transport: LegacySessionTransport,
    generation: int,
) -> None:
    _require_text(principal_subject, "principal_subject")
    _validate_scope(scope)
    _require_exact_type(role, ControlRole, "role")
    AuthenticatedPrincipal(principal_subject, frozenset({role}), scope)
    if role is not _expected_role(audience, transport):
        raise ValueError("unsupported workload role pairing")
    _require_generation(generation)


def _validate_session_id(session_id: UUID) -> None:
    _require_exact_type(session_id, UUID, "session_id")


def _require_exact_type(value: object, expected: type, name: str) -> None:
    if type(value) is not expected:
        raise TypeError(f"{name} must use the exact contract type")


def _require_text(value: str, name: str, *, maximum: int = 512) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if len(value) > maximum:
        raise ValueError(f"{name} must not exceed {maximum} characters")


def _require_sha256(value: str, name: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


def _require_generation(value: int) -> None:
    if type(value) is not int or not 1 <= value <= _MAX_GENERATION:
        raise ValueError("generation must be a bounded positive integer")


def _require_optional_version(value: int | None, *, required: bool = False) -> None:
    if value is None and not required:
        return
    if type(value) is not int or value < 1:
        raise ValueError("state version must be a positive integer")


def _require_limit(value: int) -> None:
    if type(value) is not int or not 1 <= value <= _MAX_LIST_LIMIT:
        raise ValueError(f"limit must be between 1 and {_MAX_LIST_LIMIT}")


def _require_utc(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is not UTC:
        raise ValueError("timestamp must be an exact UTC datetime")
    return value


def _to_micros(value: datetime) -> int:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    value = value.astimezone(UTC)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = value - epoch
    result = (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds
    if not -(2**63) <= result < 2**63:
        raise ValueError("timestamp is outside signed 64-bit microseconds")
    return result


def _from_micros(value: int) -> datetime:
    if type(value) is not int or not -(2**63) <= value < 2**63:
        raise RuntimeError("stored timestamp is outside signed 64-bit microseconds")
    return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=value)


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
        raise ValueError("value must be canonical JSON serializable") from exc


def _digest_json(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()
