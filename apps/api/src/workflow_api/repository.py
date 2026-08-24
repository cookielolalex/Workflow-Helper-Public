import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from .control_scope import TenantWorkspaceScope, _validate_scope
from .models import (
    ProcessingCompletionPayload,
    ProcessingResultPayload,
    ProcessingStatus,
    ReviewStatus,
    SessionCreate,
    SessionRecord,
)


class SessionNotFoundError(KeyError):
    pass


class SessionConflictError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class _SessionAuthorization:
    scope: TenantWorkspaceScope
    owner_subject: str

    def __post_init__(self) -> None:
        _validate_scope(self.scope)
        if not isinstance(self.owner_subject, str) or not self.owner_subject:
            raise ValueError("owner subject is required")


class InMemorySessionRepository:
    """Deprecated in-memory contract/reference adapter.

    It is not installed by default or by the sealed session-plane runtime.
    ``SQLiteLegacySessionStore``, behind explicit security composition, is the
    durable synthetic session-plane reference. This adapter is retained
    temporarily for compatibility and tests only; it is not a PostgreSQL plan.
    """

    def __init__(self) -> None:
        self._items: dict[UUID, SessionRecord] = {}
        self._authorization: dict[UUID, _SessionAuthorization] = {}
        self._lock = asyncio.Lock()

    async def create(
        self,
        value: SessionCreate,
        retention_days: int,
        *,
        scope: TenantWorkspaceScope,
        owner_subject: str,
    ) -> SessionRecord:
        authorization = _SessionAuthorization(scope, owner_subject)
        async with self._lock:
            if value.session_id in self._items:
                if self._authorization[value.session_id] != authorization:
                    raise SessionNotFoundError("session unavailable")
                raise SessionConflictError(str(value.session_id))
            record = SessionRecord.from_create(value, retention_days)
            self._items[value.session_id] = record
            self._authorization[value.session_id] = authorization
            return record.model_copy(deep=True)

    async def list(self, *, scope: TenantWorkspaceScope) -> list[SessionRecord]:
        _validate_scope(scope)
        async with self._lock:
            values = sorted(
                (
                    value
                    for session_id, value in self._items.items()
                    if self._authorization[session_id].scope == scope
                ),
                key=lambda item: item.started_at,
                reverse=True,
            )
            return [value.model_copy(deep=True) for value in values]

    async def get(
        self,
        session_id: UUID,
        *,
        scope: TenantWorkspaceScope,
        owner_subject: str | None = None,
    ) -> SessionRecord:
        _validate_scope(scope)
        async with self._lock:
            try:
                authorization = self._authorization[session_id]
                value = self._items[session_id]
            except KeyError as exc:
                raise SessionNotFoundError(str(session_id)) from exc
            if authorization.scope != scope or (
                owner_subject is not None and authorization.owner_subject != owner_subject
            ):
                raise SessionNotFoundError(str(session_id))
            return value.model_copy(deep=True)

    async def mark_uploaded(
        self,
        session_id: UUID,
        object_key: str,
        *,
        scope: TenantWorkspaceScope,
        owner_subject: str,
    ) -> tuple[SessionRecord, bool]:
        _validate_scope(scope)
        async with self._lock:
            try:
                value = self._items[session_id]
                authorization = self._authorization[session_id]
            except KeyError as exc:
                raise SessionNotFoundError(str(session_id)) from exc
            if authorization != _SessionAuthorization(scope, owner_subject):
                raise SessionNotFoundError(str(session_id))
            if value.raw_object_key is not None and value.raw_object_key != object_key:
                raise SessionConflictError("session already references another raw object")
            if value.processing_status == ProcessingStatus.UPLOADED:
                return value.model_copy(deep=True), True
            if value.processing_status != ProcessingStatus.REGISTERED:
                return value.model_copy(deep=True), False
            updated = value.model_copy(
                update={
                    "processing_status": ProcessingStatus.UPLOADED,
                    "raw_object_key": object_key,
                    "updated_at": datetime.now(UTC),
                }
            )
            self._items[session_id] = updated
            return updated.model_copy(deep=True), True

    async def complete_processing(
        self,
        session_id: UUID,
        completion: ProcessingCompletionPayload,
        *,
        scope: TenantWorkspaceScope,
    ) -> SessionRecord:
        _validate_scope(scope)
        async with self._lock:
            try:
                value = self._items[session_id]
                authorization = self._authorization[session_id]
            except KeyError as exc:
                raise SessionNotFoundError(str(session_id)) from exc
            if authorization.scope != scope:
                raise SessionNotFoundError(str(session_id))
            result = completion.as_result()
            processed_prefix = completion.output_object_key.rsplit("/", 1)[0] + "/"
            if value.processing_completion_id is not None:
                if (
                    value.processing_completion_id == completion.idempotency_key
                    and value.processing_output == result
                    and value.processed_prefix == processed_prefix
                ):
                    return value.model_copy(deep=True)
                raise SessionConflictError("processing completion conflicts with persisted result")
            if value.processing_status not in {
                ProcessingStatus.UPLOADED,
                ProcessingStatus.PROCESSING,
            }:
                raise SessionConflictError("session is not ready for processing completion")
            now = datetime.now(UTC)
            updated = value.model_copy(
                update={
                    "processing_status": ProcessingStatus.PROCESSED,
                    "review_status": ReviewStatus.PENDING,
                    "processed_prefix": processed_prefix,
                    "processing_output": result,
                    "processing_completion_id": completion.idempotency_key,
                    "processing_completed_at": now,
                    "updated_at": now,
                }
            )
            self._items[session_id] = updated
            return updated.model_copy(deep=True)

    async def get_timeline(
        self, session_id: UUID, *, scope: TenantWorkspaceScope
    ) -> ProcessingResultPayload:
        value = await self.get(session_id, scope=scope)
        if value.processing_output is None:
            raise SessionNotFoundError(f"timeline for {session_id}")
        return value.processing_output.model_copy(deep=True)
