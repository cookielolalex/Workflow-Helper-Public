"""Authenticated discovery for the sealed synthetic candidate runtime.

This module is intentionally a consumer-only boundary.  It owns no durable
state and performs no work at import or construction time.  The service and
its route are installed only when an exact sealed candidate bundle is supplied
to a separately created application; the default application remains inert.
A read is admitted only when the publication store is explicitly bound to the
same control database used by the authenticated control service.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from .candidate_authority import (
    CandidateAuthorityUnavailableError,
    validate_control_schema,
    verify_candidate_authority,
)
from .candidate_publication_store import (
    CandidatePublicationCursor,
    CandidatePublicationError,
    CandidatePublicationMetadata,
    CandidatePublicationRecord,
    SQLiteCandidatePublicationStore,
)
from .control_auth import (
    AuthenticatedPrincipal,
    AuthorizationDeniedError,
    ControlAction,
)
from .control_scope import TenantWorkspaceScope
from .control_service import ControlService
from .control_store import ControlStoreError, ReviewProjection

MAX_DISCOVERY_LIMIT = 100
_DISCOVERY_TARGET = "candidate-publication-discovery"
_MAX_COMMAND_LENGTH = 128
_MAX_STORED_JSON_BYTES = 262_144


class CandidateDiscoveryError(RuntimeError):
    """Base error for the bounded discovery boundary."""


class CandidateDiscoveryValidationError(ValueError, CandidateDiscoveryError):
    """The caller supplied an invalid bounded discovery input."""


class CandidateDiscoveryUnavailableError(CandidateDiscoveryError):
    """The explicit publication/control read authority is unavailable."""


class _CandidateReviewReadUnavailableError(CandidateDiscoveryUnavailableError):
    """One candidate's authoritative control projection could not be read."""


class _InvalidReviewProjection:
    """Distinguish an invalid control result from a genuine absent projection."""


_INVALID_REVIEW_PROJECTION = _InvalidReviewProjection()


@dataclass(frozen=True, slots=True)
class CandidateReviewQueueRecord:
    """Server-only review binding plus the minimum informed display evidence."""

    publication_key: str
    review_target_id: str
    command_sequence: tuple[str, ...]
    occurrence_count: int
    provenance: str
    review_status: str
    finalized_at_us: int


@dataclass(frozen=True, slots=True)
class CandidateReviewOutcomeRecord:
    """Display-only terminal result with no review or publication binding."""

    command_sequence: tuple[str, ...]
    occurrence_count: int
    provenance: str
    review_status: str
    decided_at_us: int


class CandidateDiscoveryService:
    """Read finalized candidate metadata through existing authorities only."""

    def __init__(
        self,
        publication_store: SQLiteCandidatePublicationStore,
        control_service: ControlService,
    ) -> None:
        if type(publication_store) is not SQLiteCandidatePublicationStore:
            raise TypeError(
                "publication_store must use the exact SQLiteCandidatePublicationStore type"
            )
        if type(control_service) is not ControlService:
            raise TypeError("control_service must use the exact ControlService type")
        # Do not inspect either database or path here.  Construction is an
        # inert dependency-binding step; all authority checks happen per read.
        self._publication_store = publication_store
        self._control_service = control_service

    def list_finalized_unreviewed(
        self,
        principal: AuthenticatedPrincipal,
        *,
        correlation_id: str,
        limit: int = MAX_DISCOVERY_LIMIT,
        cursor: CandidatePublicationCursor | str | None = None,
    ) -> list[CandidatePublicationMetadata]:
        """Return one bounded page of currently unreviewed publication metadata.

        The cursor is an opaque store cursor.  Rows are first selected through
        the publication store and then checked again through the control
        service so a review race, malformed authority, scope mismatch, or
        authorization failure can only suppress a row.
        """

        scope = self._authorize_read(principal, correlation_id)
        _require_limit(limit)
        scan_cursor = _coerce_cursor(cursor)
        self._verify_authority()

        discovered: list[CandidatePublicationMetadata] = []
        while len(discovered) < limit:
            remaining = limit - len(discovered)
            self._verify_authority()
            rows = self._read_publication_page(scope, remaining, scan_cursor)
            if not rows:
                break

            progressed = False
            for row in rows:
                row_cursor = _metadata_cursor(row)
                if row_cursor is None:
                    continue
                if scan_cursor is not None and _cursor_key(row_cursor) <= _cursor_key(scan_cursor):
                    continue
                scan_cursor = row_cursor
                progressed = True

                if type(row) is not CandidatePublicationMetadata:
                    continue
                if row.state != "finalized" or type(row.finalized_at_us) is not int:
                    continue
                try:
                    row_scope = row.scope
                except (TypeError, ValueError):
                    continue
                if row_scope != scope:
                    continue
                if not self._still_unreviewed(row, principal, correlation_id):
                    continue
                discovered.append(row)
                if len(discovered) == limit:
                    break

            # The store's own operation advances over finalized rows it
            # filtered.  This loop additionally advances over rows that lose
            # the race during this service's second, authoritative read.
            if not progressed:
                break

        return discovered

    # Descriptive aliases preserve one implementation and one bounded read.
    discover_finalized_unreviewed = list_finalized_unreviewed
    list_unreviewed = list_finalized_unreviewed

    def list_review_queue(
        self,
        principal: AuthenticatedPrincipal,
        *,
        correlation_id: str,
    ) -> list[CandidateReviewQueueRecord]:
        """Return bounded display evidence while retaining review bindings server-side.

        The metadata read remains unchanged.  Each selected row is then read
        again through ``get_finalized`` so the immutable candidate and its
        derivation evidence are independently verified by the existing store.
        Any row-local mismatch, malformed display projection, or review race is
        suppressed rather than disclosed.
        """

        scope = self._authorize_read(principal, correlation_id)
        projected: list[CandidateReviewQueueRecord] = []
        scan_cursor: CandidatePublicationCursor | None = None
        while len(projected) < MAX_DISCOVERY_LIMIT:
            self._verify_authority()
            try:
                rows = self._publication_store.list_finalized(
                    scope,
                    limit=MAX_DISCOVERY_LIMIT,
                    cursor=scan_cursor,
                )
            except CandidatePublicationError:
                raise CandidateDiscoveryUnavailableError(
                    "candidate discovery publication authority is unavailable"
                ) from None
            except (OSError, RuntimeError, sqlite3.Error) as exc:
                raise CandidateDiscoveryUnavailableError(
                    "candidate discovery publication authority is unavailable"
                ) from exc
            if type(rows) is not list or len(rows) > MAX_DISCOVERY_LIMIT:
                raise CandidateDiscoveryUnavailableError(
                    "candidate discovery publication authority is unavailable"
                )
            if not rows:
                break

            progressed = False
            for metadata in rows:
                row_cursor = _metadata_cursor(metadata)
                if row_cursor is None:
                    continue
                if scan_cursor is not None and _cursor_key(row_cursor) <= _cursor_key(scan_cursor):
                    continue
                scan_cursor = row_cursor
                progressed = True
                if type(metadata) is not CandidatePublicationMetadata:
                    continue
                try:
                    review_status = self._effective_review_status(
                        metadata,
                        principal,
                        correlation_id,
                    )
                except (AuthorizationDeniedError, _CandidateReviewReadUnavailableError):
                    continue
                if review_status not in {"unreviewed", "pending"}:
                    continue
                try:
                    record = self._publication_store.get_finalized(
                        metadata.scope,
                        metadata.publication_key,
                    )
                except CandidatePublicationError:
                    continue
                except (OSError, RuntimeError, sqlite3.Error) as exc:
                    raise CandidateDiscoveryUnavailableError(
                        "candidate discovery publication authority is unavailable"
                    ) from exc
                if type(record) is not CandidatePublicationRecord:
                    continue
                try:
                    if record.without_bytes() != metadata:
                        continue
                    item = _review_queue_record(record, review_status)
                except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
                    continue
                try:
                    confirmed_status = self._effective_review_status(
                        record.without_bytes(),
                        principal,
                        correlation_id,
                    )
                except (AuthorizationDeniedError, _CandidateReviewReadUnavailableError):
                    continue
                if confirmed_status != review_status:
                    continue
                projected.append(item)
                if len(projected) == MAX_DISCOVERY_LIMIT:
                    break

            if not progressed or len(rows) < MAX_DISCOVERY_LIMIT:
                break
        return projected

    def list_review_outcomes(
        self,
        principal: AuthenticatedPrincipal,
        *,
        correlation_id: str,
    ) -> list[CandidateReviewOutcomeRecord]:
        """Return terminal decisions only after evidence and authority correlation."""

        scope = self._authorize_read(principal, correlation_id)
        projected: list[CandidateReviewOutcomeRecord] = []
        scan_cursor: CandidatePublicationCursor | None = None
        while len(projected) < MAX_DISCOVERY_LIMIT:
            rows = self._read_all_finalized_page(scope, scan_cursor)
            if not rows:
                break
            progressed = False
            for metadata in rows:
                row_cursor = _metadata_cursor(metadata)
                if row_cursor is None:
                    continue
                if scan_cursor is not None and _cursor_key(row_cursor) <= _cursor_key(scan_cursor):
                    continue
                scan_cursor = row_cursor
                progressed = True
                if type(metadata) is not CandidatePublicationMetadata:
                    continue
                projection = self._review_projection(metadata, principal, correlation_id)
                if type(projection) is not ReviewProjection or projection.status not in {
                    "approved",
                    "rejected",
                    "needs_changes",
                }:
                    continue
                try:
                    record = self._publication_store.get_finalized(
                        metadata.scope,
                        metadata.publication_key,
                    )
                except CandidatePublicationError:
                    continue
                except (OSError, RuntimeError, sqlite3.Error) as exc:
                    raise CandidateDiscoveryUnavailableError(
                        "candidate discovery publication authority is unavailable"
                    ) from exc
                if type(record) is not CandidatePublicationRecord:
                    continue
                try:
                    if record.without_bytes() != metadata:
                        continue
                    commands = _verified_display_evidence(record)
                    decided_at_us = _projection_micros(projection)
                except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
                    continue
                if self._review_projection(
                    record.without_bytes(),
                    principal,
                    correlation_id,
                ) != projection:
                    continue
                projected.append(
                    CandidateReviewOutcomeRecord(
                        command_sequence=commands,
                        occurrence_count=len(commands),
                        provenance="observed",
                        review_status=projection.status,
                        decided_at_us=decided_at_us,
                    )
                )
                if len(projected) == MAX_DISCOVERY_LIMIT:
                    break
            if not progressed or len(rows) < MAX_DISCOVERY_LIMIT:
                break
        return projected

    def _read_all_finalized_page(
        self,
        scope: TenantWorkspaceScope,
        cursor: CandidatePublicationCursor | None,
    ) -> list[CandidatePublicationMetadata]:
        self._verify_authority()
        try:
            rows = self._publication_store.list_finalized(
                scope,
                limit=MAX_DISCOVERY_LIMIT,
                cursor=cursor,
            )
        except CandidatePublicationError:
            raise CandidateDiscoveryUnavailableError(
                "candidate discovery publication authority is unavailable"
            ) from None
        except (OSError, RuntimeError, sqlite3.Error) as exc:
            raise CandidateDiscoveryUnavailableError(
                "candidate discovery publication authority is unavailable"
            ) from exc
        if type(rows) is not list or len(rows) > MAX_DISCOVERY_LIMIT:
            raise CandidateDiscoveryUnavailableError(
                "candidate discovery publication authority is unavailable"
            )
        return rows

    def _effective_review_status(
        self,
        metadata: CandidatePublicationMetadata,
        principal: AuthenticatedPrincipal,
        correlation_id: str,
    ) -> str | None:
        projection = self._review_projection(metadata, principal, correlation_id)
        if projection is None:
            return "unreviewed"
        if type(projection) is not ReviewProjection:
            return None
        if projection.status == "pending":
            return "pending"
        if projection.status in {"approved", "rejected", "needs_changes"}:
            return None
        return None

    def _review_projection(
        self,
        metadata: CandidatePublicationMetadata,
        principal: AuthenticatedPrincipal,
        correlation_id: str,
    ) -> ReviewProjection | None | _InvalidReviewProjection:
        try:
            self._verify_authority()
            projection = self._control_service.read_candidate_review(
                principal,
                review_target_id=metadata.review_target_id,
                correlation_id=correlation_id,
            )
        except CandidateDiscoveryUnavailableError:
            raise
        except AuthorizationDeniedError:
            raise
        except (ControlStoreError, OSError, RuntimeError, sqlite3.Error) as exc:
            raise _CandidateReviewReadUnavailableError(
                "candidate discovery control authority is unavailable"
            ) from exc
        except (TypeError, ValueError, KeyError):
            return _INVALID_REVIEW_PROJECTION
        if projection is None:
            return None
        if (
            type(projection) is not ReviewProjection
            or projection.target_id != metadata.review_target_id
            or type(projection.version) is not int
            or projection.version < 1
            or type(projection.last_event_id) is not str
            or not projection.last_event_id
            or type(projection.occurred_at) is not datetime
            or projection.occurred_at.tzinfo is not UTC
        ):
            return _INVALID_REVIEW_PROJECTION
        return projection

    def _authorize_read(
        self,
        principal: AuthenticatedPrincipal,
        correlation_id: str,
    ) -> TenantWorkspaceScope:
        if type(principal) is not AuthenticatedPrincipal:
            raise TypeError("principal must use the exact AuthenticatedPrincipal type")
        try:
            scope = self._control_service._require_scope(principal)
            self._control_service._authorize(
                principal,
                ControlAction.REVIEW_READ,
                _DISCOVERY_TARGET,
                correlation_id,
                None,
            )
        except AuthorizationDeniedError:
            raise
        except (TypeError, ValueError) as exc:
            raise AuthorizationDeniedError("action forbidden") from exc
        return scope

    def _verify_authority(self) -> None:
        try:
            verify_candidate_authority(self._publication_store, self._control_service)
        except CandidateAuthorityUnavailableError as exc:
            raise CandidateDiscoveryUnavailableError(
                str(exc)
            ) from exc

    def _read_publication_page(
        self,
        scope: TenantWorkspaceScope,
        limit: int,
        cursor: CandidatePublicationCursor | None,
    ) -> list[CandidatePublicationMetadata]:
        try:
            rows = self._publication_store.list_finalized_unreviewed(
                scope,
                limit=limit,
                cursor=cursor,
            )
        except CandidatePublicationError:
            # The store suppresses row-local corruption.  A store-level
            # failure is an unavailable read authority and returns no data.
            raise CandidateDiscoveryUnavailableError(
                "candidate discovery publication authority is unavailable"
            ) from None
        except (OSError, RuntimeError, sqlite3.Error) as exc:
            raise CandidateDiscoveryUnavailableError(
                "candidate discovery publication authority is unavailable"
            ) from exc
        if type(rows) is not list:
            raise CandidateDiscoveryUnavailableError(
                "candidate discovery publication authority is unavailable"
            )
        return rows

    def _still_unreviewed(
        self,
        metadata: CandidatePublicationMetadata,
        principal: AuthenticatedPrincipal,
        correlation_id: str,
    ) -> bool:
        try:
            self._verify_authority()
            projection = self._control_service.read_candidate_review(
                principal,
                review_target_id=metadata.review_target_id,
                correlation_id=correlation_id,
            )
        except CandidateDiscoveryUnavailableError:
            raise
        except (AuthorizationDeniedError, ControlStoreError, OSError, RuntimeError, sqlite3.Error):
            return False
        except (TypeError, ValueError, KeyError):
            return False
        if projection is None:
            return True
        if type(projection) is not ReviewProjection:
            return False
        return False


def _require_limit(value: Any) -> None:
    if type(value) is not int or not 1 <= value <= MAX_DISCOVERY_LIMIT:
        raise CandidateDiscoveryValidationError(
            f"limit must be between 1 and {MAX_DISCOVERY_LIMIT}"
        )


def _coerce_cursor(value: Any) -> CandidatePublicationCursor | None:
    if value is None:
        return None
    if type(value) is CandidatePublicationCursor:
        return value
    if type(value) is str:
        try:
            return CandidatePublicationCursor.decode(value)
        except (TypeError, ValueError, CandidatePublicationError) as exc:
            raise CandidateDiscoveryValidationError("cursor is malformed") from exc
    raise CandidateDiscoveryValidationError("cursor is malformed")


def _metadata_cursor(value: Any) -> CandidatePublicationCursor | None:
    if type(value) is not CandidatePublicationMetadata:
        return None
    try:
        cursor = value.cursor
    except (AttributeError, TypeError, ValueError, CandidatePublicationError):
        return None
    return cursor if type(cursor) is CandidatePublicationCursor else None


def _cursor_key(value: CandidatePublicationCursor) -> tuple[int, str]:
    return value.finalized_at_us, value.publication_key


def _review_queue_record(
    record: CandidatePublicationRecord,
    review_status: str,
) -> CandidateReviewQueueRecord:
    if review_status not in {"unreviewed", "pending"}:
        raise ValueError("candidate publication is not displayable")
    commands = _verified_display_evidence(record)
    return CandidateReviewQueueRecord(
        publication_key=record.publication_key,
        review_target_id=record.review_target_id,
        command_sequence=commands,
        occurrence_count=len(commands),
        provenance="observed",
        review_status=review_status,
        finalized_at_us=record.finalized_at_us,
    )


def _verified_display_evidence(record: CandidatePublicationRecord) -> tuple[str, ...]:
    if (
        record.state != "finalized"
        or type(record.finalized_at_us) is not int
        or record.finalized_at_us <= 0
        or type(record.derivation_evidence_jcs) is not bytes
        or type(record.canonical_bytes) is not bytes
        or not 1 <= len(record.derivation_evidence_jcs) <= _MAX_STORED_JSON_BYTES
        or not 1 <= len(record.canonical_bytes) <= _MAX_STORED_JSON_BYTES
    ):
        raise ValueError("candidate publication is not displayable")

    evidence = json.loads(record.derivation_evidence_jcs.decode("utf-8"))
    candidate = json.loads(record.canonical_bytes.decode("utf-8"))
    if type(evidence) is not dict or type(candidate) is not dict:
        raise ValueError("candidate publication evidence is invalid")

    occurrences = evidence.get("occurrences")
    if type(occurrences) is not list or not 2 <= len(occurrences) <= 64:
        raise ValueError("candidate occurrence evidence is invalid")
    if (
        type(evidence.get("qualifying_run_length")) is not int
        or evidence["qualifying_run_length"] != len(occurrences)
    ):
        raise ValueError("candidate occurrence count is inconsistent")

    commands: list[str] = []
    source_event_ids: list[str] = []
    for index, occurrence in enumerate(occurrences, start=1):
        if type(occurrence) is not dict or set(occurrence) != {
            "event_id",
            "command_name",
            "segment_sequence",
        }:
            raise ValueError("candidate occurrence evidence is invalid")
        command = occurrence["command_name"]
        event_id = occurrence["event_id"]
        if (
            type(command) is not str
            or not 1 <= len(command) <= _MAX_COMMAND_LENGTH
            or command != command.strip()
            or any(ord(character) < 32 or ord(character) == 127 for character in command)
            or type(event_id) is not str
            or not 1 <= len(event_id) <= 64
            or type(occurrence["segment_sequence"]) is not int
            or occurrence["segment_sequence"] != index
        ):
            raise ValueError("candidate occurrence evidence is invalid")
        if str(UUID(event_id)) != event_id:
            raise ValueError("candidate occurrence identity is invalid")
        commands.append(command)
        source_event_ids.append(event_id)

    actions = candidate.get("ordered_actions")
    if (
        candidate.get("schema_version") != "1.0"
        or candidate.get("provenance") != "observed"
        or candidate.get("approval_status") != "unreviewed"
        or type(actions) is not list
        or len(actions) != len(commands)
    ):
        raise ValueError("candidate publication state is invalid")
    for index, (action, command, event_id) in enumerate(
        zip(actions, commands, source_event_ids, strict=True),
        start=1,
    ):
        expected_instruction = (
            "AutoCAD command: "
            + json.dumps(command, ensure_ascii=False, separators=(",", ":"))
            + "; source_event_id="
            + event_id
        )
        if (
            type(action) is not dict
            or set(action) != {"sequence", "instruction", "parameter_names"}
            or type(action.get("sequence")) is not int
            or action["sequence"] != index
            or action.get("instruction") != expected_instruction
            or action.get("parameter_names") != []
        ):
            raise ValueError("candidate action evidence is inconsistent")

    return tuple(commands)


def _projection_micros(projection: ReviewProjection) -> int:
    if type(projection.occurred_at) is not datetime or projection.occurred_at.tzinfo is not UTC:
        raise ValueError("candidate decision time is invalid")
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = projection.occurred_at - epoch
    value = delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds
    if value <= 0:
        raise ValueError("candidate decision time is invalid")
    return value


_validate_control_schema = validate_control_schema


__all__ = [
    "MAX_DISCOVERY_LIMIT",
    "CandidateDiscoveryError",
    "CandidateDiscoveryService",
    "CandidateDiscoveryUnavailableError",
    "CandidateDiscoveryValidationError",
    "CandidateReviewOutcomeRecord",
    "CandidateReviewQueueRecord",
]
