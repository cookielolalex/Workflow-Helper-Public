"""Authenticated discovery for the sealed synthetic candidate runtime.

This module is intentionally a consumer-only boundary.  It owns no durable
state and performs no work at import or construction time.  The service and
its route are installed only when an exact sealed candidate bundle is supplied
to a separately created application; the default application remains inert.
A read is admitted only when the publication store is explicitly bound to the
same control database used by the authenticated control service.
"""

from __future__ import annotations

import sqlite3
from typing import Any

from .candidate_authority import (
    CandidateAuthorityUnavailableError,
    validate_control_schema,
    verify_candidate_authority,
)
from .candidate_publication_store import (
    CandidatePublicationCursor,
    CandidatePublicationError,
    CandidatePublicationMetadata,
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


class CandidateDiscoveryError(RuntimeError):
    """Base error for the bounded discovery boundary."""


class CandidateDiscoveryValidationError(ValueError, CandidateDiscoveryError):
    """The caller supplied an invalid bounded discovery input."""


class CandidateDiscoveryUnavailableError(CandidateDiscoveryError):
    """The explicit publication/control read authority is unavailable."""


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


_validate_control_schema = validate_control_schema


__all__ = [
    "MAX_DISCOVERY_LIMIT",
    "CandidateDiscoveryError",
    "CandidateDiscoveryService",
    "CandidateDiscoveryUnavailableError",
    "CandidateDiscoveryValidationError",
]
