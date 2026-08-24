"""Fail-closed binding checks for the synthetic candidate authorities.

The candidate publication database is only a metadata source.  The control
database remains the review authority, and every read is admitted only after
the two stores' configured path, inode, and control-schema binding has been
verified.  This module deliberately performs no work at import or
construction time; callers invoke :func:`verify_candidate_authority` at the
read boundary.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from .candidate_publication_store import (
    CandidatePublicationError,
    SQLiteCandidatePublicationStore,
    _sqlite_readonly_uri,
)
from .control_service import ControlService
from .control_store import SQLiteControlStore


class CandidateAuthorityUnavailableError(CandidatePublicationError):
    """The configured publication/control authority cannot be verified."""


_REQUIRED_CONTROL_COLUMNS: dict[str, frozenset[str]] = {
    "control_jobs": frozenset(
        {
            "job_id",
            "state",
        }
    ),
    "lease_events": frozenset(
        {
            "sequence",
            "event_id",
            "job_id",
        }
    ),
    "review_events": frozenset(
        {
            "sequence",
            "event_id",
            "target_id",
            "idempotency_key",
            "content_digest",
            "actor_id",
            "status",
            "provenance_json",
            "detail_json",
            "occurred_at",
        }
    ),
    "review_projection": frozenset(
        {
            "target_id",
            "status",
            "version",
            "last_event_id",
            "actor_id",
            "provenance_json",
            "detail_json",
            "occurred_at",
        }
    ),
    "audit_events": frozenset(
        {
            "sequence",
            "event_id",
            "correlation_id",
            "idempotency_key",
            "subject_id",
            "roles_json",
            "action",
            "target_id",
            "result",
            "occurred_at",
        }
    ),
}


def verify_candidate_authority(
    publication_store: SQLiteCandidatePublicationStore,
    control_service: ControlService,
) -> None:
    """Verify the exact publication/control binding before a publication read.

    This is intentionally the same check used by candidate discovery.  It
    resolves aliases and symlinks, compares device/inode identity, rejects a
    shared publication/control file, and independently validates the control
    schema through a read-only SQLite connection.
    """

    if type(publication_store) is not SQLiteCandidatePublicationStore:
        raise CandidateAuthorityUnavailableError(
            "candidate publication authority is unavailable"
        )
    if type(control_service) is not ControlService:
        raise CandidateAuthorityUnavailableError(
            "candidate control authority is unavailable"
        )

    publication_path = _path_value(publication_store.database_path)
    bound_control_path = _path_value(publication_store.control_database_path)
    control_store = getattr(control_service, "_store", None)
    if type(control_store) is not SQLiteControlStore:
        raise CandidateAuthorityUnavailableError(
            "candidate discovery control authority is unavailable"
        )
    authority_path = _path_value(getattr(control_store, "_database_path", None))
    if publication_path is None or bound_control_path is None or authority_path is None:
        raise CandidateAuthorityUnavailableError(
            "candidate discovery control binding is unavailable"
        )
    try:
        bound = bound_control_path.resolve(strict=True)
        authority = authority_path.resolve(strict=True)
        publication = publication_path.resolve(strict=True)
        bound_stat = bound.stat()
        authority_stat = authority.stat()
        publication_stat = publication.stat()
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError) as exc:
        raise CandidateAuthorityUnavailableError(
            "candidate discovery control binding is unavailable"
        ) from exc
    if (
        not bound.is_file()
        or not authority.is_file()
        or bound != authority
        or (bound_stat.st_dev, bound_stat.st_ino)
        != (authority_stat.st_dev, authority_stat.st_ino)
    ):
        raise CandidateAuthorityUnavailableError(
            "candidate discovery control binding is unavailable"
        )
    if publication == authority or (
        (publication_stat.st_dev, publication_stat.st_ino)
        == (authority_stat.st_dev, authority_stat.st_ino)
    ):
        raise CandidateAuthorityUnavailableError(
            "candidate discovery publication and control authorities conflict"
        )
    try:
        validate_control_schema(bound)
    except (OSError, RuntimeError, sqlite3.Error, ValueError, TypeError) as exc:
        raise CandidateAuthorityUnavailableError(
            "candidate discovery control schema is unavailable"
        ) from exc


def _path_value(value: Any) -> Path | None:
    if isinstance(value, Path):
        return value
    if isinstance(value, str) and value and value != ":memory:":
        return Path(value)
    return None


def validate_control_schema(path: Path) -> None:
    """Validate the read-only control schema required by candidate reviews."""

    uri = _sqlite_readonly_uri(path)
    with sqlite3.connect(uri, uri=True, timeout=5.0) as connection:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA foreign_keys = ON")
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        if integrity is None or integrity[0] != "ok":
            raise RuntimeError("control database integrity check failed")
        tables = {
            row[0]: row[1]
            for row in connection.execute(
                "SELECT name, type FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        for table, required_columns in _REQUIRED_CONTROL_COLUMNS.items():
            if tables.get(table) != "table":
                raise RuntimeError("control database schema is incomplete")
            columns = {
                row[1]
                for row in connection.execute(
                    f'PRAGMA table_info("{table}")'
                ).fetchall()
            }
            if not required_columns.issubset(columns):
                raise RuntimeError("control database schema is incomplete")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise RuntimeError("control database foreign-key integrity failed")


__all__ = [
    "CandidateAuthorityUnavailableError",
    "verify_candidate_authority",
]
