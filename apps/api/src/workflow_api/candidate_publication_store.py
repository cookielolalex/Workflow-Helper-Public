"""Provider-neutral immutable candidate publication bytes.

This module is deliberately an isolated component.  Importing it does not open
or create a database; callers must explicitly construct a store with a path.
The only durable state owned here is a small SQLite table containing a bounded
canonical candidate byte string and the verified derivation evidence from which
that string can be reconstructed.

The implementation follows Decision 116/120.  In particular, source evidence
is never guessed, candidate approval is never inferred from a producer field,
and a finalized row is create-once.  Provider reads, route registration,
runtime composition, and migrations are intentionally outside this module.
The sealed synthetic activation composes this store explicitly; importing the
module still performs no wiring.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePath, PureWindowsPath
from typing import Any
from urllib.parse import quote
from uuid import UUID

from .candidate_skill_semantics import validate_candidate_skill_internal_coherence
from .control_scope import TenantWorkspaceScope, _qualify, _validate_scope
from .models import ArtifactRef, ProcessingJobV2, ProcessingResultV2
from .processing_job_v2_identity import processing_job_v2_payload_digest

SCHEMA_VERSION = "1.0"
RESULT_DIGEST_SCHEME_ID = "workflow-helper.processing-job-v2.result.sha256-jcs.v1"
RESULT_DIGEST_DOMAIN_PREFIX = (
    b"workflow-helper\0processing-job-v2\0result-digest\0sha256-jcs-v1\0"
)
MAX_CANONICAL_BYTES = 256 * 1024
MAX_LEASE_SECONDS = 30 * 60
DISCOVERY_SCAN_BATCH = 100
MAX_SIGNED_64 = (1 << 63) - 1
MIN_SIGNED_64 = -(1 << 63)
MAX_EPOCH = (1 << 63) - 1

_OWNER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_PUBLICATION_KEY_PATTERN = re.compile(
    r"^candidate-publication:1\.0:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_WINDOWS_DRIVE_PATH_PATTERN = re.compile(r"^[A-Za-z]:[\\/]")


class CandidatePublicationError(RuntimeError):
    """Base class for bounded publication-store failures."""


class CandidatePublicationValidationError(ValueError, CandidatePublicationError):
    """The caller supplied an invalid or incomplete immutable evidence set."""


class NoCandidateError(CandidatePublicationValidationError):
    """The admitted result has no unique qualifying CAD run."""


class CandidatePublicationConflictError(CandidatePublicationError):
    """An immutable identity or finalized-byte conflict was detected."""


class CandidatePublicationUnavailableError(CandidatePublicationError):
    """A live reservation is owned by another writer or the store is unavailable."""


class CandidatePublicationNotFoundError(CandidatePublicationError):
    """The requested scoped publication does not exist."""


class CandidatePublicationCorruptionError(CandidatePublicationError):
    """Durable state failed independent verification; it is never repaired here."""


class CandidatePublicationStaleReservationError(CandidatePublicationError):
    """A reservation owner or fencing epoch is no longer current."""


# Useful short aliases for callers that use the control-store naming convention.
PublicationConflictError = CandidatePublicationConflictError
PublicationUnavailableError = CandidatePublicationUnavailableError
PublicationNotFoundError = CandidatePublicationNotFoundError
PublicationCorruptionError = CandidatePublicationCorruptionError
StalePublicationReservationError = CandidatePublicationStaleReservationError


@dataclass(frozen=True, slots=True)
class CandidatePublicationCursor:
    """Opaque stable cursor for finalized discovery."""

    finalized_at_us: int
    publication_key: str

    def __post_init__(self) -> None:
        _require_int(self.finalized_at_us, "cursor.finalized_at_us")
        _require_i64(self.finalized_at_us, "cursor.finalized_at_us")
        if not isinstance(self.publication_key, str) or not _PUBLICATION_KEY_PATTERN.fullmatch(
            self.publication_key
        ):
            raise CandidatePublicationValidationError("cursor publication key is invalid")

    def encode(self) -> str:
        return json.dumps(
            [self.finalized_at_us, self.publication_key],
            ensure_ascii=False,
            separators=(",", ":"),
        )

    @classmethod
    def decode(cls, value: str) -> CandidatePublicationCursor:
        if not isinstance(value, str):
            raise CandidatePublicationValidationError("cursor must be text")
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError) as exc:
            raise CandidatePublicationValidationError("cursor is malformed") from exc
        if type(parsed) is not list or len(parsed) != 2:
            raise CandidatePublicationValidationError("cursor is malformed")
        return cls(parsed[0], parsed[1])


@dataclass(frozen=True, slots=True)
class CandidatePublicationRecord:
    """Immutable caller-visible metadata for one scoped publication."""

    tenant_id: str
    workspace_id: str
    publication_key: str
    schema_version: str
    job_id: str
    session_id: str
    source_result_sha256: str
    derivation_evidence_jcs: bytes
    derivation_evidence_sha256: str
    review_target_id: str
    content_sha256: str
    full_sha256: str
    publication_identity: str
    byte_length: int
    state: str
    reservation_owner_id: str
    reservation_epoch: int
    reservation_expires_at_us: int | None
    canonical_bytes: bytes | None
    reserved_at_us: int
    updated_at_us: int
    finalized_at_us: int | None
    writer_epoch: int = 1

    def __post_init__(self) -> None:
        # Dataclass instances returned by every public method are independent
        # snapshots.  Convert mutable byte-like subclasses and reject them.
        if type(self.derivation_evidence_jcs) is not bytes:
            raise TypeError("derivation evidence must be exact bytes")
        if self.canonical_bytes is not None and type(self.canonical_bytes) is not bytes:
            raise TypeError("canonical bytes must be exact bytes")

    @property
    def scope(self) -> TenantWorkspaceScope:
        return TenantWorkspaceScope(self.tenant_id, self.workspace_id)

    @property
    def cursor(self) -> CandidatePublicationCursor | None:
        if self.finalized_at_us is None:
            return None
        return CandidatePublicationCursor(self.finalized_at_us, self.publication_key)

    def without_bytes(self) -> CandidatePublicationMetadata:
        """Return a discovery-safe projection with no BLOB-bearing fields."""

        return CandidatePublicationMetadata(
            tenant_id=self.tenant_id,
            workspace_id=self.workspace_id,
            publication_key=self.publication_key,
            schema_version=self.schema_version,
            job_id=self.job_id,
            session_id=self.session_id,
            source_result_sha256=self.source_result_sha256,
            derivation_evidence_sha256=self.derivation_evidence_sha256,
            review_target_id=self.review_target_id,
            content_sha256=self.content_sha256,
            full_sha256=self.full_sha256,
            publication_identity=self.publication_identity,
            byte_length=self.byte_length,
            state=self.state,
            reserved_at_us=self.reserved_at_us,
            updated_at_us=self.updated_at_us,
            finalized_at_us=self.finalized_at_us,
            writer_epoch=self.writer_epoch,
        )


@dataclass(frozen=True, slots=True)
class CandidatePublicationMetadata:
    """Discovery metadata; deliberately contains no candidate/evidence BLOBs."""

    tenant_id: str
    workspace_id: str
    publication_key: str
    schema_version: str
    job_id: str
    session_id: str
    source_result_sha256: str
    derivation_evidence_sha256: str
    review_target_id: str
    content_sha256: str
    full_sha256: str
    publication_identity: str
    byte_length: int
    state: str
    reserved_at_us: int
    updated_at_us: int
    finalized_at_us: int | None
    writer_epoch: int = 1

    @property
    def scope(self) -> TenantWorkspaceScope:
        return TenantWorkspaceScope(self.tenant_id, self.workspace_id)

    @property
    def cursor(self) -> CandidatePublicationCursor | None:
        if self.finalized_at_us is None:
            return None
        return CandidatePublicationCursor(self.finalized_at_us, self.publication_key)


@dataclass(frozen=True, slots=True)
class CandidateDerivationEvidence:
    """Convenience immutable envelope accepted by :meth:`reserve`.

    The store also accepts an equivalent mapping.  Keeping this dataclass here
    makes construction explicit for terminal synthetic tests while preserving a
    JSON-only durable representation.
    """

    job: Any
    result: Any
    result_manifest: Mapping[str, Any]
    timeline_binding: Mapping[str, Any]
    drawing_ref: str
    occurrences: Sequence[Mapping[str, Any]]
    rejected_alternative_count: int = 0
    qualifying_run_length: int | None = None
    envelope_version: str = "1.0"

    def as_mapping(self) -> dict[str, Any]:
        return {
            "envelope_version": self.envelope_version,
            "job": _json_value(self.job),
            "result": _json_value(self.result),
            "result_manifest": _json_value(self.result_manifest),
            "timeline_binding": _json_value(self.timeline_binding),
            "drawing_ref": self.drawing_ref,
            "occurrences": _json_value(list(self.occurrences)),
            "rejected_alternative_count": self.rejected_alternative_count,
            **(
                {}
                if self.qualifying_run_length is None
                else {"qualifying_run_length": self.qualifying_run_length}
            ),
        }


@dataclass(frozen=True, slots=True)
class _PreparedPublication:
    envelope: dict[str, Any]
    evidence_bytes: bytes
    candidate: dict[str, Any]
    candidate_bytes: bytes
    content_bytes: bytes
    job_id: str
    session_id: str
    source_result_sha256: str
    publication_key: str
    publication_identity: str
    review_target_id: str
    content_sha256: str
    full_sha256: str


_SCHEMA = """
CREATE TABLE IF NOT EXISTS candidate_publications (
    tenant_id TEXT NOT NULL,
    workspace_id TEXT NOT NULL,
    publication_key TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    job_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    source_result_sha256 TEXT NOT NULL,
    derivation_evidence_jcs BLOB NOT NULL,
    derivation_evidence_sha256 TEXT NOT NULL,
    review_target_id TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    full_sha256 TEXT NOT NULL,
    byte_length INTEGER NOT NULL,
    state TEXT NOT NULL,
    reservation_owner_id TEXT NOT NULL,
    reservation_epoch INTEGER NOT NULL,
    reservation_expires_at_us INTEGER,
    canonical_bytes BLOB,
    reserved_at_us INTEGER NOT NULL,
    updated_at_us INTEGER NOT NULL,
    finalized_at_us INTEGER,
    writer_epoch INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, workspace_id, publication_key),
    UNIQUE (tenant_id, workspace_id, job_id),
    CHECK (schema_version = '1.0'),
    CHECK (length(publication_key) > 0),
    CHECK (length(job_id) = 36 AND length(session_id) = 36),
    CHECK (length(source_result_sha256) = 64),
    CHECK (length(derivation_evidence_sha256) = 64),
    CHECK (length(review_target_id) > 0),
    CHECK (length(content_sha256) = 64),
    CHECK (length(full_sha256) = 64),
    CHECK (byte_length BETWEEN 1 AND 262144),
    CHECK (state IN ('reserved', 'finalized')),
    CHECK (reservation_epoch BETWEEN 1 AND 9223372036854775807),
    CHECK (writer_epoch = 1),
    CHECK (reserved_at_us BETWEEN -9223372036854775808 AND 9223372036854775807),
    CHECK (updated_at_us BETWEEN -9223372036854775808 AND 9223372036854775807),
    CHECK (finalized_at_us IS NULL OR finalized_at_us BETWEEN -9223372036854775808 AND 9223372036854775807),
    CHECK (
        (state = 'reserved'
         AND canonical_bytes IS NULL
         AND finalized_at_us IS NULL
         AND reservation_expires_at_us IS NOT NULL
         AND reservation_expires_at_us BETWEEN -9223372036854775808 AND 9223372036854775807
         AND reserved_at_us <= updated_at_us
         AND updated_at_us < reservation_expires_at_us)
        OR
        (state = 'finalized'
         AND typeof(canonical_bytes) = 'blob'
         AND length(canonical_bytes) = byte_length
         AND finalized_at_us IS NOT NULL
         AND reservation_expires_at_us IS NULL
         AND reserved_at_us <= updated_at_us
         AND updated_at_us <= finalized_at_us)
    )
);
CREATE INDEX IF NOT EXISTS candidate_publications_discovery_idx
    ON candidate_publications (tenant_id, workspace_id, state, finalized_at_us, publication_key);
CREATE TRIGGER IF NOT EXISTS candidate_publications_no_delete_finalized
BEFORE DELETE ON candidate_publications
WHEN OLD.state = 'finalized'
BEGIN
    SELECT RAISE(ABORT, 'finalized candidate publication is immutable');
END;
CREATE TRIGGER IF NOT EXISTS candidate_publications_no_update_finalized
BEFORE UPDATE ON candidate_publications
WHEN OLD.state = 'finalized'
BEGIN
    SELECT RAISE(ABORT, 'finalized candidate publication is immutable');
END;
CREATE TRIGGER IF NOT EXISTS candidate_publications_identity_immutable
BEFORE UPDATE ON candidate_publications
WHEN OLD.tenant_id <> NEW.tenant_id
  OR OLD.workspace_id <> NEW.workspace_id
  OR OLD.publication_key <> NEW.publication_key
  OR OLD.schema_version <> NEW.schema_version
  OR OLD.job_id <> NEW.job_id
  OR OLD.session_id <> NEW.session_id
  OR OLD.source_result_sha256 <> NEW.source_result_sha256
  OR OLD.derivation_evidence_jcs <> NEW.derivation_evidence_jcs
  OR OLD.derivation_evidence_sha256 <> NEW.derivation_evidence_sha256
  OR OLD.review_target_id <> NEW.review_target_id
  OR OLD.content_sha256 <> NEW.content_sha256
  OR OLD.full_sha256 <> NEW.full_sha256
  OR OLD.byte_length <> NEW.byte_length
  OR OLD.writer_epoch <> NEW.writer_epoch
BEGIN
    SELECT RAISE(ABORT, 'candidate publication identity is immutable');
END;
CREATE TRIGGER IF NOT EXISTS candidate_publications_bytes_once
BEFORE UPDATE ON candidate_publications
WHEN OLD.canonical_bytes IS NOT NULL AND NEW.canonical_bytes <> OLD.canonical_bytes
BEGIN
    SELECT RAISE(ABORT, 'candidate publication bytes are immutable');
END;
"""


class SQLiteCandidatePublicationStore:
    """Scoped, fenced, immutable candidate publication persistence."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        control_database_path: str | Path | Any | None = None,
        busy_timeout_seconds: float = 5.0,
        clock: Callable[[], int | datetime] | None = None,
    ) -> None:
        if isinstance(database_path, Path):
            path = database_path
        elif isinstance(database_path, str):
            path = Path(database_path)
        else:
            raise TypeError("database_path must be a filesystem path")
        if str(path) == ":memory:":
            raise ValueError("candidate publication store requires a filesystem path")
        if not path.name:
            raise ValueError("database_path must name a file")
        if type(busy_timeout_seconds) not in (int, float) or busy_timeout_seconds <= 0:
            raise ValueError("busy_timeout_seconds must be positive")
        if control_database_path is not None and hasattr(control_database_path, "_database_path"):
            control_database_path = control_database_path._database_path
        if control_database_path is not None and not isinstance(
            control_database_path, (str, Path)
        ):
            raise TypeError("control_database_path must be a filesystem path")
        self._database_path = str(path)
        self._control_database_path = (
            None if control_database_path is None else str(control_database_path)
        )
        self._busy_timeout_ms = int(float(busy_timeout_seconds) * 1000)
        self._clock = clock or (lambda: time.time_ns() // 1000)

        # Explicit construction is the activation boundary. Importing this
        # module above performs none of these filesystem operations.
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connection() as connection:
            connection.executescript(_SCHEMA)
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")

    @property
    def database_path(self) -> str:
        return self._database_path

    @property
    def control_database_path(self) -> str | None:
        return self._control_database_path

    def reserve(
        self,
        scope: TenantWorkspaceScope,
        derivation_evidence: Mapping[str, Any] | CandidateDerivationEvidence | None = None,
        reservation_owner_id: str | None = None,
        lease_duration_seconds: int | None = None,
        *,
        evidence: Mapping[str, Any] | CandidateDerivationEvidence | None = None,
        owner_id: str | None = None,
        lease_seconds: int | None = None,
        now: int | datetime | None = None,
        **parts: Any,
    ) -> CandidatePublicationRecord:
        """Validate and reserve one complete evidence envelope.

        ``evidence`` is the canonical spelling. The aliases and keyword parts
        remain compatibility inputs for explicit adapters; they are normalized
        into the same exact envelope before any SQLite mutation.
        """

        scope = _checked_scope(scope)
        evidence = derivation_evidence if derivation_evidence is not None else evidence
        if evidence is None and parts:
            evidence = _parts_to_evidence(parts)
        if evidence is None:
            raise CandidatePublicationValidationError("complete derivation evidence is required")
        reservation_owner_id = (
            reservation_owner_id if reservation_owner_id is not None else owner_id
        )
        lease_duration_seconds = (
            lease_duration_seconds if lease_duration_seconds is not None else lease_seconds
        )
        _require_owner(reservation_owner_id)
        _require_lease_seconds(lease_duration_seconds)
        now_us = _resolve_now(self._clock, now)
        prepared = _prepare_publication(evidence)

        with self._transaction() as connection:
            row = connection.execute(
                """SELECT * FROM candidate_publications
                   WHERE tenant_id = ? AND workspace_id = ? AND publication_key = ?""",
                (scope.tenant_id, scope.workspace_id, prepared.publication_key),
            ).fetchone()
            if row is not None:
                # Existing durable evidence is untrusted input.  Validate it
                # before comparing identity or changing a live reservation so
                # malformed/non-admitting rows cannot surface as conflicts or
                # be silently reacquired.
                if row["state"] == "finalized":
                    self._verified_record_from_row(connection, row, scope)
                else:
                    self._verified_stored_evidence(row)
                self._assert_same_immutable_identity(row, scope, prepared)
                if row["state"] == "finalized":
                    # Replay is successful only after full independent readback.
                    return self._verified_record_from_row(connection, row, scope)
                if now_us < row["reservation_expires_at_us"]:
                    if row["reservation_owner_id"] != reservation_owner_id:
                        raise CandidatePublicationUnavailableError(
                            "candidate publication reservation is held by another owner"
                        )
                    return self._record_from_row(row, include_bytes=False)
                previous_epoch = row["reservation_epoch"]
                if previous_epoch >= MAX_EPOCH:
                    raise CandidatePublicationUnavailableError(
                        "candidate publication reservation epoch is exhausted"
                    )
                next_epoch = previous_epoch + 1
                expires = _lease_expiry(now_us, lease_duration_seconds)
                connection.execute(
                    """UPDATE candidate_publications
                       SET reservation_owner_id = ?, reservation_epoch = ?,
                           reservation_expires_at_us = ?, updated_at_us = ?
                       WHERE tenant_id = ? AND workspace_id = ? AND publication_key = ?
                         AND state = 'reserved' AND reservation_epoch = ?""",
                    (
                        reservation_owner_id,
                        next_epoch,
                        expires,
                        now_us,
                        scope.tenant_id,
                        scope.workspace_id,
                        prepared.publication_key,
                        previous_epoch,
                    ),
                )
                updated = connection.execute(
                    "SELECT * FROM candidate_publications WHERE tenant_id = ? AND workspace_id = ? AND publication_key = ?",
                    (scope.tenant_id, scope.workspace_id, prepared.publication_key),
                ).fetchone()
                if updated is None:
                    raise CandidatePublicationUnavailableError("reservation disappeared")
                return self._record_from_row(updated, include_bytes=False)

            # The job uniqueness constraint is scoped, never global.
            same_job = connection.execute(
                """SELECT publication_key FROM candidate_publications
                   WHERE tenant_id = ? AND workspace_id = ? AND job_id = ?""",
                (scope.tenant_id, scope.workspace_id, prepared.job_id),
            ).fetchone()
            if same_job is not None:
                raise CandidatePublicationConflictError(
                    "candidate publication job identity conflicts with an existing publication"
                )

            expires = _lease_expiry(now_us, lease_duration_seconds)
            connection.execute(
                """INSERT INTO candidate_publications (
                    tenant_id, workspace_id, publication_key, schema_version,
                    job_id, session_id, source_result_sha256,
                    derivation_evidence_jcs, derivation_evidence_sha256,
                    review_target_id, content_sha256, full_sha256, byte_length,
                    state, reservation_owner_id, reservation_epoch,
                    reservation_expires_at_us, canonical_bytes, reserved_at_us,
                    updated_at_us, finalized_at_us, writer_epoch
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'reserved', ?, 1,
                          ?, NULL, ?, ?, NULL, 1)""",
                (
                    scope.tenant_id,
                    scope.workspace_id,
                    prepared.publication_key,
                    SCHEMA_VERSION,
                    prepared.job_id,
                    prepared.session_id,
                    prepared.source_result_sha256,
                    sqlite3.Binary(prepared.evidence_bytes),
                    hashlib.sha256(prepared.evidence_bytes).hexdigest(),
                    prepared.review_target_id,
                    prepared.content_sha256,
                    prepared.full_sha256,
                    len(prepared.candidate_bytes),
                    reservation_owner_id,
                    expires,
                    now_us,
                    now_us,
                ),
            )
            inserted = connection.execute(
                "SELECT * FROM candidate_publications WHERE tenant_id = ? AND workspace_id = ? AND publication_key = ?",
                (scope.tenant_id, scope.workspace_id, prepared.publication_key),
            ).fetchone()
            if inserted is None:  # pragma: no cover - SQLite transaction invariant
                raise CandidatePublicationUnavailableError("reserved row is missing")
            return self._record_from_row(inserted, include_bytes=False)

    # Explicitly named aliases are useful to callers without changing semantics.
    reserve_publication = reserve
    reserve_candidate = reserve

    def finalize(
        self,
        scope: TenantWorkspaceScope,
        publication_key: str,
        reservation_owner_id: str | None = None,
        reservation_epoch: int | None = None,
        canonical_bytes: bytes | None = None,
        *,
        owner_id: str | None = None,
        fencing_epoch: int | None = None,
        candidate_bytes: bytes | None = None,
        now: int | datetime | None = None,
    ) -> CandidatePublicationRecord:
        """Fence, verify, and atomically finalize one immutable byte string."""

        scope = _checked_scope(scope)
        publication_key = _require_publication_key(publication_key)
        reservation_owner_id = (
            reservation_owner_id if reservation_owner_id is not None else owner_id
        )
        reservation_epoch = (
            reservation_epoch if reservation_epoch is not None else fencing_epoch
        )
        canonical_bytes = (
            canonical_bytes if canonical_bytes is not None else candidate_bytes
        )
        _require_owner(reservation_owner_id)
        _require_positive_epoch(reservation_epoch, "reservation_epoch")
        if type(canonical_bytes) is not bytes:
            raise CandidatePublicationValidationError("canonical_bytes must be exact bytes")
        _require_byte_cap(canonical_bytes, "canonical_bytes")
        now_us = _resolve_now(self._clock, now)

        # Verification before the write is intentionally repeated in the
        # transaction below: another process may reacquire between these reads.
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM candidate_publications WHERE tenant_id = ? AND workspace_id = ? AND publication_key = ?",
                (scope.tenant_id, scope.workspace_id, publication_key),
            ).fetchone()
            if row is None:
                raise CandidatePublicationNotFoundError("candidate publication not found")
            if row["state"] == "finalized":
                verified = self._verified_record_from_row(connection, row, scope)
                if verified.canonical_bytes != canonical_bytes:
                    raise CandidatePublicationConflictError(
                        "finalized candidate bytes conflict with the immutable publication"
                    )
                return verified
            self._assert_live_reservation(row, reservation_owner_id, reservation_epoch, now_us)
            self._verify_supplied_bytes(connection, row, scope, canonical_bytes)

        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM candidate_publications WHERE tenant_id = ? AND workspace_id = ? AND publication_key = ?",
                (scope.tenant_id, scope.workspace_id, publication_key),
            ).fetchone()
            if row is None:
                raise CandidatePublicationNotFoundError("candidate publication not found")
            if row["state"] == "finalized":
                verified = self._verified_record_from_row(connection, row, scope)
                if verified.canonical_bytes != canonical_bytes:
                    raise CandidatePublicationConflictError(
                        "finalized candidate bytes conflict with the immutable publication"
                    )
                return verified
            self._assert_live_reservation(row, reservation_owner_id, reservation_epoch, now_us)
            self._verify_supplied_bytes(connection, row, scope, canonical_bytes)
            if now_us < row["updated_at_us"]:
                raise CandidatePublicationUnavailableError(
                    "finalization clock moved before the reservation update"
                )
            connection.execute(
                """UPDATE candidate_publications
                   SET state = 'finalized', canonical_bytes = ?,
                       reservation_expires_at_us = NULL, finalized_at_us = ?,
                       updated_at_us = ?
                   WHERE tenant_id = ? AND workspace_id = ? AND publication_key = ?
                     AND state = 'reserved' AND reservation_owner_id = ?
                     AND reservation_epoch = ?""",
                (
                    sqlite3.Binary(canonical_bytes),
                    now_us,
                    now_us,
                    scope.tenant_id,
                    scope.workspace_id,
                    publication_key,
                    reservation_owner_id,
                    reservation_epoch,
                ),
            )
            updated = connection.execute(
                "SELECT * FROM candidate_publications WHERE tenant_id = ? AND workspace_id = ? AND publication_key = ?",
                (scope.tenant_id, scope.workspace_id, publication_key),
            ).fetchone()
            if updated is None:
                raise CandidatePublicationUnavailableError("finalized row is missing")
            return self._verified_record_from_row(connection, updated, scope)

    finalize_publication = finalize
    finalize_candidate = finalize

    def get_finalized(
        self,
        scope: TenantWorkspaceScope,
        publication_key: str,
    ) -> CandidatePublicationRecord:
        scope = _checked_scope(scope)
        publication_key = _require_publication_key(publication_key)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM candidate_publications WHERE tenant_id = ? AND workspace_id = ? AND publication_key = ?",
                (scope.tenant_id, scope.workspace_id, publication_key),
            ).fetchone()
            if row is None or row["state"] != "finalized":
                raise CandidatePublicationNotFoundError("finalized candidate publication not found")
            return self._verified_record_from_row(connection, row, scope)

    get_finalized_publication = get_finalized
    get_candidate = get_finalized

    def read_finalized_bytes(
        self,
        scope: TenantWorkspaceScope,
        publication_key: str,
    ) -> bytes:
        record = self.get_finalized(scope, publication_key)
        if record.canonical_bytes is None:  # pragma: no cover - invariant
            raise CandidatePublicationCorruptionError("finalized bytes are missing")
        # Force a fresh immutable allocation so callers cannot use object
        # identity as a hidden mutable cache.
        return bytes(bytearray(record.canonical_bytes))

    read_bytes = read_finalized_bytes
    read_finalized = read_finalized_bytes

    def list_finalized(
        self,
        scope: TenantWorkspaceScope,
        limit: int = 100,
        cursor: CandidatePublicationCursor | str | tuple[int, str] | Mapping[str, Any] | None = None,
    ) -> list[CandidatePublicationMetadata]:
        """List bounded verified finalized rows without interpreting review state."""

        scope = _checked_scope(scope)
        _require_limit(limit)
        scan_cursor = _coerce_cursor(cursor)
        with self._connection() as connection:
            records: list[CandidatePublicationMetadata] = []
            while len(records) < limit:
                params: list[Any] = [scope.tenant_id, scope.workspace_id]
                sql = """SELECT * FROM candidate_publications
                         WHERE tenant_id = ? AND workspace_id = ? AND state = 'finalized'"""
                if scan_cursor is not None:
                    sql += " AND (finalized_at_us > ? OR (finalized_at_us = ? AND publication_key > ?))"
                    params.extend(
                        [
                            scan_cursor.finalized_at_us,
                            scan_cursor.finalized_at_us,
                            scan_cursor.publication_key,
                        ]
                    )
                sql += " ORDER BY finalized_at_us ASC, publication_key ASC LIMIT ?"
                params.append(DISCOVERY_SCAN_BATCH)
                rows = connection.execute(sql, params).fetchall()
                if not rows:
                    break
                for row in rows:
                    scan_cursor = CandidatePublicationCursor(
                        row["finalized_at_us"], row["publication_key"]
                    )
                    try:
                        verified = self._verified_record_from_row(connection, row, scope)
                        records.append(verified.without_bytes())
                        if len(records) == limit:
                            break
                    except CandidatePublicationError:
                        continue
                if len(rows) < DISCOVERY_SCAN_BATCH or len(records) == limit:
                    break
            return records

    def list_finalized_unreviewed(
        self,
        scope: TenantWorkspaceScope,
        limit: int = 100,
        cursor: CandidatePublicationCursor | str | tuple[int, str] | Mapping[str, Any] | None = None,
    ) -> list[CandidatePublicationMetadata]:
        scope = _checked_scope(scope)
        _require_limit(limit)
        scan_cursor = _coerce_cursor(cursor)
        with self._connection() as connection:
            records: list[CandidatePublicationMetadata] = []
            while len(records) < limit:
                params: list[Any] = [scope.tenant_id, scope.workspace_id]
                sql = """SELECT * FROM candidate_publications
                         WHERE tenant_id = ? AND workspace_id = ? AND state = 'finalized'"""
                if scan_cursor is not None:
                    sql += " AND (finalized_at_us > ? OR (finalized_at_us = ? AND publication_key > ?))"
                    params.extend(
                        [
                            scan_cursor.finalized_at_us,
                            scan_cursor.finalized_at_us,
                            scan_cursor.publication_key,
                        ]
                    )
                sql += " ORDER BY finalized_at_us ASC, publication_key ASC LIMIT ?"
                params.append(DISCOVERY_SCAN_BATCH)
                rows = connection.execute(sql, params).fetchall()
                if not rows:
                    break
                for row in rows:
                    scan_cursor = CandidatePublicationCursor(
                        row["finalized_at_us"], row["publication_key"]
                    )
                    try:
                        # Metadata discovery must independently verify the same
                        # immutable row but intentionally discards the BLOB.
                        verified = self._verified_record_from_row(connection, row, scope)
                        if not self._review_is_effectively_unreviewed(scope, verified):
                            continue
                        records.append(verified.without_bytes())
                        if len(records) == limit:
                            break
                    except CandidatePublicationError:
                        # A corrupt or ambiguous review projection is fail-closed
                        # for discovery and does not leak any metadata.
                        continue
                if len(rows) < DISCOVERY_SCAN_BATCH or len(records) == limit:
                    break
            return records

    list_unreviewed = list_finalized_unreviewed
    discover_finalized_unreviewed = list_finalized_unreviewed

    def _verify_supplied_bytes(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        scope: TenantWorkspaceScope,
        canonical_bytes: bytes,
    ) -> None:
        prepared = self._verified_stored_evidence(row)
        expected = self._record_from_row(row, include_bytes=True)
        if expected.state != "reserved":
            raise CandidatePublicationConflictError("candidate publication is not reserved")
        if hashlib.sha256(canonical_bytes).hexdigest() != expected.full_sha256:
            raise CandidatePublicationConflictError("canonical bytes digest conflicts with reservation")
        if len(canonical_bytes) != expected.byte_length:
            raise CandidatePublicationConflictError("canonical bytes length conflicts with reservation")
        # Compare to reconstructed bytes, not only to the stored digest; this
        # catches a maliciously modified row whose digest was also modified.
        if (
            prepared.candidate_bytes != canonical_bytes
            or prepared.publication_key != expected.publication_key
            or prepared.job_id != expected.job_id
            or prepared.session_id != expected.session_id
            or prepared.source_result_sha256 != expected.source_result_sha256
            or prepared.review_target_id != expected.review_target_id
            or prepared.content_sha256 != expected.content_sha256
            or prepared.full_sha256 != expected.full_sha256
        ):
            raise CandidatePublicationConflictError("canonical bytes conflict with derivation evidence")

    @staticmethod
    def _verified_stored_evidence(row: sqlite3.Row) -> _PreparedPublication:
        """Decode and independently admit evidence stored in a publication row.

        SQLite BLOBs are a persistence trust boundary.  Decode, JSON parsing,
        canonical-byte equality, and admission failures all become one
        corruption class so callers never mistake damaged durable state for a
        caller conflict or continue into a reservation mutation.
        """

        evidence = row["derivation_evidence_jcs"]
        if type(evidence) not in (bytes, bytearray, memoryview):
            raise CandidatePublicationCorruptionError(
                "stored derivation evidence storage type is invalid"
            )
        evidence_bytes = bytes(evidence)
        try:
            evidence_value = json.loads(evidence_bytes.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise CandidatePublicationCorruptionError(
                "stored derivation evidence is not valid UTF-8"
            ) from exc
        except json.JSONDecodeError as exc:
            raise CandidatePublicationCorruptionError(
                "stored derivation evidence JSON is malformed"
            ) from exc
        except RecursionError as exc:
            raise CandidatePublicationCorruptionError(
                "stored derivation evidence JSON is too deeply nested"
            ) from exc
        except (TypeError, ValueError) as exc:
            raise CandidatePublicationCorruptionError(
                "stored derivation evidence cannot be decoded"
            ) from exc
        try:
            prepared = _prepare_publication(evidence_value)
        except CandidatePublicationError as exc:
            raise CandidatePublicationCorruptionError(
                "stored derivation evidence is not admitted"
            ) from exc
        except Exception as exc:
            raise CandidatePublicationCorruptionError(
                "stored derivation evidence admission failed"
            ) from exc
        if prepared.evidence_bytes != evidence_bytes:
            raise CandidatePublicationCorruptionError(
                "stored derivation evidence is not canonical"
            )
        expected = {
            "publication_key": prepared.publication_key,
            "job_id": prepared.job_id,
            "session_id": prepared.session_id,
            "source_result_sha256": prepared.source_result_sha256,
            "review_target_id": prepared.review_target_id,
            "content_sha256": prepared.content_sha256,
            "full_sha256": prepared.full_sha256,
            "byte_length": len(prepared.candidate_bytes),
        }
        for field, value in expected.items():
            if row[field] != value:
                raise CandidatePublicationCorruptionError(
                    f"stored candidate publication {field} is inconsistent"
                )
        if hashlib.sha256(evidence_bytes).hexdigest() != row["derivation_evidence_sha256"]:
            raise CandidatePublicationCorruptionError(
                "stored derivation evidence digest is invalid"
            )
        return prepared

    def _verified_record_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        scope: TenantWorkspaceScope,
        *,
        include_bytes: bool = True,
    ) -> CandidatePublicationRecord:
        try:
            record = self._record_from_row(row, include_bytes=include_bytes)
            if record.state != "finalized":
                raise CandidatePublicationCorruptionError("row is not finalized")
            if record.canonical_bytes is None:
                raise CandidatePublicationCorruptionError("finalized candidate bytes are missing")
            if len(record.canonical_bytes) != record.byte_length:
                raise CandidatePublicationCorruptionError("finalized candidate length is invalid")
            if hashlib.sha256(record.canonical_bytes).hexdigest() != record.full_sha256:
                raise CandidatePublicationCorruptionError("finalized candidate digest is invalid")
            prepared = self._verified_stored_evidence(row)
            if prepared.candidate_bytes != record.canonical_bytes:
                raise CandidatePublicationCorruptionError("candidate bytes do not reconstruct")
            if (
                prepared.publication_key != record.publication_key
                or prepared.job_id != record.job_id
                or prepared.session_id != record.session_id
                or prepared.source_result_sha256 != record.source_result_sha256
                or prepared.review_target_id != record.review_target_id
                or prepared.content_sha256 != record.content_sha256
                or prepared.full_sha256 != record.full_sha256
                or prepared.publication_identity != record.publication_identity
            ):
                raise CandidatePublicationCorruptionError("candidate publication identity changed")
            if hashlib.sha256(record.derivation_evidence_jcs).hexdigest() != record.derivation_evidence_sha256:
                raise CandidatePublicationCorruptionError("derivation evidence digest is invalid")
            return record
        except CandidatePublicationError:
            raise
        except Exception as exc:
            raise CandidatePublicationCorruptionError("candidate publication readback failed") from exc

    @staticmethod
    def _record_from_row(
        row: sqlite3.Row,
        *,
        include_bytes: bool,
    ) -> CandidatePublicationRecord:
        evidence = row["derivation_evidence_jcs"]
        canonical = row["canonical_bytes"]
        if type(evidence) not in (bytes, bytearray, memoryview):
            raise CandidatePublicationCorruptionError("derivation evidence storage type is invalid")
        if canonical is not None and type(canonical) not in (bytes, bytearray, memoryview):
            raise CandidatePublicationCorruptionError("canonical byte storage type is invalid")
        return CandidatePublicationRecord(
            tenant_id=row["tenant_id"],
            workspace_id=row["workspace_id"],
            publication_key=row["publication_key"],
            schema_version=row["schema_version"],
            job_id=row["job_id"],
            session_id=row["session_id"],
            source_result_sha256=row["source_result_sha256"],
            derivation_evidence_jcs=bytes(evidence),
            derivation_evidence_sha256=row["derivation_evidence_sha256"],
            review_target_id=row["review_target_id"],
            content_sha256=row["content_sha256"],
            full_sha256=row["full_sha256"],
            publication_identity=_publication_identity(
                row["job_id"], row["source_result_sha256"], row["full_sha256"]
            ),
            byte_length=row["byte_length"],
            state=row["state"],
            reservation_owner_id=row["reservation_owner_id"],
            reservation_epoch=row["reservation_epoch"],
            reservation_expires_at_us=row["reservation_expires_at_us"],
            canonical_bytes=(None if canonical is None or not include_bytes else bytes(canonical)),
            reserved_at_us=row["reserved_at_us"],
            updated_at_us=row["updated_at_us"],
            finalized_at_us=row["finalized_at_us"],
            writer_epoch=row["writer_epoch"],
        )

    @staticmethod
    def _assert_same_immutable_identity(
        row: sqlite3.Row,
        scope: TenantWorkspaceScope,
        prepared: _PreparedPublication,
    ) -> None:
        expected = {
            "tenant_id": scope.tenant_id,
            "workspace_id": scope.workspace_id,
            "publication_key": prepared.publication_key,
            "schema_version": SCHEMA_VERSION,
            "job_id": prepared.job_id,
            "session_id": prepared.session_id,
            "source_result_sha256": prepared.source_result_sha256,
            "derivation_evidence_jcs": prepared.evidence_bytes,
            "derivation_evidence_sha256": hashlib.sha256(prepared.evidence_bytes).hexdigest(),
            "review_target_id": prepared.review_target_id,
            "content_sha256": prepared.content_sha256,
            "full_sha256": prepared.full_sha256,
            "byte_length": len(prepared.candidate_bytes),
        }
        for field, value in expected.items():
            actual = row[field]
            if field == "derivation_evidence_jcs":
                actual = bytes(actual)
            if actual != value:
                raise CandidatePublicationConflictError(
                    f"candidate publication immutable identity conflicts: {field}"
                )

    @staticmethod
    def _assert_live_reservation(
        row: sqlite3.Row,
        reservation_owner_id: str,
        reservation_epoch: int,
        now_us: int,
    ) -> None:
        if row["state"] != "reserved":
            raise CandidatePublicationConflictError("candidate publication is not reserved")
        if row["reservation_owner_id"] != reservation_owner_id or row["reservation_epoch"] != reservation_epoch:
            raise CandidatePublicationStaleReservationError("candidate reservation fencing token is stale")
        if row["reservation_expires_at_us"] is None or now_us >= row["reservation_expires_at_us"]:
            raise CandidatePublicationStaleReservationError("candidate reservation has expired")

    def _review_is_effectively_unreviewed(
        self,
        scope: TenantWorkspaceScope,
        record: CandidatePublicationRecord | CandidatePublicationMetadata,
    ) -> bool:
        if self._control_database_path is None:
            # The component has no review authority of its own.  With no
            # supplied control DB, the defined initial state is unreviewed.
            return True
        path = Path(self._control_database_path)
        try:
            if not path.is_file():
                return False
            uri = _sqlite_readonly_uri(self._control_database_path)
            with sqlite3.connect(uri, uri=True, timeout=self._busy_timeout_ms / 1000) as control:
                control.row_factory = sqlite3.Row
                control.execute("PRAGMA query_only = ON")
                tables = {
                    row["name"]
                    for row in control.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }
                if "review_projection" not in tables or "review_events" not in tables:
                    return False
                target = _qualify(scope, "review_target", record.review_target_id)
                projection = control.execute(
                    "SELECT * FROM review_projection WHERE target_id = ?", (target,)
                ).fetchone()
                if projection is None:
                    event = control.execute(
                        "SELECT 1 FROM review_events WHERE target_id = ? LIMIT 1", (target,)
                    ).fetchone()
                    # No event is the one defined initial unreviewed state; an
                    # event without a projection is ambiguous and excluded.
                    return event is None
                return self._valid_unreviewed_projection(control, projection, target)
        except (OSError, RuntimeError, UnicodeError, sqlite3.Error, ValueError, TypeError):
            return False

    @staticmethod
    def _valid_unreviewed_projection(
        control: sqlite3.Connection,
        projection: sqlite3.Row,
        target: str,
    ) -> bool:
        try:
            if projection["target_id"] != target or projection["status"] != "unreviewed":
                return False
            if type(projection["version"]) is not int or projection["version"] <= 0:
                return False
            events = control.execute(
                "SELECT * FROM review_events WHERE target_id = ? ORDER BY sequence", (target,)
            ).fetchall()
            # The lifecycle's initial state has no review event or projection.
            # Any event-backed ``unreviewed`` row is reserved/corrupt history,
            # even when its JSON and digest happen to be internally consistent.
            if events:
                return False
            return False
        except (KeyError, TypeError, ValueError, json.JSONDecodeError, sqlite3.Error):
            return False

    @contextmanager
    def _connection(self) -> Any:
        connection = self._connect()
        try:
            yield connection
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._database_path,
            timeout=self._busy_timeout_ms / 1000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
        return connection

    @contextmanager
    def _transaction(self) -> Any:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except Exception:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()


def _sqlite_readonly_uri(database_path: str | Path) -> str:
    """Return an encoded SQLite ``file:`` URI with read-only query mode.

    ``Path.as_uri`` is portable for native paths, but a path received as a
    string can still use Windows drive or UNC syntax when running on POSIX
    (for example, while a control-store path is configured remotely).  Handle
    those forms explicitly and quote every path character that is not a URI
    path separator or drive-letter colon.  The query is intentionally fixed to
    ``mode=ro`` so discovery cannot create or mutate a review database.
    """

    if not isinstance(database_path, (str, PurePath)):
        raise TypeError("database_path must be a filesystem path")
    raw = str(database_path)
    if _WINDOWS_DRIVE_PATH_PATTERN.match(raw):
        return _sqlite_windows_readonly_uri(raw)
    if raw.startswith((r"\\", "//")):
        return _sqlite_windows_readonly_uri(raw)
    resolved = Path(raw).resolve(strict=False)
    resolved_text = str(resolved)
    resolved_posix = resolved.as_posix()
    if _WINDOWS_DRIVE_PATH_PATTERN.match(resolved_text):
        return _sqlite_windows_readonly_uri(resolved_text)
    if _WINDOWS_DRIVE_PATH_PATTERN.match(resolved_posix):
        return _sqlite_windows_readonly_uri(resolved_posix)
    if resolved_text.startswith((r"\\", "//")):
        return _sqlite_windows_readonly_uri(resolved_text)
    if resolved_posix.startswith((r"\\", "//")):
        return _sqlite_windows_readonly_uri(resolved_posix)
    return f"file://{quote(resolved_posix, safe='/')}?mode=ro"


def _sqlite_windows_readonly_uri(database_path: str) -> str:
    windows_path = PureWindowsPath(database_path).as_posix()
    if _WINDOWS_DRIVE_PATH_PATTERN.match(windows_path):
        return f"file:///{quote(windows_path, safe='/:')}?mode=ro"
    return f"file://{quote(windows_path, safe='/')}?mode=ro"


def build_candidate_publication_body(evidence: Mapping[str, Any] | CandidateDerivationEvidence) -> dict[str, Any]:
    """Return the exact Decision-116 candidate body reconstructed from evidence."""

    return _prepare_publication(evidence).candidate


def canonical_candidate_publication_bytes(
    evidence: Mapping[str, Any] | CandidateDerivationEvidence,
) -> bytes:
    """Return complete sorted-key compact UTF-8 candidate bytes."""

    return _prepare_publication(evidence).candidate_bytes


def canonical_candidate_content_bytes(
    candidate: Mapping[str, Any],
) -> bytes:
    """Serialize the exact content projection (only approval fields removed)."""

    normalized = _validate_candidate_object(candidate)
    return _canonical_json_bytes(
        {key: value for key, value in normalized.items() if key not in {"approval_status", "human_approval_evidence"}}
    )


def candidate_publication_key(job_id: str | UUID) -> str:
    job = _canonical_uuid(job_id, "job_id")
    return f"candidate-publication:1.0:{job}"


def candidate_publication_identity(job_id: str | UUID, source_result_sha256: str, full_sha256: str) -> str:
    job = _canonical_uuid(job_id, "job_id")
    _require_sha256(source_result_sha256, "source_result_sha256")
    _require_sha256(full_sha256, "full_sha256")
    return _publication_identity(job, source_result_sha256, full_sha256)


def _prepare_publication(
    evidence: Mapping[str, Any] | CandidateDerivationEvidence,
) -> _PreparedPublication:
    envelope = _normalize_envelope(evidence)
    job, _result, source_h, artifact, namespace, drawing_ref, occurrences = _admit_evidence(envelope)
    # The qualifying run length is part of the complete durable envelope.  A
    # convenience caller may omit it, in which case it is derived once from
    # the admitted result before canonicalization; no caller summary is used.
    envelope["qualifying_run_length"] = len(occurrences)
    evidence_bytes = _canonical_json_bytes(envelope)
    _require_byte_cap(evidence_bytes, "derivation evidence")
    job_id = str(job.job_id)
    session_id = str(job.session_id)
    candidate = _build_candidate(
        job_id,
        session_id,
        source_h,
        artifact,
        namespace,
        drawing_ref,
        occurrences,
    )
    candidate_bytes = _canonical_json_bytes(candidate)
    _require_byte_cap(candidate_bytes, "candidate bytes")
    content = {
        key: value for key, value in candidate.items() if key not in {"approval_status", "human_approval_evidence"}
    }
    content_bytes = _canonical_json_bytes(content)
    content_sha256 = hashlib.sha256(content_bytes).hexdigest()
    full_sha256 = hashlib.sha256(candidate_bytes).hexdigest()
    publication_key = candidate_publication_key(job_id)
    review_target_id = f"candidate-skill:1.0:{job_id}:sha256:{content_sha256}"
    publication_identity = _publication_identity(job_id, source_h, full_sha256)
    if candidate.get("skill_id") != job_id:
        raise CandidatePublicationValidationError("skill_id does not match job_id")
    return _PreparedPublication(
        envelope=envelope,
        evidence_bytes=evidence_bytes,
        candidate=candidate,
        candidate_bytes=candidate_bytes,
        content_bytes=content_bytes,
        job_id=job_id,
        session_id=session_id,
        source_result_sha256=source_h,
        publication_key=publication_key,
        publication_identity=publication_identity,
        review_target_id=review_target_id,
        content_sha256=content_sha256,
        full_sha256=full_sha256,
    )


def _normalize_envelope(
    evidence: Mapping[str, Any] | CandidateDerivationEvidence,
) -> dict[str, Any]:
    if isinstance(evidence, CandidateDerivationEvidence):
        evidence = evidence.as_mapping()
    elif not isinstance(evidence, Mapping):
        # A pydantic-like evidence object may be passed by a future producer;
        # only its explicit dump is admitted, never arbitrary attributes.
        if hasattr(evidence, "model_dump"):
            evidence = evidence.model_dump(mode="json")
        else:
            raise CandidatePublicationValidationError("derivation evidence must be an object")
    try:
        value = _json_value(evidence)
        if type(value) is not dict:
            raise TypeError
        allowed = {
            "envelope_version",
            "job",
            "result",
            "result_manifest",
            "manifest",
            "timeline_binding",
            "drawing_ref",
            "occurrences",
            "rejected_alternative_count",
            "qualifying_run_length",
        }
        if any(key not in allowed for key in value):
            raise CandidatePublicationValidationError("derivation evidence contains an unknown field")
        if "result_manifest" not in value and "manifest" in value:
            value["result_manifest"] = value.pop("manifest")
        for required in (
            "envelope_version",
            "job",
            "result",
            "result_manifest",
            "timeline_binding",
            "drawing_ref",
            "occurrences",
            "rejected_alternative_count",
        ):
            if required not in value:
                raise CandidatePublicationValidationError(
                    f"derivation evidence missing {required}"
                )
        if value["envelope_version"] != "1.0":
            raise CandidatePublicationValidationError("derivation evidence version must be 1.0")
        _require_int(value["rejected_alternative_count"], "rejected_alternative_count")
        if value["rejected_alternative_count"] != 0:
            raise CandidatePublicationValidationError("rejected alternatives must be exactly zero")
        if "qualifying_run_length" in value:
            _require_int(value["qualifying_run_length"], "qualifying_run_length")
        return value
    except CandidatePublicationError:
        raise
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CandidatePublicationValidationError("derivation evidence is not canonical JSON") from exc


def _admit_evidence(
    envelope: dict[str, Any],
) -> tuple[ProcessingJobV2, ProcessingResultV2, str, dict[str, Any], str, str, list[dict[str, Any]]]:
    try:
        job = envelope["job"]
        if not isinstance(job, ProcessingJobV2):
            job = ProcessingJobV2.model_validate(job)
        if type(job) is not ProcessingJobV2:
            raise TypeError
        job = ProcessingJobV2.model_validate_json(job.model_dump_json())
        result_value = envelope["result"]
        if isinstance(result_value, ProcessingResultV2):
            result = ProcessingResultV2.model_validate_json(result_value.model_dump_json())
        else:
            result = ProcessingResultV2.model_validate(result_value)
        if type(result) is not ProcessingResultV2 or result.session_id != job.session_id:
            raise ValueError("result/session identity mismatch")
        manifest = envelope["result_manifest"]
        if not isinstance(manifest, Mapping):
            raise TypeError
        manifest = _json_value(manifest)
        source_h = _verify_result_manifest(job, manifest)
        binding = _select_timeline_binding(manifest, envelope["timeline_binding"])
        artifact = _admit_timeline_artifact(binding["artifact_ref"])
        namespace = binding["store_namespace"]
        if type(namespace) is not str or not namespace:
            raise ValueError("timeline store namespace is invalid")
        drawing_ref = envelope["drawing_ref"]
        if type(drawing_ref) is not str or not drawing_ref:
            raise ValueError("drawing_ref is invalid")
        derived_occurrences, derived_drawing, run_length = _derive_occurrences(result)
        supplied_run_length = envelope.get("qualifying_run_length")
        if drawing_ref != derived_drawing or (
            supplied_run_length is not None and run_length != supplied_run_length
        ):
            raise NoCandidateError("qualifying run evidence does not match result")
        supplied_occurrences = _normalize_occurrences(envelope["occurrences"])
        if supplied_occurrences != derived_occurrences:
            raise CandidatePublicationValidationError("occurrence evidence does not match result")
        return job, result, source_h, artifact, namespace, drawing_ref, derived_occurrences
    except NoCandidateError:
        raise
    except CandidatePublicationValidationError:
        raise
    except Exception as exc:
        raise CandidatePublicationValidationError("derivation evidence rejected") from exc


def _verify_result_manifest(job: ProcessingJobV2, manifest: Mapping[str, Any]) -> str:
    try:
        allowed = {
            "schema_version",
            "job_id",
            "session_id",
            "payload_digest",
            "payload_digest_scheme",
            "outputs",
            "result_manifest_jcs",
            "source_result_sha256",
            "result_sha256",
        }
        if any(key not in allowed for key in manifest):
            raise ValueError("manifest has unknown fields")
        if manifest.get("schema_version") != "1.0":
            raise ValueError("manifest schema version")
        if _canonical_uuid(manifest.get("job_id"), "manifest.job_id") != str(job.job_id):
            raise ValueError("manifest job identity")
        if _canonical_uuid(manifest.get("session_id"), "manifest.session_id") != str(job.session_id):
            raise ValueError("manifest session identity")
        expected_payload = processing_job_v2_payload_digest(job)
        if manifest.get("payload_digest") != expected_payload:
            raise ValueError("manifest payload digest")
        if manifest.get("payload_digest_scheme") != "workflow-helper.processing-job-v2.payload.sha256-jcs.v1":
            raise ValueError("manifest payload digest scheme")
        outputs = manifest.get("outputs")
        if type(outputs) is not list or not outputs:
            raise ValueError("manifest outputs")
        manifest_object = {
            "schema_version": manifest["schema_version"],
            "job_id": manifest["job_id"],
            "session_id": manifest["session_id"],
            "payload_digest": manifest["payload_digest"],
            "payload_digest_scheme": manifest["payload_digest_scheme"],
            "outputs": outputs,
        }
        manifest_jcs = _restricted_jcs(manifest_object).encode("utf-8")
        supplied_jcs = manifest.get("result_manifest_jcs")
        if supplied_jcs is not None:
            if type(supplied_jcs) is str:
                supplied_jcs_bytes = supplied_jcs.encode("utf-8")
            elif type(supplied_jcs) is bytes:
                supplied_jcs_bytes = supplied_jcs
            else:
                raise TypeError("manifest JCS type")
            if supplied_jcs_bytes != manifest_jcs:
                raise ValueError("manifest JCS bytes")
        source_h = hashlib.sha256(RESULT_DIGEST_DOMAIN_PREFIX + manifest_jcs).hexdigest()
        for field in ("source_result_sha256", "result_sha256"):
            if field in manifest and manifest[field] != source_h:
                raise ValueError("manifest result digest")
        return source_h
    except CandidatePublicationError:
        raise
    except Exception as exc:
        raise CandidatePublicationValidationError("verified result manifest rejected") from exc


def _select_timeline_binding(
    manifest: Mapping[str, Any],
    supplied: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(supplied, Mapping):
        raise CandidatePublicationValidationError("timeline binding is not an object")
    supplied = _json_value(supplied)
    outputs = manifest["outputs"]
    candidates: list[dict[str, Any]] = []
    for output in outputs:
        if not isinstance(output, Mapping):
            raise CandidatePublicationValidationError("manifest output is malformed")
        artifact = output.get("artifact_ref", output.get("artifact"))
        if not isinstance(artifact, Mapping):
            continue
        if artifact.get("role") == "timeline" and artifact.get("mime_type") == "application/json":
            candidates.append(
                {
                    "artifact_ref": _json_value(artifact),
                    "store_namespace": output.get("store_namespace"),
                }
            )
    if len(candidates) != 1:
        raise NoCandidateError("result manifest must have exactly one timeline binding")
    supplied_artifact = supplied.get("artifact_ref", supplied.get("artifact"))
    supplied_namespace = supplied.get("store_namespace")
    if _json_value(supplied_artifact) != candidates[0]["artifact_ref"] or supplied_namespace != candidates[0]["store_namespace"]:
        raise CandidatePublicationValidationError("timeline binding does not match verified manifest")
    return candidates[0]


def _admit_timeline_artifact(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        model = value if isinstance(value, ArtifactRef) else ArtifactRef.model_validate(value)
        if type(model) is not ArtifactRef:
            raise TypeError
        if model.role.value != "timeline" or model.mime_type != "application/json":
            raise ValueError("timeline ArtifactRef role or MIME")
        return model.model_dump(mode="json")
    except Exception as exc:
        raise CandidatePublicationValidationError("timeline ArtifactRef rejected") from exc


def _derive_occurrences(result: ProcessingResultV2) -> tuple[list[dict[str, Any]], str, int]:
    timeline = list(result.timeline)
    segments = list(result.operation_segments)
    admitted_lifecycle = {
        "session_started",
        "drawing_opened",
        "drawing_saved",
        "session_ended",
    }
    by_event: dict[UUID, Any] = {}
    for segment in segments:
        if len(segment.command_names) != 1 or len(segment.source_event_ids) != 1:
            raise CandidatePublicationValidationError("operation segment cardinality is ambiguous")
        event_id = segment.source_event_ids[0]
        if event_id in by_event:
            raise CandidatePublicationValidationError("source event maps to multiple segments")
        by_event[event_id] = segment

    timeline_ids = {item.source_event_id for item in timeline}
    cad_ids = {
        item.source_event_id
        for item in timeline
        if item.event_type.value == "cad_command"
    }
    if set(by_event) - timeline_ids:
        raise CandidatePublicationValidationError("operation segment source evidence is not in the timeline")
    if set(by_event) - cad_ids:
        raise CandidatePublicationValidationError("non-CAD timeline events cannot have operation segments")
    if cad_ids - set(by_event):
        raise CandidatePublicationValidationError("CAD event has no operation segment")

    units: list[tuple[str, Any, Any | None]] = []
    for item in timeline:
        event_type = item.event_type.value
        if event_type == "cad_command":
            units.append(("cad", item, by_event[item.source_event_id]))
        elif event_type in admitted_lifecycle:
            units.append(("lifecycle", item, None))
        else:
            raise NoCandidateError("timeline contains a non-admitted non-CAD event")

    runs: list[list[tuple[Any, Any]]] = []
    current: list[tuple[Any, Any]] = []
    for kind, item, segment in units:
        if kind == "lifecycle":
            if current:
                runs.append(current)
                current = []
            continue
        assert segment is not None
        current.append((item, segment))
    if current:
        runs.append(current)
    if len(runs) != 1 or not 2 <= len(runs[0]) <= 64:
        raise NoCandidateError("result has no unique qualifying CAD run")

    run = runs[0]
    drawing_refs = {segment.drawing_ref for _, segment in run}
    if len(drawing_refs) != 1:
        raise NoCandidateError("qualifying timeline changes drawing_ref")
    drawing_ref = run[0][1].drawing_ref
    commands = [segment.command_names[0] for _, segment in run]
    run_length = len(commands)
    period = next(
        (
            candidate
            for candidate in range(1, run_length)
            if run_length % candidate == 0
            and all(commands[index] == commands[index % candidate] for index in range(run_length))
        ),
        None,
    )
    if period is None:
        raise NoCandidateError("qualifying CAD run is not an exact repeated command sequence")

    occurrences = [
        {
            "event_id": str(item.source_event_id),
            "command_name": segment.command_names[0],
            "segment_sequence": segment.sequence,
        }
        for item, segment in run
    ]
    return occurrences, drawing_ref, run_length


def _normalize_occurrences(value: Any) -> list[dict[str, Any]]:
    if type(value) is not list:
        raise CandidatePublicationValidationError("occurrences must be an array")
    normalized: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise CandidatePublicationValidationError("occurrence must be an object")
        item = _json_value(item)
        if set(item) != {"event_id", "command_name", "segment_sequence"}:
            raise CandidatePublicationValidationError("occurrence fields are not exact")
        event_id = _canonical_uuid(item["event_id"], "occurrence.event_id")
        if type(item["command_name"]) is not str or not item["command_name"]:
            raise CandidatePublicationValidationError("occurrence command is invalid")
        _require_int(item["segment_sequence"], "occurrence.segment_sequence")
        normalized.append(
            {
                "event_id": event_id,
                "command_name": item["command_name"],
                "segment_sequence": item["segment_sequence"],
            }
        )
    return normalized


def _build_candidate(
    job_id: str,
    session_id: str,
    source_h: str,
    artifact: Mapping[str, Any],
    namespace: str,
    drawing_ref: str,
    occurrences: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    quoted_drawing = _quote_json_string(drawing_ref)
    count = len(occurrences)
    actions = [
        {
            "sequence": index,
            "instruction": "AutoCAD command: "
            + _quote_json_string(item["command_name"])
            + "; source_event_id="
            + item["event_id"],
            "parameter_names": [],
        }
        for index, item in enumerate(occurrences, start=1)
    ]
    return {
        "schema_version": "1.0",
        "skill_id": job_id,
        "name": "Observed CAD run " + source_h,
        "description": "Source result " + source_h + "; drawing_ref=" + quoted_drawing + "; command_count=" + str(count),
        "trigger": {
            "condition": "Observed CAD command run on drawing_ref=" + quoted_drawing,
            "signals": ["source_result_sha256=" + source_h],
        },
        "preconditions": ["A verified result-manifest timeline binding exists."],
        "inputs": [
            {
                "name": "timeline_artifact",
                "kind": "artifact",
                "description": "Verified result timeline ArtifactRef.",
                "required": True,
            }
        ],
        "relevant_drawing_state": {
            "description": "drawing_ref=" + quoted_drawing,
            "required_conditions": ["All command occurrences use the same drawing_ref."],
            "excluded_conditions": [],
        },
        "ordered_actions": actions,
        "parameters": [],
        "constraints": ["Preserve source command order, duplicate occurrences, and source-event identity."],
        "expected_result": {
            "description": "The qualifying command run is represented in source order.",
            "observable_outcomes": ["source_result_sha256=" + source_h],
        },
        "validation_checks": [
            {
                "description": "Verify the candidate against the exact source result.",
                "success_criterion": "The verified source-result digest and timeline ArtifactRef match the published supporting evidence.",
            }
        ],
        "known_exceptions": [],
        "supporting_examples": [
            {
                "session_id": session_id,
                "summary": "source_result_sha256=" + source_h + ";timeline_store_namespace=" + _quote_json_string(namespace),
                "artifact_references": [dict(artifact)],
            }
        ],
        "confidence": 0,
        "provenance": "observed",
        "approval_status": "unreviewed",
        "human_approval_evidence": None,
    }


def _validate_candidate_object(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise CandidatePublicationCorruptionError("candidate body is not an object")
    value = _json_value(value)
    expected = {
        "schema_version", "skill_id", "name", "description", "trigger", "preconditions",
        "inputs", "relevant_drawing_state", "ordered_actions", "parameters", "constraints",
        "expected_result", "validation_checks", "known_exceptions", "supporting_examples",
        "confidence", "provenance", "approval_status", "human_approval_evidence",
    }
    if set(value) != expected:
        raise CandidatePublicationCorruptionError("candidate field set is not exact")
    if value["schema_version"] != "1.0" or type(value["confidence"]) is not int or value["confidence"] != 0:
        raise CandidatePublicationCorruptionError("candidate fixed semantics are invalid")
    if value["approval_status"] != "unreviewed" or value["human_approval_evidence"] is not None:
        raise CandidatePublicationCorruptionError("candidate approval authority is invalid")
    try:
        _canonical_uuid(value["skill_id"], "candidate.skill_id")
        validate_candidate_skill_internal_coherence(value)
        _validate_candidate_shape(value)
    except CandidatePublicationError:
        raise
    except Exception as exc:
        raise CandidatePublicationCorruptionError("candidate contract/coherence check failed") from exc
    return value


def _validate_candidate_shape(value: Mapping[str, Any]) -> None:
    text_limits = {
        "name": (1, 160),
        "description": (1, 2000),
    }
    for field, (minimum, maximum) in text_limits.items():
        item = value[field]
        if type(item) is not str or not minimum <= len(item) <= maximum:
            raise ValueError(field)
    _exact_object(value["trigger"], {"condition", "signals"})
    _text(value["trigger"]["condition"], 1, 2000)
    _text_array(value["trigger"]["signals"], 1, 32, unique=True)
    _text_array(value["preconditions"], 1, 64, unique=True)
    if type(value["inputs"]) is not list or not 1 <= len(value["inputs"]) <= 64:
        raise ValueError("inputs")
    for item in value["inputs"]:
        _exact_object(item, {"name", "kind", "description", "required"})
        _text(item["name"], 1, 128)
        if item["kind"] not in {"drawing_state", "artifact", "measurement", "parameter", "instruction"}:
            raise ValueError("input kind")
        _text(item["description"], 1, 2000)
        if type(item["required"]) is not bool:
            raise ValueError("required")
    state = value["relevant_drawing_state"]
    _exact_object(state, {"description", "required_conditions", "excluded_conditions"})
    _text(state["description"], 1, 2000)
    _text_array(state["required_conditions"], 0, 64, unique=True)
    _text_array(state["excluded_conditions"], 0, 64, unique=True)
    actions = value["ordered_actions"]
    if type(actions) is not list or not 1 <= len(actions) <= 256:
        raise ValueError("actions")
    for index, item in enumerate(actions, start=1):
        _exact_object(item, {"sequence", "instruction", "parameter_names"})
        if type(item["sequence"]) is not int or item["sequence"] != index:
            raise ValueError("sequence")
        _text(item["instruction"], 1, 2000)
        _text_array(item["parameter_names"], 0, 32, unique=True, max_length=128)
    if type(value["parameters"]) is not list or len(value["parameters"]) > 128:
        raise ValueError("parameters")
    for item in value["parameters"]:
        _exact_object(item, {"name", "value", "unit", "provenance"})
        _text(item["name"], 1, 128)
        if type(item["unit"]) is not str and item["unit"] is not None:
            raise ValueError("unit")
        if item["unit"] is not None and len(item["unit"]) > 64:
            raise ValueError("unit")
        if item["provenance"] not in {"observed", "deterministic", "ai_inferred", "human_supplied"}:
            raise ValueError("parameter provenance")
    _text_array(value["constraints"], 1, 128, unique=True)
    expected = value["expected_result"]
    _exact_object(expected, {"description", "observable_outcomes"})
    _text(expected["description"], 1, 2000)
    _text_array(expected["observable_outcomes"], 1, 64, unique=True)
    checks = value["validation_checks"]
    if type(checks) is not list or not 1 <= len(checks) <= 128:
        raise ValueError("checks")
    for item in checks:
        _exact_object(item, {"description", "success_criterion"})
        _text(item["description"], 1, 2000)
        _text(item["success_criterion"], 1, 2000)
    if type(value["known_exceptions"]) is not list or len(value["known_exceptions"]) > 128:
        raise ValueError("exceptions")
    for item in value["known_exceptions"]:
        _exact_object(item, {"condition", "handling"})
        _text(item["condition"], 1, 2000)
        _text(item["handling"], 1, 2000)
    examples = value["supporting_examples"]
    if type(examples) is not list or not 1 <= len(examples) <= 128:
        raise ValueError("examples")
    for item in examples:
        _exact_object(item, {"session_id", "summary", "artifact_references"})
        _canonical_uuid(item["session_id"], "example.session_id")
        _text(item["summary"], 1, 2000)
        if type(item["artifact_references"]) is not list or not 1 <= len(item["artifact_references"]) <= 32:
            raise ValueError("artifact references")
        for artifact in item["artifact_references"]:
            _admit_timeline_artifact(artifact)
    if value["provenance"] not in {"observed", "deterministic", "ai_inferred", "human_supplied"}:
        raise ValueError("provenance")
    if value["approval_status"] not in {"unreviewed", "approved", "rejected", "needs_changes"}:
        raise ValueError("approval status")


def _exact_object(value: Any, fields: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError("object fields")
    return value


def _text(value: Any, minimum: int, maximum: int) -> None:
    if type(value) is not str or not minimum <= len(value) <= maximum:
        raise ValueError("bounded text")


def _text_array(value: Any, minimum: int, maximum: int, *, unique: bool, max_length: int = 2000) -> None:
    if type(value) is not list or not minimum <= len(value) <= maximum:
        raise ValueError("text array")
    if any(type(item) is not str or not 1 <= len(item) <= max_length for item in value):
        raise ValueError("text array item")
    if unique and len(set(value)) != len(value):
        raise ValueError("text array uniqueness")


def _parts_to_evidence(parts: Mapping[str, Any]) -> CandidateDerivationEvidence:
    required = {"job", "result", "result_manifest", "timeline_binding", "drawing_ref", "occurrences"}
    if not required.issubset(parts):
        raise CandidatePublicationValidationError("complete derivation evidence is required")
    return CandidateDerivationEvidence(
        job=parts["job"],
        result=parts["result"],
        result_manifest=parts["result_manifest"],
        timeline_binding=parts["timeline_binding"],
        drawing_ref=parts["drawing_ref"],
        occurrences=parts["occurrences"],
        rejected_alternative_count=parts.get("rejected_alternative_count", 0),
        qualifying_run_length=parts.get("qualifying_run_length"),
    )


def _json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "model_dump"):
        return _json_value(value.model_dump(mode="json"))
    if isinstance(value, UUID):
        return str(value)
    raise TypeError("evidence contains a non-JSON value")


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        text = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"), sort_keys=True)
        encoded = text.encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CandidatePublicationValidationError("value is not canonical UTF-8 JSON") from exc
    if json.loads(encoded.decode("utf-8")) != value:
        raise CandidatePublicationValidationError("value is not stable canonical JSON")
    return encoded


def _restricted_jcs(value: Any) -> str:
    if type(value) is str:
        return _quote_json_string(value)
    if type(value) is int:
        return str(value)
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise CandidatePublicationValidationError("manifest key is not text")
        return "{" + ",".join(
            _quote_json_string(key) + ":" + _restricted_jcs(value[key])
            for key in sorted(value, key=lambda key: key.encode("utf-16-be"))
        ) + "}"
    if type(value) is list:
        return "[" + ",".join(_restricted_jcs(item) for item in value) + "]"
    raise CandidatePublicationValidationError("manifest contains unsupported JSON value")


def _quote_json_string(value: Any) -> str:
    if type(value) is not str:
        raise CandidatePublicationValidationError("string value is required")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise CandidatePublicationValidationError("lone surrogate is not allowed")
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _publication_identity(job_id: str, source_h: str, full_h: str) -> str:
    return f"candidate-publication:1.0:{job_id}:source:{source_h}:sha256:{full_h}"


def _canonical_uuid(value: Any, name: str = "uuid") -> str:
    if isinstance(value, UUID):
        value = str(value)
    if type(value) is not str or not _UUID_PATTERN.fullmatch(value) or value != value.lower():
        raise CandidatePublicationValidationError(f"{name} must be lowercase canonical UUID text")
    try:
        if str(UUID(value)) != value:
            raise ValueError
    except (TypeError, ValueError) as exc:
        raise CandidatePublicationValidationError(f"{name} must be a canonical UUID") from exc
    return value


def _require_sha256(value: Any, name: str) -> None:
    if type(value) is not str or not _SHA256_PATTERN.fullmatch(value):
        raise CandidatePublicationValidationError(f"{name} must be lowercase SHA-256")


def _require_owner(value: Any) -> None:
    if type(value) is not str or not _OWNER_PATTERN.fullmatch(value):
        raise CandidatePublicationValidationError("reservation owner is invalid")


def _require_int(value: Any, name: str) -> None:
    if type(value) is not int:
        raise CandidatePublicationValidationError(f"{name} must be an integer")


def _require_i64(value: Any, name: str) -> None:
    _require_int(value, name)
    if not MIN_SIGNED_64 <= value <= MAX_SIGNED_64:
        raise CandidatePublicationValidationError(f"{name} is outside signed 64-bit range")


def _require_positive_epoch(value: Any, name: str) -> None:
    _require_int(value, name)
    if not 1 <= value <= MAX_EPOCH:
        raise CandidatePublicationValidationError(f"{name} is outside positive signed 63-bit range")


def _require_lease_seconds(value: Any) -> None:
    _require_int(value, "lease_duration_seconds")
    if not 1 <= value <= MAX_LEASE_SECONDS:
        raise CandidatePublicationValidationError("lease duration must be 1..1800 integer seconds")


def _require_limit(value: Any) -> None:
    _require_int(value, "limit")
    if not 1 <= value <= 100:
        raise CandidatePublicationValidationError("limit must be 1..100 integer")


def _require_byte_cap(value: bytes, name: str) -> None:
    if type(value) is not bytes or not 1 <= len(value) <= MAX_CANONICAL_BYTES:
        raise CandidatePublicationValidationError(f"{name} must be 1..262144 exact bytes")


def _require_publication_key(value: Any) -> str:
    if type(value) is not str or not _PUBLICATION_KEY_PATTERN.fullmatch(value):
        raise CandidatePublicationValidationError("publication key is invalid")
    return value


def _checked_scope(value: Any) -> TenantWorkspaceScope:
    try:
        _validate_scope(value)
    except (TypeError, ValueError) as exc:
        raise CandidatePublicationValidationError("scope is not the exact tenant/workspace scope") from exc
    return value


def _resolve_now(clock: Callable[[], int | datetime], value: int | datetime | None) -> int:
    value = clock() if value is None else value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise CandidatePublicationValidationError("timestamp must be timezone-aware")
        value = int(value.astimezone(UTC).timestamp() * 1_000_000)
    _require_i64(value, "timestamp")
    return value


def _lease_expiry(now_us: int, lease_seconds: int) -> int:
    _require_i64(now_us, "timestamp")
    expiry = now_us + lease_seconds * 1_000_000
    if expiry > MAX_SIGNED_64:
        raise CandidatePublicationUnavailableError("reservation expiry exceeds signed 64-bit range")
    return expiry


def _coerce_cursor(value: Any) -> CandidatePublicationCursor | None:
    if value is None:
        return None
    if isinstance(value, CandidatePublicationCursor):
        return value
    if isinstance(value, str):
        return CandidatePublicationCursor.decode(value)
    if isinstance(value, tuple) and len(value) == 2:
        return CandidatePublicationCursor(value[0], value[1])
    if isinstance(value, Mapping):
        return CandidatePublicationCursor(value["finalized_at_us"], value["publication_key"])
    raise CandidatePublicationValidationError("cursor is malformed")


__all__ = [
    "MAX_CANONICAL_BYTES",
    "MAX_LEASE_SECONDS",
    "CandidateDerivationEvidence",
    "CandidatePublicationConflictError",
    "CandidatePublicationCorruptionError",
    "CandidatePublicationCursor",
    "CandidatePublicationError",
    "CandidatePublicationMetadata",
    "CandidatePublicationNotFoundError",
    "CandidatePublicationRecord",
    "CandidatePublicationStaleReservationError",
    "CandidatePublicationUnavailableError",
    "CandidatePublicationValidationError",
    "NoCandidateError",
    "SQLiteCandidatePublicationStore",
    "build_candidate_publication_body",
    "candidate_publication_identity",
    "candidate_publication_key",
    "canonical_candidate_content_bytes",
    "canonical_candidate_publication_bytes",
]
