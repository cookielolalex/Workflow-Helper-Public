"""Hermetic provider-neutral artifact metadata oracle for synthetic integration.

This module deliberately has no provider SDK imports and accepts no payload bytes.
It records only bounded object-key, digest, size, and queue-evidence metadata.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import quote
from uuid import UUID

from .control_scope import TenantWorkspaceScope, _validate_scope
from .models import SessionRecord

_DIGEST_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_CAPTURE_OWNER_SUBJECT_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,127}$")
_MAX_PACKAGE_SIZE_BYTES = 512 * 1024 * 1024
_MAX_TTL_SECONDS = 900


class ArtifactGatewayUnavailableError(RuntimeError):
    """The synthetic oracle could not complete an exact metadata operation."""


@dataclass(frozen=True, slots=True)
class ArtifactAuthority:
    """Exact tenant/workspace and capture-owner authority for one artifact."""

    scope: TenantWorkspaceScope
    capture_owner_subject: str

    def __post_init__(self) -> None:
        _require_artifact_authority(self)


class ArtifactGateway(Protocol):
    """Narrow artifact boundary used by the legacy session routes."""

    @property
    def presigned_url_ttl_seconds(self) -> int: ...

    @property
    def max_package_size_bytes(self) -> int: ...

    def create_package_upload(
        self,
        authority: ArtifactAuthority,
        session_id: UUID,
        package_sha256: str,
        package_size_bytes: int,
    ) -> tuple[str, str, dict[str, str]]: ...

    def verify_package_upload(
        self,
        authority: ArtifactAuthority,
        object_key: str,
        registration: SessionRecord,
    ) -> None: ...

    def enqueue_processing(
        self, authority: ArtifactAuthority, session_id: UUID, object_key: str
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class ArtifactReceipt:
    """Digest-and-size-only synthetic artifact evidence."""

    object_key: str
    package_sha256: str
    package_size_bytes: int


@dataclass(frozen=True, slots=True)
class ArtifactQueueEvidence:
    """Authority-bound evidence that one exact synthetic artifact was queued."""

    authority: ArtifactAuthority
    session_id: UUID
    object_key: str
    package_sha256: str
    package_size_bytes: int


class NoNetworkArtifactGateway:
    """Deterministic in-memory success oracle with no I/O capability."""

    __slots__ = (
        "_max_package_size_bytes",
        "_presigned_url_ttl_seconds",
        "_queued",
        "_receipts",
        "_registrations",
        "_ticket_origin",
    )

    def __init__(
        self,
        *,
        ticket_origin: str,
        presigned_url_ttl_seconds: int,
        max_package_size_bytes: int,
    ) -> None:
        if type(ticket_origin) is not str or ticket_origin != "https://uploads.synthetic.example":
            raise ValueError("an inert reserved synthetic ticket origin is required")
        if (
            type(presigned_url_ttl_seconds) is not int
            or not 1 <= presigned_url_ttl_seconds <= _MAX_TTL_SECONDS
        ):
            raise ValueError("synthetic ticket TTL is outside its bound")
        if (
            type(max_package_size_bytes) is not int
            or not 1 <= max_package_size_bytes <= _MAX_PACKAGE_SIZE_BYTES
        ):
            raise ValueError("synthetic package limit is outside its bound")
        self._ticket_origin = ticket_origin
        self._presigned_url_ttl_seconds = presigned_url_ttl_seconds
        self._max_package_size_bytes = max_package_size_bytes
        self._registrations: dict[tuple[ArtifactAuthority, str], ArtifactReceipt] = {}
        self._receipts: dict[tuple[ArtifactAuthority, str], ArtifactReceipt] = {}
        self._queued: dict[tuple[ArtifactAuthority, str], ArtifactQueueEvidence] = {}

    @property
    def ticket_origin(self) -> str:
        return self._ticket_origin

    @property
    def presigned_url_ttl_seconds(self) -> int:
        return self._presigned_url_ttl_seconds

    @property
    def max_package_size_bytes(self) -> int:
        return self._max_package_size_bytes

    @property
    def queue_evidence(self) -> tuple[ArtifactQueueEvidence, ...]:
        return tuple(self._queued.values())

    def create_package_upload(
        self,
        authority: ArtifactAuthority,
        session_id: UUID,
        package_sha256: str,
        package_size_bytes: int,
    ) -> tuple[str, str, dict[str, str]]:
        exact_authority = _require_artifact_authority(authority)
        session = _require_uuid(session_id)
        digest = _require_digest(package_sha256)
        size = _require_size(package_size_bytes, self._max_package_size_bytes)
        object_key = _object_key(session, digest)
        receipt = ArtifactReceipt(object_key, digest, size)
        authority_key = (exact_authority, object_key)
        existing = self._registrations.get(authority_key)
        if existing is not None and existing != receipt:
            raise ValueError("artifact registration conflicts")
        self._registrations[authority_key] = receipt
        ticket = f"{self._ticket_origin}/{quote(object_key, safe='/')}"
        headers = {
            "Content-Length": str(size),
            "X-Workflow-Content-SHA256": digest,
        }
        return object_key, ticket, headers

    def record_receipt(
        self,
        *,
        authority: ArtifactAuthority,
        object_key: str,
        package_sha256: str,
        package_size_bytes: int,
    ) -> ArtifactReceipt:
        """Test-only receipt seam; it cannot accept or retain payload bytes."""

        exact_authority = _require_artifact_authority(authority)
        key = _require_object_key(object_key)
        digest = _require_digest(package_sha256)
        size = _require_size(package_size_bytes, self._max_package_size_bytes)
        authority_key = (exact_authority, key)
        expected = self._registrations.get(authority_key)
        receipt = ArtifactReceipt(key, digest, size)
        if expected is None or expected != receipt:
            raise ValueError("artifact receipt rejected")
        self._receipts[authority_key] = receipt
        return receipt

    def verify_package_upload(
        self,
        authority: ArtifactAuthority,
        object_key: str,
        registration: SessionRecord,
    ) -> None:
        exact_authority = _require_artifact_authority(authority)
        if type(registration) is not SessionRecord:
            raise TypeError("an exact session registration is required")
        key = _require_object_key(object_key)
        expected = ArtifactReceipt(
            key,
            _require_digest(registration.package_sha256),
            _require_size(registration.package_size_bytes, self._max_package_size_bytes),
        )
        if key != _object_key(registration.session_id, expected.package_sha256):
            raise ValueError("artifact receipt rejected")
        authority_key = (exact_authority, key)
        if (
            self._registrations.get(authority_key) != expected
            or self._receipts.get(authority_key) != expected
        ):
            raise ValueError("artifact receipt rejected")

    def enqueue_processing(
        self,
        authority: ArtifactAuthority,
        session_id: UUID,
        object_key: str,
    ) -> None:
        exact_authority = _require_artifact_authority(authority)
        session = _require_uuid(session_id)
        key = _require_object_key(object_key)
        authority_key = (exact_authority, key)
        receipt = self._receipts.get(authority_key)
        if receipt is None or key != _object_key(session, receipt.package_sha256):
            raise ArtifactGatewayUnavailableError("artifact queue unavailable")
        self._queued.setdefault(
            authority_key,
            ArtifactQueueEvidence(
                exact_authority,
                session,
                key,
                receipt.package_sha256,
                receipt.package_size_bytes,
            ),
        )


def _object_key(session_id: UUID, digest: str) -> str:
    return f"sessions/{session_id}/packages/{digest}.zip"


def _require_artifact_authority(value: ArtifactAuthority) -> ArtifactAuthority:
    if type(value) is not ArtifactAuthority:
        raise TypeError("an exact artifact authority is required")
    _validate_scope(value.scope)
    if (
        type(value.capture_owner_subject) is not str
        or not _CAPTURE_OWNER_SUBJECT_PATTERN.fullmatch(value.capture_owner_subject)
    ):
        raise ValueError("artifact authority rejected")
    return value


def _require_uuid(value: UUID) -> UUID:
    if type(value) is not UUID:
        raise TypeError("an exact session identifier is required")
    return value


def _require_digest(value: str) -> str:
    if type(value) is not str or not _DIGEST_PATTERN.fullmatch(value):
        raise ValueError("artifact metadata rejected")
    return value


def _require_size(value: int, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError("artifact metadata rejected")
    return value


def _require_object_key(value: str) -> str:
    if type(value) is not str or not 1 <= len(value) <= 1024:
        raise ValueError("artifact metadata rejected")
    return value
