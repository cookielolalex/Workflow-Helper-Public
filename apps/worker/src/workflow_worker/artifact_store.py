"""Provider-neutral, synthetic-only artifact storage for contract tests."""

from __future__ import annotations

from hashlib import sha256
from typing import Protocol
from uuid import UUID

from workflow_worker.models import ArtifactProvider, ArtifactRef, ArtifactRole

MAX_ARTIFACT_BYTES = 512 * 1024 * 1024

_INVALID_METADATA = "invalid artifact metadata"
_INVALID_REFERENCE = "invalid artifact reference"
_PROVIDER_MISMATCH = "artifact provider mismatch"
_REFERENCE_MISMATCH = "artifact reference mismatch"
_CONTENT_MISMATCH = "artifact content mismatch"


def _copy_reference(reference: ArtifactRef, *, error: str) -> ArtifactRef:
    """Revalidate into an independent canonical model without leaking input details."""

    if type(reference) is not ArtifactRef:
        raise ValueError(error)
    copied: ArtifactRef | None = None
    try:
        serialized = ArtifactRef.model_dump_json(reference)
        copied = ArtifactRef.model_validate_json(serialized)
    except Exception:  # noqa: BLE001,S110 - intentionally replace details below
        pass
    if copied is None:
        raise ValueError(error)
    return copied


class ArtifactStore(Protocol):
    provider: ArtifactProvider

    def put(
        self,
        *,
        artifact_id: str,
        content: bytes,
        mime_type: str,
        role: ArtifactRole,
    ) -> ArtifactRef: ...

    def get(self, reference: ArtifactRef) -> bytes: ...


class InMemoryArtifactStore:
    """Deterministic fake for contract tests; not a production provider adapter."""

    def __init__(self, provider: ArtifactProvider) -> None:
        if type(provider) is not ArtifactProvider:
            raise ValueError(_INVALID_METADATA)
        self.provider = provider
        self._objects: dict[str, tuple[ArtifactRef, bytes]] = {}

    def put(
        self,
        *,
        artifact_id: str,
        content: bytes,
        mime_type: str,
        role: ArtifactRole,
    ) -> ArtifactRef:
        if type(content) is not bytes:
            raise ValueError(_INVALID_METADATA)
        if len(content) > MAX_ARTIFACT_BYTES:
            raise ValueError("artifact exceeds the 512 MiB package cap")
        if artifact_id in self._objects:
            raise ValueError("artifact_id already exists; overwrites are prohibited")

        revision = str(UUID(int=len(self._objects) + 1))
        reference: ArtifactRef | None = None
        try:
            reference = ArtifactRef(
                provider=self.provider,
                file_id=artifact_id,
                revision=revision,
                sha256=sha256(content).hexdigest(),
                size_bytes=len(content),
                mime_type=mime_type,
                role=role,
            )
        except Exception:  # noqa: BLE001,S110 - intentionally replace details below
            pass
        if reference is None:
            raise ValueError(_INVALID_METADATA)

        stored_reference = _copy_reference(reference, error=_INVALID_METADATA)
        returned_reference = _copy_reference(reference, error=_INVALID_METADATA)
        self._objects[artifact_id] = (stored_reference, bytes(content))
        return returned_reference

    def get(self, reference: ArtifactRef) -> bytes:
        requested = _copy_reference(reference, error=_INVALID_REFERENCE)
        if type(self.provider) is not ArtifactProvider or requested.provider != self.provider:
            raise ValueError(_PROVIDER_MISMATCH)

        entry = self._objects.get(requested.file_id)
        if type(entry) is not tuple or len(entry) != 2:
            raise ValueError(_REFERENCE_MISMATCH)
        stored_reference, content = entry

        stored = _copy_reference(stored_reference, error=_REFERENCE_MISMATCH)
        if stored.provider != self.provider or stored != requested:
            raise ValueError(_REFERENCE_MISMATCH)
        if type(content) is not bytes:
            raise ValueError(_CONTENT_MISMATCH)
        if len(content) != stored.size_bytes:
            raise ValueError(_CONTENT_MISMATCH)
        if sha256(content).hexdigest() != stored.sha256:
            raise ValueError(_CONTENT_MISMATCH)
        return bytes(content)
