"""Dormant synthetic ArtifactRef resolver with no provider or runtime I/O."""

from __future__ import annotations

from collections.abc import Iterable
from hashlib import sha256
from types import MappingProxyType

from workflow_worker.artifact_store import InMemoryArtifactStore
from workflow_worker.models import ArtifactProvider, ArtifactRef, ProcessingJobV2

_INVALID_STORES = "invalid artifact store bindings"
_RESOLUTION_FAILED = "artifact resolution failed"


def _copy_job(job: ProcessingJobV2) -> ProcessingJobV2:
    if type(job) is not ProcessingJobV2:
        raise ValueError(_RESOLUTION_FAILED)
    copied: ProcessingJobV2 | None = None
    try:
        serialized = ProcessingJobV2.model_dump_json(job)
        copied = ProcessingJobV2.model_validate_json(serialized)
    except Exception:  # noqa: BLE001,S110 - intentionally replace details below
        pass
    if copied is None:
        raise ValueError(_RESOLUTION_FAILED)
    return copied


def _copy_reference(reference: ArtifactRef) -> ArtifactRef:
    if type(reference) is not ArtifactRef:
        raise ValueError(_RESOLUTION_FAILED)
    copied: ArtifactRef | None = None
    try:
        serialized = ArtifactRef.model_dump_json(reference)
        copied = ArtifactRef.model_validate_json(serialized)
    except Exception:  # noqa: BLE001,S110 - intentionally replace details below
        pass
    if copied is None:
        raise ValueError(_RESOLUTION_FAILED)
    return copied


class ArtifactResolver:
    """Route an exact v2 job to one explicitly bound in-memory provider store."""

    __slots__ = ("_stores",)

    def __init__(
        self,
        provider_stores: Iterable[tuple[ArtifactProvider, InMemoryArtifactStore]],
    ) -> None:
        bindings: tuple[tuple[ArtifactProvider, InMemoryArtifactStore], ...] | None = None
        try:
            bindings = tuple(provider_stores)
        except Exception:  # noqa: BLE001,S110 - intentionally replace details below
            pass
        if bindings is None:
            raise ValueError(_INVALID_STORES)

        stores: dict[ArtifactProvider, InMemoryArtifactStore] = {}
        for binding in bindings:
            if type(binding) is not tuple or len(binding) != 2:
                raise ValueError(_INVALID_STORES)
            provider, store = binding
            if type(provider) is not ArtifactProvider:
                raise ValueError(_INVALID_STORES)
            if type(store) is not InMemoryArtifactStore:
                raise ValueError(_INVALID_STORES)
            if type(store.provider) is not ArtifactProvider or store.provider != provider:
                raise ValueError(_INVALID_STORES)
            if provider in stores:
                raise ValueError(_INVALID_STORES)
            stores[provider] = store

        self._stores = MappingProxyType(stores)

    def resolve(self, job: ProcessingJobV2) -> bytes:
        snapshot = _copy_job(job)
        expected_reference = _copy_reference(snapshot.input_artifact)
        collaborator_reference = _copy_reference(expected_reference)
        store = self._stores.get(expected_reference.provider)
        if store is None:
            raise ValueError(_RESOLUTION_FAILED)

        try:
            content: object = store.get(collaborator_reference)
        except Exception:  # noqa: BLE001 - collaborator text must never escape
            content = None
        if content is None:
            raise ValueError(_RESOLUTION_FAILED)

        observed_reference = _copy_reference(collaborator_reference)
        if observed_reference != expected_reference:
            raise ValueError(_RESOLUTION_FAILED)
        if type(content) is not bytes:
            raise ValueError(_RESOLUTION_FAILED)
        if len(content) != expected_reference.size_bytes:
            raise ValueError(_RESOLUTION_FAILED)
        if sha256(content).hexdigest() != expected_reference.sha256:
            raise ValueError(_RESOLUTION_FAILED)
        return bytes(content)
