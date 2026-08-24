from hashlib import sha256

import pytest
from pydantic import ValidationError

import workflow_worker.artifact_store as artifact_store_module
from workflow_worker.artifact_store import MAX_ARTIFACT_BYTES, InMemoryArtifactStore
from workflow_worker.models import ArtifactProvider, ArtifactRef, ArtifactRole


def _put(
    store: InMemoryArtifactStore,
    *,
    content: bytes = b"synthetic-only",
) -> ArtifactRef:
    return store.put(
        artifact_id="artifact-1",
        content=content,
        mime_type="application/zip",
        role=ArtifactRole.RAW_PACKAGE,
    )


def _copy(reference: ArtifactRef) -> ArtifactRef:
    return ArtifactRef.model_validate_json(reference.model_dump_json())


@pytest.mark.parametrize(
    "provider",
    [ArtifactProvider.S3, ArtifactProvider.GOOGLE_DRIVE],
)
def test_store_round_trip_uses_canonical_provider_neutral_reference(
    provider: ArtifactProvider,
) -> None:
    store = InMemoryArtifactStore(provider)
    content = b"synthetic-only"

    reference = _put(store, content=content)

    assert type(reference) is ArtifactRef
    assert reference.provider == provider
    assert reference.sha256 == sha256(content).hexdigest()
    assert reference.size_bytes == len(content)
    assert store.get(reference) == content


def test_store_rejects_reference_for_another_provider() -> None:
    drive = InMemoryArtifactStore(ArtifactProvider.GOOGLE_DRIVE)
    reference = _put(drive)

    with pytest.raises(ValueError, match="^artifact provider mismatch$"):
        InMemoryArtifactStore(ArtifactProvider.S3).get(reference)


def test_store_never_overwrites_an_existing_artifact_id() -> None:
    store = InMemoryArtifactStore(ArtifactProvider.GOOGLE_DRIVE)
    _put(store)

    with pytest.raises(ValueError, match="overwrites are prohibited"):
        store.put(
            artifact_id="artifact-1",
            content=b"changed-synthetic-content",
            mime_type="application/zip",
            role=ArtifactRole.RAW_PACKAGE,
        )


def test_store_enforces_512_mib_cap_before_constructing_a_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(artifact_store_module, "MAX_ARTIFACT_BYTES", 1)
    store = InMemoryArtifactStore(ArtifactProvider.S3)

    with pytest.raises(ValueError, match="512 MiB package cap"):
        _put(store, content=b"xx")


def test_canonical_reference_rejects_artifacts_above_package_cap() -> None:
    with pytest.raises(ValidationError):
        ArtifactRef(
            provider=ArtifactProvider.GOOGLE_DRIVE,
            file_id="artifact-1",
            revision="1",
            sha256="a" * 64,
            size_bytes=MAX_ARTIFACT_BYTES + 1,
            mime_type="application/zip",
            role=ArtifactRole.RAW_PACKAGE,
        )


def test_returned_reference_is_independent_from_stored_identity() -> None:
    store = InMemoryArtifactStore(ArtifactProvider.S3)
    returned = _put(store)
    pristine = _copy(returned)
    stored, _ = store._objects[returned.file_id]

    assert stored is not returned
    returned.revision = "caller-mutated-revision"
    returned.mime_type = "caller/mutated"

    assert stored == pristine
    assert store.get(pristine) == b"synthetic-only"


def test_caller_owned_get_reference_cannot_mutate_stored_identity() -> None:
    store = InMemoryArtifactStore(ArtifactProvider.S3)
    returned = _put(store)
    request = _copy(returned)
    pristine = _copy(returned)

    assert store.get(request) == b"synthetic-only"
    request.role = ArtifactRole.MANIFEST

    assert store.get(pristine) == b"synthetic-only"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider", ArtifactProvider.GOOGLE_DRIVE),
        ("revision", "tampered-revision"),
        ("sha256", "b" * 64),
        ("size_bytes", 1),
        ("mime_type", "application/tampered"),
        ("role", ArtifactRole.MANIFEST),
    ],
)
def test_store_rejects_tampered_stored_reference(field: str, value: object) -> None:
    store = InMemoryArtifactStore(ArtifactProvider.S3)
    reference = _put(store)
    stored, content = store._objects[reference.file_id]
    setattr(stored, field, value)
    store._objects[reference.file_id] = (stored, content)

    with pytest.raises(ValueError, match="^artifact reference mismatch$"):
        store.get(reference)


@pytest.mark.parametrize("tampered", [b"short", b"synthetic-onlz"])
def test_store_independently_rejects_tampered_content(tampered: bytes) -> None:
    store = InMemoryArtifactStore(ArtifactProvider.S3)
    reference = _put(store)
    stored, _ = store._objects[reference.file_id]
    store._objects[reference.file_id] = (stored, tampered)

    with pytest.raises(ValueError, match="^artifact content mismatch$"):
        store.get(reference)


def test_store_rejects_invalid_mutated_reference_with_constant_error() -> None:
    store = InMemoryArtifactStore(ArtifactProvider.S3)
    reference = _put(store)
    reference.sha256 = "sensitive-invalid-value"

    with pytest.raises(ValueError, match="^invalid artifact reference$") as caught:
        store.get(reference)

    assert "sensitive" not in str(caught.value)
