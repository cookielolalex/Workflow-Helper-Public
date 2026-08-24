from pathlib import Path
from types import MappingProxyType
from uuid import UUID

import pytest

from workflow_worker.artifact_resolver import ArtifactResolver
from workflow_worker.artifact_store import InMemoryArtifactStore
from workflow_worker.models import (
    ArtifactProvider,
    ArtifactRef,
    ArtifactRole,
    ProcessingJobV2,
)

JOB_ID = UUID("11111111-1111-4111-8111-111111111111")
SESSION_ID = UUID("22222222-2222-4222-8222-222222222222")
CONTENT = b"synthetic-only"


def _store_and_job(
    provider: ArtifactProvider = ArtifactProvider.S3,
    role: ArtifactRole = ArtifactRole.RAW_PACKAGE,
) -> tuple[InMemoryArtifactStore, ProcessingJobV2, ArtifactRef]:
    store = InMemoryArtifactStore(provider)
    reference = store.put(
        artifact_id=f"synthetic-{provider.value}-{role.value}",
        content=CONTENT,
        mime_type="application/zip",
        role=role,
    )
    job = ProcessingJobV2(
        schema_version="2.0",
        job_id=JOB_ID,
        session_id=SESSION_ID,
        input_artifact=reference,
    )
    return store, job, reference


def _resolver(*stores: InMemoryArtifactStore) -> ArtifactResolver:
    return ArtifactResolver(tuple((store.provider, store) for store in stores))


def _fail_if_called(*args: object, **kwargs: object) -> object:
    raise AssertionError("prohibited collaborator call")


def test_constructor_accepts_both_one_and_zero_explicit_provider_bindings() -> None:
    s3 = InMemoryArtifactStore(ArtifactProvider.S3)
    drive = InMemoryArtifactStore(ArtifactProvider.GOOGLE_DRIVE)

    both = _resolver(s3, drive)
    one = _resolver(s3)
    empty = ArtifactResolver(())

    assert isinstance(both._stores, MappingProxyType)
    assert tuple(both._stores) == (ArtifactProvider.S3, ArtifactProvider.GOOGLE_DRIVE)
    assert tuple(one._stores) == (ArtifactProvider.S3,)
    assert tuple(empty._stores) == ()
    with pytest.raises(TypeError):
        both._stores[ArtifactProvider.S3] = drive  # type: ignore[index]


def test_constructor_rejects_store_subclass_before_property_or_method_access() -> None:
    class PoisonSubclass(InMemoryArtifactStore):
        @property
        def provider(self) -> ArtifactProvider:
            return _fail_if_called()  # type: ignore[return-value]

    poison = object.__new__(PoisonSubclass)

    with pytest.raises(ValueError, match="^invalid artifact store bindings$"):
        ArtifactResolver(((ArtifactProvider.S3, poison),))


def test_constructor_rejects_imposter_before_property_or_method_access() -> None:
    class PoisonImposter:
        @property
        def provider(self) -> ArtifactProvider:
            return _fail_if_called()  # type: ignore[return-value]

        def get(self, reference: ArtifactRef) -> bytes:
            return _fail_if_called(reference)  # type: ignore[return-value]

    with pytest.raises(ValueError, match="^invalid artifact store bindings$"):
        ArtifactResolver(((ArtifactProvider.S3, PoisonImposter()),))  # type: ignore[arg-type]


def test_constructor_rejects_duplicate_provider_bindings() -> None:
    first = InMemoryArtifactStore(ArtifactProvider.S3)
    second = InMemoryArtifactStore(ArtifactProvider.S3)
    second.get = _fail_if_called  # type: ignore[method-assign]

    with pytest.raises(ValueError, match="^invalid artifact store bindings$"):
        ArtifactResolver(
            (
                (ArtifactProvider.S3, first),
                (ArtifactProvider.S3, second),
            )
        )


def test_constructor_rejects_declared_and_store_provider_mismatch() -> None:
    store = InMemoryArtifactStore(ArtifactProvider.S3)
    store.get = _fail_if_called  # type: ignore[method-assign]

    with pytest.raises(ValueError, match="^invalid artifact store bindings$"):
        ArtifactResolver(((ArtifactProvider.GOOGLE_DRIVE, store),))


def test_constructor_rejects_mutated_noncanonical_store_provider() -> None:
    store = InMemoryArtifactStore(ArtifactProvider.S3)
    store.provider = "s3"  # type: ignore[assignment]
    store.get = _fail_if_called  # type: ignore[method-assign]

    with pytest.raises(ValueError, match="^invalid artifact store bindings$"):
        ArtifactResolver(((ArtifactProvider.S3, store),))


@pytest.mark.parametrize("provider", list(ArtifactProvider))
@pytest.mark.parametrize("role", list(ArtifactRole))
def test_resolver_routes_exact_provider_and_preserves_all_seven_reference_fields(
    provider: ArtifactProvider,
    role: ArtifactRole,
) -> None:
    store, job, original_reference = _store_and_job(provider, role)
    original_get = store.get
    observed: list[ArtifactRef] = []

    def capture(reference: ArtifactRef) -> bytes:
        observed.append(reference)
        return original_get(reference)

    store.get = capture  # type: ignore[method-assign]

    assert _resolver(store).resolve(job) == CONTENT
    assert len(observed) == 1
    assert observed[0] is not job.input_artifact
    assert observed[0].model_dump(mode="json") == original_reference.model_dump(mode="json")


def test_missing_provider_fails_without_calling_another_store() -> None:
    _, job, _ = _store_and_job(ArtifactProvider.S3)
    drive = InMemoryArtifactStore(ArtifactProvider.GOOGLE_DRIVE)
    drive.get = _fail_if_called  # type: ignore[method-assign]

    with pytest.raises(ValueError, match="^artifact resolution failed$"):
        _resolver(drive).resolve(job)


def test_selected_store_failure_is_sanitized_and_never_falls_back() -> None:
    s3, job, _ = _store_and_job(ArtifactProvider.S3)
    drive = InMemoryArtifactStore(ArtifactProvider.GOOGLE_DRIVE)

    def selected_failure(reference: ArtifactRef) -> bytes:
        raise RuntimeError(
            "credential=top-secret file_id=customer-file revision=customer-revision"
        )

    s3.get = selected_failure  # type: ignore[method-assign]
    drive.get = _fail_if_called  # type: ignore[method-assign]

    with pytest.raises(ValueError, match="^artifact resolution failed$") as caught:
        _resolver(s3, drive).resolve(job)

    rendered = str(caught.value)
    assert "secret" not in rendered
    assert "customer" not in rendered
    assert caught.value.__context__ is None


def test_caller_job_and_reference_mutation_cannot_change_resolution_snapshot() -> None:
    store, job, _ = _store_and_job()
    resolver = _resolver(store)
    original_get = store.get

    def mutate_caller_then_get(reference: ArtifactRef) -> bytes:
        job.job_id = UUID("33333333-3333-4333-8333-333333333333")
        job.input_artifact.file_id = "caller-mutated-sensitive-id"
        job.input_artifact.revision = "caller-mutated-sensitive-revision"
        return original_get(reference)

    store.get = mutate_caller_then_get  # type: ignore[method-assign]

    assert resolver.resolve(job) == CONTENT


def test_resolver_rejects_collaborator_reference_drift() -> None:
    store, job, _ = _store_and_job()
    original_get = store.get

    def drift(reference: ArtifactRef) -> bytes:
        content = original_get(reference)
        reference.mime_type = "application/collaborator-mutated"
        return content

    store.get = drift  # type: ignore[method-assign]

    with pytest.raises(ValueError, match="^artifact resolution failed$"):
        _resolver(store).resolve(job)


@pytest.mark.parametrize("returned", [b"short", b"synthetic-onlz"])
def test_resolver_independently_rejects_length_or_hash_mismatch(returned: bytes) -> None:
    store, job, _ = _store_and_job()
    store.get = lambda reference: returned  # type: ignore[method-assign]

    with pytest.raises(ValueError, match="^artifact resolution failed$"):
        _resolver(store).resolve(job)


def test_resolver_rejects_invalid_mutated_input_with_constant_error() -> None:
    store, job, _ = _store_and_job()
    job.input_artifact.sha256 = "sensitive-invalid-hash"

    with pytest.raises(ValueError, match="^artifact resolution failed$") as caught:
        _resolver(store).resolve(job)

    assert "sensitive" not in str(caught.value)


def test_resolver_accepts_only_exact_processing_job_v2() -> None:
    class ProcessingJobV2Subclass(ProcessingJobV2):
        pass

    store, job, _ = _store_and_job()
    subclass = ProcessingJobV2Subclass.model_validate(job.model_dump(mode="json"))

    with pytest.raises(ValueError, match="^artifact resolution failed$"):
        _resolver(store).resolve(subclass)
    with pytest.raises(ValueError, match="^artifact resolution failed$"):
        _resolver(store).resolve(object())  # type: ignore[arg-type]


def test_resolve_performs_no_external_io_runtime_or_fallback_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import os
    import socket
    import tempfile
    import urllib.request

    import boto3

    import workflow_worker.handler as worker_handler
    import workflow_worker.main as worker_main

    store, job, _ = _store_and_job()
    resolver = _resolver(store)

    monkeypatch.setattr(boto3, "client", _fail_if_called)
    monkeypatch.setattr(os, "getenv", _fail_if_called)
    monkeypatch.setattr(socket, "socket", _fail_if_called)
    monkeypatch.setattr(tempfile, "SpooledTemporaryFile", _fail_if_called)
    monkeypatch.setattr(urllib.request, "urlopen", _fail_if_called)
    monkeypatch.setattr(Path, "open", _fail_if_called)
    monkeypatch.setattr(worker_handler, "process_package", _fail_if_called)
    monkeypatch.setattr(worker_handler, "process_package_v2", _fail_if_called)
    monkeypatch.setattr(worker_main, "_client", _fail_if_called)
    monkeypatch.setattr(worker_main, "_publish_artifact", _fail_if_called)
    monkeypatch.setattr(worker_main, "post_completion", _fail_if_called)
    monkeypatch.setattr(worker_main, "process_message", _fail_if_called)
    monkeypatch.setattr(worker_main, "process_message_v2", _fail_if_called)
    monkeypatch.setattr(worker_main, "run_forever", _fail_if_called)

    assert resolver.resolve(job) == CONTENT


def test_resolver_remains_absent_from_runtime_and_container_entrypoints() -> None:
    root = Path(__file__).resolve().parents[3]
    runtime_paths = (
        root / "apps/worker/src/workflow_worker/main.py",
        root / "apps/worker/src/workflow_worker/handler.py",
        root / "apps/worker/Dockerfile",
        root / "docker-compose.yml",
    )

    for path in runtime_paths:
        assert "artifact_resolver" not in path.read_text(encoding="utf-8")
