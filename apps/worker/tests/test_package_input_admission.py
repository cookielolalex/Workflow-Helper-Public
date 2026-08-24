from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from uuid import UUID

import pytest

import workflow_worker.artifact_resolver as artifact_resolver_module
import workflow_worker.artifact_store as artifact_store_module
import workflow_worker.handler as worker_handler
import workflow_worker.main as worker_main
from workflow_worker.artifact_resolver import ArtifactResolver
from workflow_worker.artifact_store import InMemoryArtifactStore
from workflow_worker.models import (
    ArtifactProvider,
    ArtifactRef,
    ArtifactRole,
    ProcessingJob,
    ProcessingJobV2,
)
from workflow_worker.package_input_admission import admit_package_input

JOB_ID = UUID("11111111-1111-4111-8111-111111111111")
SESSION_ID = UUID("22222222-2222-4222-8222-222222222222")
MAX_PACKAGE_BYTES = 536_870_912
REJECTION = "package input admission rejected"


def _job(
    *,
    provider: ArtifactProvider = ArtifactProvider.S3,
    role: ArtifactRole = ArtifactRole.RAW_PACKAGE,
    mime_type: str = "application/zip",
    size_bytes: int = 1,
    file_id: str = "opaque package id / 01",
    revision: str = "opaque revision :: A/01",
) -> ProcessingJobV2:
    return ProcessingJobV2(
        schema_version="2.0",
        job_id=JOB_ID,
        session_id=SESSION_ID,
        input_artifact=ArtifactRef(
            provider=provider,
            file_id=file_id,
            revision=revision,
            sha256="a" * 64,
            size_bytes=size_bytes,
            mime_type=mime_type,
            role=role,
        ),
    )


def _assert_rejected(value: object) -> ValueError:
    with pytest.raises(ValueError, match=f"^{REJECTION}$") as caught:
        admit_package_input(value)  # type: ignore[arg-type]
    assert str(caught.value) == REJECTION
    assert caught.value.__context__ is None
    return caught.value


@pytest.mark.parametrize("provider", list(ArtifactProvider))
@pytest.mark.parametrize("size_bytes", [1, MAX_PACKAGE_BYTES])
def test_admits_both_exact_providers_and_inclusive_size_boundaries(
    provider: ArtifactProvider,
    size_bytes: int,
) -> None:
    source = _job(provider=provider, size_bytes=size_bytes)

    admitted = admit_package_input(source)

    assert type(admitted) is ProcessingJobV2
    assert type(admitted.input_artifact) is ArtifactRef
    assert admitted.model_dump(mode="json") == source.model_dump(mode="json")
    assert admitted.job_id == JOB_ID
    assert admitted.session_id == SESSION_ID
    assert admitted.input_artifact.provider is provider
    assert admitted.input_artifact.size_bytes == size_bytes


def test_snapshot_preserves_all_fields_and_is_isolated_from_caller_mutation() -> None:
    source = _job(
        provider=ArtifactProvider.GOOGLE_DRIVE,
        file_id="opaque file id with spaces / mixed-Case",
        revision="opaque revision value :: 0007",
    )
    expected = source.model_dump(mode="json")

    admitted = admit_package_input(source)

    assert admitted is not source
    assert admitted.input_artifact is not source.input_artifact
    assert admitted.model_dump(mode="json") == expected

    source.job_id = UUID("33333333-3333-4333-8333-333333333333")
    source.session_id = UUID("44444444-4444-4444-8444-444444444444")
    source.input_artifact.file_id = "caller-changed-file"
    source.input_artifact.revision = "caller-changed-revision"
    source.input_artifact.sha256 = "b" * 64
    source.input_artifact.size_bytes = 2
    source.input_artifact.mime_type = "caller/changed"
    source.input_artifact.role = ArtifactRole.MANIFEST
    source.input_artifact.provider = ArtifactProvider.S3

    assert admitted.model_dump(mode="json") == expected
    admitted.input_artifact.file_id = "snapshot-changed-file"
    assert source.input_artifact.file_id == "caller-changed-file"


@pytest.mark.parametrize(
    "role",
    [ArtifactRole.TIMELINE, ArtifactRole.CROP, ArtifactRole.MANIFEST],
)
def test_rejects_every_non_package_role(role: ArtifactRole) -> None:
    _assert_rejected(_job(role=role))


@pytest.mark.parametrize(
    "mime_type",
    [
        "Application/Zip",
        "APPLICATION/ZIP",
        "application/x-zip-compressed",
        "application/octet-stream",
        "application/zip; charset=binary",
        "application/zip;version=1",
        "application/zip ",
        " application/zip",
        "application / zip",
        "application\\zip",
        "application%2Fzip",
        "zip",
    ],
)
def test_rejects_noncanonical_mime_variants_without_normalizing(mime_type: str) -> None:
    _assert_rejected(_job(mime_type=mime_type))


@pytest.mark.parametrize("size_bytes", [0])
def test_rejects_zero_byte_package(size_bytes: int) -> None:
    _assert_rejected(_job(size_bytes=size_bytes))


def test_rejects_v1_object_subclass_and_attribute_impostor_without_inspection() -> None:
    class ProcessingJobV2Subclass(ProcessingJobV2):
        pass

    class PoisonImpostor:
        @property
        def input_artifact(self) -> object:
            raise AssertionError("impostor was inspected")

    v1 = ProcessingJob(
        schema_version="1.0",
        session_id=SESSION_ID,
        object_key=f"sessions/{SESSION_ID}/packages/{'a' * 64}.zip",
    )
    subclass = ProcessingJobV2Subclass.model_validate(_job().model_dump(mode="json"))

    for value in (v1, object(), subclass, PoisonImpostor()):
        _assert_rejected(value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "1.0"),
        ("job_id", "sensitive-job-id"),
        ("session_id", "sensitive-session-id"),
    ],
)
def test_rejects_invalid_mutated_job_fields(field: str, value: object) -> None:
    job = _job()
    setattr(job, field, value)

    _assert_rejected(job)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider", "s3"),
        ("file_id", ""),
        ("revision", ""),
        ("sha256", "sensitive-invalid-hash"),
        ("size_bytes", -1),
        ("size_bytes", MAX_PACKAGE_BYTES + 1),
        ("mime_type", ""),
        ("role", "raw_package"),
    ],
)
def test_rejects_invalid_mutated_artifact_fields(field: str, value: object) -> None:
    job = _job()
    setattr(job.input_artifact, field, value)

    _assert_rejected(job)


def test_rejects_nested_subclass_and_mutated_extra_hybrids() -> None:
    class ArtifactRefSubclass(ArtifactRef):
        pass

    nested_subclass = _job()
    nested_subclass.input_artifact = ArtifactRefSubclass.model_validate(
        nested_subclass.input_artifact.model_dump(mode="json")
    )

    top_level_hybrid = _job()
    top_level_hybrid.__dict__["object_key"] = "sensitive-object-key"

    nested_hybrid = _job()
    nested_hybrid.input_artifact.__dict__["bucket"] = "sensitive-bucket"

    pydantic_extra_hybrid = _job()
    object.__setattr__(
        pydantic_extra_hybrid,
        "__pydantic_extra__",
        {"object_key": "sensitive-extra-object-key"},
    )

    class PoisonExtra:
        def __eq__(self, other: object) -> bool:
            raise AssertionError("extra value was compared")

    poison_extra_hybrid = _job()
    object.__setattr__(poison_extra_hybrid, "__pydantic_extra__", PoisonExtra())

    for value in (
        nested_subclass,
        top_level_hybrid,
        nested_hybrid,
        pydantic_extra_hybrid,
        poison_extra_hybrid,
    ):
        _assert_rejected(value)


def test_every_failure_uses_one_bounded_message_without_input_details() -> None:
    values: list[object] = []

    invalid_identity = _job(
        file_id="customer-sensitive-file-id",
        revision="customer-sensitive-revision",
    )
    invalid_identity.job_id = "customer-sensitive-job-id"  # type: ignore[assignment]
    values.append(invalid_identity)

    invalid_hash = _job()
    invalid_hash.input_artifact.sha256 = "customer-sensitive-hash"
    values.append(invalid_hash)

    invalid_mime = _job(mime_type="customer/sensitive-mime")
    values.append(invalid_mime)

    invalid_role = _job(role=ArtifactRole.CROP)
    values.append(invalid_role)

    rendered = {str(_assert_rejected(value)) for value in values}

    assert rendered == {REJECTION}
    assert len(REJECTION) <= 64
    assert not any(
        detail in REJECTION
        for detail in (
            "customer",
            "job",
            "session",
            "file",
            "revision",
            "hash",
            "mime",
            "provider",
            "collaborator",
        )
    )


def _fail_if_called(*args: object, **kwargs: object) -> object:
    raise AssertionError("prohibited call")


def test_admission_makes_no_collaborator_runtime_or_external_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import builtins
    import os
    import socket
    import urllib.request

    import boto3

    monkeypatch.setattr(artifact_resolver_module.ArtifactResolver, "resolve", _fail_if_called)
    monkeypatch.setattr(artifact_store_module.InMemoryArtifactStore, "get", _fail_if_called)
    monkeypatch.setattr(artifact_store_module.InMemoryArtifactStore, "put", _fail_if_called)
    monkeypatch.setattr(boto3, "client", _fail_if_called)
    monkeypatch.setattr(builtins, "open", _fail_if_called)
    monkeypatch.setattr(os, "getenv", _fail_if_called)
    monkeypatch.setattr(socket, "socket", _fail_if_called)
    monkeypatch.setattr(urllib.request, "urlopen", _fail_if_called)
    monkeypatch.setattr(worker_handler, "process_package", _fail_if_called)
    monkeypatch.setattr(worker_handler, "process_package_v2", _fail_if_called)
    monkeypatch.setattr(worker_main, "_client", _fail_if_called)
    monkeypatch.setattr(worker_main, "_publish_artifact", _fail_if_called)
    monkeypatch.setattr(worker_main, "post_completion", _fail_if_called)
    monkeypatch.setattr(worker_main, "process_message", _fail_if_called)
    monkeypatch.setattr(worker_main, "process_message_v2", _fail_if_called)
    monkeypatch.setattr(worker_main, "run_forever", _fail_if_called)

    admitted = admit_package_input(_job())

    assert admitted.input_artifact.role is ArtifactRole.RAW_PACKAGE


@pytest.mark.parametrize("provider", list(ArtifactProvider))
@pytest.mark.parametrize("role", list(ArtifactRole))
def test_generic_store_and_resolver_keep_all_roles_and_zero_bytes_supported(
    provider: ArtifactProvider,
    role: ArtifactRole,
) -> None:
    store = InMemoryArtifactStore(provider)
    reference = store.put(
        artifact_id=f"synthetic-zero-{provider.value}-{role.value}",
        content=b"",
        mime_type="application/synthetic",
        role=role,
    )
    job = ProcessingJobV2(
        schema_version="2.0",
        job_id=JOB_ID,
        session_id=SESSION_ID,
        input_artifact=reference,
    )

    assert reference.size_bytes == 0
    assert reference.sha256 == sha256(b"").hexdigest()
    assert reference.role is role
    assert store.get(reference) == b""
    assert ArtifactResolver(((provider, store),)).resolve(job) == b""
    _assert_rejected(job)


def test_admission_remains_absent_from_runtime_and_container_entrypoints() -> None:
    root = Path(__file__).resolve().parents[3]
    runtime_paths = (
        root / "apps/worker/src/workflow_worker/__init__.py",
        root / "apps/worker/src/workflow_worker/main.py",
        root / "apps/worker/src/workflow_worker/handler.py",
        root / "apps/worker/src/workflow_worker/pipeline.py",
        root / "apps/worker/Dockerfile",
        root / "docker-compose.yml",
    )

    for path in runtime_paths:
        assert "package_input_admission" not in path.read_text(encoding="utf-8")
