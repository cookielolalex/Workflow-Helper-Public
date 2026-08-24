from __future__ import annotations

import ast
import builtins
import hashlib
import json
import logging
import math
import os
import socket
import urllib.request
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

import workflow_api.main as api_main
import workflow_api.processing_job_v2_identity as identity_module
from workflow_api.artifact_gateway import NoNetworkArtifactGateway
from workflow_api.control_store import SQLiteControlStore
from workflow_api.legacy_session_store import SQLiteLegacySessionStore
from workflow_api.models import (
    ArtifactProvider,
    ArtifactRef,
    ArtifactRole,
    ProcessingJobV2,
)
from workflow_api.processing_job_v2_identity import (
    PROCESSING_JOB_V2_PAYLOAD_DIGEST_DOMAIN_PREFIX,
    PROCESSING_JOB_V2_PAYLOAD_DIGEST_SCHEME_ID,
    canonical_processing_job_v2_payload_preimage,
    processing_job_v2_payload_digest,
)

JOB_ID = UUID("11111111-1111-4111-8111-111111111111")
SESSION_ID = UUID("22222222-2222-4222-8222-222222222222")
MAX_PACKAGE_BYTES = 536_870_912
REJECTION = "payload digest rejected"
EXPECTED_PREFIX = b"workflow-helper\0processing-job-v2\0payload-digest\0sha256-jcs-v1\0"


def _job(
    *,
    provider: ArtifactProvider = ArtifactProvider.S3,
    file_id: str = "opaque package ID / Mixed-Case",
    revision: str = "opaque revision :: 0001",
    sha256_value: str = "a" * 64,
    size_bytes: int = 1,
    mime_type: str = "application/zip",
    role: ArtifactRole = ArtifactRole.RAW_PACKAGE,
) -> ProcessingJobV2:
    return ProcessingJobV2(
        schema_version="2.0",
        job_id=JOB_ID,
        session_id=SESSION_ID,
        input_artifact=ArtifactRef(
            provider=provider,
            file_id=file_id,
            revision=revision,
            sha256=sha256_value,
            size_bytes=size_bytes,
            mime_type=mime_type,
            role=role,
        ),
    )


def _assert_rejected(value: object) -> ValueError:
    with pytest.raises(ValueError, match=f"^{REJECTION}$") as caught:
        processing_job_v2_payload_digest(value)  # type: ignore[arg-type]
    assert str(caught.value) == REJECTION
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    return caught.value


def _golden_vectors() -> dict[str, object]:
    root = Path(__file__).resolve().parents[3]
    path = root / "contracts/examples/processing-job-v2-payload-digest-v1.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_api_models_are_frozen_extra_forbidden_and_exactly_bounded() -> None:
    job = _job()
    assert job.model_config["frozen"] is True
    assert job.model_config["extra"] == "forbid"
    assert job.input_artifact.model_config["frozen"] is True
    assert job.input_artifact.model_config["extra"] == "forbid"

    with pytest.raises(ValidationError):
        ProcessingJobV2.model_validate({**job.model_dump(mode="json"), "extra": "x"})
    nested_extra = job.model_dump(mode="json")
    nested_extra["input_artifact"]["extra"] = "x"
    with pytest.raises(ValidationError):
        ProcessingJobV2.model_validate(nested_extra)
    with pytest.raises(ValidationError):
        job.input_artifact.file_id = "mutated"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        job.session_id = UUID("33333333-3333-4333-8333-333333333333")  # type: ignore[misc]


def test_golden_vectors_match_exact_canonical_preimages_and_digests() -> None:
    fixture = _golden_vectors()
    assert fixture["scheme_id"] == PROCESSING_JOB_V2_PAYLOAD_DIGEST_SCHEME_ID
    assert bytes.fromhex(fixture["domain_prefix_utf8_hex"]) == EXPECTED_PREFIX
    assert fixture["domain_prefix_utf8_with_json_nul_escapes"].encode() == EXPECTED_PREFIX

    assert [vector["sha256"] for vector in fixture["vectors"]] == [
        "5a5653b89eb071a70b9b861b65358bd062b83ee978962ea8041b9ca3affad1c7",
        "6370158c3d21bf6a4e5c62f0297fa12e5bdc518fa4d2c324f46527f70d9d39a1",
    ]
    for vector in fixture["vectors"]:
        job = ProcessingJobV2.model_validate(vector["admission_input"])
        canonical = vector["canonical_jcs"].encode("utf-8")
        preimage = bytes.fromhex(vector["canonical_preimage_utf8_hex"])
        assert canonical == bytes.fromhex(vector["canonical_jcs_utf8_hex"])
        assert preimage == EXPECTED_PREFIX + canonical
        assert canonical_processing_job_v2_payload_preimage(job) == preimage
        assert processing_job_v2_payload_digest(job) == vector["sha256"]
        assert hashlib.sha256(preimage).hexdigest() == vector["sha256"]


def test_exact_api_admission_creates_one_independent_frozen_snapshot() -> None:
    source = _job(
        provider=ArtifactProvider.GOOGLE_DRIVE,
        file_id="exact opaque ID / Mixed-Case / 雪",
        revision="re\u0301vision-nfd-e\u0301",
        size_bytes=MAX_PACKAGE_BYTES,
    )
    expected = source.model_dump(mode="json")
    snapshot = identity_module._admit_processing_job_v2(source)

    assert type(snapshot) is ProcessingJobV2
    assert type(snapshot.input_artifact) is ArtifactRef
    assert snapshot is not source
    assert snapshot.input_artifact is not source.input_artifact
    assert snapshot.model_dump(mode="json") == expected

    object.__setattr__(source, "job_id", UUID("33333333-3333-4333-8333-333333333333"))
    object.__setattr__(source.input_artifact, "file_id", "source-mutated")
    assert snapshot.model_dump(mode="json") == expected


def test_uuid_variants_and_integral_float_converge_to_canonical_identity() -> None:
    payload = _job().model_dump(mode="json")
    payload["job_id"] = "11111111111141118111111111111111"
    payload["session_id"] = "22222222-2222-4222-8222-222222222222".upper()
    payload["input_artifact"]["size_bytes"] = 1.0
    variant = ProcessingJobV2.model_validate_json(json.dumps(payload))
    canonical = _job()

    assert type(variant.input_artifact.size_bytes) is int
    assert processing_job_v2_payload_digest(variant) == processing_job_v2_payload_digest(canonical)
    preimage = canonical_processing_job_v2_payload_preimage(variant)
    assert b'"job_id":"11111111-1111-4111-8111-111111111111"' in preimage
    assert b'"session_id":"22222222-2222-4222-8222-222222222222"' in preimage


def _raw_job_json(size_bytes: str) -> str:
    payload = _job().model_dump(mode="json")
    payload["input_artifact"]["size_bytes"] = "__raw_number__"
    return json.dumps(payload, separators=(",", ":")).replace(
        '"__raw_number__"', size_bytes
    )


@pytest.mark.parametrize(
    ("size_bytes", "expected"),
    [
        ("0", 0),
        ("0.0", 0),
        ("1", 1),
        ("1.0", 1),
        ("1e0", 1),
        ("10e-1", 1),
        ("536870912", MAX_PACKAGE_BYTES),
        ("536870912.0", MAX_PACKAGE_BYTES),
    ],
)
@pytest.mark.parametrize("raw_type", [str, bytes, bytearray])
def test_lossless_raw_json_integral_forms_normalize_to_builtin_int(
    size_bytes: str, expected: int, raw_type: type[str | bytes | bytearray]
) -> None:
    raw_text = _raw_job_json(size_bytes)
    raw = raw_text if raw_type is str else raw_type(raw_text.encode("utf-8"))
    job = ProcessingJobV2.model_validate_json(raw)

    assert type(job.input_artifact.size_bytes) is int
    assert job.input_artifact.size_bytes == expected


@pytest.mark.parametrize(
    "size_bytes",
    [
        "0.99999999999999999",
        "1.0000000000000001",
        "536870912.0000000001",
        "1.5",
        "-1",
        "-1.0",
        "536870913",
        "true",
        '"1"',
        "null",
        "NaN",
        "Infinity",
        "-Infinity",
    ],
)
@pytest.mark.parametrize("raw_type", [str, bytes, bytearray])
def test_lossless_raw_json_fractions_nonfinite_and_wrong_types_reject(
    size_bytes: str, raw_type: type[str | bytes | bytearray]
) -> None:
    raw_text = _raw_job_json(size_bytes)
    raw = raw_text if raw_type is str else raw_type(raw_text.encode("utf-8"))

    with pytest.raises(ValueError):
        ProcessingJobV2.model_validate_json(raw)


@pytest.mark.parametrize("size_bytes", [1.0, 1.5, float("nan"), float("inf")])
def test_preparsed_python_floats_reject_without_lexeme_provenance(size_bytes: float) -> None:
    payload = _job().model_dump(mode="python")
    payload["input_artifact"]["size_bytes"] = size_bytes

    with pytest.raises(ValidationError):
        ProcessingJobV2.model_validate(payload)


@pytest.mark.parametrize("size_bytes", ["NaN", "Infinity", "-Infinity"])
@pytest.mark.parametrize("raw_type", [str, bytes, bytearray])
def test_raw_json_nonfinite_numbers_preserve_pydantic_validation_error(
    size_bytes: str, raw_type: type[str | bytes | bytearray]
) -> None:
    raw_text = _raw_job_json(size_bytes)
    raw = raw_text if raw_type is str else raw_type(raw_text.encode("utf-8"))
    with pytest.raises(ValidationError):
        ProcessingJobV2.model_validate_json(raw)


@pytest.mark.parametrize("raw_type", [str, bytes, bytearray])
def test_raw_json_extreme_exponent_maps_decimal_failure_to_validation_error(
    raw_type: type[str | bytes | bytearray],
) -> None:
    raw_text = _raw_job_json("1e9999999999999999999999999999999999999999")
    raw = raw_text if raw_type is str else raw_type(raw_text.encode("utf-8"))
    with pytest.raises(ValidationError):
        ProcessingJobV2.model_validate_json(raw)


def test_lossless_json_method_preserves_supported_validation_kwargs() -> None:
    job = ProcessingJobV2.model_validate_json(
        _raw_job_json("1.0"),
        strict=True,
        extra="forbid",
        context={"synthetic": True},
        by_alias=False,
        by_name=True,
    )

    assert type(job.input_artifact.size_bytes) is int
    assert job.input_artifact.size_bytes == 1


@pytest.mark.parametrize("provider", list(ArtifactProvider))
@pytest.mark.parametrize("size_bytes", [1, MAX_PACKAGE_BYTES])
def test_provider_and_package_size_dispatch_boundaries(
    provider: ArtifactProvider, size_bytes: int
) -> None:
    digest = processing_job_v2_payload_digest(_job(provider=provider, size_bytes=size_bytes))
    assert len(digest) == 64
    assert digest == digest.lower()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "2.1"),
        ("job_id", "not-a-uuid"),
        ("session_id", "not-a-uuid"),
    ],
)
def test_forged_version_and_identity_fields_reject_generically(field: str, value: object) -> None:
    job = _job()
    object.__setattr__(job, field, value)
    _assert_rejected(job)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider", "s3"),
        ("file_id", ""),
        ("file_id", "x" * 1025),
        ("revision", ""),
        ("revision", "x" * 256),
        ("sha256", "A" * 64),
        ("sha256", "a" * 63),
        ("size_bytes", 0),
        ("size_bytes", -1),
        ("size_bytes", MAX_PACKAGE_BYTES + 1),
        ("size_bytes", True),
        ("size_bytes", "1"),
        ("size_bytes", 1.5),
        ("size_bytes", math.nan),
        ("size_bytes", math.inf),
        ("mime_type", "Application/Zip"),
        ("mime_type", "application/zip "),
        ("role", ArtifactRole.TIMELINE),
        ("role", "raw_package"),
    ],
)
def test_forged_artifact_values_reject_generically(field: str, value: object) -> None:
    job = _job()
    object.__setattr__(job.input_artifact, field, value)
    _assert_rejected(job)


@pytest.mark.parametrize("field", ["file_id", "revision", "mime_type"])
def test_lone_surrogates_are_rejected_for_every_free_text_field(field: str) -> None:
    job = _job()
    object.__setattr__(job.input_artifact, field, "sensitive\ud800value")
    _assert_rejected(job)


def test_unicode_whitespace_case_controls_and_normalization_are_preserved() -> None:
    nfc = _job(
        file_id='  Mixed-Case/雪 " \\ / \b\t\n\f\r\x00\x1f   😀  ',
        revision="révision-é",
    )
    nfd = _job(
        file_id='  Mixed-Case/雪 " \\ / \b\t\n\f\r\x00\x1f   😀  ',
        revision="re\u0301vision-e\u0301",
    )
    nfc_preimage = canonical_processing_job_v2_payload_preimage(nfc)
    nfd_preimage = canonical_processing_job_v2_payload_preimage(nfd)

    assert "  Mixed-Case/雪".encode() in nfc_preimage
    assert b"\\b\\t\\n\\f\\r\\u0000\\u001f" in nfc_preimage
    assert "révision-é".encode() in nfc_preimage
    assert "re\u0301vision-e\u0301".encode() in nfd_preimage
    assert nfc_preimage != nfd_preimage


def test_restricted_jcs_has_ecmascript_escaping_and_utf16_key_order() -> None:
    scalar = 'quote:" reverse:\\ solidus:/ short:\b\t\n\f\r hex:\x00\x01\x1f raw: 😀'
    assert identity_module._serialize_restricted_jcs({"value": scalar}) == (
        '{"value":"quote:\\" reverse:\\\\ solidus:/ short:'
        '\\b\\t\\n\\f\\r hex:\\u0000\\u0001\\u001f raw: 😀"}'
    )
    assert identity_module._serialize_restricted_jcs({"\ue000": 1, "😀": 2}) == (
        '{"😀":2,"\ue000":1}'
    )
    for value in (None, True, 1.5, math.nan, math.inf, [], (), {1: "x"}):
        with pytest.raises(ValueError, match=f"^{REJECTION}$"):
            identity_module._serialize_restricted_jcs(value)


def test_wrong_types_subclasses_impostors_missing_and_extra_reject_before_hashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class JobSubclass(ProcessingJobV2):
        pass

    class ArtifactSubclass(ArtifactRef):
        pass

    class PoisonImpostor:
        @property
        def input_artifact(self) -> object:
            raise AssertionError("impostor was inspected")

    def hashing_started(*args: object, **kwargs: object) -> object:
        raise AssertionError("hashing began before exact admission")

    monkeypatch.setattr(identity_module, "sha256", hashing_started)
    subclass = JobSubclass.model_validate(_job().model_dump(mode="json"))
    nested_subclass = _job()
    object.__setattr__(
        nested_subclass,
        "input_artifact",
        ArtifactSubclass.model_validate(nested_subclass.input_artifact.model_dump(mode="json")),
    )
    missing = _job()
    del missing.__dict__["session_id"]
    nested_missing = _job()
    del nested_missing.input_artifact.__dict__["revision"]
    extra = _job()
    extra.__dict__["sensitive_extra"] = "must-not-leak"
    nested_extra = _job()
    nested_extra.input_artifact.__dict__["sensitive_extra"] = "must-not-leak"
    pydantic_extra = _job()
    object.__setattr__(pydantic_extra, "__pydantic_extra__", {"extra": "secret"})

    for value in (
        {},
        object(),
        PoisonImpostor(),
        subclass,
        nested_subclass,
        missing,
        nested_missing,
        extra,
        nested_extra,
        pydantic_extra,
    ):
        _assert_rejected(value)


def test_internal_snapshot_serialization_and_hash_failures_are_one_private_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secrets = ("internal-snapshot-secret", "internal-hash-secret")

    def broken_dump(*args: object, **kwargs: object) -> object:
        raise RuntimeError(secrets[0])

    monkeypatch.setattr(ProcessingJobV2, "model_dump_json", broken_dump)
    first = _assert_rejected(_job())
    monkeypatch.undo()

    def broken_hash(value: bytes) -> object:
        raise RuntimeError(secrets[1])

    monkeypatch.setattr(identity_module, "sha256", broken_hash)
    second = _assert_rejected(_job())
    for caught in (first, second):
        assert not any(secret in repr(caught) for secret in secrets)


def _fail_if_called(*args: object, **kwargs: object) -> object:
    raise AssertionError("prohibited collaborator or I/O call")


def test_identity_makes_zero_resolver_store_control_runtime_or_io_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        SQLiteLegacySessionStore, "resolve_session_capture_authority", _fail_if_called
    )
    monkeypatch.setattr(SQLiteControlStore, "register_job", _fail_if_called)
    monkeypatch.setattr(NoNetworkArtifactGateway, "create_package_upload", _fail_if_called)
    monkeypatch.setattr(NoNetworkArtifactGateway, "verify_package_upload", _fail_if_called)
    monkeypatch.setattr(NoNetworkArtifactGateway, "enqueue_processing", _fail_if_called)
    monkeypatch.setattr(api_main, "create_app", _fail_if_called)
    monkeypatch.setattr(builtins, "open", _fail_if_called)
    monkeypatch.setattr(os, "getenv", _fail_if_called)
    monkeypatch.setattr(socket, "socket", _fail_if_called)
    monkeypatch.setattr(urllib.request, "urlopen", _fail_if_called)
    monkeypatch.setattr(logging.Logger, "_log", _fail_if_called)

    assert (
        processing_job_v2_payload_digest(_job())
        == hashlib.sha256(canonical_processing_job_v2_payload_preimage(_job())).hexdigest()
    )


def test_module_is_pure_dormant_and_separate_from_capture_result_and_control() -> None:
    source_path = Path(identity_module.__file__)
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        node.module if isinstance(node, ast.ImportFrom) else alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import | ast.ImportFrom)
        for alias in node.names
    }
    assert imports == {"__future__", "hashlib", "uuid", "workflow_api.models"}
    assert PROCESSING_JOB_V2_PAYLOAD_DIGEST_SCHEME_ID == (
        "workflow-helper.processing-job-v2.payload.sha256-jcs.v1"
    )
    assert PROCESSING_JOB_V2_PAYLOAD_DIGEST_DOMAIN_PREFIX == EXPECTED_PREFIX
    prohibited = (
        "result_digest",
        "completion_result",
        "idempotency_key",
        "resolve_session_capture_authority",
        "capture_owner",
        "tenant_id",
        "workspace_id",
        "principal",
        "control_store",
        "artifact_gateway",
        "boto3",
        "open(",
        "getenv",
        "socket",
        "urlopen",
        "logging",
    )
    assert not any(token in source for token in prohibited)

    root = source_path.parents[4]
    runtime_paths = (
        root / "apps/api/src/workflow_api/__init__.py",
        root / "apps/api/src/workflow_api/main.py",
        root / "apps/api/src/workflow_api/dependencies.py",
        root / "apps/api/src/workflow_api/runtime_bundle.py",
        root / "apps/api/src/workflow_api/routes/__init__.py",
        root / "apps/api/Dockerfile",
        root / "docker-compose.yml",
    )
    for path in runtime_paths:
        assert "processing_job_v2_identity" not in path.read_text(encoding="utf-8")
