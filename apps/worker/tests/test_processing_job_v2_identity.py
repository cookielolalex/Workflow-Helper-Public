from __future__ import annotations

import ast
import builtins
import hashlib
import json
import math
import os
import socket
import urllib.request
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

import workflow_worker.artifact_resolver as artifact_resolver_module
import workflow_worker.artifact_store as artifact_store_module
import workflow_worker.handler as worker_handler
import workflow_worker.main as worker_main
import workflow_worker.processing_job_v2_identity as identity_module
from workflow_worker.models import (
    ArtifactProvider,
    ArtifactRef,
    ArtifactRole,
    ProcessingJob,
    ProcessingJobV2,
)
from workflow_worker.processing_job_v2_identity import (
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
    job_id: UUID = JOB_ID,
    session_id: UUID = SESSION_ID,
    file_id: str = "opaque package ID / Mixed-Case",
    revision: str = "opaque revision :: 0001",
    sha256_value: str = "a" * 64,
    size_bytes: int = 1,
) -> ProcessingJobV2:
    return ProcessingJobV2(
        schema_version="2.0",
        job_id=job_id,
        session_id=session_id,
        input_artifact=ArtifactRef(
            provider=provider,
            file_id=file_id,
            revision=revision,
            sha256=sha256_value,
            size_bytes=size_bytes,
            mime_type="application/zip",
            role=ArtifactRole.RAW_PACKAGE,
        ),
    )


def _assert_rejected(value: object) -> ValueError:
    with pytest.raises(ValueError, match=f"^{REJECTION}$") as caught:
        processing_job_v2_payload_digest(value)  # type: ignore[arg-type]
    assert str(caught.value) == REJECTION
    assert caught.value.__context__ is None
    return caught.value


def _golden_vectors() -> dict[str, object]:
    root = Path(__file__).resolve().parents[3]
    path = root / "contracts/examples/processing-job-v2-payload-digest-v1.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_golden_vectors_are_internally_complete_and_match_production() -> None:
    fixture = _golden_vectors()

    assert fixture["scheme_id"] == PROCESSING_JOB_V2_PAYLOAD_DIGEST_SCHEME_ID
    assert bytes.fromhex(fixture["domain_prefix_utf8_hex"]) == EXPECTED_PREFIX
    assert fixture["domain_prefix_utf8_with_json_nul_escapes"].encode() == EXPECTED_PREFIX

    vectors = fixture["vectors"]
    assert isinstance(vectors, list)
    assert {vector["admission_input"]["input_artifact"]["provider"] for vector in vectors} == {
        "s3",
        "google_drive",
    }
    for vector in vectors:
        canonical_bytes = vector["canonical_jcs"].encode("utf-8")
        preimage = bytes.fromhex(vector["canonical_preimage_utf8_hex"])
        assert canonical_bytes == bytes.fromhex(vector["canonical_jcs_utf8_hex"])
        assert preimage == EXPECTED_PREFIX + canonical_bytes
        assert hashlib.sha256(preimage).hexdigest() == vector["sha256"]

        job = ProcessingJobV2.model_validate(vector["admission_input"])
        assert canonical_processing_job_v2_payload_preimage(job) == preimage
        assert processing_job_v2_payload_digest(job) == vector["sha256"]


def test_normalized_object_has_exact_fields_and_all_eleven_semantic_values() -> None:
    job = _job(
        provider=ArtifactProvider.GOOGLE_DRIVE,
        file_id="Exact file 雪",
        revision="Exact revision",
        sha256_value="b" * 64,
        size_bytes=123,
    )
    canonical = canonical_processing_job_v2_payload_preimage(job)[len(EXPECTED_PREFIX) :]
    decoded = json.loads(canonical)

    assert list(decoded) == ["input_artifact", "job_id", "schema_version", "session_id"]
    assert list(decoded["input_artifact"]) == [
        "file_id",
        "mime_type",
        "provider",
        "revision",
        "role",
        "sha256",
        "size_bytes",
    ]
    assert decoded == {
        "input_artifact": {
            "file_id": "Exact file 雪",
            "mime_type": "application/zip",
            "provider": "google_drive",
            "revision": "Exact revision",
            "role": "raw_package",
            "sha256": "b" * 64,
            "size_bytes": 123,
        },
        "job_id": str(JOB_ID),
        "schema_version": "2.0",
        "session_id": str(SESSION_ID),
    }


@pytest.mark.parametrize(
    ("target", "field", "value", "remains_admissible"),
    [
        ("job", "schema_version", "2.1", False),
        ("job", "job_id", UUID("33333333-3333-4333-8333-333333333333"), True),
        ("job", "session_id", UUID("44444444-4444-4444-8444-444444444444"), True),
        ("job", "input_artifact", None, False),
        ("artifact", "provider", ArtifactProvider.GOOGLE_DRIVE, True),
        ("artifact", "file_id", "changed file", True),
        ("artifact", "revision", "changed revision", True),
        ("artifact", "sha256", "b" * 64, True),
        ("artifact", "size_bytes", 2, True),
        ("artifact", "mime_type", "Application/Zip", False),
        ("artifact", "role", ArtifactRole.MANIFEST, False),
    ],
)
def test_each_semantic_field_is_digest_sensitive_or_fail_closed(
    target: str,
    field: str,
    value: object,
    remains_admissible: bool,
) -> None:
    baseline = _job()
    baseline_digest = processing_job_v2_payload_digest(baseline)
    changed = baseline.model_copy(deep=True)
    subject = changed if target == "job" else changed.input_artifact
    setattr(subject, field, value)

    if remains_admissible:
        assert processing_job_v2_payload_digest(changed) != baseline_digest
    else:
        _assert_rejected(changed)


def test_json_key_order_and_whitespace_do_not_change_digest() -> None:
    canonical_order = {
        "schema_version": "2.0",
        "job_id": str(JOB_ID),
        "session_id": str(SESSION_ID),
        "input_artifact": {
            "provider": "s3",
            "file_id": "opaque",
            "revision": "revision",
            "sha256": "a" * 64,
            "size_bytes": 1,
            "mime_type": "application/zip",
            "role": "raw_package",
        },
    }
    reverse_order = {
        "input_artifact": {
            "role": "raw_package",
            "mime_type": "application/zip",
            "size_bytes": 1,
            "sha256": "a" * 64,
            "revision": "revision",
            "file_id": "opaque",
            "provider": "s3",
        },
        "session_id": str(SESSION_ID),
        "job_id": str(JOB_ID),
        "schema_version": "2.0",
    }
    compact = ProcessingJobV2.model_validate_json(json.dumps(canonical_order))
    spaced = ProcessingJobV2.model_validate_json(json.dumps(reverse_order, indent=4))

    assert processing_job_v2_payload_digest(compact) == processing_job_v2_payload_digest(
        spaced
    )


def test_uuid_lexical_variants_normalize_to_lowercase_hyphenated_form() -> None:
    lexical = _job().model_dump(mode="json")
    lexical["job_id"] = "11111111111141118111111111111111"
    lexical["session_id"] = "22222222-2222-4222-8222-222222222222".upper()
    variant = ProcessingJobV2.model_validate(lexical)
    canonical = _job()

    assert processing_job_v2_payload_digest(variant) == processing_job_v2_payload_digest(
        canonical
    )
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


def test_integral_float_is_admitted_as_the_same_mathematical_integer() -> None:
    payload = _job().model_dump(mode="json")
    payload["input_artifact"]["size_bytes"] = 1.0
    integral_float = ProcessingJobV2.model_validate_json(json.dumps(payload))

    assert type(integral_float.input_artifact.size_bytes) is int
    assert processing_job_v2_payload_digest(integral_float) == (
        processing_job_v2_payload_digest(_job(size_bytes=1))
    )


@pytest.mark.parametrize("size_bytes", [1, MAX_PACKAGE_BYTES])
@pytest.mark.parametrize("provider", list(ArtifactProvider))
def test_both_providers_and_inclusive_size_boundaries_are_supported(
    size_bytes: int,
    provider: ArtifactProvider,
) -> None:
    digest = processing_job_v2_payload_digest(
        _job(provider=provider, size_bytes=size_bytes)
    )

    assert len(digest) == 64
    assert digest == digest.lower()
    assert all(character in "0123456789abcdef" for character in digest)


def test_ecmascript_string_escaping_and_utf16_member_order() -> None:
    scalar = 'quote:" reverse:\\ solidus:/ short:\b\t\n\f\r hex:\x00\x01\x1f raw: 😀'

    assert identity_module._serialize_restricted_jcs({"value": scalar}) == (
        '{"value":"quote:\\" reverse:\\\\ solidus:/ short:'
        '\\b\\t\\n\\f\\r hex:\\u0000\\u0001\\u001f raw: 😀"}'
    )
    assert identity_module._serialize_restricted_jcs({"\ue000": 1, "😀": 2}) == (
        '{"😀":2,"\ue000":1}'
    )


def test_unicode_is_preserved_without_trim_casefold_or_normalization() -> None:
    nfc = _job(file_id="  Mixed-Case/雪  ", revision="révision-é")
    nfd = _job(file_id="  Mixed-Case/雪  ", revision="re\u0301vision-e\u0301")

    nfc_preimage = canonical_processing_job_v2_payload_preimage(nfc)
    nfd_preimage = canonical_processing_job_v2_payload_preimage(nfd)
    assert "  Mixed-Case/雪  ".encode() in nfc_preimage
    assert "révision-é".encode() in nfc_preimage
    assert "re\u0301vision-e\u0301".encode() in nfd_preimage
    assert nfc_preimage != nfd_preimage
    assert processing_job_v2_payload_digest(nfc) != processing_job_v2_payload_digest(nfd)


@pytest.mark.parametrize("field", ["file_id", "revision"])
def test_lone_surrogates_are_rejected(field: str) -> None:
    job = _job()
    setattr(job.input_artifact, field, "sensitive\ud800value")

    _assert_rejected(job)


@pytest.mark.parametrize(
    "value",
    [True, 1.5, MAX_PACKAGE_BYTES + 1, math.nan, math.inf, -math.inf],
)
def test_ambiguous_fractional_nonfinite_and_out_of_range_sizes_reject(
    value: object,
) -> None:
    job = _job()
    job.input_artifact.size_bytes = value  # type: ignore[assignment]

    _assert_rejected(job)


@pytest.mark.parametrize("value", [None, True, 1.5, math.nan, math.inf, [], ()])
def test_restricted_jcs_rejects_unsupported_scalar_and_container_types(
    value: object,
) -> None:
    with pytest.raises(ValueError, match=f"^{REJECTION}$") as caught:
        identity_module._serialize_restricted_jcs(value)
    assert caught.value.__context__ is None


def test_extra_missing_and_invalid_job_objects_reject_before_hashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_hash(*args: object, **kwargs: object) -> object:
        raise AssertionError("hashing began before admission")

    monkeypatch.setattr(identity_module, "sha256", fail_hash)

    extra = _job()
    extra.__dict__["sensitive_extra"] = "must not leak"
    nested_extra = _job()
    nested_extra.input_artifact.__dict__["sensitive_extra"] = "must not leak"
    missing = _job()
    del missing.__dict__["session_id"]
    nested_missing = _job()
    del nested_missing.input_artifact.__dict__["revision"]
    invalid = _job()
    invalid.job_id = "sensitive invalid identity"  # type: ignore[assignment]
    v1 = ProcessingJob(
        schema_version="1.0",
        session_id=SESSION_ID,
        object_key=f"sessions/{SESSION_ID}/packages/{'a' * 64}.zip",
    )

    for value in (
        extra,
        nested_extra,
        missing,
        nested_missing,
        invalid,
        v1,
        object(),
        {"schema_version": "2.0"},
    ):
        _assert_rejected(value)


def test_domain_prefix_is_exact_and_separates_payload_from_result_identity() -> None:
    assert PROCESSING_JOB_V2_PAYLOAD_DIGEST_SCHEME_ID == (
        "workflow-helper.processing-job-v2.payload.sha256-jcs.v1"
    )
    assert PROCESSING_JOB_V2_PAYLOAD_DIGEST_DOMAIN_PREFIX == EXPECTED_PREFIX
    preimage = canonical_processing_job_v2_payload_preimage(_job())
    canonical = preimage[len(EXPECTED_PREFIX) :]
    result_prefix = (
        b"workflow-helper\0processing-job-v2\0result-digest\0sha256-jcs-v1\0"
    )

    assert preimage.startswith(EXPECTED_PREFIX)
    assert not preimage.startswith(result_prefix)
    assert hashlib.sha256(preimage).digest() != hashlib.sha256(
        result_prefix + canonical
    ).digest()


def test_all_failures_are_fixed_sanitized_and_hide_input_hash_and_cause_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_values = (
        "customer-file-secret",
        "customer-revision-secret",
        "customer-hash-secret",
        "internal-hash-error-secret",
    )
    invalid_file = _job(file_id=secret_values[0], revision=secret_values[1])
    invalid_file.input_artifact.sha256 = secret_values[2]
    error = _assert_rejected(invalid_file)

    def broken_hash(value: bytes) -> object:
        raise RuntimeError(secret_values[3])

    monkeypatch.setattr(identity_module, "sha256", broken_hash)
    hashing_error = _assert_rejected(_job())

    for caught in (error, hashing_error):
        assert str(caught) == REJECTION
        assert caught.__context__ is None
        assert caught.__cause__ is None
        assert not any(secret in str(caught) for secret in secret_values)


def _fail_if_called(*args: object, **kwargs: object) -> object:
    raise AssertionError("prohibited call")


def test_digest_makes_no_collaborator_runtime_or_production_io_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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

    assert processing_job_v2_payload_digest(_job()) == (
        hashlib.sha256(canonical_processing_job_v2_payload_preimage(_job())).hexdigest()
    )


def test_production_module_has_only_pure_allowlisted_imports_and_no_runtime_wiring() -> None:
    source_path = Path(identity_module.__file__)
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        node.module if isinstance(node, ast.ImportFrom) else alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import | ast.ImportFrom)
        for alias in node.names
    }

    assert imports == {
        "__future__",
        "hashlib",
        "workflow_worker.models",
        "workflow_worker.package_input_admission",
    }
    prohibited = (
        "result_digest",
        "completion_for_v2",
        "idempotency_key",
        "artifact_resolver",
        "artifact_store",
        "workflow_worker.main",
        "workflow_worker.handler",
        "boto3",
        "open(",
        "getenv",
        "socket",
        "urlopen",
        "requests",
    )
    assert not any(token in source for token in prohibited)


def test_digest_module_remains_absent_from_runtime_and_container_entrypoints() -> None:
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
        assert "processing_job_v2_identity" not in path.read_text(encoding="utf-8")
