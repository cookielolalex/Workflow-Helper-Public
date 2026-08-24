from __future__ import annotations

import ast
import copy
import hashlib
import json
import logging
import math
import os
import shutil
import socket
import subprocess
import urllib.request
from pathlib import Path
from uuid import UUID

import pytest

import workflow_worker.processing_job_v2_result_identity as identity_module
from workflow_worker.models import ArtifactProvider, ArtifactRef, ArtifactRole, ProcessingJobV2
from workflow_worker.processing_job_v2_result_identity import (
    PROCESSING_JOB_V2_RESULT_DIGEST_SCHEME_ID,
    PROCESSING_JOB_V2_RESULT_PREIMAGE_MAX_BYTES,
    ProcessingJobV2ResultOutputBinding,
    build_processing_job_v2_result_manifest,
    canonical_processing_job_v2_result_preimage,
    processing_job_v2_result_digest,
    verify_processing_job_v2_result_manifest_preimage,
)

JOB_ID = UUID("11111111-1111-4111-8111-111111111111")
SESSION_ID = UUID("22222222-2222-4222-8222-222222222222")
PREFIX = b"workflow-helper\0processing-job-v2\0result-digest\0sha256-jcs-v1\0"
PAYLOAD_SCHEME = "workflow-helper.processing-job-v2.payload.sha256-jcs.v1"
REJECTION = "result digest rejected"
MAX_ARTIFACT_BYTES = 536_870_912


def _job() -> ProcessingJobV2:
    return ProcessingJobV2(
        schema_version="2.0",
        job_id=JOB_ID,
        session_id=SESSION_ID,
        input_artifact=ArtifactRef(
            provider=ArtifactProvider.S3,
            file_id="synthetic-input-object",
            revision="synthetic-input-version-0001",
            sha256="0" * 64,
            size_bytes=4096,
            mime_type="application/zip",
            role=ArtifactRole.RAW_PACKAGE,
        ),
    )


def _artifact(
    *,
    provider: ArtifactProvider = ArtifactProvider.S3,
    file_id: str = "synthetic-result-object",
    revision: str = "synthetic-result-version-0001",
    sha256_value: str = "1" * 64,
    size_bytes: int = 1,
    mime_type: str = "application/json",
    role: ArtifactRole = ArtifactRole.TIMELINE,
) -> ArtifactRef:
    return ArtifactRef(
        provider=provider,
        file_id=file_id,
        revision=revision,
        sha256=sha256_value,
        size_bytes=size_bytes,
        mime_type=mime_type,
        role=role,
    )


def _binding(
    *,
    namespace: str = "aws-s3://aws/000000000000/us-test-1/synthetic-results",
    artifact: ArtifactRef | None = None,
) -> ProcessingJobV2ResultOutputBinding:
    return ProcessingJobV2ResultOutputBinding(namespace, artifact or _artifact())


def _drive_binding() -> ProcessingJobV2ResultOutputBinding:
    return _binding(
        namespace="google-drive://SYNTHETIC_CUSTOMER/SYNTHETIC_SHARED_DRIVE",
        artifact=_artifact(
            provider=ArtifactProvider.GOOGLE_DRIVE,
            file_id="synthetic-drive-object",
            revision="synthetic-drive-revision-0001",
        ),
    )


def _assert_rejected(callable_object: object, *args: object) -> ValueError:
    with pytest.raises(ValueError, match=f"^{REJECTION}$") as caught:
        callable_object(*args)  # type: ignore[operator]
    assert str(caught.value) == REJECTION
    assert caught.value.__context__ is None
    assert caught.value.__cause__ is None
    return caught.value


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def _fixture() -> dict[str, object]:
    return json.loads(
        (_root() / "contracts/examples/processing-job-v2-result-digest-v1.json").read_text(
            encoding="utf-8"
        )
    )


def _bindings_from_vector(vector: dict[str, object]) -> list[ProcessingJobV2ResultOutputBinding]:
    if "outputs" in vector:
        outputs = vector["outputs"]
    else:
        template = vector["outputs_expansion"]
        outputs = [
            {
                "store_namespace": template["store_namespace"],
                "artifact_ref": {
                    "provider": template["provider"],
                    "file_id": template["file_id_format"].format(index=index),
                    "revision": template["revision_format"].format(index=index),
                    "sha256": template["sha256"],
                    "size_bytes": template["size_bytes"],
                    "mime_type": template["mime_type"],
                    "role": template["role"],
                },
            }
            for index in range(template["count"])
        ]
    return [
        ProcessingJobV2ResultOutputBinding(
            output["store_namespace"], ArtifactRef.model_validate(output["artifact_ref"])
        )
        for output in outputs
    ]


def test_constants_and_all_synthetic_vectors_match_exact_production_bytes() -> None:
    fixture = _fixture()
    assert fixture["scheme_id"] == PROCESSING_JOB_V2_RESULT_DIGEST_SCHEME_ID
    assert bytes.fromhex(fixture["domain_prefix_utf8_hex"]) == PREFIX
    assert fixture["domain_prefix_utf8_with_json_nul_escapes"].encode() == PREFIX
    assert fixture["preimage_max_bytes"] == PROCESSING_JOB_V2_RESULT_PREIMAGE_MAX_BYTES
    assert {vector["name"] for vector in fixture["vectors"]} == {
        "standalone_drive",
        "standalone_s3",
        "mixed",
        "single",
        "reordered",
        "max_count",
    }

    for vector in fixture["vectors"]:
        job = ProcessingJobV2.model_validate(vector["admission_input"])
        bindings = _bindings_from_vector(vector)
        preimage = canonical_processing_job_v2_result_preimage(job, bindings)
        canonical = preimage[len(PREFIX) :]
        assert processing_job_v2_result_digest(job, bindings) == vector["sha256"]
        assert hashlib.sha256(preimage).hexdigest() == vector["sha256"]
        if vector["name"] == "max_count":
            assert len(bindings) == 1024
            assert len(canonical) == vector["canonical_jcs_utf8_length"]
            assert len(preimage) == vector["canonical_preimage_utf8_length"]
            assert hashlib.sha256(canonical).hexdigest() == vector["canonical_jcs_sha256"]
        else:
            assert canonical == vector["canonical_jcs"].encode()
            assert canonical == bytes.fromhex(vector["canonical_jcs_utf8_hex"])
            assert preimage == bytes.fromhex(vector["canonical_preimage_utf8_hex"])


def test_independent_builtin_only_node_one_shot_matches_all_vectors() -> None:
    node = shutil.which("node")
    assert node is not None
    fixture = _fixture()
    manifests = []
    expected = []
    for vector in fixture["vectors"]:
        job = ProcessingJobV2.model_validate(vector["admission_input"])
        bindings = _bindings_from_vector(vector)
        manifests.append(build_processing_job_v2_result_manifest(job, bindings))
        expected.append(vector["sha256"])
    script = r"""
const crypto = require('crypto');
const fs = require('fs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
function quote(value) {
  if (typeof value !== 'string') throw new Error('string');
  for (const unit of value) {
    const cp = unit.codePointAt(0);
    if (cp >= 0xd800 && cp <= 0xdfff) throw new Error('surrogate');
  }
  return JSON.stringify(value);
}
function jcs(value) {
  if (typeof value === 'string') return quote(value);
  if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']';
  if (value && Object.getPrototypeOf(value) === Object.prototype) {
    return '{' + Object.keys(value).sort().map(k => quote(k) + ':' + jcs(value[k])).join(',') + '}';
  }
  throw new Error('unsupported');
}
const prefix = Buffer.from(input.prefix_hex, 'hex');
const digests = input.manifests.map(manifest => {
  const canonical = Buffer.from(jcs(manifest), 'utf8');
  return crypto.createHash('sha256').update(Buffer.concat([prefix, canonical])).digest('hex');
});
process.stdout.write(JSON.stringify(digests));
"""
    completed = subprocess.run(
        [node, "-e", script],
        input=json.dumps({"prefix_hex": PREFIX.hex(), "manifests": manifests}, ensure_ascii=False),
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
        env={"PATH": os.environ["PATH"]},
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == expected


def test_schema_is_closed_draft_2020_12_and_matches_production_manifest() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (_root() / "contracts/processing-job-v2-result-manifest-v1.schema.json").read_text()
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    manifest = build_processing_job_v2_result_manifest(_job(), [_binding(), _drive_binding()])
    assert list(validator.iter_errors(manifest)) == []
    assert schema["additionalProperties"] is False
    assert schema["$defs"]["artifact_common"]["additionalProperties"] is False
    assert schema["$defs"]["output"]["additionalProperties"] is False

    for mutate in (
        lambda value: value.update(extra="x"),
        lambda value: value["outputs"][0].update(extra="x"),
        lambda value: value["outputs"][0]["artifact_ref"].update(extra="x"),
        lambda value: value["outputs"][0]["artifact_ref"].update(role="raw_package"),
        lambda value: value["outputs"][0]["artifact_ref"].update(mime_type="image/png"),
        lambda value: value["outputs"][0].update(store_namespace="google-drive://SYNTHETIC/DRIVE"),
        lambda value: value["outputs"][0].update(
            store_namespace="aws-s3://aws/000000000000/us-" + "a" * 29 + "-1/abc"
        ),
    ):
        changed = copy.deepcopy(manifest)
        mutate(changed)
        assert list(validator.iter_errors(changed))
        _assert_rejected(verify_processing_job_v2_result_manifest_preimage, _job(), changed)


def test_schema_requires_lowercase_canonical_hyphenated_uuid_text() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (_root() / "contracts/processing-job-v2-result-manifest-v1.schema.json").read_text()
    )
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    manifest = build_processing_job_v2_result_manifest(_job(), [_binding()])
    assert list(validator.iter_errors(manifest)) == []

    for field in ("job_id", "session_id"):
        canonical = copy.deepcopy(manifest)
        canonical[field] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        assert list(validator.iter_errors(canonical)) == []

        uppercase = copy.deepcopy(canonical)
        uppercase[field] = uppercase[field].upper()
        assert list(validator.iter_errors(uppercase))

        noncanonical = copy.deepcopy(canonical)
        noncanonical[field] = noncanonical[field].replace("-", "")
        assert list(validator.iter_errors(noncanonical))


def test_manifest_has_exact_closed_shape_and_caller_cannot_choose_bound_identity() -> None:
    manifest = build_processing_job_v2_result_manifest(_job(), [_binding()])
    assert set(manifest) == {
        "schema_version",
        "job_id",
        "session_id",
        "payload_digest_scheme",
        "payload_digest",
        "outputs",
    }
    assert manifest["schema_version"] == "1.0"
    assert manifest["job_id"] == str(JOB_ID)
    assert manifest["session_id"] == str(SESSION_ID)
    assert manifest["payload_digest_scheme"] == PAYLOAD_SCHEME
    assert set(manifest["outputs"][0]) == {"store_namespace", "artifact_ref"}
    assert set(manifest["outputs"][0]["artifact_ref"]) == {
        "provider",
        "file_id",
        "revision",
        "sha256",
        "size_bytes",
        "mime_type",
        "role",
    }


def test_every_public_api_uses_the_same_fixed_rejection() -> None:
    _assert_rejected(build_processing_job_v2_result_manifest, object(), [_binding()])
    _assert_rejected(canonical_processing_job_v2_result_preimage, object(), [_binding()])
    _assert_rejected(processing_job_v2_result_digest, object(), [_binding()])
    _assert_rejected(
        verify_processing_job_v2_result_manifest_preimage,
        object(),
        build_processing_job_v2_result_manifest(_job(), [_binding()]),
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "1.1"),
        ("job_id", "33333333-3333-4333-8333-333333333333"),
        ("session_id", "44444444-4444-4444-8444-444444444444"),
        ("payload_digest_scheme", PROCESSING_JOB_V2_RESULT_DIGEST_SCHEME_ID),
        ("payload_digest", "f" * 64),
        ("outputs", []),
    ],
)
def test_every_manifest_field_mutation_rejects(field: str, value: object) -> None:
    manifest = build_processing_job_v2_result_manifest(_job(), [_binding()])
    manifest[field] = value
    _assert_rejected(verify_processing_job_v2_result_manifest_preimage, _job(), manifest)


@pytest.mark.parametrize("missing", ["schema_version", "job_id", "outputs"])
def test_missing_manifest_names_reject(missing: str) -> None:
    manifest = build_processing_job_v2_result_manifest(_job(), [_binding()])
    del manifest[missing]
    _assert_rejected(verify_processing_job_v2_result_manifest_preimage, _job(), manifest)


def test_extra_and_duplicate_json_names_reject_before_verification() -> None:
    manifest = build_processing_job_v2_result_manifest(_job(), [_binding()])
    changed = copy.deepcopy(manifest)
    changed["extra"] = "x"
    _assert_rejected(verify_processing_job_v2_result_manifest_preimage, _job(), changed)

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(REJECTION) from None
            result[key] = value
        return result

    duplicate_documents = (
        '{"schema_version":"wrong","schema_version":"1.0"}',
        '{"outputs":[{"store_namespace":"wrong","store_namespace":"also-wrong"}]}',
        '{"artifact_ref":{"revision":"wrong","revision":"also-wrong"}}',
    )
    for duplicate in duplicate_documents:
        with pytest.raises(ValueError, match=f"^{REJECTION}$") as caught:
            json.loads(duplicate, object_pairs_hook=reject_duplicates)
        assert caught.value.__context__ is None


@pytest.mark.parametrize(
    ("level", "field"),
    [
        ("output", "store_namespace"),
        ("output", "artifact_ref"),
        ("artifact", "provider"),
        ("artifact", "file_id"),
        ("artifact", "revision"),
        ("artifact", "sha256"),
        ("artifact", "size_bytes"),
        ("artifact", "mime_type"),
        ("artifact", "role"),
    ],
)
def test_missing_output_and_artifact_names_reject(level: str, field: str) -> None:
    manifest = build_processing_job_v2_result_manifest(_job(), [_binding()])
    target = manifest["outputs"][0]
    if level == "artifact":
        target = target["artifact_ref"]
    del target[field]
    _assert_rejected(verify_processing_job_v2_result_manifest_preimage, _job(), manifest)


def test_both_output_fields_are_identity_sensitive() -> None:
    baseline = processing_job_v2_result_digest(_job(), [_binding()])
    namespace_changed = _binding(namespace="aws-s3://aws/000000000000/us-test-1/synthetic-other")
    artifact_changed = _binding(
        artifact=_artifact(file_id="synthetic-other-object", revision="synthetic-other-version")
    )
    assert processing_job_v2_result_digest(_job(), [namespace_changed]) != baseline
    assert processing_job_v2_result_digest(_job(), [artifact_changed]) != baseline


@pytest.mark.parametrize(
    ("field", "value", "valid"),
    [
        ("schema_version", "2.1", False),
        ("job_id", UUID("33333333-3333-4333-8333-333333333333"), True),
        ("session_id", UUID("44444444-4444-4444-8444-444444444444"), True),
        ("input_artifact", None, False),
    ],
)
def test_every_job_field_is_sensitive_or_rejects(field: str, value: object, valid: bool) -> None:
    baseline = processing_job_v2_result_digest(_job(), [_binding()])
    changed = _job()
    setattr(changed, field, value)
    if valid:
        assert processing_job_v2_result_digest(changed, [_binding()]) != baseline
    else:
        _assert_rejected(processing_job_v2_result_digest, changed, [_binding()])


@pytest.mark.parametrize(
    ("field", "value", "valid"),
    [
        ("provider", ArtifactProvider.GOOGLE_DRIVE, True),
        ("file_id", "changed-input", True),
        ("revision", "changed-version", True),
        ("sha256", "a" * 64, True),
        ("size_bytes", 8192, True),
        ("mime_type", "image/png", False),
        ("role", ArtifactRole.TIMELINE, False),
    ],
)
def test_every_payload_artifact_field_is_sensitive_or_rejects(
    field: str, value: object, valid: bool
) -> None:
    baseline = processing_job_v2_result_digest(_job(), [_binding()])
    changed = _job()
    setattr(changed.input_artifact, field, value)
    if valid:
        assert processing_job_v2_result_digest(changed, [_binding()]) != baseline
    else:
        _assert_rejected(processing_job_v2_result_digest, changed, [_binding()])


@pytest.mark.parametrize(
    ("field", "value", "valid"),
    [
        ("provider", ArtifactProvider.GOOGLE_DRIVE, False),
        ("file_id", "changed-output", True),
        ("revision", "changed-output-version", True),
        ("sha256", "b" * 64, True),
        ("size_bytes", 2, True),
        ("mime_type", "image/png", False),
        ("role", ArtifactRole.CROP, False),
    ],
)
def test_every_output_artifact_field_is_sensitive_or_rejects(
    field: str, value: object, valid: bool
) -> None:
    baseline = processing_job_v2_result_digest(_job(), [_binding()])
    artifact = _artifact()
    setattr(artifact, field, value)
    changed = [_binding(artifact=artifact)]
    if valid:
        assert processing_job_v2_result_digest(_job(), changed) != baseline
    else:
        _assert_rejected(processing_job_v2_result_digest, _job(), changed)


def test_namespace_is_digest_sensitive_and_outputs_are_order_sensitive() -> None:
    first = _binding()
    second = _binding(artifact=_artifact(file_id="synthetic-second", revision="synthetic-v2"))
    changed_namespace = _binding(namespace="aws-s3://aws/000000000000/us-test-1/synthetic-other")
    assert processing_job_v2_result_digest(_job(), [first]) != (
        processing_job_v2_result_digest(_job(), [changed_namespace])
    )
    assert processing_job_v2_result_digest(_job(), [first, second]) != (
        processing_job_v2_result_digest(_job(), [second, first])
    )


@pytest.mark.parametrize(
    ("namespace", "provider"),
    [
        ("google-drive://A/B", ArtifactProvider.GOOGLE_DRIVE),
        ("google-drive://" + "A" * 128 + "/" + "_" * 128, ArtifactProvider.GOOGLE_DRIVE),
        ("aws-s3://aws/000000000000/us-test-1/abc", ArtifactProvider.S3),
        (
            "aws-s3://aws-cn/123456789012/cn-northwest-test-1/a" + "b" * 61 + "c",
            ArtifactProvider.S3,
        ),
        ("aws-s3://aws-us-gov/999999999999/us-gov-test-1/synthetic", ArtifactProvider.S3),
    ],
)
def test_exact_drive_and_s3_namespace_boundaries_accept(
    namespace: str, provider: ArtifactProvider
) -> None:
    artifact = _artifact(provider=provider)
    assert (
        len(
            processing_job_v2_result_digest(
                _job(), [_binding(namespace=namespace, artifact=artifact)]
            )
        )
        == 64
    )


@pytest.mark.parametrize(
    ("namespace", "provider"),
    [
        ("google-drive://A/B", ArtifactProvider.S3),
        ("aws-s3://aws/000000000000/us-test-1/abc", ArtifactProvider.GOOGLE_DRIVE),
        ("google-drive://A", ArtifactProvider.GOOGLE_DRIVE),
        ("google-drive://A/B/C", ArtifactProvider.GOOGLE_DRIVE),
        ("google-drive://Å/B", ArtifactProvider.GOOGLE_DRIVE),
        ("google-drive://" + "A" * 129 + "/B", ArtifactProvider.GOOGLE_DRIVE),
        ("aws-s3://AWS/000000000000/us-test-1/abc", ArtifactProvider.S3),
        ("aws-s3://aws/00000000000/us-test-1/abc", ArtifactProvider.S3),
        ("aws-s3://aws/000000000000/US-test-1/abc", ArtifactProvider.S3),
        ("aws-s3://aws/000000000000/us-test-1/a.bc", ArtifactProvider.S3),
        ("aws-s3://aws/000000000000/us-test-1/ab", ArtifactProvider.S3),
        ("aws-s3://aws/000000000000/us-" + "a" * 29 + "-1/abc", ArtifactProvider.S3),
        ("aws-s3://aws/000000000000/us-test-1/abc/extra", ArtifactProvider.S3),
        ("aws-s3://aws/000000000000/us-test-1/%61bc", ArtifactProvider.S3),
    ],
)
def test_malformed_or_cross_provider_namespaces_reject(
    namespace: str, provider: ArtifactProvider
) -> None:
    _assert_rejected(
        processing_job_v2_result_digest,
        _job(),
        [_binding(namespace=namespace, artifact=_artifact(provider=provider))],
    )


def test_exact_locator_duplicate_rejects_regardless_of_metadata() -> None:
    first = _binding()
    exact_duplicate = _binding()
    metadata_variant = _binding(artifact=_artifact(sha256_value="f" * 64, size_bytes=2))
    _assert_rejected(processing_job_v2_result_digest, _job(), [first, exact_duplicate])
    _assert_rejected(processing_job_v2_result_digest, _job(), [first, metadata_variant])


def test_adjacent_locator_and_metadata_only_change_are_distinct() -> None:
    first = _binding()
    adjacent = _binding(artifact=_artifact(revision="synthetic-result-version-0002"))
    assert processing_job_v2_result_digest(_job(), [first, adjacent])
    metadata_changed = _binding(artifact=_artifact(sha256_value="f" * 64))
    assert processing_job_v2_result_digest(_job(), [first]) != (
        processing_job_v2_result_digest(_job(), [metadata_changed])
    )


@pytest.mark.parametrize(
    ("role", "mime"),
    [
        (ArtifactRole.TIMELINE, "application/json"),
        (ArtifactRole.MANIFEST, "application/json"),
        (ArtifactRole.CROP, "image/png"),
    ],
)
def test_exact_role_mime_pairs_accept(role: ArtifactRole, mime: str) -> None:
    artifact = _artifact(role=role, mime_type=mime)
    assert processing_job_v2_result_digest(_job(), [_binding(artifact=artifact)])


@pytest.mark.parametrize(
    ("role", "mime"),
    [
        (ArtifactRole.RAW_PACKAGE, "application/zip"),
        (ArtifactRole.TIMELINE, "image/png"),
        (ArtifactRole.MANIFEST, "text/json"),
        (ArtifactRole.CROP, "application/json"),
    ],
)
def test_raw_package_and_wrong_role_mime_pairs_reject(role: ArtifactRole, mime: str) -> None:
    _assert_rejected(
        processing_job_v2_result_digest,
        _job(),
        [_binding(artifact=_artifact(role=role, mime_type=mime))],
    )


def test_integral_float_converges_to_int_without_float_in_manifest() -> None:
    payload = _artifact().model_dump(mode="json")
    payload["size_bytes"] = 1.0
    artifact = ArtifactRef.model_validate_json(json.dumps(payload))
    assert type(artifact.size_bytes) is int
    manifest = build_processing_job_v2_result_manifest(_job(), [_binding(artifact=artifact)])
    assert type(manifest["outputs"][0]["artifact_ref"]["size_bytes"]) is int
    assert processing_job_v2_result_digest(_job(), [_binding(artifact=artifact)]) == (
        processing_job_v2_result_digest(_job(), [_binding(artifact=_artifact(size_bytes=1))])
    )


@pytest.mark.parametrize(
    "value", [True, 1.5, 0, -1, MAX_ARTIFACT_BYTES + 1, math.nan, math.inf, -math.inf]
)
def test_bool_fraction_nonfinite_zero_and_out_of_range_size_reject(value: object) -> None:
    artifact = _artifact()
    artifact.size_bytes = value  # type: ignore[assignment]
    _assert_rejected(processing_job_v2_result_digest, _job(), [_binding(artifact=artifact)])


@pytest.mark.parametrize("count", [0, 1025])
def test_output_count_outside_closed_bounds_rejects(count: int) -> None:
    outputs = [
        _binding(artifact=_artifact(file_id=f"synthetic-{index}", revision=f"v-{index}"))
        for index in range(count)
    ]
    _assert_rejected(processing_job_v2_result_digest, _job(), outputs)


def test_output_count_boundaries_accept() -> None:
    assert processing_job_v2_result_digest(_job(), [_binding()])
    outputs = [
        _binding(artifact=_artifact(file_id=f"synthetic-{index}", revision=f"v-{index}"))
        for index in range(1024)
    ]
    assert processing_job_v2_result_digest(_job(), outputs)


def test_ecmascript_escapes_utf16_order_and_array_order() -> None:
    scalar = 'quote:" reverse:\\ solidus:/ short:\b\t\n\f\r hex:\x00\x01\x1f raw: 😀'
    assert identity_module._serialize_restricted_jcs({"value": scalar}) == (
        '{"value":"quote:\\" reverse:\\\\ solidus:/ short:'
        '\\b\\t\\n\\f\\r hex:\\u0000\\u0001\\u001f raw: 😀"}'
    )
    assert identity_module._serialize_restricted_jcs({"\ue000": 1, "😀": 2}) == (
        '{"😀":2,"\ue000":1}'
    )
    assert identity_module._serialize_restricted_jcs([2, 1]) == "[2,1]"


def test_unicode_controls_and_nfc_nfd_are_preserved_exactly() -> None:
    nfc = _binding(artifact=_artifact(file_id="  Mixed-Case/雪  ", revision="révision-é"))
    nfd = _binding(
        artifact=_artifact(file_id="  Mixed-Case/雪  ", revision="re\u0301vision-e\u0301")
    )
    nfc_preimage = canonical_processing_job_v2_result_preimage(_job(), [nfc])
    nfd_preimage = canonical_processing_job_v2_result_preimage(_job(), [nfd])
    assert "  Mixed-Case/雪  ".encode() in nfc_preimage
    assert "révision-é".encode() in nfc_preimage
    assert "re\u0301vision-e\u0301".encode() in nfd_preimage
    assert nfc_preimage != nfd_preimage


@pytest.mark.parametrize("field", ["file_id", "revision", "mime_type"])
def test_lone_surrogate_in_any_artifact_token_rejects(field: str) -> None:
    artifact = _artifact()
    setattr(artifact, field, "synthetic\ud800token")
    _assert_rejected(processing_job_v2_result_digest, _job(), [_binding(artifact=artifact)])


def test_token_scalar_and_utf8_byte_boundaries() -> None:
    assert processing_job_v2_result_digest(
        _job(), [_binding(artifact=_artifact(file_id="😀" * 1024, revision="😀" * 255))]
    )
    assert len(("😀" * 255).encode()) == 1020

    for field, value in (
        ("file_id", "a" * 1025),
        ("revision", "a" * 256),
        ("revision", "😀" * 256),
    ):
        artifact = _artifact()
        setattr(artifact, field, value)
        _assert_rejected(processing_job_v2_result_digest, _job(), [_binding(artifact=artifact)])
    assert len(("😀" * 256).encode()) == 1024


def test_full_preimage_exact_limit_and_one_byte_over(monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _fixture()["preimage_limit_representations"]
    exact = fixture["exact"]
    over = fixture["over"]
    assert bytes.fromhex(exact["prefix_utf8_hex"]) == PREFIX
    assert exact["canonical_octet_repeat_count"] + len(PREFIX) == exact["total_bytes"]
    assert over["canonical_octet_repeat_count"] + len(PREFIX) == over["total_bytes"]

    canonical_length = len(canonical_processing_job_v2_result_preimage(_job(), [_binding()])) - len(
        PREFIX
    )
    monkeypatch.setattr(
        identity_module,
        "PROCESSING_JOB_V2_RESULT_DIGEST_DOMAIN_PREFIX",
        b"x" * (PROCESSING_JOB_V2_RESULT_PREIMAGE_MAX_BYTES - canonical_length),
    )
    assert len(canonical_processing_job_v2_result_preimage(_job(), [_binding()])) == (
        PROCESSING_JOB_V2_RESULT_PREIMAGE_MAX_BYTES
    )
    monkeypatch.setattr(
        identity_module,
        "PROCESSING_JOB_V2_RESULT_DIGEST_DOMAIN_PREFIX",
        b"x" * (PROCESSING_JOB_V2_RESULT_PREIMAGE_MAX_BYTES - canonical_length + 1),
    )
    _assert_rejected(canonical_processing_job_v2_result_preimage, _job(), [_binding()])


def test_builder_and_verifier_take_defensive_snapshots() -> None:
    job = _job()
    artifact = _artifact()
    outputs = [_binding(artifact=artifact)]
    manifest = build_processing_job_v2_result_manifest(job, outputs)
    preimage = verify_processing_job_v2_result_manifest_preimage(job, manifest)
    assert preimage == canonical_processing_job_v2_result_preimage(_job(), [_binding()])
    job.input_artifact.file_id = "mutated-input"
    artifact.file_id = "mutated-output"
    outputs.clear()
    assert manifest["outputs"][0]["artifact_ref"]["file_id"] == "synthetic-result-object"
    manifest["outputs"][0]["artifact_ref"]["file_id"] = "mutated-manifest"
    assert b"mutated-manifest" not in preimage


def test_builder_binds_all_job_identity_to_one_admitted_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = build_processing_job_v2_result_manifest(_job(), [_binding()])
    job = _job()
    original_admit = identity_module.admit_package_input

    def mutate_source_after_admission(source: ProcessingJobV2) -> ProcessingJobV2:
        admitted = original_admit(source)
        source.job_id = UUID("33333333-3333-4333-8333-333333333333")
        source.session_id = UUID("44444444-4444-4444-8444-444444444444")
        source.input_artifact.file_id = "mutated-after-admission"
        source.input_artifact.sha256 = "f" * 64
        return admitted

    monkeypatch.setattr(identity_module, "admit_package_input", mutate_source_after_admission)
    assert build_processing_job_v2_result_manifest(job, [_binding()]) == expected


def test_verifier_binds_all_job_identity_to_one_admitted_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline_job = _job()
    manifest = build_processing_job_v2_result_manifest(baseline_job, [_binding()])
    expected_preimage = verify_processing_job_v2_result_manifest_preimage(baseline_job, manifest)
    job = _job()
    original_admit = identity_module.admit_package_input

    def mutate_source_after_admission(source: ProcessingJobV2) -> ProcessingJobV2:
        admitted = original_admit(source)
        source.job_id = UUID("33333333-3333-4333-8333-333333333333")
        source.session_id = UUID("44444444-4444-4444-8444-444444444444")
        source.input_artifact.file_id = "mutated-after-admission"
        source.input_artifact.sha256 = "f" * 64
        return admitted

    monkeypatch.setattr(identity_module, "admit_package_input", mutate_source_after_admission)
    assert verify_processing_job_v2_result_manifest_preimage(job, manifest) == expected_preimage


def test_impostors_subclasses_and_post_construction_model_mutation_reject() -> None:
    class JobImpostor:
        pass

    class JobSubclass(ProcessingJobV2):
        pass

    impostor = JobImpostor()
    impostor.schema_version = "2.0"
    impostor.job_id = JOB_ID
    impostor.session_id = SESSION_ID
    impostor.input_artifact = _job().input_artifact
    _assert_rejected(processing_job_v2_result_digest, impostor, [_binding()])
    _assert_rejected(
        processing_job_v2_result_digest, JobSubclass(**_job().model_dump()), [_binding()]
    )
    changed = _artifact()
    changed.__dict__["extra"] = "x"
    _assert_rejected(processing_job_v2_result_digest, _job(), [_binding(artifact=changed)])


def test_digest_is_not_any_excluded_identity_or_representation() -> None:
    job = _job()
    outputs = [_binding(), _drive_binding()]
    manifest = build_processing_job_v2_result_manifest(job, outputs)
    canonical = canonical_processing_job_v2_result_preimage(job, outputs)[len(PREFIX) :]
    digest = processing_job_v2_result_digest(job, outputs)
    payload_digest = manifest["payload_digest"]
    completion_idempotency_key = hashlib.sha256(b"synthetic completion key").hexdigest()
    publication_digest = hashlib.sha256(json.dumps(manifest, indent=2).encode()).hexdigest()
    etag = hashlib.md5(b"synthetic body", usedforsecurity=False).hexdigest()
    provider_checksum = hashlib.sha256(b"synthetic provider checksum").hexdigest()
    reordered = processing_job_v2_result_digest(job, list(reversed(outputs)))
    assert digest not in {
        payload_digest,
        completion_idempotency_key,
        publication_digest,
        etag,
        provider_checksum,
        reordered,
        hashlib.sha256(canonical).hexdigest(),
    }


def test_main_is_the_sole_runtime_user_of_result_identity() -> None:
    source_root = _root() / "apps/worker/src/workflow_worker"
    references = []
    for path in source_root.glob("*.py"):
        if path.name == "processing_job_v2_result_identity.py":
            continue
        source = path.read_text(encoding="utf-8")
        if "processing_job_v2_result_identity" in source:
            references.append(path.name)
    assert references == ["main.py"]

    main_source = (source_root / "main.py").read_text(encoding="utf-8")
    assert "from .processing_job_v2_result_identity import (" in main_source

    tree = ast.parse((source_root / "processing_job_v2_result_identity.py").read_text())
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    prohibited = {
        "boto3",
        "botocore",
        "os",
        "pathlib",
        "socket",
        "sqlite3",
        "subprocess",
        "urllib",
    }
    assert imported.isdisjoint(prohibited)


def test_pure_calls_have_no_filesystem_network_environment_callback_or_logging_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def forbidden(*args: object, **kwargs: object) -> None:
        calls.append("effect")
        raise AssertionError("external effect")

    monkeypatch.setattr("builtins.open", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(logging.Logger, "_log", forbidden)
    before = dict(os.environ)
    manifest = build_processing_job_v2_result_manifest(_job(), [_binding()])
    assert processing_job_v2_result_digest(_job(), [_binding()])
    assert verify_processing_job_v2_result_manifest_preimage(_job(), manifest)
    assert calls == []
    assert dict(os.environ) == before


def test_rejections_disclose_no_values_bytes_namespace_digest_or_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sensitive = "SYNTHETIC-SENSITIVE-TOKEN"
    artifact = _artifact(revision=sensitive)
    artifact.sha256 = "INVALID-" + sensitive
    error = _assert_rejected(processing_job_v2_result_digest, _job(), [_binding(artifact=artifact)])
    disclosed = str(error)
    assert sensitive not in disclosed
    assert "aws-s3" not in disclosed
    assert "canonical" not in disclosed
    assert caplog.records == []
