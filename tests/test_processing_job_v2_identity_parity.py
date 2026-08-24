from __future__ import annotations

import ast
import json
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError
from workflow_api.models import ProcessingJobV2 as ApiProcessingJobV2
from workflow_api.processing_job_v2_identity import (
    PROCESSING_JOB_V2_PAYLOAD_DIGEST_DOMAIN_PREFIX as API_PREFIX,
)
from workflow_api.processing_job_v2_identity import (
    PROCESSING_JOB_V2_PAYLOAD_DIGEST_SCHEME_ID as API_SCHEME,
)
from workflow_api.processing_job_v2_identity import (
    canonical_processing_job_v2_payload_preimage as api_preimage,
)
from workflow_api.processing_job_v2_identity import (
    processing_job_v2_payload_digest as api_digest,
)
from workflow_worker.models import ProcessingJobV2 as WorkerProcessingJobV2
from workflow_worker.processing_job_v2_identity import (
    PROCESSING_JOB_V2_PAYLOAD_DIGEST_DOMAIN_PREFIX as WORKER_PREFIX,
)
from workflow_worker.processing_job_v2_identity import (
    PROCESSING_JOB_V2_PAYLOAD_DIGEST_SCHEME_ID as WORKER_SCHEME,
)
from workflow_worker.processing_job_v2_identity import (
    canonical_processing_job_v2_payload_preimage as worker_preimage,
)
from workflow_worker.processing_job_v2_identity import (
    processing_job_v2_payload_digest as worker_digest,
)

ROOT = Path(__file__).resolve().parents[1]
VECTOR_PATH = ROOT / "contracts/examples/processing-job-v2-payload-digest-v1.json"
EXPECTED_SCHEME = "workflow-helper.processing-job-v2.payload.sha256-jcs.v1"
EXPECTED_PREFIX = b"workflow-helper\0processing-job-v2\0payload-digest\0sha256-jcs-v1\0"
EXPECTED_DIGESTS = (
    "5a5653b89eb071a70b9b861b65358bd062b83ee978962ea8041b9ca3affad1c7",
    "6370158c3d21bf6a4e5c62f0297fa12e5bdc518fa4d2c324f46527f70d9d39a1",
)


def _fixture() -> dict[str, object]:
    return json.loads(VECTOR_PATH.read_text(encoding="utf-8"))


def _raw_job_json(size_bytes: str) -> str:
    payload = json.loads(json.dumps(_fixture()["vectors"][0]["admission_input"]))
    payload["input_artifact"]["size_bytes"] = "__raw_number__"
    return json.dumps(payload, separators=(",", ":")).replace(
        '"__raw_number__"', size_bytes
    )


@pytest.mark.parametrize(
    ("size_bytes", "expected"),
    [
        ("0", 0),
        ("1", 1),
        ("1.0", 1),
        ("1e0", 1),
        ("10e-1", 1),
        ("536870912", 536870912),
        ("536870912.0", 536870912),
    ],
)
@pytest.mark.parametrize("raw_type", [str, bytes, bytearray])
def test_api_worker_raw_numeric_admission_is_lossless_and_nominally_symmetric(
    size_bytes: str, expected: int, raw_type: type[str | bytes | bytearray]
) -> None:
    raw_text = _raw_job_json(size_bytes)
    raw = raw_text if raw_type is str else raw_type(raw_text.encode("utf-8"))
    api_job = ApiProcessingJobV2.model_validate_json(raw)
    worker_job = WorkerProcessingJobV2.model_validate_json(raw)

    assert type(api_job.input_artifact.size_bytes) is int
    assert type(worker_job.input_artifact.size_bytes) is int
    assert api_job.input_artifact.size_bytes == expected
    assert worker_job.input_artifact.size_bytes == expected


@pytest.mark.parametrize(
    "size_bytes",
    [
        "0.99999999999999999",
        "1.0000000000000001",
        "536870912.0000000001",
        "1.5",
        "-1",
        "536870913",
        "true",
        '"1"',
        "null",
        "NaN",
        "Infinity",
        "-Infinity",
    ],
)
def test_api_worker_raw_numeric_admission_rejects_lossy_or_invalid_values(
    size_bytes: str,
) -> None:
    raw = _raw_job_json(size_bytes)

    for model in (ApiProcessingJobV2, WorkerProcessingJobV2):
        with pytest.raises(ValidationError):
            model.model_validate_json(raw)


def test_api_worker_extreme_exponent_maps_decimal_failure_to_validation_error() -> None:
    raw = _raw_job_json("1e9999999999999999999999999999999999999999")

    for model in (ApiProcessingJobV2, WorkerProcessingJobV2):
        with pytest.raises(ValidationError):
            model.model_validate_json(raw)


def test_api_worker_preparsed_python_floats_reject() -> None:
    payload = json.loads(json.dumps(_fixture()["vectors"][0]["admission_input"]))
    payload["input_artifact"]["size_bytes"] = 1.0

    for model in (ApiProcessingJobV2, WorkerProcessingJobV2):
        with pytest.raises(ValueError):
            model.model_validate(payload)


def test_frozen_vectors_are_byte_exact_across_api_worker_and_expected() -> None:
    fixture = _fixture()
    assert fixture["scheme_id"] == API_SCHEME == WORKER_SCHEME == EXPECTED_SCHEME
    assert API_PREFIX == WORKER_PREFIX == EXPECTED_PREFIX
    assert tuple(vector["sha256"] for vector in fixture["vectors"]) == EXPECTED_DIGESTS

    for vector in fixture["vectors"]:
        api_job = ApiProcessingJobV2.model_validate(vector["admission_input"])
        worker_job = WorkerProcessingJobV2.model_validate(vector["admission_input"])
        canonical = vector["canonical_jcs"].encode("utf-8")
        expected_preimage = bytes.fromhex(vector["canonical_preimage_utf8_hex"])

        assert canonical == bytes.fromhex(vector["canonical_jcs_utf8_hex"])
        assert expected_preimage == EXPECTED_PREFIX + canonical
        assert api_preimage(api_job) == worker_preimage(worker_job) == expected_preimage
        assert api_preimage(api_job)[len(EXPECTED_PREFIX) :] == canonical
        assert worker_preimage(worker_job)[len(EXPECTED_PREFIX) :] == canonical
        assert api_digest(api_job) == worker_digest(worker_job) == vector["sha256"]


def test_runtime_models_are_nominally_separate_and_cross_runtime_inputs_fail_closed() -> (
    None
):
    fixture = _fixture()
    for vector in fixture["vectors"]:
        api_job = ApiProcessingJobV2.model_validate(vector["admission_input"])
        worker_job = WorkerProcessingJobV2.model_validate(vector["admission_input"])
        assert type(api_job) is ApiProcessingJobV2
        assert type(worker_job) is WorkerProcessingJobV2
        assert ApiProcessingJobV2 is not WorkerProcessingJobV2

        with pytest.raises(ValueError, match="^payload digest rejected$") as api_error:
            api_digest(worker_job)  # type: ignore[arg-type]
        with pytest.raises(
            ValueError, match="^payload digest rejected$"
        ) as worker_error:
            worker_digest(api_job)  # type: ignore[arg-type]
        assert api_error.value.__context__ is None
        assert worker_error.value.__context__ is None


def test_api_and_worker_mechanisms_do_not_import_each_other() -> None:
    paths = (
        ROOT / "apps/api/src/workflow_api/processing_job_v2_identity.py",
        ROOT / "apps/worker/src/workflow_worker/processing_job_v2_identity.py",
    )
    imports: list[set[str | None]] = []
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports.append(
            {
                node.module if isinstance(node, ast.ImportFrom) else alias.name
                for node in ast.walk(tree)
                if isinstance(node, ast.Import | ast.ImportFrom)
                for alias in node.names
            }
        )
    assert not any(name and name.startswith("workflow_worker") for name in imports[0])
    assert not any(name and name.startswith("workflow_api") for name in imports[1])


def test_builtin_only_node_reproduction_matches_both_golden_digests() -> None:
    script = r"""
const fs = require("fs");
const crypto = require("crypto");

const fixture = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
const prefix = Buffer.from(
  "workflow-helper\0processing-job-v2\0payload-digest\0sha256-jcs-v1\0",
  "utf8",
);

function uuid(value) {
  const hex = value.replaceAll("-", "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) throw new Error("invalid UUID");
  return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join("-");
}

const digests = [];
for (const vector of fixture.vectors) {
  const input = vector.admission_input;
  const artifact = input.input_artifact;
  const normalized = {
    input_artifact: {
      file_id: artifact.file_id,
      mime_type: artifact.mime_type,
      provider: artifact.provider,
      revision: artifact.revision,
      role: artifact.role,
      sha256: artifact.sha256,
      size_bytes: artifact.size_bytes,
    },
    job_id: uuid(input.job_id),
    schema_version: input.schema_version,
    session_id: uuid(input.session_id),
  };
  const canonical = JSON.stringify(normalized);
  if (Buffer.from(canonical, "utf8").toString("hex") !== vector.canonical_jcs_utf8_hex) {
    throw new Error(`canonical mismatch: ${vector.name}`);
  }
  const preimage = Buffer.concat([prefix, Buffer.from(canonical, "utf8")]);
  if (preimage.toString("hex") !== vector.canonical_preimage_utf8_hex) {
    throw new Error(`preimage mismatch: ${vector.name}`);
  }
  const digest = crypto.createHash("sha256").update(preimage).digest("hex");
  if (digest !== vector.sha256) throw new Error(`digest mismatch: ${vector.name}`);
  digests.push(digest);
}
process.stdout.write(JSON.stringify(digests));
"""
    completed = subprocess.run(
        ["node", "-e", script, str(VECTOR_PATH)],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert tuple(json.loads(completed.stdout)) == EXPECTED_DIGESTS
