#!/usr/bin/env python3
"""Dependency-light repository checks used locally and in CI."""

from __future__ import annotations

import compileall
import copy
import json
import math
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    from jsonschema import Draft202012Validator, FormatChecker, RefResolver
except ImportError as exc:
    raise SystemExit(
        'schema validation requires: python -m pip install "jsonschema[format]>=4.23,<5"'
    ) from exc


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_SESSION_KEYS = {
    "schema_version",
    "session_id",
    "machine_id",
    "started_at",
    "ended_at",
    "processing_status",
    "drawing_files",
    "cad_events",
    "labels",
    "skills",
}
FORBIDDEN_SUFFIXES = {".dwg", ".dxf", ".mp4", ".mkv", ".webm", ".pem", ".key"}
IGNORED_DIRECTORY_NAMES = {
    ".git",
    ".next",
    ".venv",
    "bin",
    "cdk.out",
    "node_modules",
    "obj",
}


def validate_json() -> None:
    for path in sorted((ROOT / "contracts").rglob("*.json")):
        with path.open(encoding="utf-8") as handle:
            json.load(handle)
        print(f"json ok: {path.relative_to(ROOT)}")

    example_path = ROOT / "contracts/examples/session.json"
    example = json.loads(example_path.read_text(encoding="utf-8"))
    missing = REQUIRED_SESSION_KEYS - example.keys()
    if missing:
        raise ValueError(f"session example missing keys: {sorted(missing)}")
    if example["schema_version"] != "1.0":
        raise ValueError("session example must use schema_version 1.0")


def validate_json_schemas() -> None:
    schema_paths = sorted((ROOT / "contracts").glob("*.schema.json"))
    schemas = {
        path.name: json.loads(path.read_text(encoding="utf-8")) for path in schema_paths
    }
    store = {schema["$id"]: schema for schema in schemas.values()}
    validators: dict[str, Draft202012Validator] = {}
    for name, schema in schemas.items():
        Draft202012Validator.check_schema(schema)
        validators[name] = Draft202012Validator(
            schema,
            resolver=RefResolver.from_schema(schema, store=store),
            format_checker=FormatChecker(),
        )
        print(f"draft 2020-12 schema ok: contracts/{name}")

    valid_fixtures = {
        "artifact-ref.schema.json": ROOT / "contracts/examples/artifact-ref.json",
        "session.schema.json": ROOT / "contracts/examples/session.json",
        "processing-result.schema.json": ROOT / "contracts/examples/processing-result.json",
        "processing-completion.schema.json": (
            ROOT / "contracts/examples/processing-completion.json"
        ),
        "processing-result-v2.schema.json": (
            ROOT / "contracts/examples/processing-result-v2.json"
        ),
        "processing-completion-v2.schema.json": (
            ROOT / "contracts/examples/processing-completion-v2.json"
        ),
        "processing-job.schema.json": ROOT / "contracts/examples/processing-job.json",
        "processing-job-v2.schema.json": (
            ROOT / "contracts/examples/processing-job-v2.json"
        ),
        "upload-ticket.schema.json": ROOT / "contracts/examples/upload-ticket.json",
    }
    for schema_name, fixture_path in valid_fixtures.items():
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        validators[schema_name].validate(fixture)
        if schema_name in {
            "processing-result-v2.schema.json",
            "processing-completion-v2.schema.json",
        }:
            validate_processing_result_v2_semantics(fixture)
        print(f"schema fixture valid: {fixture_path.relative_to(ROOT)}")

    processing_v2_invalid_expectations = {
        "processing-result-v1-operation-segments.json": (
            "processing-result.schema.json",
            "additionalProperties",
            (),
        ),
        "processing-result-v2-additional-property.json": (
            "processing-result-v2.schema.json",
            "additionalProperties",
            ("operation_segments", 0),
        ),
        "processing-result-v2-missing-source-evidence.json": (
            "processing-result-v2.schema.json",
            "required",
            ("operation_segments", 0),
        ),
        "processing-completion-v2-v1-output-key.json": (
            "processing-completion-v2.schema.json",
            "pattern",
            ("output_object_key",),
        ),
    }
    for fixture_name, (
        schema_name,
        expected_validator,
        expected_path,
    ) in processing_v2_invalid_expectations.items():
        fixture_path = ROOT / "contracts/invalid" / fixture_name
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        errors = list(validators[schema_name].iter_errors(fixture))
        intended_error = any(
            error.validator == expected_validator
            and tuple(error.absolute_path) == expected_path
            for error in errors
        )
        if not intended_error:
            raise ValueError(
                "invalid processing v2 fixture was not rejected for its intended "
                f"reason: {fixture_path.relative_to(ROOT)}"
            )
        print(
            "schema fixture rejected for intended reason: "
            f"{fixture_path.relative_to(ROOT)}"
        )

    validate_processing_result_v2_semantic_rejections(
        json.loads(
            (ROOT / "contracts/examples/processing-result-v2.json").read_text(
                encoding="utf-8"
            )
        )
    )

    candidate_fixture_paths = (
        ROOT / "contracts/examples/candidate-skill-unreviewed.json",
        ROOT / "contracts/examples/candidate-skill-human-approved.json",
    )
    for fixture_path in candidate_fixture_paths:
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        validators["candidate-skill.schema.json"].validate(fixture)
        print(f"schema fixture valid: {fixture_path.relative_to(ROOT)}")

    invalid_fixtures = {
        "event.schema.json": sorted((ROOT / "contracts/invalid").glob("event-*.json")),
    }
    for schema_name, fixture_paths in invalid_fixtures.items():
        for fixture_path in fixture_paths:
            fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
            errors = list(validators[schema_name].iter_errors(fixture))
            if not errors:
                raise ValueError(
                    f"invalid fixture unexpectedly passed: {fixture_path.relative_to(ROOT)}"
                )
            print(f"schema fixture rejected: {fixture_path.relative_to(ROOT)}")

    candidate_invalid_expectations = {
        "candidate-skill-ai-approved-without-human-evidence.json": (
            "type",
            ("human_approval_evidence",),
        ),
        "candidate-skill-missing-supporting-evidence.json": (
            "minItems",
            ("supporting_examples",),
        ),
        "candidate-skill-additional-property.json": ("additionalProperties", ()),
    }
    candidate_validator = validators["candidate-skill.schema.json"]
    for fixture_name, (expected_validator, expected_path) in (
        candidate_invalid_expectations.items()
    ):
        fixture_path = ROOT / "contracts/invalid" / fixture_name
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        errors = list(candidate_validator.iter_errors(fixture))
        intended_error = any(
            error.validator == expected_validator
            and tuple(error.absolute_path) == expected_path
            for error in errors
        )
        if not intended_error:
            raise ValueError(
                "invalid candidate fixture was not rejected for its intended reason: "
                f"{fixture_path.relative_to(ROOT)}"
            )
        print(
            "schema fixture rejected for intended reason: "
            f"{fixture_path.relative_to(ROOT)}"
        )


def validate_processing_result_v2_semantics(document: dict[str, object]) -> None:
    """Validate v2 relationships that JSON Schema Draft 2020-12 cannot express."""

    timeline = document["timeline"]
    segments = document["operation_segments"]
    if not isinstance(timeline, list) or not isinstance(segments, list):
        raise ValueError("processing v2 collections must be arrays")

    timeline_events: dict[str, float] = {}
    for event in timeline:
        if not isinstance(event, dict):
            raise ValueError("processing v2 timeline entries must be objects")
        source_event_id = event["source_event_id"]
        offset = event["offset_seconds"]
        if not isinstance(source_event_id, str) or not isinstance(offset, (int, float)):
            raise ValueError("processing v2 timeline evidence is malformed")
        if not math.isfinite(offset):
            raise ValueError("processing v2 timeline offsets must be finite")
        if source_event_id in timeline_events:
            raise ValueError("processing v2 timeline source evidence must be unique")
        timeline_events[source_event_id] = float(offset)

    previous_end = -1.0
    used_source_event_ids: set[str] = set()
    for expected_sequence, segment in enumerate(segments, start=1):
        if not isinstance(segment, dict):
            raise ValueError("processing v2 operation segments must be objects")
        if segment["sequence"] != expected_sequence:
            raise ValueError("processing v2 operation segment sequence is not contiguous")
        start = segment["start_offset_seconds"]
        end = segment["end_offset_seconds"]
        if not isinstance(start, (int, float)) or not isinstance(end, (int, float)):
            raise ValueError("processing v2 operation segment offsets are malformed")
        start_value = float(start)
        end_value = float(end)
        if not math.isfinite(start_value) or not math.isfinite(end_value):
            raise ValueError("processing v2 operation segment offsets must be finite")
        if start_value > end_value:
            raise ValueError("processing v2 operation segment bounds are reversed")
        if start_value < previous_end:
            raise ValueError("processing v2 operation segments overlap or are unordered")

        source_event_ids = segment["source_event_ids"]
        if not isinstance(source_event_ids, list) or not source_event_ids:
            raise ValueError("processing v2 operation segment evidence is missing")
        for source_event_id in source_event_ids:
            if not isinstance(source_event_id, str):
                raise ValueError("processing v2 source evidence is malformed")
            if source_event_id not in timeline_events:
                raise ValueError("processing v2 source evidence is not in the timeline")
            if source_event_id in used_source_event_ids:
                raise ValueError("processing v2 source evidence is assigned more than once")
            event_offset = timeline_events[source_event_id]
            if not start_value <= event_offset <= end_value:
                raise ValueError("processing v2 source evidence is outside segment bounds")
            used_source_event_ids.add(source_event_id)
        previous_end = end_value

    if "output_object_key" in document:
        expected_key = f"sessions/{document['session_id']}/timeline-v2.json"
        if document["output_object_key"] != expected_key:
            raise ValueError("processing completion v2 output key does not match session")


def validate_processing_result_v2_semantic_rejections(
    valid_document: dict[str, object],
) -> None:
    mutations = {
        "noncontiguous sequence": lambda value: value["operation_segments"][1].__setitem__(
            "sequence", 3
        ),
        "reversed bounds": lambda value: value["operation_segments"][0].__setitem__(
            "start_offset_seconds", 1.5
        ),
        "unordered overlap": lambda value: value["operation_segments"][1].__setitem__(
            "start_offset_seconds", 0.5
        ),
        "unknown source evidence": lambda value: value["operation_segments"][0].__setitem__(
            "source_event_ids", ["33333333-3333-4333-8333-333333333333"]
        ),
    }
    for label, mutate in mutations.items():
        candidate = copy.deepcopy(valid_document)
        mutate(candidate)
        try:
            validate_processing_result_v2_semantics(candidate)
        except ValueError:
            print(f"processing v2 semantics rejected: {label}")
        else:
            raise ValueError(f"processing v2 semantics unexpectedly accepted: {label}")


def validate_python() -> None:
    for source_dir in (
        ROOT / "apps/api/src",
        ROOT / "apps/api/tests",
        ROOT / "apps/worker/src",
        ROOT / "apps/worker/tests",
    ):
        if source_dir.exists() and not compileall.compile_dir(source_dir, quiet=1):
            raise ValueError(f"python compilation failed: {source_dir}")
    print("python compile ok")


def validate_dotnet_project() -> None:
    project = ROOT / "apps/capture-agent/WorkflowHelper.CaptureAgent.csproj"
    if project.exists():
        ET.parse(project)
        print("dotnet project xml ok")


def validate_no_sensitive_artifacts() -> None:
    offenders = [
        path.relative_to(ROOT)
        for path in ROOT.rglob("*")
        if path.is_file()
        and not any(part in IGNORED_DIRECTORY_NAMES for part in path.relative_to(ROOT).parts)
        and path.suffix.lower() in FORBIDDEN_SUFFIXES
    ]
    if offenders:
        raise ValueError(f"sensitive artifact types found: {offenders}")
    print("sensitive artifact check ok")


def main() -> int:
    validate_json()
    validate_json_schemas()
    validate_python()
    validate_dotnet_project()
    validate_no_sensitive_artifacts()
    print("all scaffold checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
