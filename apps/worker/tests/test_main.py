import hashlib
import io
import json
import zipfile
from base64 import b64encode
from urllib.error import URLError
from uuid import UUID, uuid4

import boto3
import pytest
from botocore.exceptions import ClientError

import workflow_worker.main as worker_main
from workflow_worker.main import (
    _artifact_bytes,
    _completion_for,
    _download_package,
    _publish_artifact,
    process_message,
    process_message_v2,
)
from workflow_worker.models import EventType, ProcessingJob, ProcessingResult, TimelineItem


def _package(session_id) -> bytes:
    event = {
        "event_id": str(uuid4()),
        "occurred_at": "2026-08-16T04:00:00Z",
        "event_type": "session_ended",
        "source": "agent",
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(
            "metadata.json",
            json.dumps({"schema_version": "1.0", "session_id": str(session_id)}),
        )
        archive.writestr("events.jsonl", json.dumps(event))
    return output.getvalue()


def _package_with_events(session_id, events: list[dict[str, object]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(
            "metadata.json",
            json.dumps({"schema_version": "1.0", "session_id": str(session_id)}),
        )
        archive.writestr("events.jsonl", "\n".join(json.dumps(event) for event in events))
    return output.getvalue()


def _client_error(code: str, status: int) -> ClientError:
    return ClientError(
        {
            "Error": {"Code": code, "Message": f"synthetic {code}"},
            "ResponseMetadata": {"HTTPStatusCode": status},
        },
        "PutObject",
    )


class FakeS3:
    def __init__(self, package: bytes) -> None:
        self.package = package
        self.puts: list[dict[str, object]] = []
        self.accepted_puts: list[dict[str, object]] = []
        self.processed_object: dict[str, object] | None = None
        self.race_on_next_put = False
        self.put_errors: list[ClientError] = []
        self.processed_heads = 0

    def get_object(self, **kwargs):
        if kwargs["Bucket"] == "raw":
            return {"Body": io.BytesIO(self.package), "ContentLength": len(self.package)}
        assert kwargs["Bucket"] == "processed"
        assert self.processed_object is not None
        body = self.processed_object["Body"]
        return {"Body": io.BytesIO(body), "ContentLength": len(body)}

    def head_object(self, **kwargs):
        if kwargs["Bucket"] == "raw":
            return {"ContentLength": len(self.package)}
        assert kwargs["Bucket"] == "processed"
        assert kwargs["ChecksumMode"] == "ENABLED"
        assert self.processed_object is not None
        self.processed_heads += 1
        return {
            "ContentLength": self.processed_object["ContentLength"],
            **(
                {"ChecksumSHA256": self.processed_object["ChecksumSHA256"]}
                if "ChecksumSHA256" in self.processed_object
                else {}
            ),
            "Metadata": self.processed_object.get("Metadata", {}),
        }

    def put_object(self, **kwargs):
        self.puts.append(kwargs)
        assert kwargs["Bucket"] == "processed"
        assert kwargs["IfNoneMatch"] == "*"
        candidate = {
            "Body": kwargs["Body"],
            "ContentLength": len(kwargs["Body"]),
            "ChecksumSHA256": kwargs["ChecksumSHA256"],
            "Metadata": kwargs["Metadata"],
        }
        if self.put_errors:
            raise self.put_errors.pop(0)
        if self.race_on_next_put:
            self.race_on_next_put = False
            self.processed_object = candidate
            raise self._precondition_failed()
        if self.processed_object is not None:
            raise self._precondition_failed()
        self.processed_object = candidate
        self.accepted_puts.append(kwargs)

    @staticmethod
    def _precondition_failed() -> ClientError:
        return _client_error("PreconditionFailed", 412)


def test_content_addressed_processing_job_rejects_legacy_or_mismatched_key() -> None:
    session_id = uuid4()
    digest = "a" * 64
    valid = ProcessingJob(
        schema_version="1.0",
        session_id=session_id,
        object_key=f"sessions/{session_id}/packages/{digest}.zip",
    )
    assert valid.session_id == session_id

    with pytest.raises(ValueError):
        ProcessingJob(
            schema_version="1.0",
            session_id=session_id,
            object_key=f"sessions/{session_id}/package.zip",
        )
    with pytest.raises(ValueError):
        ProcessingJob(
            schema_version="1.0",
            session_id=session_id,
            object_key=f"sessions/{uuid4()}/packages/{digest}.zip",
        )


def test_v1_artifact_bytes_and_completion_digest_are_pinned() -> None:
    session_id = UUID("11111111-1111-4111-8111-111111111111")
    result = ProcessingResult(
        session_id=session_id,
        event_count=1,
        meaningful_event_count=1,
        timeline=[
            TimelineItem(
                offset_seconds=0,
                event_type=EventType.SESSION_ENDED,
                summary="Approved CAD session ended",
                source_event_id=UUID("22222222-2222-4222-8222-222222222222"),
            )
        ],
        keyframes=[],
        warnings=[],
    )
    artifact = _artifact_bytes(result)
    completion = _completion_for(result, f"sessions/{session_id}/timeline.json")

    assert hashlib.sha256(artifact).hexdigest() == (
        "d902fb08722c1a635c5d36a61b44608864c1329ac8cc4783ddbfc5386c145b94"
    )
    assert completion.idempotency_key == (
        "7e08b29fd0dd48e046a1437c2526123c60ec0e11d5ba5b1cc9d371e07439f5c1"
    )
def test_sequential_duplicate_reuses_one_timeline_and_completion_key(monkeypatch) -> None:
    monkeypatch.setenv("RAW_BUCKET", "raw")
    monkeypatch.setenv("PROCESSED_BUCKET", "processed")
    session_id = uuid4()
    package = _package(session_id)
    package_sha256 = hashlib.sha256(package).hexdigest()
    key = f"sessions/{session_id}/packages/{package_sha256}.zip"
    body = json.dumps(
        {"schema_version": "1.0", "session_id": str(session_id), "object_key": key}
    )
    s3 = FakeS3(package)
    completions = []

    first = process_message(body, s3=s3, completion_callback=completions.append)
    second = process_message(body, s3=s3, completion_callback=completions.append)

    assert len(s3.puts) == 2
    assert len(s3.accepted_puts) == 1
    assert s3.puts[0]["Key"] == f"sessions/{session_id}/timeline.json"
    assert s3.puts[0]["Body"] == s3.puts[1]["Body"]
    assert s3.puts[0]["ChecksumSHA256"]
    assert s3.puts[0]["IfNoneMatch"] == "*"
    assert first == second == completions[0] == completions[1]
    assert first.output_object_key == f"sessions/{session_id}/timeline.json"
    assert len(first.idempotency_key) == 64


def test_dormant_v2_replay_is_byte_identical_and_publishes_before_callback(
    monkeypatch,
) -> None:
    monkeypatch.setenv("RAW_BUCKET", "raw")
    monkeypatch.setenv("PROCESSED_BUCKET", "processed")
    session_id = uuid4()
    package = _package(session_id)
    package_sha256 = hashlib.sha256(package).hexdigest()
    body = json.dumps(
        {
            "schema_version": "1.0",
            "session_id": str(session_id),
            "object_key": f"sessions/{session_id}/packages/{package_sha256}.zip",
        }
    )
    s3 = FakeS3(package)
    callbacks = []

    def after_publish(completion):
        assert s3.processed_object is not None
        callbacks.append(completion)

    first = process_message_v2(body, s3=s3, completion_callback=after_publish)
    first_artifact = s3.puts[0]["Body"]
    second = process_message_v2(body, s3=s3, completion_callback=after_publish)

    assert len(s3.accepted_puts) == 1
    assert s3.puts[0]["Key"] == f"sessions/{session_id}/timeline-v2.json"
    assert s3.puts[1]["Body"] == first_artifact
    assert first == second == callbacks[0] == callbacks[1]
    assert first.schema_version == "2.0"
    assert first.output_object_key == f"sessions/{session_id}/timeline-v2.json"


@pytest.mark.parametrize("conflict", ["size", "checksum", "metadata", "body"])
def test_dormant_v2_existing_artifact_conflict_suppresses_callback(
    monkeypatch,
    conflict,
) -> None:
    monkeypatch.setenv("RAW_BUCKET", "raw")
    monkeypatch.setenv("PROCESSED_BUCKET", "processed")
    session_id = uuid4()
    package = _package(session_id)
    package_sha256 = hashlib.sha256(package).hexdigest()
    body = json.dumps(
        {
            "schema_version": "1.0",
            "session_id": str(session_id),
            "object_key": f"sessions/{session_id}/packages/{package_sha256}.zip",
        }
    )
    s3 = FakeS3(package)
    process_message_v2(body, s3=s3, completion_callback=lambda completion: None)
    assert s3.processed_object is not None
    if conflict == "size":
        s3.processed_object["ContentLength"] += 1
    elif conflict == "checksum":
        s3.processed_object["ChecksumSHA256"] = "wrong"
    elif conflict == "metadata":
        s3.processed_object["Metadata"] = {"sha256": "0" * 64}
    else:
        artifact = s3.processed_object["Body"]
        s3.processed_object["Body"] = bytes([artifact[0] ^ 1]) + artifact[1:]
    callbacks = []

    with pytest.raises(RuntimeError, match="existing output artifact conflicts"):
        process_message_v2(body, s3=s3, completion_callback=callbacks.append)

    assert callbacks == []


def test_dormant_v2_409_race_accepts_only_exact_winner(monkeypatch) -> None:
    monkeypatch.setenv("RAW_BUCKET", "raw")
    monkeypatch.setenv("PROCESSED_BUCKET", "processed")
    session_id = uuid4()
    package = _package(session_id)
    package_sha256 = hashlib.sha256(package).hexdigest()
    body = json.dumps(
        {
            "schema_version": "1.0",
            "session_id": str(session_id),
            "object_key": f"sessions/{session_id}/packages/{package_sha256}.zip",
        }
    )
    s3 = FakeS3(package)
    completion = process_message_v2(
        body,
        s3=s3,
        completion_callback=lambda completion: None,
    )
    s3.put_errors = [_client_error("ConditionalRequestConflict", 409)]
    callbacks = []

    replay = process_message_v2(body, s3=s3, completion_callback=callbacks.append)

    assert replay == completion
    assert callbacks == [completion]
    assert s3.processed_heads == 1


def test_dormant_v2_persistent_409_is_bounded_and_suppresses_callback(monkeypatch) -> None:
    monkeypatch.setenv("RAW_BUCKET", "raw")
    monkeypatch.setenv("PROCESSED_BUCKET", "processed")
    session_id = uuid4()
    package = _package(session_id)
    package_sha256 = hashlib.sha256(package).hexdigest()
    body = json.dumps(
        {
            "schema_version": "1.0",
            "session_id": str(session_id),
            "object_key": f"sessions/{session_id}/packages/{package_sha256}.zip",
        }
    )
    s3 = FakeS3(package)
    s3.put_errors = [
        _client_error("ConditionalRequestConflict", 409),
        _client_error("ConditionalRequestConflict", 409),
        _client_error("ConditionalRequestConflict", 409),
    ]
    callbacks = []

    with pytest.raises(RuntimeError, match="remained conflicted after 3 attempts"):
        process_message_v2(body, s3=s3, completion_callback=callbacks.append)

    assert len(s3.puts) == 3
    assert callbacks == []


def test_dormant_v2_model_failure_precedes_publication_and_callback(monkeypatch) -> None:
    monkeypatch.setenv("RAW_BUCKET", "raw")
    monkeypatch.setenv("PROCESSED_BUCKET", "processed")
    session_id = uuid4()
    duplicate_id = str(uuid4())
    package = _package_with_events(
        session_id,
        [
            {
                "event_id": duplicate_id,
                "occurred_at": "2026-08-16T04:00:00Z",
                "event_type": "cad_command",
                "source": "autocad",
                "command_name": "LINE",
                "drawing_ref": "drawing",
            },
            {
                "event_id": duplicate_id,
                "occurred_at": "2026-08-16T04:00:01Z",
                "event_type": "cad_command",
                "source": "autocad",
                "command_name": "TRIM",
                "drawing_ref": "drawing",
            },
        ],
    )
    package_sha256 = hashlib.sha256(package).hexdigest()
    body = json.dumps(
        {
            "schema_version": "1.0",
            "session_id": str(session_id),
            "object_key": f"sessions/{session_id}/packages/{package_sha256}.zip",
        }
    )
    s3 = FakeS3(package)
    callbacks = []

    with pytest.raises(ValueError, match="source event_id values must be unique"):
        process_message_v2(body, s3=s3, completion_callback=callbacks.append)

    assert s3.puts == []
    assert callbacks == []


def test_callback_failure_after_write_is_safe_on_redelivery(monkeypatch) -> None:
    monkeypatch.setenv("RAW_BUCKET", "raw")
    monkeypatch.setenv("PROCESSED_BUCKET", "processed")
    session_id = uuid4()
    package = _package(session_id)
    package_sha256 = hashlib.sha256(package).hexdigest()
    body = json.dumps(
        {
            "schema_version": "1.0",
            "session_id": str(session_id),
            "object_key": f"sessions/{session_id}/packages/{package_sha256}.zip",
        }
    )
    s3 = FakeS3(package)
    attempted = []

    def fail_after_write(completion):
        attempted.append(completion)
        raise RuntimeError("synthetic callback outage")

    with pytest.raises(RuntimeError, match="synthetic callback outage"):
        process_message(body, s3=s3, completion_callback=fail_after_write)

    delivered = []
    redelivered = process_message(body, s3=s3, completion_callback=delivered.append)

    assert len(s3.accepted_puts) == 1
    assert len(s3.puts) == 2
    assert attempted == delivered == [redelivered]


def test_preseeded_legacy_pretty_timeline_allows_callback_redelivery(monkeypatch) -> None:
    monkeypatch.setenv("RAW_BUCKET", "raw")
    monkeypatch.setenv("PROCESSED_BUCKET", "processed")
    session_id = uuid4()
    package = _package(session_id)
    package_sha256 = hashlib.sha256(package).hexdigest()
    body = json.dumps(
        {
            "schema_version": "1.0",
            "session_id": str(session_id),
            "object_key": f"sessions/{session_id}/packages/{package_sha256}.zip",
        }
    )
    result = worker_main.process_package(session_id, io.BytesIO(package))
    legacy_artifact = result.model_dump_json(indent=2).encode("utf-8")
    legacy_digest = hashlib.sha256(legacy_artifact).digest()
    s3 = FakeS3(package)
    s3.processed_object = {
        "Body": legacy_artifact,
        "ContentLength": len(legacy_artifact),
        "ChecksumSHA256": b64encode(legacy_digest).decode("ascii"),
        "Metadata": {"sha256": legacy_digest.hex()},
    }
    completions = []

    completion = process_message(body, s3=s3, completion_callback=completions.append)
    expected = _completion_for(result, f"sessions/{session_id}/timeline.json")

    assert completions == [expected]
    assert completion.idempotency_key == expected.idempotency_key
    assert len(s3.puts) == 1
    assert s3.puts[0]["Body"] == legacy_artifact
    assert s3.accepted_puts == []
    assert s3.processed_heads == 1


def test_conditional_409_retries_then_publishes() -> None:
    s3 = FakeS3(b"unused")
    s3.put_errors = [_client_error("ConditionalRequestConflict", 409)]

    _publish_artifact(s3, "processed", "sessions/synthetic/timeline.json", b"artifact")

    assert len(s3.puts) == 2
    assert len(s3.accepted_puts) == 1
    assert s3.processed_heads == 0


def test_conditional_409_then_412_verifies_identical_winner() -> None:
    artifact = b"deterministic-artifact"
    digest = hashlib.sha256(artifact).digest()
    s3 = FakeS3(b"unused")
    s3.processed_object = {
        "Body": artifact,
        "ContentLength": len(artifact),
        "ChecksumSHA256": b64encode(digest).decode("ascii"),
        "Metadata": {"sha256": digest.hex()},
    }
    s3.put_errors = [_client_error("ConditionalRequestConflict", 409)]

    _publish_artifact(s3, "processed", "sessions/synthetic/timeline.json", artifact)

    assert len(s3.puts) == 2
    assert s3.accepted_puts == []
    assert s3.processed_heads == 1


def test_persistent_conditional_409_direct_publish_is_bounded() -> None:
    s3 = FakeS3(b"unused")
    s3.put_errors = [
        _client_error("ConditionalRequestConflict", 409),
        _client_error("ConditionalRequestConflict", 409),
        _client_error("ConditionalRequestConflict", 409),
    ]

    with pytest.raises(RuntimeError, match="remained conflicted after 3 attempts") as raised:
        _publish_artifact(s3, "processed", "sessions/synthetic/timeline.json", b"artifact")

    assert isinstance(raised.value.__cause__, ClientError)
    assert len(s3.puts) == 3
    assert s3.processed_heads == 0


def test_persistent_conditional_409_is_bounded_and_skips_callback(monkeypatch) -> None:
    monkeypatch.setenv("RAW_BUCKET", "raw")
    monkeypatch.setenv("PROCESSED_BUCKET", "processed")
    session_id = uuid4()
    package = _package(session_id)
    package_sha256 = hashlib.sha256(package).hexdigest()
    body = json.dumps(
        {
            "schema_version": "1.0",
            "session_id": str(session_id),
            "object_key": f"sessions/{session_id}/packages/{package_sha256}.zip",
        }
    )
    s3 = FakeS3(package)
    s3.put_errors = [
        _client_error("ConditionalRequestConflict", 409),
        _client_error("ConditionalRequestConflict", 409),
        _client_error("ConditionalRequestConflict", 409),
    ]
    completions = []

    with pytest.raises(RuntimeError, match="remained conflicted after 3 attempts"):
        process_message(body, s3=s3, completion_callback=completions.append)

    assert len(s3.puts) == 3
    assert s3.processed_heads == 0
    assert completions == []


def test_unrelated_put_client_error_passes_through_without_head() -> None:
    s3 = FakeS3(b"unused")
    denied = _client_error("AccessDenied", 403)
    s3.put_errors = [denied]

    with pytest.raises(ClientError) as raised:
        _publish_artifact(s3, "processed", "sessions/synthetic/timeline.json", b"artifact")

    assert raised.value is denied
    assert len(s3.puts) == 1
    assert s3.processed_heads == 0


def test_boto3_s3_put_object_model_supports_if_none_match() -> None:
    s3 = boto3.client(
        "s3",
        region_name="us-east-1",
        aws_access_key_id="synthetic",
        aws_secret_access_key="synthetic",
    )
    put_object_input = s3.meta.service_model.operation_model("PutObject").input_shape

    assert put_object_input is not None
    assert "IfNoneMatch" in put_object_input.members


@pytest.mark.parametrize(
    "conflict",
    [
        pytest.param("size", id="size"),
        pytest.param("checksum", id="checksum"),
        pytest.param("metadata", id="metadata"),
        pytest.param("content", id="content"),
    ],
)
def test_conflicting_existing_timeline_fails_closed(monkeypatch, conflict) -> None:
    monkeypatch.setenv("RAW_BUCKET", "raw")
    monkeypatch.setenv("PROCESSED_BUCKET", "processed")
    session_id = uuid4()
    package = _package(session_id)
    package_sha256 = hashlib.sha256(package).hexdigest()
    body = json.dumps(
        {
            "schema_version": "1.0",
            "session_id": str(session_id),
            "object_key": f"sessions/{session_id}/packages/{package_sha256}.zip",
        }
    )
    s3 = FakeS3(package)
    completions = []
    process_message(body, s3=s3, completion_callback=completions.append)
    assert s3.processed_object is not None

    if conflict == "size":
        s3.processed_object["ContentLength"] += 1
    elif conflict == "checksum":
        s3.processed_object["ChecksumSHA256"] = "not-the-expected-checksum"
    elif conflict == "metadata":
        s3.processed_object["Metadata"] = {"sha256": "0" * 64}
    else:
        original = s3.processed_object["Body"]
        conflicting = bytes([original[0] ^ 1]) + original[1:]
        conflicting_digest = hashlib.sha256(conflicting).digest()
        s3.processed_object.update(
            {
                "Body": conflicting,
                "ChecksumSHA256": b64encode(conflicting_digest).decode("ascii"),
                "Metadata": {"sha256": conflicting_digest.hex()},
            }
        )

    with pytest.raises(RuntimeError, match="existing output artifact conflicts"):
        process_message(body, s3=s3, completion_callback=completions.append)

    assert len(s3.accepted_puts) == 1
    assert len(completions) == 1


@pytest.mark.parametrize("missing_field", ["ChecksumSHA256", "Metadata"])
def test_existing_timeline_with_missing_checksum_evidence_fails_closed(
    monkeypatch, missing_field
) -> None:
    monkeypatch.setenv("RAW_BUCKET", "raw")
    monkeypatch.setenv("PROCESSED_BUCKET", "processed")
    session_id = uuid4()
    package = _package(session_id)
    package_sha256 = hashlib.sha256(package).hexdigest()
    body = json.dumps(
        {
            "schema_version": "1.0",
            "session_id": str(session_id),
            "object_key": f"sessions/{session_id}/packages/{package_sha256}.zip",
        }
    )
    s3 = FakeS3(package)
    process_message(body, s3=s3, completion_callback=lambda completion: None)
    assert s3.processed_object is not None
    s3.processed_object.pop(missing_field)
    completions = []

    with pytest.raises(RuntimeError, match="existing output artifact conflicts"):
        process_message(body, s3=s3, completion_callback=completions.append)

    assert completions == []


def test_concurrent_first_writer_race_reuses_identical_timeline(monkeypatch) -> None:
    monkeypatch.setenv("RAW_BUCKET", "raw")
    monkeypatch.setenv("PROCESSED_BUCKET", "processed")
    session_id = uuid4()
    package = _package(session_id)
    package_sha256 = hashlib.sha256(package).hexdigest()
    body = json.dumps(
        {
            "schema_version": "1.0",
            "session_id": str(session_id),
            "object_key": f"sessions/{session_id}/packages/{package_sha256}.zip",
        }
    )
    s3 = FakeS3(package)
    s3.race_on_next_put = True
    completions = []

    completion = process_message(body, s3=s3, completion_callback=completions.append)

    assert len(s3.puts) == 1
    assert s3.accepted_puts == []
    assert s3.processed_object is not None
    assert completions == [completion]


def test_completion_key_changes_with_result_content() -> None:
    session_id = UUID("11111111-1111-4111-8111-111111111111")
    base = ProcessingResult(
        session_id=session_id,
        event_count=0,
        meaningful_event_count=0,
        timeline=[],
        keyframes=[],
        warnings=[],
    )
    changed = base.model_copy(update={"warnings": ["synthetic warning"]})
    output_key = f"sessions/{session_id}/timeline.json"

    assert _completion_for(base, output_key).idempotency_key != _completion_for(
        changed, output_key
    ).idempotency_key


def test_queue_service_failures_exit_after_bounded_retries(monkeypatch) -> None:
    class FailingSqs:
        attempts = 0

        def receive_message(self, **kwargs):
            self.attempts += 1
            raise ConnectionError("synthetic LocalStack outage")

    sqs = FailingSqs()
    monkeypatch.setenv("PROCESSING_QUEUE_URL", "http://localstack/queue")
    monkeypatch.setenv("WORKER_MAX_SERVICE_FAILURES", "3")
    monkeypatch.setattr(worker_main, "_client", lambda service: sqs)
    monkeypatch.setattr(worker_main.time, "sleep", lambda seconds: None)

    with pytest.raises(ConnectionError, match="synthetic LocalStack outage"):
        worker_main.run_forever()

    assert sqs.attempts == 3


def test_queue_loop_uses_v2_once_and_deletes_after_success(monkeypatch) -> None:
    class OneMessageSqs:
        receives = 0
        deletes = 0

        def receive_message(self, **kwargs):
            self.receives += 1
            if self.receives == 1:
                return {
                    "Messages": [
                        {
                            "Body": "synthetic-v1-job",
                            "ReceiptHandle": "synthetic-receipt",
                            "Attributes": {"ApproximateReceiveCount": "1"},
                        }
                    ]
                }
            raise RuntimeError("bounded synthetic stop")

        def delete_message(self, **kwargs):
            self.deletes += 1

    sqs = OneMessageSqs()
    processed = []
    monkeypatch.setenv("PROCESSING_QUEUE_URL", "http://localstack/queue")
    monkeypatch.setenv("WORKER_MAX_SERVICE_FAILURES", "1")
    monkeypatch.setattr(worker_main, "_client", lambda service: sqs)
    monkeypatch.setattr(worker_main, "process_message_v2", processed.append)

    with pytest.raises(RuntimeError, match="bounded synthetic stop"):
        worker_main.run_forever()

    assert processed == ["synthetic-v1-job"]
    assert sqs.deletes == 1


def test_queue_loop_does_not_delete_after_v2_failure(monkeypatch) -> None:
    class OneMessageSqs:
        receives = 0
        deletes = 0

        def receive_message(self, **kwargs):
            self.receives += 1
            if self.receives == 1:
                return {
                    "Messages": [
                        {
                            "Body": "synthetic-v1-job",
                            "ReceiptHandle": "synthetic-receipt",
                            "Attributes": {"ApproximateReceiveCount": "1"},
                        }
                    ]
                }
            raise RuntimeError("bounded synthetic stop")

        def delete_message(self, **kwargs):
            self.deletes += 1

    sqs = OneMessageSqs()
    processed = []
    monkeypatch.setenv("PROCESSING_QUEUE_URL", "http://localstack/queue")
    monkeypatch.setenv("WORKER_MAX_SERVICE_FAILURES", "1")
    monkeypatch.setattr(worker_main, "_client", lambda service: sqs)

    def fail_v2(body):
        processed.append(body)
        raise RuntimeError("synthetic v2 failure")

    monkeypatch.setattr(worker_main, "process_message_v2", fail_v2)

    with pytest.raises(RuntimeError, match="bounded synthetic stop"):
        worker_main.run_forever()

    assert processed == ["synthetic-v1-job"]
    assert sqs.deletes == 0


def test_completion_callback_retries_and_sends_worker_token(monkeypatch) -> None:
    session_id = uuid4()
    result = ProcessingResult(
        session_id=session_id,
        event_count=0,
        meaningful_event_count=0,
        timeline=[],
        keyframes=[],
        warnings=[],
    )
    completion = _completion_for(result, f"sessions/{session_id}/timeline.json")
    requests = []
    sleeps = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

    def fake_urlopen(request, timeout):
        requests.append(request)
        if len(requests) < 3:
            raise URLError("synthetic API startup race")
        return Response()

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("WORKFLOW_WORKER_TOKEN", "synthetic-worker-token")
    monkeypatch.setenv("WORKER_CALLBACK_MAX_ATTEMPTS", "3")
    monkeypatch.setenv("WORKER_RETRY_BASE_SECONDS", "0.25")
    monkeypatch.setattr(worker_main, "urlopen", fake_urlopen)

    worker_main.post_completion(completion, sleep=sleeps.append)

    assert len(requests) == 3
    assert sleeps == [0.25, 0.5]
    assert requests[-1].get_header("X-workflow-worker-token") == "synthetic-worker-token"
    assert requests[-1].get_header("Idempotency-key") == completion.idempotency_key


def test_package_download_rejects_oversized_head_before_get(monkeypatch) -> None:
    class OversizedS3:
        get_called = False

        def head_object(self, **kwargs):
            return {"ContentLength": 5}

        def get_object(self, **kwargs):
            self.get_called = True
            raise AssertionError("GET must not be called")

    session_id = uuid4()
    job = ProcessingJob(
        schema_version="1.0",
        session_id=session_id,
        object_key=f"sessions/{session_id}/packages/{'a' * 64}.zip",
    )
    s3 = OversizedS3()
    monkeypatch.setenv("MAX_PACKAGE_SIZE_BYTES", "4")

    with pytest.raises(RuntimeError, match="exceeds MAX_PACKAGE_SIZE_BYTES"):
        _download_package(s3, "raw", job)

    assert not s3.get_called


def test_package_download_rejects_truncated_body(monkeypatch) -> None:
    class TruncatedS3:
        def head_object(self, **kwargs):
            return {"ContentLength": 10}

        def get_object(self, **kwargs):
            return {"ContentLength": 10, "Body": io.BytesIO(b"short")}

    session_id = uuid4()
    job = ProcessingJob(
        schema_version="1.0",
        session_id=session_id,
        object_key=f"sessions/{session_id}/packages/{'a' * 64}.zip",
    )
    monkeypatch.setenv("MAX_PACKAGE_SIZE_BYTES", "100")

    with pytest.raises(RuntimeError, match="truncated"):
        _download_package(TruncatedS3(), "raw", job)


def test_package_download_uses_bounded_reads_and_verifies_hash(monkeypatch) -> None:
    package = b"synthetic-package-body"

    class TrackingBody(io.BytesIO):
        def __init__(self, value: bytes) -> None:
            super().__init__(value)
            self.read_sizes = []

        def read(self, size=-1):
            self.read_sizes.append(size)
            return super().read(size)

    class StreamingS3:
        def __init__(self) -> None:
            self.body = TrackingBody(package)

        def head_object(self, **kwargs):
            return {"ContentLength": len(package)}

        def get_object(self, **kwargs):
            return {"ContentLength": len(package), "Body": self.body}

    session_id = uuid4()
    digest = hashlib.sha256(package).hexdigest()
    job = ProcessingJob(
        schema_version="1.0",
        session_id=session_id,
        object_key=f"sessions/{session_id}/packages/{digest}.zip",
    )
    s3 = StreamingS3()
    monkeypatch.setenv("MAX_PACKAGE_SIZE_BYTES", "100")
    monkeypatch.setenv("UPLOAD_STREAM_CHUNK_BYTES", "4")

    with _download_package(s3, "raw", job) as package_file:
        assert package_file.read() == package

    assert s3.body.read_sizes
    assert all(size == 4 for size in s3.body.read_sizes)


def test_package_download_rejects_content_address_hash_mismatch(monkeypatch) -> None:
    package = b"synthetic-package-body"

    class MismatchedS3:
        def head_object(self, **kwargs):
            return {"ContentLength": len(package)}

        def get_object(self, **kwargs):
            return {"ContentLength": len(package), "Body": io.BytesIO(package)}

    session_id = uuid4()
    job = ProcessingJob(
        schema_version="1.0",
        session_id=session_id,
        object_key=f"sessions/{session_id}/packages/{'a' * 64}.zip",
    )
    monkeypatch.setenv("MAX_PACKAGE_SIZE_BYTES", "100")

    with pytest.raises(RuntimeError, match="SHA-256 does not match"):
        _download_package(MismatchedS3(), "raw", job)
