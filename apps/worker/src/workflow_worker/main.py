import hashlib
import json
import logging
import os
import tempfile
import time
from base64 import b64encode
from collections.abc import Callable
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import boto3
from botocore.exceptions import ClientError

from .handler import process_package, process_package_v2
from .models import ProcessingCompletion, ProcessingJob, ProcessingResult
from .processing_v2 import (
    ProcessingCompletionV2,
    artifact_bytes_v2,
    completion_for_v2,
)

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
LOGGER = logging.getLogger("workflow-helper-worker")

DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_BASE_SECONDS = 1.0
DEFAULT_MAX_PACKAGE_BYTES = 512 * 1024 * 1024
DEFAULT_STREAM_CHUNK_BYTES = 1024 * 1024
DEFAULT_SPOOL_MEMORY_BYTES = 8 * 1024 * 1024
MAX_CONDITIONAL_WRITE_ATTEMPTS = 3


def _client(service: str):
    return boto3.client(
        service,
        region_name=os.getenv("AWS_REGION", "ap-northeast-1"),
        endpoint_url=os.getenv("AWS_ENDPOINT_URL") or None,
    )


def _positive_int_env(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value < 1:
        raise RuntimeError(f"{name} must be at least 1")
    return value


def _completion_for(
    result: ProcessingResult,
    output_object_key: str,
) -> ProcessingCompletion:
    stable_payload = {
        **result.model_dump(mode="json"),
        "output_object_key": output_object_key,
    }
    canonical = json.dumps(
        stable_payload,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return ProcessingCompletion(
        **stable_payload,
        idempotency_key=hashlib.sha256(canonical).hexdigest(),
    )


def _expected_package_sha256(object_key: str) -> str:
    return object_key.rsplit("/", 1)[-1].removesuffix(".zip")


def _artifact_bytes(result: ProcessingResult) -> bytes:
    return result.model_dump_json(indent=2).encode("utf-8")


def _conditional_write_status(exc: ClientError) -> int | None:
    response = exc.response
    code = str(response.get("Error", {}).get("Code", ""))
    status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    if code in {"412", "PreconditionFailed"} or status == 412:
        return 412
    if code in {"409", "ConditionalRequestConflict"} or status == 409:
        return 409
    return None


def _verify_existing_artifact(
    s3_client: Any,
    bucket: str,
    object_key: str,
    artifact: bytes,
    digest: bytes,
    *,
    verify_body: bool = False,
) -> None:
    head = s3_client.head_object(
        Bucket=bucket,
        Key=object_key,
        ChecksumMode="ENABLED",
    )
    expected_checksum = b64encode(digest).decode("ascii")
    stored_checksum = head.get("ChecksumSHA256")
    stored_digest = {
        str(key).lower(): str(value).lower()
        for key, value in head.get("Metadata", {}).items()
    }.get("sha256")
    if (
        int(head.get("ContentLength", -1)) != len(artifact)
        or stored_digest != digest.hex()
        or stored_checksum != expected_checksum
    ):
        raise RuntimeError(
            f"existing output artifact conflicts with deterministic result: {object_key}"
        )
    if verify_body:
        response = s3_client.get_object(Bucket=bucket, Key=object_key)
        body = response["Body"]
        stored_body = bytearray()
        try:
            while len(stored_body) <= len(artifact):
                chunk = body.read(
                    min(
                        DEFAULT_STREAM_CHUNK_BYTES,
                        len(artifact) + 1 - len(stored_body),
                    )
                )
                if not chunk:
                    break
                stored_body.extend(chunk)
                if len(stored_body) > len(artifact):
                    break
        finally:
            close = getattr(body, "close", None)
            if close is not None:
                close()
        if bytes(stored_body) != artifact:
            raise RuntimeError(
                f"existing output artifact conflicts with deterministic result: {object_key}"
            )


def _publish_artifact(
    s3_client: Any,
    bucket: str,
    object_key: str,
    artifact: bytes,
    *,
    verify_existing_body: bool = False,
) -> None:
    digest = hashlib.sha256(artifact).digest()
    for attempt in range(1, MAX_CONDITIONAL_WRITE_ATTEMPTS + 1):
        try:
            s3_client.put_object(
                Bucket=bucket,
                Key=object_key,
                Body=artifact,
                ContentType="application/json",
                ChecksumSHA256=b64encode(digest).decode("ascii"),
                Metadata={"sha256": digest.hex()},
                IfNoneMatch="*",
            )
            return
        except ClientError as exc:
            status = _conditional_write_status(exc)
            if status == 412:
                _verify_existing_artifact(
                    s3_client,
                    bucket,
                    object_key,
                    artifact,
                    digest,
                    verify_body=verify_existing_body,
                )
                return
            if status != 409:
                raise
            if attempt == MAX_CONDITIONAL_WRITE_ATTEMPTS:
                raise RuntimeError(
                    "conditional output publication remained conflicted after "
                    f"{MAX_CONDITIONAL_WRITE_ATTEMPTS} attempts: {object_key}"
                ) from exc


def _download_package(s3_client: Any, bucket: str, job: ProcessingJob):
    max_bytes = _positive_int_env("MAX_PACKAGE_SIZE_BYTES", DEFAULT_MAX_PACKAGE_BYTES)
    chunk_bytes = _positive_int_env("UPLOAD_STREAM_CHUNK_BYTES", DEFAULT_STREAM_CHUNK_BYTES)
    spool_bytes = _positive_int_env("UPLOAD_SPOOL_MEMORY_BYTES", DEFAULT_SPOOL_MEMORY_BYTES)
    head = s3_client.head_object(Bucket=bucket, Key=job.object_key)
    expected_length = int(head.get("ContentLength", -1))
    if expected_length < 1:
        raise RuntimeError("package ContentLength must be positive")
    if expected_length > max_bytes:
        raise RuntimeError("package ContentLength exceeds MAX_PACKAGE_SIZE_BYTES")

    response = s3_client.get_object(Bucket=bucket, Key=job.object_key)
    response_length = int(response.get("ContentLength", expected_length))
    if response_length != expected_length:
        raise RuntimeError("package ContentLength changed between HEAD and GET")
    body = response["Body"]
    # Ownership is transferred to the caller, which uses the returned file as a context manager.
    package_file = tempfile.SpooledTemporaryFile(  # noqa: SIM115
        max_size=spool_bytes,
        mode="w+b",
    )
    digest = hashlib.sha256()
    total = 0
    try:
        while True:
            chunk = body.read(chunk_bytes)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes or total > expected_length:
                raise RuntimeError("package body exceeds its bounded ContentLength")
            digest.update(chunk)
            package_file.write(chunk)
    except Exception:
        package_file.close()
        raise
    finally:
        close = getattr(body, "close", None)
        if close is not None:
            close()

    if total != expected_length:
        package_file.close()
        raise RuntimeError("package body is truncated")
    if digest.hexdigest() != _expected_package_sha256(job.object_key):
        package_file.close()
        raise RuntimeError("package SHA-256 does not match the content-addressed object key")
    package_file.seek(0)
    return package_file


def _worker_token() -> str | None:
    token = os.getenv("WORKFLOW_WORKER_TOKEN")
    environment = os.getenv("ENVIRONMENT", "development").lower()
    if environment not in {"development", "dev", "local", "test"} and not token:
        raise RuntimeError("WORKFLOW_WORKER_TOKEN is required outside development")
    return token


def post_completion(
    completion: ProcessingCompletion,
    *,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    api_base_url = os.getenv("API_BASE_URL", "http://api:8000").rstrip("/")
    url = (
        f"{api_base_url}/v1/internal/sessions/"
        f"{completion.session_id}/processing-completion"
    )
    body = completion.model_dump_json().encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Idempotency-Key": completion.idempotency_key,
    }
    token = _worker_token()
    if token:
        headers["X-Workflow-Worker-Token"] = token

    attempts = _positive_int_env("WORKER_CALLBACK_MAX_ATTEMPTS", DEFAULT_MAX_RETRIES)
    base_delay = float(os.getenv("WORKER_RETRY_BASE_SECONDS", str(DEFAULT_RETRY_BASE_SECONDS)))
    for attempt in range(1, attempts + 1):
        try:
            request = Request(url, data=body, method="POST", headers=headers)
            with urlopen(request, timeout=10) as response:
                if 200 <= response.status < 300:
                    return
                raise RuntimeError(f"completion API returned {response.status}")
        except (HTTPError, URLError, TimeoutError, RuntimeError) as exc:
            if attempt == attempts:
                raise RuntimeError(
                    f"completion callback failed after {attempts} attempts"
                ) from exc
            sleep(min(base_delay * (2 ** (attempt - 1)), 10.0))


def process_message(
    body: str,
    *,
    s3: Any | None = None,
    completion_callback: Callable[[ProcessingCompletion], None] = post_completion,
) -> ProcessingCompletion:
    job = ProcessingJob.model_validate_json(body)
    raw_bucket = os.environ["RAW_BUCKET"]
    processed_bucket = os.environ["PROCESSED_BUCKET"]
    s3_client = s3 or _client("s3")
    with _download_package(s3_client, raw_bucket, job) as package_file:
        result = process_package(job.session_id, package_file)
    output_key = f"sessions/{job.session_id}/timeline.json"
    artifact = _artifact_bytes(result)
    _publish_artifact(s3_client, processed_bucket, output_key, artifact)
    completion = _completion_for(result, output_key)
    completion_callback(completion)
    LOGGER.info(
        "processed session %s with %s meaningful events",
        job.session_id,
        result.meaningful_event_count,
    )
    return completion


def process_message_v2(
    body: str,
    *,
    s3: Any | None = None,
    completion_callback: Callable[[ProcessingCompletionV2], None] = post_completion,
) -> ProcessingCompletionV2:
    """Process an existing v1 queue envelope and publish the v2 result."""
    job = ProcessingJob.model_validate_json(body)
    raw_bucket = os.environ["RAW_BUCKET"]
    processed_bucket = os.environ["PROCESSED_BUCKET"]
    s3_client = s3 or _client("s3")
    with _download_package(s3_client, raw_bucket, job) as package_file:
        result = process_package_v2(job.session_id, package_file)
    output_key = f"sessions/{job.session_id}/timeline-v2.json"
    artifact = artifact_bytes_v2(result)
    _publish_artifact(
        s3_client,
        processed_bucket,
        output_key,
        artifact,
        verify_existing_body=True,
    )
    completion = completion_for_v2(result, output_key)
    completion_callback(completion)
    LOGGER.info(
        "processed v2 session %s with %s operation segments",
        job.session_id,
        len(result.operation_segments),
    )
    return completion


def run_forever() -> None:
    queue_url = os.getenv("PROCESSING_QUEUE_URL")
    if not queue_url:
        raise RuntimeError("PROCESSING_QUEUE_URL is required")
    sqs = _client("sqs")
    max_service_failures = _positive_int_env(
        "WORKER_MAX_SERVICE_FAILURES", DEFAULT_MAX_RETRIES
    )
    max_message_attempts = _positive_int_env(
        "WORKER_MAX_MESSAGE_ATTEMPTS", DEFAULT_MAX_RETRIES
    )
    consecutive_service_failures = 0
    while True:
        try:
            response = sqs.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=1,
                WaitTimeSeconds=20,
                VisibilityTimeout=120,
                AttributeNames=["ApproximateReceiveCount"],
            )
            consecutive_service_failures = 0
        except Exception:
            consecutive_service_failures += 1
            LOGGER.exception(
                "queue receive failed (%s/%s)",
                consecutive_service_failures,
                max_service_failures,
            )
            if consecutive_service_failures >= max_service_failures:
                raise
            time.sleep(min(2 ** (consecutive_service_failures - 1), 10))
            continue

        for message in response.get("Messages", []):
            receive_count = int(message.get("Attributes", {}).get("ApproximateReceiveCount", "1"))
            try:
                process_message_v2(message["Body"])
            except Exception:
                LOGGER.exception(
                    "processing failed on attempt %s/%s",
                    receive_count,
                    max_message_attempts,
                )
                if receive_count >= max_message_attempts:
                    LOGGER.error("message reached the bounded retry limit; awaiting SQS redrive")
                continue
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])


def main() -> None:
    run_forever()


if __name__ == "__main__":
    main()
