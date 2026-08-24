import base64
import hashlib
import json
import tempfile
import zipfile
from functools import lru_cache
from uuid import UUID

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from pydantic import ValidationError

from .artifact_gateway import ArtifactAuthority, _require_artifact_authority
from .config import Settings, get_settings
from .models import PackageMetadata, SessionRecord


class ProcessingQueueError(RuntimeError):
    pass


class AwsGateway:
    def __init__(self, settings: Settings) -> None:
        internal_options = {
            "region_name": settings.aws_region,
            "endpoint_url": settings.aws_endpoint_url,
        }
        self._settings = settings
        self._s3 = boto3.client("s3", **internal_options)
        self._sqs = boto3.client("sqs", **internal_options)
        self._presign_s3 = boto3.client(
            "s3",
            region_name=settings.aws_region,
            endpoint_url=settings.aws_s3_presigned_endpoint_url or settings.aws_endpoint_url,
            config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
        )

    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def presigned_url_ttl_seconds(self) -> int:
        return self._settings.presigned_url_ttl_seconds

    @property
    def max_package_size_bytes(self) -> int:
        return self._settings.max_package_size_bytes

    @staticmethod
    def checksum_sha256_header(sha256: str) -> str:
        return base64.b64encode(bytes.fromhex(sha256)).decode("ascii")

    def create_package_upload(
        self,
        authority: ArtifactAuthority,
        session_id: UUID,
        package_sha256: str,
        package_size_bytes: int,
    ) -> tuple[str, str, dict[str, str]]:
        _require_artifact_authority(authority)
        if package_size_bytes > self._settings.max_package_size_bytes:
            raise ValueError("package compressed size exceeds the configured limit")
        object_key = f"sessions/{session_id}/packages/{package_sha256}.zip"
        checksum = self.checksum_sha256_header(package_sha256)
        url = self._presign_s3.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": self._settings.raw_bucket,
                "Key": object_key,
                "ContentType": "application/zip",
                "ContentLength": package_size_bytes,
                "ChecksumSHA256": checksum,
                "IfNoneMatch": "*",
                "Metadata": {"sha256": package_sha256},
            },
            ExpiresIn=self._settings.presigned_url_ttl_seconds,
        )
        return object_key, url, {
            "Content-Type": "application/zip",
            "Content-Length": str(package_size_bytes),
            "If-None-Match": "*",
            "x-amz-checksum-sha256": checksum,
            "x-amz-meta-sha256": package_sha256,
        }

    def enqueue_processing(
        self, authority: ArtifactAuthority, session_id: UUID, object_key: str
    ) -> None:
        _require_artifact_authority(authority)
        if not self._settings.processing_queue_url:
            development = self._settings.environment.lower() in {
                "development",
                "dev",
                "local",
                "test",
            }
            if development:
                return
            raise ProcessingQueueError("processing queue is not configured")
        try:
            self._sqs.send_message(
                QueueUrl=self._settings.processing_queue_url,
                MessageBody=json.dumps(
                    {
                        "schema_version": "1.0",
                        "session_id": str(session_id),
                        "object_key": object_key,
                    }
                ),
            )
        except (BotoCoreError, ClientError) as exc:
            raise ProcessingQueueError("processing queue is temporarily unavailable") from exc

    def verify_package_upload(
        self,
        authority: ArtifactAuthority,
        object_key: str,
        registration: SessionRecord,
    ) -> None:
        _require_artifact_authority(authority)
        size_bytes = registration.package_size_bytes
        sha256 = registration.package_sha256
        if size_bytes > self._settings.max_package_size_bytes:
            raise ValueError("package compressed size exceeds the configured limit")
        response = self._s3.head_object(
            Bucket=self._settings.raw_bucket,
            Key=object_key,
            ChecksumMode="ENABLED",
        )
        stored_sha256 = response.get("Metadata", {}).get("sha256")
        if stored_sha256 != sha256:
            raise ValueError("uploaded package hash metadata does not match registration")
        if response.get("ContentLength") != size_bytes:
            raise ValueError("uploaded package size does not match registration")
        checksum = response.get("ChecksumSHA256")
        if checksum != self.checksum_sha256_header(sha256):
            raise ValueError("uploaded package provider checksum does not match registration")

        get_options: dict[str, object] = {
            "Bucket": self._settings.raw_bucket,
            "Key": object_key,
        }
        etag = response.get("ETag")
        if etag:
            get_options["IfMatch"] = etag
        package = self._s3.get_object(**get_options)["Body"]
        digest = hashlib.sha256()
        total = 0
        try:
            with tempfile.SpooledTemporaryFile(
                max_size=self._settings.upload_spool_memory_bytes, mode="w+b"
            ) as temporary:
                while True:
                    chunk = package.read(self._settings.upload_stream_chunk_bytes)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > size_bytes or total > self._settings.max_package_size_bytes:
                        raise ValueError(
                            "uploaded package exceeds the registered or configured size"
                        )
                    digest.update(chunk)
                    temporary.write(chunk)
                if total != size_bytes:
                    raise ValueError("downloaded package size does not match registration")
                if digest.hexdigest() != sha256:
                    raise ValueError("uploaded package content hash does not match registration")
                temporary.seek(0)
                self._validate_metadata(temporary, registration)
        finally:
            package.close()

    def _validate_metadata(self, package, registration: SessionRecord) -> None:
        try:
            with zipfile.ZipFile(package) as archive:
                matches = [item for item in archive.infolist() if item.filename == "metadata.json"]
                if len(matches) != 1:
                    raise ValueError("package must contain exactly one root metadata.json")
                member = matches[0]
                if member.file_size > self._settings.max_metadata_size_bytes:
                    raise ValueError("metadata.json exceeds the configured limit")
                with archive.open(member) as metadata_file:
                    raw = metadata_file.read(self._settings.max_metadata_size_bytes + 1)
                    if len(raw) > self._settings.max_metadata_size_bytes:
                        raise ValueError("metadata.json exceeds the configured limit")
                metadata = PackageMetadata.model_validate_json(raw)
        except (zipfile.BadZipFile, UnicodeDecodeError, ValidationError, RuntimeError) as exc:
            raise ValueError("package metadata.json is invalid") from exc
        metadata.assert_matches_registration(registration)


@lru_cache
def get_aws_gateway() -> AwsGateway:
    return AwsGateway(get_settings())
