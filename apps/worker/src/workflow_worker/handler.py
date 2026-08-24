import io
import json
import zipfile
from typing import BinaryIO
from uuid import UUID

from .models import CadEvent, ProcessingResult
from .pipeline import process_events
from .processing_v2 import ProcessingResultV2, process_events_v2

MAX_MEMBER_BYTES = 100 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 10_000
MAX_EVENT_LINE_BYTES = 256 * 1024
MAX_EVENT_LINES = 100_000
MAX_METADATA_BYTES = 1024 * 1024


class UnsafePackageError(ValueError):
    pass


def _validated_members(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    members = archive.infolist()
    if len(members) > MAX_MEMBERS:
        raise UnsafePackageError("package contains too many files")
    if sum(member.file_size for member in members) > MAX_TOTAL_BYTES:
        raise UnsafePackageError("package uncompressed size exceeds the limit")
    result: dict[str, zipfile.ZipInfo] = {}
    for member in members:
        path = member.filename.replace("\\", "/")
        if path.startswith(("/", "../")) or path == ".." or "/../" in path:
            raise UnsafePackageError("package contains an unsafe path")
        if member.file_size > MAX_MEMBER_BYTES:
            raise UnsafePackageError("package member exceeds the size limit")
        result[path] = member
    return result


def _validate_metadata_binding(
    archive: zipfile.ZipFile,
    metadata_member: zipfile.ZipInfo | None,
    session_id: UUID,
) -> None:
    if metadata_member is None:
        raise UnsafePackageError("metadata.json is required")
    with archive.open(metadata_member) as metadata_stream:
        raw_metadata = metadata_stream.read(MAX_METADATA_BYTES + 1)
    if len(raw_metadata) > MAX_METADATA_BYTES:
        raise UnsafePackageError("metadata.json exceeds the byte limit")
    try:
        metadata = json.loads(raw_metadata.decode("utf-8"))
        metadata_session_id = UUID(str(metadata["session_id"]))
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise UnsafePackageError("metadata.json binding fields are invalid") from exc
    if metadata.get("schema_version") != "1.0":
        raise UnsafePackageError("metadata.json schema_version is unsupported")
    if metadata_session_id != session_id:
        raise UnsafePackageError("metadata.json session_id does not match the processing job")


def process_package(session_id: UUID, package_source: bytes | BinaryIO) -> ProcessingResult:
    return process_events(session_id, _package_events(session_id, package_source))


def process_package_v2(
    session_id: UUID,
    package_source: bytes | BinaryIO,
) -> ProcessingResultV2:
    return process_events_v2(session_id, _package_events(session_id, package_source))


def _package_events(
    session_id: UUID,
    package_source: bytes | BinaryIO,
) -> list[CadEvent]:
    source = io.BytesIO(package_source) if isinstance(package_source, bytes) else package_source
    with zipfile.ZipFile(source) as archive:
        members = _validated_members(archive)
        _validate_metadata_binding(archive, members.get("metadata.json"), session_id)
        events_member = members.get("events.jsonl")
        if events_member is None:
            return []
        events: list[CadEvent] = []
        with archive.open(events_member) as event_stream:
            for line_number in range(1, MAX_EVENT_LINES + 2):
                raw_line = event_stream.readline(MAX_EVENT_LINE_BYTES + 1)
                if not raw_line:
                    break
                if len(raw_line) > MAX_EVENT_LINE_BYTES:
                    raise UnsafePackageError(
                        f"events.jsonl line {line_number} exceeds the byte limit"
                    )
                if line_number > MAX_EVENT_LINES:
                    raise UnsafePackageError("events.jsonl contains too many lines")
                if not raw_line.strip():
                    continue
                try:
                    line = raw_line.decode("utf-8")
                    payload = json.loads(line)
                    events.append(CadEvent.model_validate(payload))
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                    raise UnsafePackageError(
                        f"events.jsonl line {line_number} is invalid"
                    ) from exc
        return events
