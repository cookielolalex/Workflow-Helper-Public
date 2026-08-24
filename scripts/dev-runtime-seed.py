#!/usr/bin/env python3
"""Seed one canonical synthetic candidate through the sealed dev runtime."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import os
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit
from uuid import UUID

from workflow_worker.main import process_message_v2

from workflow_api import dev_server
from workflow_api.artifact_gateway import ArtifactAuthority, NoNetworkArtifactGateway
from workflow_api.control_scope import TenantWorkspaceScope
from workflow_api.runtime_bundle import SealedSyntheticRuntimeBundle

_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_SCOPE = TenantWorkspaceScope("tenant.synthetic", "workspace.synthetic")
_CAPTURE_SUBJECT = "capture-uploader.synthetic"


@dataclass(frozen=True, slots=True)
class _Response:
    status: int
    headers: tuple[tuple[bytes, bytes], ...]
    body: bytes

    def json(self) -> object:
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("synthetic runtime returned an invalid response") from exc


class _ASGIDriver:
    """A bounded single-request ASGI harness using only the standard library."""

    def __init__(self, application: Any) -> None:
        self._application = application

    def request(
        self,
        method: str,
        target: str,
        *,
        headers: dict[str, str] | None = None,
        payload: object | None = None,
    ) -> _Response:
        if method not in {"GET", "POST"}:
            raise RuntimeError("synthetic runtime request method is not allowed")
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or parsed.fragment or not parsed.path.startswith("/"):
            raise RuntimeError("synthetic runtime request target is invalid")
        body = b""
        request_headers = {
            "accept": "application/json",
            "host": "api.synthetic",
            **(headers or {}),
        }
        if payload is not None:
            body = json.dumps(
                payload,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            request_headers["content-type"] = "application/json"
        if len(body) > _MAX_REQUEST_BYTES:
            raise RuntimeError("synthetic runtime request exceeds its bound")
        request_headers["content-length"] = str(len(body))
        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": parsed.path,
            "raw_path": parsed.path.encode("ascii"),
            "query_string": parsed.query.encode("ascii"),
            "root_path": "",
            "headers": tuple(
                (name.lower().encode("ascii"), value.encode("ascii"))
                for name, value in request_headers.items()
            ),
            "client": ("127.0.0.1", 1),
            "server": ("api.synthetic", 80),
        }
        return asyncio.run(self._request(scope, body))

    async def _request(self, scope: dict[str, object], body: bytes) -> _Response:
        received = False
        status: int | None = None
        response_headers: tuple[tuple[bytes, bytes], ...] = ()
        response_body = bytearray()

        async def receive() -> dict[str, object]:
            nonlocal received
            if received:
                return {"type": "http.disconnect"}
            received = True
            return {"type": "http.request", "body": body, "more_body": False}

        async def send(message: dict[str, object]) -> None:
            nonlocal status, response_headers
            message_type = message.get("type")
            if message_type == "http.response.start":
                if status is not None:
                    raise RuntimeError("synthetic runtime returned duplicate headers")
                value = message.get("status")
                headers = message.get("headers")
                if type(value) is not int or not isinstance(headers, list):
                    raise RuntimeError("synthetic runtime returned invalid headers")
                status = value
                response_headers = tuple(headers)
                return
            if message_type != "http.response.body" or status is None:
                raise RuntimeError("synthetic runtime returned an invalid ASGI message")
            chunk = message.get("body", b"")
            if type(chunk) is not bytes:
                raise RuntimeError("synthetic runtime returned an invalid body")
            response_body.extend(chunk)
            if len(response_body) > _MAX_RESPONSE_BYTES:
                raise RuntimeError("synthetic runtime response exceeds its bound")

        await self._application(scope, receive, send)
        if status is None:
            raise RuntimeError("synthetic runtime returned no response")
        return _Response(status, response_headers, bytes(response_body))


class _InMemoryS3:
    """Exact bounded object operations used by the default v2 worker."""

    def __init__(self, raw_bucket: str, object_key: str, package: bytes) -> None:
        self._objects: dict[tuple[str, str], bytes] = {
            (raw_bucket, object_key): package,
        }

    def head_object(self, *, Bucket: str, Key: str, **_kwargs: object) -> dict[str, object]:
        body = self._objects.get((Bucket, Key))
        if body is None:
            raise RuntimeError("synthetic object is unavailable")
        digest = hashlib.sha256(body).digest()
        return {
            "ContentLength": len(body),
            "ChecksumSHA256": base64.b64encode(digest).decode("ascii"),
            "Metadata": {"sha256": digest.hex()},
        }

    def get_object(self, *, Bucket: str, Key: str, **_kwargs: object) -> dict[str, object]:
        body = self._objects.get((Bucket, Key))
        if body is None:
            raise RuntimeError("synthetic object is unavailable")
        return {"ContentLength": len(body), "Body": io.BytesIO(body)}

    def put_object(self, *, Bucket: str, Key: str, Body: bytes, **kwargs: object) -> None:
        if type(Body) is not bytes or kwargs.get("IfNoneMatch") != "*":
            raise RuntimeError("synthetic output publication is invalid")
        target = (Bucket, Key)
        if target in self._objects:
            raise RuntimeError("synthetic output already exists")
        expected = base64.b64encode(hashlib.sha256(Body).digest()).decode("ascii")
        metadata = kwargs.get("Metadata")
        if (
            kwargs.get("ChecksumSHA256") != expected
            or type(metadata) is not dict
            or metadata.get("sha256") != hashlib.sha256(Body).hexdigest()
        ):
            raise RuntimeError("synthetic output digest is invalid")
        self._objects[target] = Body


def _contract_path() -> Path:
    value = os.environ.get("WORKFLOW_DEV_CONTRACT_PATH")
    if type(value) is not str or value != value.strip() or not value:
        raise RuntimeError("canonical synthetic contract path is required")
    path = Path(value)
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_file()
        or path.name != "session.json"
        or path.stat().st_size > 1024 * 1024
    ):
        raise RuntimeError("canonical synthetic contract path is invalid")
    return path


def _canonical_package() -> tuple[dict[str, object], bytes]:
    path = _contract_path()
    raw = path.read_bytes()
    try:
        session = json.loads(raw.decode("utf-8"))
        events = session["cad_events"]
        UUID(session["session_id"])
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("canonical synthetic contract is invalid") from exc
    if type(session) is not dict or not isinstance(events, list) or session.get("recording") is not None:
        raise RuntimeError("canonical synthetic contract is invalid")

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        metadata = zipfile.ZipInfo("metadata.json", date_time=(1980, 1, 1, 0, 0, 0))
        metadata.compress_type = zipfile.ZIP_STORED
        metadata.external_attr = 0o600 << 16
        archive.writestr(metadata, raw)
        event_bytes = (
            "\n".join(
                json.dumps(event, ensure_ascii=False, separators=(",", ":"))
                for event in events
            )
            + "\n"
        ).encode("utf-8")
        event_info = zipfile.ZipInfo("events.jsonl", date_time=(1980, 1, 1, 0, 0, 0))
        event_info.compress_type = zipfile.ZIP_STORED
        event_info.external_attr = 0o600 << 16
        archive.writestr(event_info, event_bytes)
    return session, output.getvalue()


def _require_status(response: _Response, expected: int) -> object:
    if response.status != expected:
        raise RuntimeError("synthetic runtime route failed")
    return response.json()


def _reviewer_headers() -> dict[str, str]:
    return {
        "cookie": "workflow_session=" + os.environ["WORKFLOW_DEV_REVIEWER_SESSION"],
        "x-workflow-dev-reviewer-proof": os.environ["WORKFLOW_DEV_REVIEWER_PROOF"],
    }


def _candidate_listing(driver: _ASGIDriver, correlation: str) -> dict[str, object]:
    response = driver.request(
        "GET",
        "/v1/control/candidate-publications?" + urlencode(
            {"correlation_id": correlation, "limit": "100"}
        ),
        headers=_reviewer_headers(),
    )
    value = _require_status(response, 200)
    if type(value) is not dict:
        raise RuntimeError("synthetic candidate listing is invalid")
    return value


def seed() -> None:
    application = dev_server.open_existing_app()
    bundle = application.state.runtime_bundle
    if (
        type(bundle) is not SealedSyntheticRuntimeBundle
        or type(bundle.artifact_gateway) is not NoNetworkArtifactGateway
    ):
        raise RuntimeError("synthetic runtime bundle is unavailable")
    driver = _ASGIDriver(application)
    session, package = _canonical_package()
    session_id = UUID(session["session_id"])
    package_sha256 = hashlib.sha256(package).hexdigest()
    capture_headers = {
        "x-workflow-dev-proof": os.environ["WORKFLOW_DEV_CAPTURE_PROOF"]
    }
    worker_headers = {
        "x-workflow-dev-proof": os.environ["WORKFLOW_DEV_WORKER_PROOF"]
    }
    registration = {
        key: session[key]
        for key in (
            "schema_version",
            "session_id",
            "machine_id",
            "project_id",
            "started_at",
            "ended_at",
            "active_duration_seconds",
            "approved_process",
        )
    }
    registration.update(
        package_sha256=package_sha256,
        package_size_bytes=len(package),
    )
    _require_status(
        driver.request("POST", "/v1/sessions", headers=capture_headers, payload=registration),
        201,
    )
    upload = _require_status(
        driver.request(
            "POST",
            f"/v1/sessions/{session_id}/upload-url",
            headers=capture_headers,
        ),
        200,
    )
    if type(upload) is not dict or type(upload.get("object_key")) is not str:
        raise RuntimeError("synthetic upload ticket is invalid")
    object_key = upload["object_key"]
    expected_key = f"sessions/{session_id}/packages/{package_sha256}.zip"
    if object_key != expected_key:
        raise RuntimeError("synthetic upload ticket is invalid")
    bundle.artifact_gateway.record_receipt(
        authority=ArtifactAuthority(_SCOPE, _CAPTURE_SUBJECT),
        object_key=object_key,
        package_sha256=package_sha256,
        package_size_bytes=len(package),
    )
    _require_status(
        driver.request(
            "POST",
            f"/v1/sessions/{session_id}/uploaded",
            headers=capture_headers,
            payload={"object_key": object_key},
        ),
        202,
    )
    queued = bundle.artifact_gateway.queue_evidence
    if len(queued) != 1 or queued[0].object_key != object_key:
        raise RuntimeError("synthetic processing queue evidence is invalid")
    queued_body = json.dumps(
        {
            "schema_version": "1.0",
            "session_id": str(session_id),
            "object_key": object_key,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    callback_order: list[str] = []

    def complete(completion: Any) -> None:
        callback_order.append("completion")
        _require_status(
            driver.request(
                "POST",
                f"/v1/internal/sessions/{session_id}/processing-completion",
                headers=worker_headers,
                payload=completion.model_dump(mode="json"),
            ),
            200,
        )

    def publish(evidence: dict[str, Any]) -> None:
        callback_order.append("candidate")
        _require_status(
            driver.request(
                "POST",
                f"/v1/internal/sessions/{session_id}/candidate-publication",
                headers=worker_headers,
                payload=evidence,
            ),
            200,
        )

    raw_bucket = os.environ.get("RAW_BUCKET")
    processed_bucket = os.environ.get("PROCESSED_BUCKET")
    if not raw_bucket or not processed_bucket:
        raise RuntimeError("synthetic worker buckets are required")
    process_message_v2(
        queued_body,
        s3=_InMemoryS3(raw_bucket, object_key, package),
        completion_callback=complete,
        candidate_callback=publish,
    )
    if callback_order != ["completion", "candidate"]:
        raise RuntimeError("synthetic worker callback order is invalid")
    listing = _candidate_listing(driver, "dev-seed")
    if listing.get("count") != 1:
        raise RuntimeError("synthetic candidate was not published")


def verify_empty() -> None:
    driver = _ASGIDriver(dev_server.open_existing_app())
    listing = _candidate_listing(driver, "dev-independent-verify")
    if listing.get("count") != 0 or listing.get("items") != []:
        raise RuntimeError("synthetic candidate review is not durable")


def main() -> None:
    if sys.argv == [sys.argv[0]]:
        seed()
        print("synthetic candidate seed complete")
        return
    if sys.argv == [sys.argv[0], "--verify-empty"]:
        verify_empty()
        print("synthetic candidate durability verified")
        return
    raise SystemExit("usage: dev-runtime-seed.py [--verify-empty]")


if __name__ == "__main__":
    main()
