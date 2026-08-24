import sqlite3
from collections.abc import Callable, Coroutine
from dataclasses import asdict
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from ..artifact_gateway import (
    ArtifactAuthority,
    ArtifactGateway,
    ArtifactGatewayUnavailableError,
)
from ..candidate_publication_service import (
    CandidatePublicationRequest,
    CandidatePublicationService,
)
from ..candidate_publication_store import (
    CandidatePublicationError,
    CandidatePublicationValidationError,
    NoCandidateError,
    SQLiteCandidatePublicationStore,
)
from ..config import Settings
from ..control_auth import ControlAction
from ..dependencies import (
    RuntimeBundleDependency,
    get_artifact_gateway,
    get_provider_neutral_security_composition,
    get_runtime_settings,
)
from ..identity import IdentityRejectedError
from ..legacy_session_composition import (
    LegacySessionCompositionUnavailableError,
    ProviderNeutralSecurityComposition,
)
from ..legacy_session_security import (
    AuthorizedLegacySessionRequest,
    LegacySessionAudience,
    LegacySessionSecurityRejectedError,
    LegacySessionTransport,
)
from ..models import (
    ProcessingCompletionPayload,
    ProcessingJobV2,
    ProcessingResultPayload,
    ProcessingResultV2,
    SessionCreate,
    SessionList,
    SessionRecord,
    UploadComplete,
    UploadUrlResponse,
)
from ..repository import (
    SessionConflictError,
    SessionNotFoundError,
)
from ..runtime_bundle import SealedSyntheticRuntimeBundle
from ..session_security import SessionSecurityRejectedError

SettingsDependency = Annotated[Settings, Depends(get_runtime_settings)]
ArtifactGatewayDependency = Annotated[ArtifactGateway, Depends(get_artifact_gateway)]
CompositionDependency = Annotated[
    ProviderNeutralSecurityComposition,
    Depends(get_provider_neutral_security_composition),
]
Guard = Callable[..., Coroutine[Any, Any, AuthorizedLegacySessionRequest]]
StoreOperationalError = (sqlite3.Error, RuntimeError, OSError)
_CANDIDATE_PUBLICATION_FIELDS = frozenset(
    {
        "envelope_version",
        "job",
        "result",
        "result_manifest",
        "timeline_binding",
        "drawing_ref",
        "occurrences",
        "rejected_alternative_count",
        "qualifying_run_length",
    }
)


def _workload_guard(
    *,
    action: ControlAction,
    audience: LegacySessionAudience,
    transport: LegacySessionTransport,
) -> Guard:
    async def guard(
        request: Request,
        composition: CompositionDependency,
    ) -> AuthorizedLegacySessionRequest:
        if request.url.query:
            raise _authorization_rejected()
        if type(composition) is not ProviderNeutralSecurityComposition:
            raise _service_unavailable()
        try:
            return await composition.authorize_workload(
                request=request,
                action=action,
                audience=audience,
                transport=transport,
            )
        except LegacySessionCompositionUnavailableError as exc:
            raise _service_unavailable() from exc
        except LegacySessionSecurityRejectedError as exc:
            raise _authorization_rejected() from exc

    return guard


def _browser_guard(*, action: ControlAction) -> Guard:
    async def guard(
        request: Request,
        composition: CompositionDependency,
    ) -> AuthorizedLegacySessionRequest:
        if request.url.query:
            raise _authorization_rejected()
        if type(composition) is not ProviderNeutralSecurityComposition:
            raise _service_unavailable()
        try:
            return composition.authorize_browser_request(
                request=request,
                action=action,
            )
        except LegacySessionCompositionUnavailableError as exc:
            raise _service_unavailable() from exc
        except (
            IdentityRejectedError,
            LegacySessionSecurityRejectedError,
            SessionSecurityRejectedError,
        ) as exc:
            raise _authorization_rejected() from exc

    return guard


def _authorization_rejected() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="request authorization rejected",
    )


def _service_unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="legacy session service unavailable",
    )


def _session_absent() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session unavailable")


def _session_conflict() -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail="session conflict")


require_capture_register = _workload_guard(
    action=ControlAction.SESSION_REGISTER,
    audience=LegacySessionAudience.CAPTURE_UPLOAD,
    transport=LegacySessionTransport.CAPTURE_WORKLOAD,
)
require_capture_presign = _workload_guard(
    action=ControlAction.SESSION_PRESIGN,
    audience=LegacySessionAudience.CAPTURE_UPLOAD,
    transport=LegacySessionTransport.CAPTURE_WORKLOAD,
)
require_capture_upload_complete = _workload_guard(
    action=ControlAction.SESSION_UPLOAD_COMPLETE,
    audience=LegacySessionAudience.CAPTURE_UPLOAD,
    transport=LegacySessionTransport.CAPTURE_WORKLOAD,
)
require_worker_completion = _workload_guard(
    action=ControlAction.SESSION_PROCESSING_COMPLETE,
    audience=LegacySessionAudience.PROCESSING_COMPLETION,
    transport=LegacySessionTransport.WORKER_WORKLOAD,
)
require_reviewer_list = _browser_guard(action=ControlAction.SESSION_LIST)
require_reviewer_read = _browser_guard(action=ControlAction.SESSION_READ)
require_reviewer_timeline = _browser_guard(action=ControlAction.SESSION_TIMELINE_READ)

router = APIRouter(prefix="/v1/sessions", tags=["sessions"])
internal_router = APIRouter(prefix="/v1/internal/sessions", tags=["internal"])
candidate_internal_router = APIRouter(
    prefix="/v1/internal/sessions",
    tags=["internal"],
)


@router.post("", response_model=SessionRecord, status_code=status.HTTP_201_CREATED)
async def register_session(
    authorization: Annotated[AuthorizedLegacySessionRequest, Depends(require_capture_register)],
    payload: SessionCreate,
    composition: CompositionDependency,
    settings: SettingsDependency,
) -> SessionRecord:
    if payload.ended_at < payload.started_at:
        raise HTTPException(status_code=422, detail="request rejected")
    if payload.package_size_bytes > settings.max_package_size_bytes:
        raise HTTPException(status_code=413, detail="request rejected")
    try:
        return await composition.store.create(
            payload,
            settings.raw_retention_days,
            scope=authorization.scope,
            owner_subject=authorization.principal.subject,
            actor_subject=authorization.principal.subject,
        )
    except SessionNotFoundError as exc:
        raise _session_absent() from exc
    except SessionConflictError as exc:
        raise _session_conflict() from exc
    except StoreOperationalError as exc:
        raise _service_unavailable() from exc


@router.get("", response_model=SessionList)
async def list_sessions(
    authorization: Annotated[AuthorizedLegacySessionRequest, Depends(require_reviewer_list)],
    composition: CompositionDependency,
) -> SessionList:
    try:
        items = await composition.store.list(scope=authorization.scope)
    except StoreOperationalError as exc:
        raise _service_unavailable() from exc
    return SessionList(items=items, count=len(items))


@router.get("/{session_id}", response_model=SessionRecord)
async def get_session(
    session_id: UUID,
    authorization: Annotated[AuthorizedLegacySessionRequest, Depends(require_reviewer_read)],
    composition: CompositionDependency,
) -> SessionRecord:
    try:
        return await composition.store.get(session_id, scope=authorization.scope)
    except SessionNotFoundError as exc:
        raise _session_absent() from exc
    except StoreOperationalError as exc:
        raise _service_unavailable() from exc


@router.post("/{session_id}/upload-url", response_model=UploadUrlResponse)
async def create_upload_url(
    session_id: UUID,
    authorization: Annotated[AuthorizedLegacySessionRequest, Depends(require_capture_presign)],
    composition: CompositionDependency,
    gateway: ArtifactGatewayDependency,
) -> UploadUrlResponse:
    try:
        record = await composition.store.get(
            session_id,
            scope=authorization.scope,
            owner_subject=authorization.principal.subject,
        )
    except SessionNotFoundError as exc:
        raise _session_absent() from exc
    except StoreOperationalError as exc:
        raise _service_unavailable() from exc
    try:
        authority = ArtifactAuthority(
            authorization.scope,
            authorization.principal.subject,
        )
        object_key, url, required_headers = gateway.create_package_upload(
            authority,
            session_id,
            record.package_sha256,
            record.package_size_bytes,
        )
    except ValueError as exc:
        raise _session_conflict() from exc
    except Exception as exc:
        raise _service_unavailable() from exc
    return UploadUrlResponse(
        upload_url=url,
        object_key=object_key,
        expires_in_seconds=gateway.presigned_url_ttl_seconds,
        required_headers=required_headers,
    )


@router.post("/{session_id}/uploaded", response_model=SessionRecord)
async def complete_upload(
    session_id: UUID,
    authorization: Annotated[
        AuthorizedLegacySessionRequest, Depends(require_capture_upload_complete)
    ],
    payload: UploadComplete,
    response: Response,
    composition: CompositionDependency,
    gateway: ArtifactGatewayDependency,
) -> SessionRecord:
    try:
        existing = await composition.store.get(
            session_id,
            scope=authorization.scope,
            owner_subject=authorization.principal.subject,
        )
    except SessionNotFoundError as exc:
        raise _session_absent() from exc
    except StoreOperationalError as exc:
        raise _service_unavailable() from exc
    expected_key = f"sessions/{session_id}/packages/{existing.package_sha256}.zip"
    if payload.object_key != expected_key:
        raise HTTPException(status_code=422, detail="request rejected")
    try:
        authority = ArtifactAuthority(
            authorization.scope,
            authorization.principal.subject,
        )
        gateway.verify_package_upload(authority, payload.object_key, existing)
    except ValueError as exc:
        raise _session_conflict() from exc
    except Exception as exc:
        raise _service_unavailable() from exc
    try:
        record, queue_pending = await composition.store.mark_uploaded(
            session_id,
            payload.object_key,
            scope=authorization.scope,
            owner_subject=authorization.principal.subject,
            actor_subject=authorization.principal.subject,
        )
    except SessionNotFoundError as exc:
        raise _session_absent() from exc
    except SessionConflictError as exc:
        raise _session_conflict() from exc
    except StoreOperationalError as exc:
        raise _service_unavailable() from exc
    if queue_pending:
        try:
            gateway.enqueue_processing(authority, session_id, payload.object_key)
        except ArtifactGatewayUnavailableError as exc:
            raise HTTPException(
                status_code=503,
                detail="legacy session service unavailable",
                headers={"Retry-After": "1"},
            ) from exc
        except Exception as exc:
            raise _service_unavailable() from exc
    response.status_code = status.HTTP_202_ACCEPTED
    return record


@router.get("/{session_id}/timeline", response_model=ProcessingResultPayload)
async def get_session_timeline(
    session_id: UUID,
    authorization: Annotated[
        AuthorizedLegacySessionRequest, Depends(require_reviewer_timeline)
    ],
    composition: CompositionDependency,
) -> ProcessingResultPayload:
    try:
        return await composition.store.get_timeline(session_id, scope=authorization.scope)
    except SessionNotFoundError as exc:
        raise _session_absent() from exc
    except StoreOperationalError as exc:
        raise _service_unavailable() from exc


@internal_router.post(
    "/{session_id}/processing-completion",
    response_model=SessionRecord,
    include_in_schema=False,
)
async def complete_processing(
    session_id: UUID,
    authorization: Annotated[
        AuthorizedLegacySessionRequest, Depends(require_worker_completion)
    ],
    payload: ProcessingCompletionPayload,
    composition: CompositionDependency,
) -> SessionRecord:
    if payload.session_id != session_id:
        raise HTTPException(status_code=422, detail="request rejected")
    try:
        return await composition.store.complete_processing(
            session_id,
            payload,
            scope=authorization.scope,
            actor_subject=authorization.principal.subject,
        )
    except SessionNotFoundError as exc:
        raise _session_absent() from exc
    except SessionConflictError as exc:
        raise _session_conflict() from exc
    except StoreOperationalError as exc:
        raise _service_unavailable() from exc


@candidate_internal_router.post(
    "/{session_id}/candidate-publication",
    include_in_schema=False,
)
async def publish_candidate(
    session_id: UUID,
    authorization: Annotated[
        AuthorizedLegacySessionRequest, Depends(require_worker_completion)
    ],
    payload: dict[str, Any],
    composition: CompositionDependency,
    bundle: RuntimeBundleDependency,
) -> dict[str, Any]:
    """Admit one worker-derived candidate only after durable v2 completion."""

    if type(payload) is not dict or set(payload) != _CANDIDATE_PUBLICATION_FIELDS:
        raise HTTPException(status_code=422, detail="request rejected")
    if type(composition) is not ProviderNeutralSecurityComposition:
        raise _service_unavailable()
    if (
        type(bundle) is not SealedSyntheticRuntimeBundle
        or type(bundle.candidate_publication_store) is not SQLiteCandidatePublicationStore
    ):
        raise _service_unavailable()

    try:
        job = ProcessingJobV2.model_validate(payload["job"])
        result = ProcessingResultV2.model_validate(payload["result"])
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="request rejected") from exc
    if job.session_id != session_id or result.session_id != session_id:
        raise HTTPException(status_code=422, detail="request rejected")

    try:
        persisted = await composition.store.get_timeline(
            session_id,
            scope=authorization.scope,
        )
    except SessionNotFoundError as exc:
        raise _session_absent() from exc
    except StoreOperationalError as exc:
        raise _service_unavailable() from exc
    if type(persisted) is not ProcessingResultV2 or (
        persisted.model_dump(mode="json") != result.model_dump(mode="json")
    ):
        raise _session_conflict()

    try:
        service = CandidatePublicationService(
            bundle.candidate_publication_store,
            bundle.control_service,
        )
        request = CandidatePublicationRequest(
            scope=authorization.scope,
            job=job,
            result=result,
            result_manifest=payload["result_manifest"],
            timeline_binding=payload["timeline_binding"],
            drawing_ref=payload["drawing_ref"],
            timeline_commands=payload["occurrences"],
            rejected_alternative_count=payload["rejected_alternative_count"],
            qualifying_run_length=payload["qualifying_run_length"],
            reservation_owner_id=authorization.principal.subject,
            lease_duration_seconds=30,
            envelope_version=payload["envelope_version"],
        )
        metadata = service.publish_request(request)
    except (NoCandidateError, CandidatePublicationValidationError) as exc:
        raise HTTPException(status_code=422, detail="request rejected") from exc
    except CandidatePublicationError as exc:
        raise _service_unavailable() from exc
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="request rejected") from exc
    return asdict(metadata)
