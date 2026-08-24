from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .artifact_gateway import NoNetworkArtifactGateway
from .config import get_settings
from .control_auth import AuthenticatedPrincipal
from .dependencies import (
    get_authenticated_principal,
    get_runtime_bundle,
    get_session_security_context_provider,
)
from .routes.control import router as control_router
from .routes.datasets import router as dataset_router
from .routes.health import router as health_router
from .routes.retention import router as retention_router
from .routes.safety import router as safety_router
from .routes.sessions import internal_router as internal_sessions_router
from .routes.sessions import router as sessions_router
from .runtime_bundle import SealedSyntheticRuntimeBundle, _validate_candidate_pair
from .session_security import (
    SessionSecurityContextProvider,
    SessionSecurityRejectedError,
    validate_session_security,
)

PrincipalDependency = Annotated[
    AuthenticatedPrincipal, Depends(get_authenticated_principal)
]
SessionProviderDependency = Annotated[
    SessionSecurityContextProvider,
    Depends(get_session_security_context_provider),
]


class _InertHealthSettings:
    """Health-only constant that cannot discover or validate configuration."""

    environment = "unconfigured"


_INERT_HEALTH_SETTINGS = _InertHealthSettings()


def require_control_session_security(
    request: Request,
    principal: PrincipalDependency,
    provider: SessionProviderDependency,
) -> None:
    """Shared fail-closed guard for every authenticated private control route."""

    try:
        context = provider.get_session_security_context()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="session security unavailable",
        ) from exc
    try:
        validate_session_security(
            context=context,
            route_principal=principal,
            method=request.method,
            headers=request.headers,
        )
    except SessionSecurityRejectedError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="request security rejected",
        ) from exc


control_session_dependencies = [Depends(require_control_session_security)]


def create_app(bundle: SealedSyntheticRuntimeBundle | None = None) -> FastAPI:
    """Create one fresh app, atomically bound to one exact optional bundle."""

    if bundle is not None and type(bundle) is not SealedSyntheticRuntimeBundle:
        raise TypeError("an exact sealed runtime bundle is required")
    application = FastAPI(
        title="Workflow Helper API",
        version="0.1.0",
        description="Privacy-conscious CAD workflow session control plane",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        swagger_ui_oauth2_redirect_url=None,
    )
    application.state.runtime_bundle = bundle
    origins = [] if bundle is None else bundle.settings.allowed_origins
    application.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "If-None-Match",
            "Origin",
            "X-CSRF-Token",
            "X-Workflow-Content-SHA256",
        ],
    )

    @application.exception_handler(RequestValidationError)
    async def bounded_validation_error(
        _request: Request, _error: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": "request rejected"})

    application.include_router(health_router)
    application.include_router(sessions_router)
    application.include_router(internal_sessions_router)
    application.include_router(control_router, dependencies=control_session_dependencies)
    application.include_router(dataset_router, dependencies=control_session_dependencies)
    application.include_router(retention_router, dependencies=control_session_dependencies)
    application.include_router(safety_router, dependencies=control_session_dependencies)

    if _candidate_registration_allowed(bundle):
        # Keep the dormant router import itself behind the explicit synthetic
        # activation boundary.  The route's own dependency remains the only
        # application override; auth and session security are shared with the
        # existing private control routes above.
        from .candidate_publication_service import CandidatePublicationService
        from .routes.candidate_discovery import (
            get_candidate_discovery_service,
            get_candidate_publication_service,
        )
        from .routes.candidate_discovery import router as candidate_router

        candidate_service = bundle.candidate_discovery_service
        publication_service = CandidatePublicationService(
            bundle.candidate_publication_store,
            bundle.control_service,
        )
        application.include_router(
            candidate_router,
            dependencies=control_session_dependencies,
        )
        application.dependency_overrides[get_candidate_discovery_service] = (
            lambda: candidate_service
        )
        application.dependency_overrides[get_candidate_publication_service] = (
            lambda: publication_service
        )

    health_settings = _INERT_HEALTH_SETTINGS if bundle is None else bundle.settings
    application.dependency_overrides[get_settings] = lambda: health_settings
    if bundle is not None:
        application.dependency_overrides[get_runtime_bundle] = lambda: bundle
    return application


def _candidate_registration_allowed(
    bundle: SealedSyntheticRuntimeBundle | None,
) -> bool:
    """Admit only a complete bundle graph with the exact no-network gateway."""

    if bundle is None or type(bundle) is not SealedSyntheticRuntimeBundle:
        return False
    if type(bundle.artifact_gateway) is not NoNetworkArtifactGateway:
        return False
    try:
        _validate_candidate_pair(
            candidate_publication_store=bundle.candidate_publication_store,
            candidate_discovery_service=bundle.candidate_discovery_service,
            control_service=bundle.control_service,
        )
    except (AttributeError, TypeError, ValueError):
        return False
    return (
        bundle.candidate_publication_store is not None
        and bundle.candidate_discovery_service is not None
    )


app = create_app()
