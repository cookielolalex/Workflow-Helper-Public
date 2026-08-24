from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from .artifact_gateway import ArtifactGateway
from .config import Settings
from .control_auth import AuthenticatedPrincipal
from .control_service import ControlService
from .identity import IdentityRejectedError
from .legacy_session_composition import (
    LegacySessionCompositionUnavailableError,
    ProviderNeutralSecurityComposition,
)
from .legacy_session_security import LegacySessionSecurityProvider
from .runtime_bundle import SealedSyntheticRuntimeBundle
from .safety_control import SafetyControlService
from .session_security import (
    SessionSecurityContext,
    SessionSecurityContextProvider,
    SessionSecurityRejectedError,
)


class _ResolvedSessionSecurityContextProvider:
    def __init__(self, context: SessionSecurityContext) -> None:
        self._context = context

    def get_session_security_context(self) -> SessionSecurityContext:
        return self._context

def get_runtime_bundle() -> SealedSyntheticRuntimeBundle:
    """Return no default; a fresh app factory must install one exact bundle."""

    return None  # type: ignore[return-value]


RuntimeBundleDependency = Annotated[
    SealedSyntheticRuntimeBundle,
    Depends(get_runtime_bundle),
]


def _require_bundle(bundle: object) -> SealedSyntheticRuntimeBundle:
    if type(bundle) is not SealedSyntheticRuntimeBundle:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="runtime unavailable",
        )
    return bundle


def get_provider_neutral_security_composition(
    bundle: RuntimeBundleDependency = None,  # type: ignore[assignment]
) -> ProviderNeutralSecurityComposition:
    """Return the bundle's exact singleton security composition."""

    if bundle is None:
        return None  # type: ignore[return-value]
    return _require_bundle(bundle).composition


CompositionDependency = Annotated[
    ProviderNeutralSecurityComposition,
    Depends(get_provider_neutral_security_composition),
]


def get_authenticated_principal(
    request: Request = None,  # type: ignore[assignment]
    composition: CompositionDependency = None,  # type: ignore[assignment]
) -> AuthenticatedPrincipal:
    """Resolve verified identity through the installed composition only."""

    if request is None or type(composition) is not ProviderNeutralSecurityComposition:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="control authentication unavailable",
        )
    try:
        return composition.authenticate_principal(request)
    except IdentityRejectedError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="identity rejected",
        ) from exc
    except LegacySessionCompositionUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="control authentication unavailable",
        ) from exc


def get_session_security_context_provider(
    request: Request = None,  # type: ignore[assignment]
    composition: CompositionDependency = None,  # type: ignore[assignment]
) -> SessionSecurityContextProvider:
    """Resolve the request-scoped browser provider from the composition."""

    if request is None or type(composition) is not ProviderNeutralSecurityComposition:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="session security unavailable",
        )
    try:
        provider = composition.browser_session_provider(request)
    except SessionSecurityRejectedError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="request security rejected",
        ) from exc
    except LegacySessionCompositionUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="session security unavailable",
        ) from exc
    try:
        context = provider.get_session_security_context()
    except (SessionSecurityRejectedError, TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="request security rejected",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="session security unavailable",
        ) from exc
    return _ResolvedSessionSecurityContextProvider(context)


def get_legacy_session_security_provider(
    request: Request = None,  # type: ignore[assignment]
    composition: CompositionDependency = None,  # type: ignore[assignment]
) -> LegacySessionSecurityProvider:
    """Resolve the request-scoped workload verifier from the composition."""

    if request is None or type(composition) is not ProviderNeutralSecurityComposition:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="legacy session authorization unavailable",
        )
    try:
        return composition.workload_credential_verifier(request)
    except LegacySessionCompositionUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="legacy session authorization unavailable",
        ) from exc


def get_control_service(
    bundle: RuntimeBundleDependency = None,  # type: ignore[assignment]
) -> ControlService:
    """Return the bundle's exact singleton control service."""

    if bundle is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="control service unavailable",
        )
    return _require_bundle(bundle).control_service


def get_safety_control_service(
    bundle: RuntimeBundleDependency = None,  # type: ignore[assignment]
) -> SafetyControlService:
    """Return the bundle's exact singleton safety service."""

    if bundle is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="safety control service unavailable",
        )
    return _require_bundle(bundle).safety_control_service


def get_runtime_settings(
    bundle: RuntimeBundleDependency = None,  # type: ignore[assignment]
) -> Settings:
    """Return the bundle's validated explicit settings snapshot."""

    return _require_bundle(bundle).settings


def get_artifact_gateway(
    bundle: RuntimeBundleDependency = None,  # type: ignore[assignment]
) -> ArtifactGateway:
    """Return the bundle's exact admitted artifact gateway."""

    return _require_bundle(bundle).artifact_gateway
