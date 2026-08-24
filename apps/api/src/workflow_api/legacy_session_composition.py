"""Explicit provider-neutral composition for the legacy session surface.

The composition is deliberately inert until a caller constructs it with
request-scoped provider factories and one already-initialized durable store.
It owns policy, but it owns no provider configuration or database path.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable

from starlette.requests import Request

from .control_auth import AuthenticatedPrincipal, ControlAction
from .identity import (
    Authenticator,
    GroupRoleMapping,
    IdentityRejectedError,
    SubjectScopePolicy,
    VerifiedIdentityEvidence,
    authenticate_principal,
)
from .legacy_session_security import (
    AuthorizedLegacySessionRequest,
    LegacySessionAudience,
    LegacySessionSecurityProvider,
    LegacySessionSecurityRejectedError,
    LegacySessionTransport,
    authorize_browser_request,
    raw_body_sha256,
)
from .legacy_session_store import SQLiteLegacySessionStore
from .session_security import (
    SessionSecurityContextProvider,
    SessionSecurityRejectedError,
)

AuthenticatorFactory = Callable[[Request], Authenticator]
BrowserSessionProviderFactory = Callable[[Request], SessionSecurityContextProvider]
WorkloadCredentialVerifierFactory = Callable[[Request], LegacySessionSecurityProvider]


class LegacySessionCompositionUnavailableError(RuntimeError):
    """A configured collaborator or durable authority was unavailable."""


class _ProviderOperationalFailure(RuntimeError):
    """Internal marker separating provider failure from invalid evidence."""


class _OperationalBoundaryAuthenticator:
    def __init__(self, authenticator: Authenticator) -> None:
        self._authenticator = authenticator

    def authenticate(self) -> VerifiedIdentityEvidence:
        try:
            return self._authenticator.authenticate()
        except (IdentityRejectedError, TypeError, ValueError) as exc:
            raise IdentityRejectedError("identity rejected") from exc
        except Exception as exc:
            raise _ProviderOperationalFailure from exc


class ProviderNeutralSecurityComposition:
    """One policy-and-store authority shared by guards and legacy handlers."""

    __slots__ = (
        "_authenticator_factory",
        "_browser_session_provider_factory",
        "_group_role_mapping",
        "_store",
        "_subject_scope_policy",
        "_workload_credential_verifier_factory",
    )

    def __init__(
        self,
        *,
        group_role_mapping: GroupRoleMapping,
        subject_scope_policy: SubjectScopePolicy,
        authenticator_factory: AuthenticatorFactory,
        browser_session_provider_factory: BrowserSessionProviderFactory,
        workload_credential_verifier_factory: WorkloadCredentialVerifierFactory,
        store: SQLiteLegacySessionStore,
    ) -> None:
        if type(group_role_mapping) is not GroupRoleMapping:
            raise TypeError("exact group-role mapping is required")
        if type(subject_scope_policy) is not SubjectScopePolicy:
            raise TypeError("exact subject-scope policy is required")
        if type(store) is not SQLiteLegacySessionStore:
            raise TypeError("one exact preconstructed SQLite legacy store is required")
        for factory in (
            authenticator_factory,
            browser_session_provider_factory,
            workload_credential_verifier_factory,
        ):
            if not callable(factory):
                raise TypeError("request-scoped collaborator factory is required")
        self._group_role_mapping = group_role_mapping
        self._subject_scope_policy = subject_scope_policy
        self._authenticator_factory = authenticator_factory
        self._browser_session_provider_factory = browser_session_provider_factory
        self._workload_credential_verifier_factory = workload_credential_verifier_factory
        self._store = store

    @property
    def store(self) -> SQLiteLegacySessionStore:
        """Return the one store used by both proof claims and handlers."""

        return self._store

    @property
    def browser_factory(self) -> BrowserSessionProviderFactory:
        """Return the exact installed browser-provider factory without invoking it."""

        return self._browser_session_provider_factory

    def authenticate_principal(self, request: Request) -> AuthenticatedPrincipal:
        """Verify provider evidence, MFA, exact groups, and exact subject scope."""

        try:
            authenticator = self._authenticator_factory(request)
        except Exception as exc:
            raise LegacySessionCompositionUnavailableError from exc
        if not callable(getattr(authenticator, "authenticate", None)):
            raise LegacySessionCompositionUnavailableError
        try:
            return authenticate_principal(
                _OperationalBoundaryAuthenticator(authenticator),
                self._group_role_mapping,
                self._subject_scope_policy,
            )
        except IdentityRejectedError as exc:
            if _cause_contains(exc, _ProviderOperationalFailure):
                raise LegacySessionCompositionUnavailableError from exc
            raise

    def browser_session_provider(self, request: Request) -> SessionSecurityContextProvider:
        """Resolve only the request-scoped browser-session collaborator."""

        try:
            provider = self._browser_session_provider_factory(request)
        except SessionSecurityRejectedError:
            raise
        except Exception as exc:
            raise LegacySessionCompositionUnavailableError from exc
        if not callable(getattr(provider, "get_session_security_context", None)):
            raise LegacySessionCompositionUnavailableError
        return provider

    def workload_credential_verifier(self, request: Request) -> LegacySessionSecurityProvider:
        """Resolve only the request-scoped workload credential verifier."""

        try:
            provider = self._workload_credential_verifier_factory(request)
        except Exception as exc:
            raise LegacySessionCompositionUnavailableError from exc
        if not callable(getattr(provider, "get_workload_context", None)):
            raise LegacySessionCompositionUnavailableError
        return provider

    def authorize_browser_request(
        self,
        *,
        request: Request,
        action: ControlAction,
    ) -> AuthorizedLegacySessionRequest:
        """Run the complete browser identity and session-integrity chain."""

        principal = self.authenticate_principal(request)
        provider = self.browser_session_provider(request)
        try:
            context = provider.get_session_security_context()
        except (
            LegacySessionSecurityRejectedError,
            SessionSecurityRejectedError,
            TypeError,
            ValueError,
        ) as exc:
            raise LegacySessionSecurityRejectedError(
                "request authorization rejected"
            ) from exc
        except Exception as exc:
            raise LegacySessionCompositionUnavailableError from exc
        return authorize_browser_request(
            context=context,
            principal=principal,
            method=request.method,
            path=request.url.path,
            headers=request.headers,
            action=action,
        )

    async def authorize_workload(
        self,
        *,
        request: Request,
        action: ControlAction,
        audience: LegacySessionAudience,
        transport: LegacySessionTransport,
    ) -> AuthorizedLegacySessionRequest:
        """Verify provider credentials, then durably claim the proof once."""

        body = await request.body()
        provider = self.workload_credential_verifier(request)
        try:
            context = provider.get_workload_context(
                method=request.method,
                path=request.url.path,
                body_sha256=raw_body_sha256(body),
                headers=request.headers,
            )
        except (LegacySessionSecurityRejectedError, TypeError, ValueError) as exc:
            raise LegacySessionSecurityRejectedError(
                "request authorization rejected"
            ) from exc
        except Exception as exc:
            raise LegacySessionCompositionUnavailableError from exc
        try:
            return self._store.claim_workload_proof(
                context=context,
                method=request.method,
                path=request.url.path,
                body=body,
                action=action,
                audience=audience,
                transport=transport,
            )
        except LegacySessionSecurityRejectedError as exc:
            if _cause_contains_store_failure(exc):
                raise LegacySessionCompositionUnavailableError from exc
            raise


def _cause_contains(error: BaseException, expected: type[BaseException]) -> bool:
    current: BaseException | None = error
    while current is not None:
        if isinstance(current, expected):
            return True
        current = current.__cause__
    return False


def _cause_contains_store_failure(error: BaseException) -> bool:
    current = error.__cause__
    while current is not None:
        if isinstance(current, (RuntimeError, OSError)) or (
            isinstance(current, sqlite3.Error)
            and not isinstance(current, sqlite3.IntegrityError)
        ):
            return True
        current = current.__cause__
    return False
