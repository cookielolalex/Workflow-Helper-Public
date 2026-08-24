"""Provider-neutral synthetic session-integrity and anti-CSRF policy."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Protocol
from urllib.parse import urlsplit

from starlette.datastructures import Headers

from .control_auth import AuthenticatedPrincipal

_DIGEST_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_CSRF_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_DNS_NAME_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_MAX_ABSOLUTE_LIFETIME = timedelta(hours=8)
_MAX_IDLE_LIFETIME = timedelta(minutes=30)
_MAX_CLOCK_SKEW = timedelta(seconds=60)
_MAX_ORIGIN_LENGTH = 255
_MAX_GENERATION = 2**31 - 1


class SessionTransport(StrEnum):
    """Server-classified transport supported by this synthetic control-plane seam."""

    BROWSER_COOKIE = "browser_cookie"


class SessionSecurityRejectedError(PermissionError):
    """Session or request evidence failed the bounded generic policy."""


@dataclass(frozen=True, slots=True)
class SessionSecurityContext:
    """Immutable provider output containing digests, never raw session or CSRF material."""

    principal: AuthenticatedPrincipal
    session_identifier_digest: str
    session_generation: int
    active_generation: int
    issued_at: datetime
    authenticated_at: datetime
    last_seen_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
    revoked: bool
    transport: SessionTransport
    allowed_browser_origin: str
    csrf_token_digest: str

    def __post_init__(self) -> None:
        _validate_context(self, now=None)


class SessionSecurityContextProvider(Protocol):
    """Server-supplied provider; deliberately has no default implementation."""

    def get_session_security_context(self) -> SessionSecurityContext:
        """Return authoritative server-side context for the current request."""


def csrf_token_digest(token: str) -> str:
    """Validate canonical 256-bit material and return only its SHA-256 digest."""

    return hashlib.sha256(_decode_csrf_token(token)).hexdigest()


def validate_session_security(
    *,
    context: SessionSecurityContext,
    route_principal: AuthenticatedPrincipal,
    method: str,
    headers: Headers,
    now: datetime | None = None,
) -> None:
    """Revalidate provider output and enforce unsafe-request evidence."""

    try:
        evaluation_time = datetime.now(UTC) if now is None else now
        _validate_utc(evaluation_time)
        _validate_context(context, now=evaluation_time)
        _validate_principal(route_principal)
        if context.principal != route_principal:
            raise ValueError("principal mismatch")
        if not isinstance(method, str) or method != method.upper():
            raise ValueError("ambiguous method")
        if method not in _SAFE_METHODS and method not in _UNSAFE_METHODS:
            raise ValueError("unsupported method")
        if method in _UNSAFE_METHODS:
            _validate_unsafe_request(context, headers)
    except SessionSecurityRejectedError:
        raise
    except Exception as exc:
        raise SessionSecurityRejectedError("request security rejected") from exc


def _validate_context(context: SessionSecurityContext, now: datetime | None) -> None:
    if type(context) is not SessionSecurityContext:
        raise TypeError("context must use the exact contract type")
    _validate_principal(context.principal)
    for digest in (context.session_identifier_digest, context.csrf_token_digest):
        if not isinstance(digest, str) or not _DIGEST_PATTERN.fullmatch(digest):
            raise ValueError("invalid digest")
    for generation in (context.session_generation, context.active_generation):
        if type(generation) is not int or not 1 <= generation <= _MAX_GENERATION:
            raise ValueError("invalid generation")
    if context.session_generation != context.active_generation:
        raise ValueError("stale generation")
    if type(context.revoked) is not bool or context.revoked:
        raise ValueError("inactive session")
    if type(context.transport) is not SessionTransport:
        raise TypeError("invalid transport")
    if context.transport is not SessionTransport.BROWSER_COOKIE:
        raise ValueError("unsupported transport")
    _validate_origin(context.allowed_browser_origin)

    timestamps = (
        context.issued_at,
        context.authenticated_at,
        context.last_seen_at,
        context.idle_expires_at,
        context.absolute_expires_at,
    )
    for value in timestamps:
        _validate_utc(value)
    if not (
        context.issued_at
        <= context.authenticated_at
        <= context.last_seen_at
        < context.idle_expires_at
        <= context.absolute_expires_at
    ):
        raise ValueError("ill-ordered timestamps")
    if context.absolute_expires_at - context.authenticated_at > _MAX_ABSOLUTE_LIFETIME:
        raise ValueError("absolute lifetime exceeds cap")
    if context.idle_expires_at - context.last_seen_at > _MAX_IDLE_LIFETIME:
        raise ValueError("idle lifetime exceeds cap")
    if now is not None:
        if context.issued_at > now + _MAX_CLOCK_SKEW:
            raise ValueError("future session")
        if context.authenticated_at > now or context.last_seen_at > now:
            raise ValueError("future session")
        if now >= context.idle_expires_at or now >= context.absolute_expires_at:
            raise ValueError("expired session")


def _validate_principal(principal: AuthenticatedPrincipal) -> None:
    if type(principal) is not AuthenticatedPrincipal:
        raise TypeError("principal must use the exact contract type")
    if principal.scope is None:
        raise ValueError("principal scope is required")
    rebuilt = AuthenticatedPrincipal(principal.subject, principal.roles, principal.scope)
    if rebuilt != principal:
        raise ValueError("ambiguous principal")


def _validate_unsafe_request(
    context: SessionSecurityContext,
    headers: Headers,
) -> None:
    if type(headers) is not Headers:
        raise TypeError("headers must use the exact contract type")
    origins = headers.getlist("origin")
    tokens = headers.getlist("x-csrf-token")
    if len(origins) != 1 or len(tokens) != 1:
        raise ValueError("missing or ambiguous request evidence")
    origin = origins[0]
    token = tokens[0]
    _validate_origin(origin)
    if origin != context.allowed_browser_origin:
        raise ValueError("origin mismatch")
    presented_digest = csrf_token_digest(token)
    if not hmac.compare_digest(presented_digest, context.csrf_token_digest):
        raise ValueError("csrf mismatch")


def _decode_csrf_token(token: str) -> bytes:
    if not isinstance(token, str) or not _CSRF_TOKEN_PATTERN.fullmatch(token):
        raise ValueError("invalid csrf material")
    try:
        raw = base64.urlsafe_b64decode(token + "=")
    except Exception as exc:
        raise ValueError("invalid csrf material") from exc
    if len(raw) != 32:
        raise ValueError("csrf material must contain exactly 256 bits")
    canonical = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    if canonical != token:
        raise ValueError("non-canonical csrf material")
    return raw


def _validate_origin(origin: str) -> None:
    if (
        not isinstance(origin, str)
        or not 1 <= len(origin) <= _MAX_ORIGIN_LENGTH
        or origin != origin.strip()
        or origin == "null"
    ):
        raise ValueError("invalid origin")
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.netloc
        or parsed.hostname is None
    ):
        raise ValueError("invalid origin")
    host = parsed.hostname
    if host != host.lower() or not _DNS_NAME_PATTERN.fullmatch(host):
        raise ValueError("invalid origin host")
    if parsed.netloc.startswith("[") or parsed.netloc.endswith("."):
        raise ValueError("invalid origin host")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid origin port") from exc
    if port == 443:
        raise ValueError("default port must be omitted")
    canonical_netloc = host if port is None else f"{host}:{port}"
    if parsed.netloc != canonical_netloc or origin != f"https://{canonical_netloc}":
        raise ValueError("non-canonical origin")


def _validate_utc(value: datetime) -> None:
    if type(value) is not datetime or value.tzinfo is not UTC:
        raise ValueError("timestamp must be an exact UTC datetime")
