"""Digest-only durable browser-session lifecycle reference.

The store accepts only already-derived canonical SHA-256 digests.  It does not
know how session or CSRF material is issued and is inert until explicitly
constructed with a caller-supplied filesystem path.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from starlette.requests import Request

from .browser_session_schema import initialize_browser_session_schema
from .control_auth import AuthenticatedPrincipal, ControlRole
from .control_scope import TenantWorkspaceScope
from .session_security import (
    SessionSecurityContext,
    SessionSecurityContextProvider,
    SessionSecurityRejectedError,
    SessionTransport,
)

_DIGEST_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_SESSION_MATERIAL_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_MAX_IDLE_LIFETIME = timedelta(minutes=30)
_MAX_CLOCK_SKEW = timedelta(seconds=60)
_MAX_GENERATION = 2**31 - 1
_SESSION_COLUMNS = """
session_identifier_digest, csrf_token_digest, principal_subject, roles_json,
tenant_id, workspace_id, allowed_browser_origin, generation, issued_at_us,
authenticated_at_us, last_seen_at_us, idle_expires_at_us,
absolute_expires_at_us, revoked_at_us, state_version
"""


class BrowserSessionRejectedError(SessionSecurityRejectedError):
    """Presented evidence or a requested lifecycle transition was rejected."""


class BrowserSessionStoreUnavailableError(RuntimeError):
    """Durable state could not be interpreted as the exact component contract."""


@dataclass(frozen=True, slots=True)
class BrowserSessionState:
    """Exact durable browser-session state; contains digests but no raw material."""

    principal: AuthenticatedPrincipal
    session_identifier_digest: str
    csrf_token_digest: str
    allowed_browser_origin: str
    generation: int
    issued_at: datetime
    authenticated_at: datetime
    last_seen_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
    revoked_at: datetime | None
    state_version: int

    @property
    def revoked(self) -> bool:
        return self.revoked_at is not None

    def as_security_context(self) -> SessionSecurityContext:
        """Project active durable state into the existing exact policy contract."""

        return SessionSecurityContext(
            principal=self.principal,
            session_identifier_digest=self.session_identifier_digest,
            session_generation=self.generation,
            active_generation=self.generation,
            issued_at=self.issued_at,
            authenticated_at=self.authenticated_at,
            last_seen_at=self.last_seen_at,
            idle_expires_at=self.idle_expires_at,
            absolute_expires_at=self.absolute_expires_at,
            revoked=self.revoked,
            transport=SessionTransport.BROWSER_COOKIE,
            allowed_browser_origin=self.allowed_browser_origin,
            csrf_token_digest=self.csrf_token_digest,
        )


class SQLiteBrowserSessionStore:
    """Connection-per-operation SQLite authority for browser sessions."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        busy_timeout_seconds: float = 5.0,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if (
            not isinstance(busy_timeout_seconds, (int, float))
            or isinstance(busy_timeout_seconds, bool)
            or busy_timeout_seconds <= 0
        ):
            raise ValueError("busy_timeout_seconds must be positive")
        if not isinstance(database_path, (str, Path)) or str(database_path) == ":memory:":
            raise ValueError("a caller-supplied filesystem path is required")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        self._database_path = str(Path(database_path))
        self._busy_timeout_ms = max(1, int(busy_timeout_seconds * 1_000))
        self._clock = clock or (lambda: datetime.now(UTC))
        Path(self._database_path).parent.mkdir(parents=True, exist_ok=True)

        with closing(self._connect()) as connection:
            initialize_browser_session_schema(
                connection,
                installed_at_us=_to_micros(self._now()),
            )
            mode = connection.execute("pragma journal_mode = wal").fetchone()
            if mode is None or str(mode[0]).casefold() != "wal":
                raise BrowserSessionStoreUnavailableError("browser session store unavailable")

    @property
    def database_path(self) -> str:
        return self._database_path

    def register_session(
        self,
        *,
        session_identifier_digest: str,
        csrf_token_digest: str,
        principal: AuthenticatedPrincipal,
        allowed_browser_origin: str,
        issued_at: datetime,
        authenticated_at: datetime,
        last_seen_at: datetime,
        idle_expires_at: datetime,
        absolute_expires_at: datetime,
        now: datetime | None = None,
    ) -> BrowserSessionState:
        """Atomically register one generation-one active digest pair."""

        try:
            evaluation_time = self._now() if now is None else _require_utc(now)
            candidate = BrowserSessionState(
                principal=_require_principal(principal),
                session_identifier_digest=_require_digest(session_identifier_digest),
                csrf_token_digest=_require_digest(csrf_token_digest),
                allowed_browser_origin=allowed_browser_origin,
                generation=1,
                issued_at=_require_utc(issued_at),
                authenticated_at=_require_utc(authenticated_at),
                last_seen_at=_require_utc(last_seen_at),
                idle_expires_at=_require_utc(idle_expires_at),
                absolute_expires_at=_require_utc(absolute_expires_at),
                revoked_at=None,
                state_version=1,
            )
            candidate.as_security_context()
            _require_current(candidate, evaluation_time)
            roles_json = _roles_json(candidate.principal)
            scope = candidate.principal.scope
            assert scope is not None
            with self._transaction() as connection:
                self._claim_digest_pair(
                    connection,
                    session_identifier_digest=candidate.session_identifier_digest,
                    csrf_token_digest=candidate.csrf_token_digest,
                    allocated_at_us=_to_micros(evaluation_time),
                )
                connection.execute(
                    """
                    insert into browser_sessions (
                        session_identifier_digest, csrf_token_digest,
                        principal_subject, roles_json, tenant_id, workspace_id,
                        allowed_browser_origin, generation, issued_at_us,
                        authenticated_at_us, last_seen_at_us, idle_expires_at_us,
                        absolute_expires_at_us, revoked_at_us, state_version
                    ) values (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, null, 1)
                    """,
                    (
                        candidate.session_identifier_digest,
                        candidate.csrf_token_digest,
                        candidate.principal.subject,
                        roles_json,
                        scope.tenant_id,
                        scope.workspace_id,
                        candidate.allowed_browser_origin,
                        _to_micros(candidate.issued_at),
                        _to_micros(candidate.authenticated_at),
                        _to_micros(candidate.last_seen_at),
                        _to_micros(candidate.idle_expires_at),
                        _to_micros(candidate.absolute_expires_at),
                    ),
                )
            return candidate
        except BrowserSessionRejectedError:
            raise
        except (SessionSecurityRejectedError, TypeError, ValueError, sqlite3.IntegrityError):
            raise BrowserSessionRejectedError("browser session rejected") from None

    def resolve_session(
        self,
        *,
        session_identifier_digest: str,
        now: datetime | None = None,
    ) -> SessionSecurityContext:
        """Resolve one exact digest without touching or renewing durable state."""

        try:
            digest = _require_digest(session_identifier_digest)
            evaluation_time = self._now() if now is None else _require_utc(now)
        except (TypeError, ValueError):
            raise BrowserSessionRejectedError("browser session rejected") from None
        with closing(self._connect()) as connection:
            row = self._select(connection, digest)
        if row is None:
            raise BrowserSessionRejectedError("browser session rejected")
        state = _state_from_row(row)
        try:
            _require_current(state, evaluation_time)
            return state.as_security_context()
        except (SessionSecurityRejectedError, TypeError, ValueError):
            raise BrowserSessionRejectedError("browser session rejected") from None

    def touch_session(
        self,
        *,
        session_identifier_digest: str,
        expected_state_version: int,
        now: datetime | None = None,
    ) -> BrowserSessionState:
        """Advance last-seen and bounded idle expiry with optimistic versioning."""

        try:
            digest = _require_digest(session_identifier_digest)
            version = _require_state_version(expected_state_version)
            evaluation_time = self._now() if now is None else _require_utc(now)
        except (TypeError, ValueError):
            raise BrowserSessionRejectedError("browser session rejected") from None

        with self._transaction() as connection:
            state = self._active_for_mutation(connection, digest, version, evaluation_time)
            if evaluation_time < state.last_seen_at:
                raise BrowserSessionRejectedError("browser session rejected")
            idle_expires_at = min(
                _checked_add(evaluation_time, _MAX_IDLE_LIFETIME),
                state.absolute_expires_at,
            )
            if idle_expires_at <= evaluation_time:
                raise BrowserSessionRejectedError("browser session rejected")
            cursor = connection.execute(
                """
                update browser_sessions
                set last_seen_at_us = ?, idle_expires_at_us = ?, state_version = ?
                where session_identifier_digest = ? and state_version = ?
                  and revoked_at_us is null
                """,
                (
                    _to_micros(evaluation_time),
                    _to_micros(idle_expires_at),
                    version + 1,
                    digest,
                    version,
                ),
            )
            if cursor.rowcount != 1:
                raise BrowserSessionRejectedError("browser session rejected")
            updated = self._select(connection, digest)
            if updated is None:
                raise BrowserSessionStoreUnavailableError("browser session store unavailable")
            return _state_from_row(updated)

    def rotate_session(
        self,
        *,
        session_identifier_digest: str,
        new_session_identifier_digest: str,
        new_csrf_token_digest: str,
        expected_state_version: int,
        now: datetime | None = None,
    ) -> BrowserSessionState:
        """Atomically replace both digests and advance generation and version."""

        try:
            digest = _require_digest(session_identifier_digest)
            new_digest = _require_digest(new_session_identifier_digest)
            new_csrf = _require_digest(new_csrf_token_digest)
            version = _require_state_version(expected_state_version)
            evaluation_time = self._now() if now is None else _require_utc(now)
            if digest == new_digest:
                raise ValueError("identifier digest must change")
        except (TypeError, ValueError):
            raise BrowserSessionRejectedError("browser session rejected") from None

        try:
            with self._transaction() as connection:
                state = self._active_for_mutation(connection, digest, version, evaluation_time)
                if new_csrf == state.csrf_token_digest or state.generation >= _MAX_GENERATION:
                    raise BrowserSessionRejectedError("browser session rejected")
                self._claim_digest_pair(
                    connection,
                    session_identifier_digest=new_digest,
                    csrf_token_digest=new_csrf,
                    allocated_at_us=_to_micros(evaluation_time),
                )
                cursor = connection.execute(
                    """
                    update browser_sessions
                    set session_identifier_digest = ?, csrf_token_digest = ?,
                        generation = ?, state_version = ?
                    where session_identifier_digest = ? and state_version = ?
                      and revoked_at_us is null
                    """,
                    (
                        new_digest,
                        new_csrf,
                        state.generation + 1,
                        version + 1,
                        digest,
                        version,
                    ),
                )
                if cursor.rowcount != 1:
                    raise BrowserSessionRejectedError("browser session rejected")
                updated = self._select(connection, new_digest)
                if updated is None:
                    raise BrowserSessionStoreUnavailableError("browser session store unavailable")
                return _state_from_row(updated)
        except sqlite3.IntegrityError:
            raise BrowserSessionRejectedError("browser session rejected") from None

    def revoke_session(
        self,
        *,
        session_identifier_digest: str,
        expected_state_version: int,
        now: datetime | None = None,
    ) -> BrowserSessionState:
        """Atomically and permanently mark one digest authority revoked."""

        try:
            digest = _require_digest(session_identifier_digest)
            version = _require_state_version(expected_state_version)
            evaluation_time = self._now() if now is None else _require_utc(now)
        except (TypeError, ValueError):
            raise BrowserSessionRejectedError("browser session rejected") from None

        with self._transaction() as connection:
            row = self._select(connection, digest)
            if row is None:
                raise BrowserSessionRejectedError("browser session rejected")
            state = _state_from_row(row)
            if (
                state.state_version != version
                or state.revoked
                or evaluation_time < state.last_seen_at
            ):
                raise BrowserSessionRejectedError("browser session rejected")
            cursor = connection.execute(
                """
                update browser_sessions
                set revoked_at_us = ?, state_version = ?
                where session_identifier_digest = ? and state_version = ?
                  and revoked_at_us is null
                """,
                (_to_micros(evaluation_time), version + 1, digest, version),
            )
            if cursor.rowcount != 1:
                raise BrowserSessionRejectedError("browser session rejected")
            updated = self._select(connection, digest)
            if updated is None:
                raise BrowserSessionStoreUnavailableError("browser session store unavailable")
            return _state_from_row(updated)

    def _active_for_mutation(
        self,
        connection: sqlite3.Connection,
        digest: str,
        expected_state_version: int,
        now: datetime,
    ) -> BrowserSessionState:
        row = self._select(connection, digest)
        if row is None:
            raise BrowserSessionRejectedError("browser session rejected")
        state = _state_from_row(row)
        if state.state_version != expected_state_version:
            raise BrowserSessionRejectedError("browser session rejected")
        try:
            _require_current(state, now)
        except (SessionSecurityRejectedError, TypeError, ValueError):
            raise BrowserSessionRejectedError("browser session rejected") from None
        return state

    @staticmethod
    def _select(connection: sqlite3.Connection, digest: str) -> sqlite3.Row | None:
        return connection.execute(
            f"""
            select {_SESSION_COLUMNS}
            from browser_sessions
            where session_identifier_digest = ?
            """,
            (digest,),
        ).fetchone()

    @staticmethod
    def _claim_digest_pair(
        connection: sqlite3.Connection,
        *,
        session_identifier_digest: str,
        csrf_token_digest: str,
        allocated_at_us: int,
    ) -> None:
        connection.executemany(
            """
            insert into browser_session_digest_allocations (
                digest, digest_kind, allocated_at_us
            ) values (?, ?, ?)
            """,
            (
                (session_identifier_digest, "session_identifier", allocated_at_us),
                (csrf_token_digest, "csrf", allocated_at_us),
            ),
        )

    def _now(self) -> datetime:
        return _require_utc(self._clock())

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("begin immediate")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._database_path,
            timeout=self._busy_timeout_ms / 1_000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("pragma foreign_keys = on")
        connection.execute(f"pragma busy_timeout = {self._busy_timeout_ms}")
        connection.execute("pragma synchronous = full")
        if connection.execute("pragma foreign_keys").fetchone()[0] != 1:
            connection.close()
            raise BrowserSessionStoreUnavailableError("browser session store unavailable")
        return connection


class StoreBackedSessionSecurityContextProvider(SessionSecurityContextProvider):
    """Explicit request-scoped provider over one canonical presented digest."""

    __slots__ = ("_session_identifier_digest", "_store")

    def __init__(
        self,
        *,
        store: SQLiteBrowserSessionStore,
        session_identifier_digest: str,
    ) -> None:
        if type(store) is not SQLiteBrowserSessionStore:
            raise TypeError("an exact browser session store is required")
        try:
            digest = _require_digest(session_identifier_digest)
        except (TypeError, ValueError):
            raise BrowserSessionRejectedError("browser session rejected") from None
        self._store = store
        self._session_identifier_digest = digest

    def get_session_security_context(self) -> SessionSecurityContext:
        try:
            return self._store.resolve_session(
                session_identifier_digest=self._session_identifier_digest
            )
        except BrowserSessionRejectedError:
            raise
        except (sqlite3.Error, OSError, RuntimeError):
            raise BrowserSessionStoreUnavailableError("browser session store unavailable") from None


class StoreBackedBrowserSessionProviderFactory:
    """Exact request factory over one store and one fixed cookie surface."""

    __slots__ = ("_store",)

    def __init__(self, *, store: SQLiteBrowserSessionStore) -> None:
        if type(store) is not SQLiteBrowserSessionStore:
            raise TypeError("an exact browser session store is required")
        self._store = store

    @property
    def store(self) -> SQLiteBrowserSessionStore:
        """Expose the exact durable authority for bundle identity checks."""

        return self._store

    def __call__(self, request: Request) -> StoreBackedSessionSecurityContextProvider:
        if type(request) is not Request:
            raise BrowserSessionRejectedError("browser session rejected")
        cookie_headers = request.headers.getlist("cookie")
        if len(cookie_headers) != 1:
            raise BrowserSessionRejectedError("browser session rejected")
        matches: list[str] = []
        for item in cookie_headers[0].split(";"):
            name, separator, value = item.strip().partition("=")
            if separator and name == "workflow_session":
                matches.append(value)
        if len(matches) != 1:
            raise BrowserSessionRejectedError("browser session rejected")
        material = matches[0]
        if not _SESSION_MATERIAL_PATTERN.fullmatch(material):
            raise BrowserSessionRejectedError("browser session rejected")
        try:
            raw = base64.urlsafe_b64decode(material + "=")
        except (binascii.Error, ValueError):
            raise BrowserSessionRejectedError("browser session rejected") from None
        if (
            len(raw) != 32
            or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != material
        ):
            raise BrowserSessionRejectedError("browser session rejected")
        return StoreBackedSessionSecurityContextProvider(
            store=self._store,
            session_identifier_digest=hashlib.sha256(raw).hexdigest(),
        )


def _state_from_row(row: sqlite3.Row) -> BrowserSessionState:
    try:
        roles_value = json.loads(row["roles_json"])
        if (
            type(roles_value) is not list
            or not roles_value
            or any(type(value) is not str for value in roles_value)
            or roles_value != sorted(set(roles_value))
            or row["roles_json"] != json.dumps(tuple(roles_value), separators=(",", ":"))
        ):
            raise ValueError("invalid stored roles")
        roles = frozenset(ControlRole(value) for value in roles_value)
        scope = TenantWorkspaceScope(row["tenant_id"], row["workspace_id"])
        principal = AuthenticatedPrincipal(row["principal_subject"], roles, scope)
        state = BrowserSessionState(
            principal=principal,
            session_identifier_digest=_require_digest(row["session_identifier_digest"]),
            csrf_token_digest=_require_digest(row["csrf_token_digest"]),
            allowed_browser_origin=row["allowed_browser_origin"],
            generation=_require_generation(row["generation"]),
            issued_at=_from_micros(row["issued_at_us"]),
            authenticated_at=_from_micros(row["authenticated_at_us"]),
            last_seen_at=_from_micros(row["last_seen_at_us"]),
            idle_expires_at=_from_micros(row["idle_expires_at_us"]),
            absolute_expires_at=_from_micros(row["absolute_expires_at_us"]),
            revoked_at=(
                None if row["revoked_at_us"] is None else _from_micros(row["revoked_at_us"])
            ),
            state_version=_require_state_version(row["state_version"]),
        )
        if state.generation > state.state_version or (
            state.revoked_at is not None and state.revoked_at < state.issued_at
        ):
            raise ValueError("invalid stored lifecycle state")
        # Validate all persisted policy fields without treating a legitimate
        # durable revocation marker as malformed storage.
        SessionSecurityContext(
            principal=state.principal,
            session_identifier_digest=state.session_identifier_digest,
            session_generation=state.generation,
            active_generation=state.generation,
            issued_at=state.issued_at,
            authenticated_at=state.authenticated_at,
            last_seen_at=state.last_seen_at,
            idle_expires_at=state.idle_expires_at,
            absolute_expires_at=state.absolute_expires_at,
            revoked=False,
            transport=SessionTransport.BROWSER_COOKIE,
            allowed_browser_origin=state.allowed_browser_origin,
            csrf_token_digest=state.csrf_token_digest,
        )
        return state
    except (
        IndexError,
        KeyError,
        SessionSecurityRejectedError,
        TypeError,
        ValueError,
    ):
        raise BrowserSessionStoreUnavailableError("browser session store unavailable") from None


def _require_current(state: BrowserSessionState, now: datetime) -> None:
    if state.revoked:
        raise BrowserSessionRejectedError("browser session rejected")
    if state.issued_at > _checked_add(now, _MAX_CLOCK_SKEW):
        raise BrowserSessionRejectedError("browser session rejected")
    if state.authenticated_at > now or state.last_seen_at > now:
        raise BrowserSessionRejectedError("browser session rejected")
    if now >= state.idle_expires_at or now >= state.absolute_expires_at:
        raise BrowserSessionRejectedError("browser session rejected")


def _require_principal(principal: AuthenticatedPrincipal) -> AuthenticatedPrincipal:
    if type(principal) is not AuthenticatedPrincipal or principal.scope is None:
        raise TypeError("an exact scoped principal is required")
    rebuilt = AuthenticatedPrincipal(principal.subject, principal.roles, principal.scope)
    if rebuilt != principal:
        raise ValueError("ambiguous principal")
    return principal


def _roles_json(principal: AuthenticatedPrincipal) -> str:
    if not principal.roles:
        raise ValueError("at least one role is required")
    return json.dumps(principal.role_values, separators=(",", ":"))


def _require_digest(value: str) -> str:
    if type(value) is not str or not _DIGEST_PATTERN.fullmatch(value):
        raise ValueError("invalid digest")
    return value


def _require_generation(value: int) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_GENERATION:
        raise ValueError("invalid generation")
    return value


def _require_state_version(value: int) -> int:
    if type(value) is not int or not 1 <= value < 2**63 - 1:
        raise ValueError("invalid state version")
    return value


def _require_utc(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is not UTC:
        raise ValueError("timestamp must be an exact UTC datetime")
    return value


def _to_micros(value: datetime) -> int:
    value = _require_utc(value)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = value - epoch
    result = (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds
    if not -(2**63) <= result < 2**63:
        raise ValueError("timestamp is outside signed 64-bit microseconds")
    return result


def _from_micros(value: int) -> datetime:
    if type(value) is not int or not -(2**63) <= value < 2**63:
        raise ValueError("stored timestamp is invalid")
    try:
        return datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=value)
    except OverflowError:
        raise ValueError("stored timestamp is invalid") from None


def _checked_add(value: datetime, delta: timedelta) -> datetime:
    try:
        return value + delta
    except OverflowError:
        raise BrowserSessionStoreUnavailableError("browser session store unavailable") from None
