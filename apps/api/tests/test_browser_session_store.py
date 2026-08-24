from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from workflow_api.browser_session_schema import (
    BROWSER_SESSION_COMPONENT_ID,
    BROWSER_SESSION_SCHEMA_CHECKSUM,
    BrowserSessionSchemaError,
    validate_browser_session_schema,
)
from workflow_api.browser_session_store import (
    BrowserSessionRejectedError,
    BrowserSessionStoreUnavailableError,
    SQLiteBrowserSessionStore,
    StoreBackedSessionSecurityContextProvider,
)
from workflow_api.control_auth import AuthenticatedPrincipal, ControlRole
from workflow_api.control_scope import TenantWorkspaceScope

NOW = datetime(2026, 8, 18, 6, 30, tzinfo=UTC)
SCOPE = TenantWorkspaceScope("tenant-synthetic", "workspace-synthetic")
ORIGIN = "https://review.example.com"


def _principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        "reviewer-synthetic",
        frozenset({ControlRole.REVIEWER, ControlRole.AUDIT_READER}),
        SCOPE,
    )


def _store(path: Path, *, now: datetime = NOW) -> SQLiteBrowserSessionStore:
    return SQLiteBrowserSessionStore(path, clock=lambda: now)


def _register(
    store: SQLiteBrowserSessionStore,
    *,
    identifier_digest: str = "a" * 64,
    csrf_digest: str = "b" * 64,
    now: datetime = NOW,
    absolute_expires_at: datetime | None = None,
):
    absolute = absolute_expires_at or now + timedelta(hours=7)
    return store.register_session(
        session_identifier_digest=identifier_digest,
        csrf_token_digest=csrf_digest,
        principal=_principal(),
        allowed_browser_origin=ORIGIN,
        issued_at=now - timedelta(minutes=5),
        authenticated_at=now - timedelta(minutes=4),
        last_seen_at=now - timedelta(minutes=1),
        idle_expires_at=min(now + timedelta(minutes=29), absolute),
        absolute_expires_at=absolute,
        now=now,
    )


def _snapshot(path: Path) -> tuple[list[tuple], dict[str, list[tuple]]]:
    with sqlite3.connect(path) as connection:
        schema = connection.execute(
            """
            select type, name, tbl_name, sql from sqlite_master
            where name not like 'sqlite_%' order by type, name
            """
        ).fetchall()
        data = {
            name: connection.execute(f'select * from "{name}"').fetchall()
            for (name,) in connection.execute(
                """
                select name from sqlite_master
                where type = 'table' and name not like 'sqlite_%'
                order by name
                """
            )
        }
    return schema, data


def test_constructor_creates_only_exact_component_schema_and_reopens(tmp_path: Path) -> None:
    path = tmp_path / "browser.sqlite3"
    first = _store(path)
    second = _store(path)

    assert first.database_path == second.database_path == str(path)
    with sqlite3.connect(path) as connection:
        connection.execute("pragma foreign_keys = on")
        validate_browser_session_schema(connection)
        assert connection.execute("pragma journal_mode").fetchone() == ("wal",)
        assert connection.execute(
            "select component_id, schema_checksum from browser_session_component_schema"
        ).fetchone() == (BROWSER_SESSION_COMPONENT_ID, BROWSER_SESSION_SCHEMA_CHECKSUM)
        names = {
            row[0]
            for row in connection.execute(
                "select name from sqlite_master where name not like 'sqlite_%'"
            )
        }
    assert names == {
        "browser_session_component_schema",
        "browser_session_digest_allocations",
        "browser_session_digest_allocations_no_delete",
        "browser_session_digest_allocations_no_update",
        "browser_sessions",
        "browser_sessions_principal_scope_idx",
    }


@pytest.mark.parametrize("drift", ("partial", "unknown", "manifest", "shape"))
def test_constructor_rejects_partial_drifted_or_colliding_state_without_repair(
    tmp_path: Path,
    drift: str,
) -> None:
    path = tmp_path / f"{drift}.sqlite3"
    if drift == "partial":
        with sqlite3.connect(path) as connection:
            connection.execute("create table browser_sessions (value text)")
    elif drift == "unknown":
        with sqlite3.connect(path) as connection:
            connection.execute("create table unrelated (value text)")
            connection.execute("insert into unrelated values ('preserve-me')")
    else:
        _store(path)
        with sqlite3.connect(path) as connection:
            if drift == "manifest":
                connection.execute(
                    "update browser_session_component_schema set schema_version = 999"
                )
            else:
                connection.execute("drop index browser_sessions_principal_scope_idx")
                connection.execute(
                    "create index browser_sessions_principal_scope_idx "
                    "on browser_sessions (principal_subject)"
                )
    before = _snapshot(path)

    with pytest.raises(BrowserSessionSchemaError):
        _store(path)

    assert _snapshot(path) == before


def test_registration_and_resolution_are_digest_only_exact_and_read_only(
    tmp_path: Path,
) -> None:
    path = tmp_path / "resolve.sqlite3"
    store = _store(path)
    state = _register(store)
    before = _snapshot(path)

    context = store.resolve_session(session_identifier_digest="a" * 64, now=NOW)
    provider_context = StoreBackedSessionSecurityContextProvider(
        store=store,
        session_identifier_digest="a" * 64,
    ).get_session_security_context()

    assert state.state_version == state.generation == 1
    assert context == provider_context
    assert context.principal == _principal()
    assert context.allowed_browser_origin == ORIGIN
    assert context.session_identifier_digest == "a" * 64
    assert context.csrf_token_digest == "b" * 64
    assert _snapshot(path) == before


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("session_identifier_digest", "A" * 64),
        ("csrf_token_digest", "not-a-digest"),
        ("allowed_browser_origin", "http://review.example.com"),
        ("absolute_expires_at", NOW + timedelta(hours=9)),
        ("idle_expires_at", NOW + timedelta(minutes=31)),
        ("issued_at", NOW + timedelta(seconds=61)),
    ),
)
def test_registration_rejects_invalid_policy_generically_and_without_rows(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    store = _store(tmp_path / f"invalid-{field}.sqlite3")
    values = {
        "session_identifier_digest": "a" * 64,
        "csrf_token_digest": "b" * 64,
        "principal": _principal(),
        "allowed_browser_origin": ORIGIN,
        "issued_at": NOW - timedelta(minutes=5),
        "authenticated_at": NOW - timedelta(minutes=4),
        "last_seen_at": NOW - timedelta(minutes=1),
        "idle_expires_at": NOW + timedelta(minutes=29),
        "absolute_expires_at": NOW + timedelta(hours=7),
        "now": NOW,
    }
    values[field] = value

    with pytest.raises(BrowserSessionRejectedError, match="^browser session rejected$"):
        store.register_session(**values)  # type: ignore[arg-type]
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("select count(*) from browser_sessions").fetchone() == (0,)


def test_duplicate_digest_and_invalid_resolution_are_indistinguishable(tmp_path: Path) -> None:
    store = _store(tmp_path / "generic.sqlite3")
    _register(store)

    failures = []
    for operation in (
        lambda: _register(store),
        lambda: store.resolve_session(session_identifier_digest="c" * 64, now=NOW),
        lambda: store.resolve_session(session_identifier_digest="malformed", now=NOW),
    ):
        with pytest.raises(BrowserSessionRejectedError) as caught:
            operation()
        failures.append(str(caught.value))
        assert caught.value.__cause__ is None
    assert failures == ["browser session rejected"] * 3


def test_touch_is_explicit_versioned_and_never_extends_absolute_expiry(tmp_path: Path) -> None:
    store = _store(tmp_path / "touch.sqlite3")
    absolute = NOW + timedelta(minutes=10)
    original = _register(store, absolute_expires_at=absolute)
    untouched = store.resolve_session(session_identifier_digest="a" * 64, now=NOW)
    assert untouched.last_seen_at == original.last_seen_at

    touched = store.touch_session(
        session_identifier_digest="a" * 64,
        expected_state_version=1,
        now=NOW + timedelta(minutes=1),
    )
    assert touched.state_version == 2
    assert touched.last_seen_at == NOW + timedelta(minutes=1)
    assert touched.idle_expires_at == absolute
    with pytest.raises(BrowserSessionRejectedError):
        store.touch_session(
            session_identifier_digest="a" * 64,
            expected_state_version=1,
            now=NOW + timedelta(minutes=2),
        )


def test_rotation_replaces_both_digests_atomically_and_revocation_is_terminal(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path / "rotate-revoke.sqlite3")
    _register(store)
    rotated = store.rotate_session(
        session_identifier_digest="a" * 64,
        new_session_identifier_digest="c" * 64,
        new_csrf_token_digest="d" * 64,
        expected_state_version=1,
        now=NOW,
    )
    assert (rotated.generation, rotated.state_version) == (2, 2)
    assert rotated.session_identifier_digest == "c" * 64
    assert rotated.csrf_token_digest == "d" * 64
    with pytest.raises(BrowserSessionRejectedError):
        store.resolve_session(session_identifier_digest="a" * 64, now=NOW)

    revoked = store.revoke_session(
        session_identifier_digest="c" * 64,
        expected_state_version=2,
        now=NOW + timedelta(seconds=1),
    )
    assert revoked.revoked and revoked.state_version == 3
    for operation in (
        lambda: store.resolve_session(session_identifier_digest="c" * 64, now=NOW),
        lambda: store.touch_session(
            session_identifier_digest="c" * 64,
            expected_state_version=3,
            now=NOW + timedelta(minutes=1),
        ),
        lambda: store.rotate_session(
            session_identifier_digest="c" * 64,
            new_session_identifier_digest="e" * 64,
            new_csrf_token_digest="f" * 64,
            expected_state_version=3,
            now=NOW + timedelta(minutes=1),
        ),
    ):
        with pytest.raises(BrowserSessionRejectedError):
            operation()


def test_allocated_digests_can_never_be_reactivated_and_survive_reopen(
    tmp_path: Path,
) -> None:
    path = tmp_path / "digest-history.sqlite3"
    store = _store(path)
    _register(store)
    store.rotate_session(
        session_identifier_digest="a" * 64,
        new_session_identifier_digest="c" * 64,
        new_csrf_token_digest="d" * 64,
        expected_state_version=1,
        now=NOW,
    )

    for operation in (
        lambda target: target.rotate_session(
            session_identifier_digest="c" * 64,
            new_session_identifier_digest="a" * 64,
            new_csrf_token_digest="b" * 64,
            expected_state_version=2,
            now=NOW + timedelta(seconds=1),
        ),
        lambda target: _register(target),
    ):
        with pytest.raises(BrowserSessionRejectedError, match="^browser session rejected$"):
            operation(store)

    reopened = _store(path)
    for operation in (
        lambda target: target.rotate_session(
            session_identifier_digest="c" * 64,
            new_session_identifier_digest="a" * 64,
            new_csrf_token_digest="b" * 64,
            expected_state_version=2,
            now=NOW + timedelta(seconds=1),
        ),
        lambda target: _register(target),
    ):
        with pytest.raises(BrowserSessionRejectedError):
            operation(reopened)

    context = reopened.resolve_session(session_identifier_digest="c" * 64, now=NOW)
    assert context.csrf_token_digest == "d" * 64
    with sqlite3.connect(path) as connection:
        allocations = connection.execute(
            "select digest, digest_kind from browser_session_digest_allocations order by digest"
        ).fetchall()
    assert allocations == [
        ("a" * 64, "session_identifier"),
        ("b" * 64, "csrf"),
        ("c" * 64, "session_identifier"),
        ("d" * 64, "csrf"),
    ]


def test_digest_pair_claim_failure_is_atomic_for_registration_and_rotation(
    tmp_path: Path,
) -> None:
    path = tmp_path / "digest-atomic.sqlite3"
    store = _store(path)
    _register(store)

    with pytest.raises(BrowserSessionRejectedError):
        _register(store, identifier_digest="c" * 64, csrf_digest="b" * 64)
    # The first allocation in the failed pair was rolled back.
    _register(store, identifier_digest="c" * 64, csrf_digest="d" * 64)

    with pytest.raises(BrowserSessionRejectedError):
        store.rotate_session(
            session_identifier_digest="a" * 64,
            new_session_identifier_digest="e" * 64,
            new_csrf_token_digest="d" * 64,
            expected_state_version=1,
            now=NOW,
        )
    # Neither the tentative identifier allocation nor the session update survived.
    original = store.resolve_session(session_identifier_digest="a" * 64, now=NOW)
    assert original.session_generation == 1
    rotated = store.rotate_session(
        session_identifier_digest="a" * 64,
        new_session_identifier_digest="e" * 64,
        new_csrf_token_digest="f" * 64,
        expected_state_version=1,
        now=NOW,
    )
    assert (rotated.session_identifier_digest, rotated.csrf_token_digest) == (
        "e" * 64,
        "f" * 64,
    )
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "select count(*) from browser_session_digest_allocations"
        ).fetchone() == (6,)


def test_digest_allocation_history_is_database_immutable(tmp_path: Path) -> None:
    store = _store(tmp_path / "digest-immutable.sqlite3")
    _register(store)
    for statement in (
        "update browser_session_digest_allocations set digest_kind = 'csrf'",
        "delete from browser_session_digest_allocations",
    ):
        with (
            sqlite3.connect(store.database_path) as connection,
            pytest.raises(sqlite3.IntegrityError),
        ):
            connection.execute(statement)
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute(
            "select count(*) from browser_session_digest_allocations"
        ).fetchone() == (2,)


def test_conflicting_concurrent_mutations_have_exactly_one_winner(tmp_path: Path) -> None:
    store = _store(tmp_path / "concurrent.sqlite3")
    _register(store)

    def attempt(kind: str) -> str:
        try:
            if kind == "touch":
                store.touch_session(
                    session_identifier_digest="a" * 64,
                    expected_state_version=1,
                    now=NOW + timedelta(seconds=1),
                )
            elif kind == "rotate":
                store.rotate_session(
                    session_identifier_digest="a" * 64,
                    new_session_identifier_digest="c" * 64,
                    new_csrf_token_digest="d" * 64,
                    expected_state_version=1,
                    now=NOW + timedelta(seconds=1),
                )
            else:
                store.revoke_session(
                    session_identifier_digest="a" * 64,
                    expected_state_version=1,
                    now=NOW + timedelta(seconds=1),
                )
            return "won"
        except BrowserSessionRejectedError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=3) as executor:
        outcomes = list(executor.map(attempt, ("touch", "rotate", "revoke")))
    assert outcomes.count("won") == 1
    assert outcomes.count("rejected") == 2
    with sqlite3.connect(store.database_path) as connection:
        row = connection.execute(
            "select generation, state_version, count(*) from browser_sessions"
        ).fetchone()
    assert row is not None and row[1:] == (2, 1)
    assert row[0] in (1, 2)


def test_reopen_preserves_rotated_touched_revoked_and_expired_state(tmp_path: Path) -> None:
    path = tmp_path / "reopen.sqlite3"
    first = _store(path)
    _register(first, identifier_digest="a" * 64, csrf_digest="b" * 64)
    _register(first, identifier_digest="e" * 64, csrf_digest="f" * 64)
    first.touch_session(
        session_identifier_digest="a" * 64,
        expected_state_version=1,
        now=NOW + timedelta(minutes=1),
    )
    first.rotate_session(
        session_identifier_digest="a" * 64,
        new_session_identifier_digest="c" * 64,
        new_csrf_token_digest="d" * 64,
        expected_state_version=2,
        now=NOW + timedelta(minutes=1),
    )
    first.revoke_session(
        session_identifier_digest="c" * 64,
        expected_state_version=3,
        now=NOW + timedelta(minutes=2),
    )

    active_reopen = _store(path, now=NOW + timedelta(minutes=3))
    assert active_reopen.resolve_session(session_identifier_digest="e" * 64).session_generation == 1

    reopened = _store(path, now=NOW + timedelta(minutes=30))
    for digest in ("c" * 64, "e" * 64):
        with pytest.raises(BrowserSessionRejectedError):
            reopened.resolve_session(session_identifier_digest=digest)
    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            """
            select session_identifier_digest, generation, revoked_at_us, state_version
            from browser_sessions order by session_identifier_digest
            """
        ).fetchall()
    assert rows[0][0] == "c" * 64 and rows[0][1:] == (2, rows[0][2], 4)
    assert rows[0][2] is not None
    assert rows[1][0] == "e" * 64 and rows[1][1:] == (1, None, 1)


@pytest.mark.parametrize("failure", ("locked", "corrupt", "unavailable"))
def test_provider_preserves_generic_invalid_error_and_operational_failure_boundary(
    tmp_path: Path,
    failure: str,
) -> None:
    store = _store(tmp_path / f"fault-{failure}.sqlite3")
    _register(store)
    provider = StoreBackedSessionSecurityContextProvider(
        store=store,
        session_identifier_digest="a" * 64,
    )
    message = {
        "locked": "database is locked private/path",
        "corrupt": "database disk image is malformed private/sql",
        "unavailable": "private runtime detail",
    }[failure]

    def broken_connect():
        if failure == "unavailable":
            raise RuntimeError(message)
        raise sqlite3.OperationalError(message)

    store._connect = broken_connect  # type: ignore[method-assign]
    with pytest.raises(BrowserSessionStoreUnavailableError) as caught:
        provider.get_session_security_context()
    assert str(caught.value) == "browser session store unavailable"
    assert caught.value.__cause__ is None
    assert message not in str(caught.value)


@pytest.mark.parametrize("stored_value", (-(2**63), 2**63 - 1))
def test_malformed_signed_64_timestamp_is_generic_store_unavailable(
    tmp_path: Path,
    stored_value: int,
) -> None:
    store = _store(tmp_path / f"malformed-time-{stored_value}.sqlite3")
    _register(store)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "update browser_sessions set issued_at_us = ?",
            (stored_value,),
        )

    with pytest.raises(BrowserSessionStoreUnavailableError) as direct:
        store.resolve_session(session_identifier_digest="a" * 64, now=NOW)
    assert str(direct.value) == "browser session store unavailable"
    assert direct.value.__cause__ is None

    provider = StoreBackedSessionSecurityContextProvider(
        store=store,
        session_identifier_digest="a" * 64,
    )
    with pytest.raises(BrowserSessionStoreUnavailableError) as provided:
        provider.get_session_security_context()
    assert str(provided.value) == "browser session store unavailable"
    assert provided.value.__cause__ is None


def test_clock_and_touch_addition_overflow_fail_closed_without_mutation(tmp_path: Path) -> None:
    maximum = datetime.max.replace(tzinfo=UTC)
    registration_time = maximum - timedelta(minutes=31)
    store = _store(tmp_path / "time-overflow.sqlite3", now=registration_time)
    state = store.register_session(
        session_identifier_digest="a" * 64,
        csrf_token_digest="b" * 64,
        principal=_principal(),
        allowed_browser_origin=ORIGIN,
        issued_at=maximum - timedelta(hours=7),
        authenticated_at=maximum - timedelta(hours=7),
        last_seen_at=registration_time,
        idle_expires_at=maximum - timedelta(minutes=1),
        absolute_expires_at=maximum,
        now=registration_time,
    )
    before = _snapshot(Path(store.database_path))

    with pytest.raises(BrowserSessionStoreUnavailableError) as touched:
        store.touch_session(
            session_identifier_digest="a" * 64,
            expected_state_version=state.state_version,
            now=maximum - timedelta(minutes=10),
        )
    assert str(touched.value) == "browser session store unavailable"
    assert touched.value.__cause__ is None
    assert _snapshot(Path(store.database_path)) == before

    store._clock = lambda: maximum  # type: ignore[assignment]
    provider = StoreBackedSessionSecurityContextProvider(
        store=store,
        session_identifier_digest="a" * 64,
    )
    with pytest.raises(BrowserSessionStoreUnavailableError) as resolved:
        provider.get_session_security_context()
    assert str(resolved.value) == "browser session store unavailable"
    assert resolved.value.__cause__ is None


def test_database_contains_digests_and_bounded_metadata_but_not_raw_material(
    tmp_path: Path,
) -> None:
    path = tmp_path / "privacy.sqlite3"
    store = _store(path)
    _register(store)
    with sqlite3.connect(path) as connection:
        session_columns = {
            row[1] for row in connection.execute("pragma table_xinfo('browser_sessions')")
        }
        allocation_columns = {
            row[1]
            for row in connection.execute(
                "pragma table_xinfo('browser_session_digest_allocations')"
            )
        }
    assert session_columns.isdisjoint(
        {"session_identifier", "csrf_token", "cookie", "secret", "raw_material"}
    )
    assert {"session_identifier_digest", "csrf_token_digest"}.issubset(session_columns)
    assert allocation_columns == {"digest", "digest_kind", "allocated_at_us"}
