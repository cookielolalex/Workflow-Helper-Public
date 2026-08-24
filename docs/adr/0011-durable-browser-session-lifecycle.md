# ADR 0011: Durable digest-only browser-session lifecycle

- Status: accepted for a hermetic, explicitly injected reference boundary
- Date: 2026-08-18
- Decision boundary: private synthetic code; default and live use blocked
- Builds on: ADR 0007 and ADR 0010

## Context

ADR 0007 defined a provider-neutral `SessionSecurityContext` and exact
Origin/CSRF enforcement, but its lifecycle evidence was supplied by an opaque
provider. It did not establish authoritative registration, explicit idle touch,
atomic rotation, revocation, optimistic concurrency, or restart behavior. A
runtime bundle built on that seam would still have lacked lifecycle authority.

## Decision

Add a dedicated `SQLiteBrowserSessionStore` whose database contains only its
own exact v1 manifest, browser-session table, and immutable digest-allocation
history. Construction requires a caller-supplied filesystem path.
Initialization atomically admits only an empty file or an exact v1 reopen.
Partial, drifted, colliding, shared, or unknown SQLite state is rejected without
adoption, repair, or migration. The browser database is not the legacy,
control, audit, retention, or safety database and does not change their
constructor-order contract.

The store accepts and persists only canonical SHA-256 digests of the session
identifier and CSRF material. It neither accepts nor generates raw material.
Each row owns the exact pseudonymous subject, sorted exact roles,
tenant/workspace scope, canonical HTTPS origin, generation, issuance,
authentication, last-seen, idle and absolute expiries, revocation time, and
optimistic state version. Absolute lifetime remains capped at eight hours, idle
lifetime at thirty minutes, and issuance skew at sixty seconds by the unchanged
ADR 0007 contract.

Registration creates generation and state version one. Resolution is an exact
digest lookup and is read-only: it never renews or writes. Missing, malformed,
expired, revoked, and prior-rotation digests have the same generic rejection.
Registration and rotation atomically claim both proposed digests in the
immutable allocation history before changing session state. A digest previously
allocated for either purpose can never be allocated again, including after
rotation or restart, so prior evidence cannot be reactivated as an identifier
or CSRF digest. A collision in either half rolls back both claims and the session
mutation.

Explicit touch advances last-seen and state version and caps idle expiry at both
thirty minutes and absolute expiry. Rotation changes both digests in one
transaction and increments generation and state version. Revocation records an
irreversible inactive state and increments state version. All mutations use an
expected state version under `BEGIN IMMEDIATE`, so conflicting touch, rotation,
revocation, and stale-version attempts have one winner without lost updates or
partial digest replacement.

`StoreBackedSessionSecurityContextProvider` is an explicit request-scoped
adapter to the existing `SessionSecurityContextProvider` protocol. It receives
one already-canonical presented identifier digest and one preconstructed store;
it has no path discovery, environment, configuration, credential, SDK, or
default. Valid evidence is projected into the exact existing
`SessionSecurityContext`. Invalid evidence remains a generic rejection;
operational storage failure becomes a generic unavailable error with no raw
exception detail.

## Composition and default boundary

`ProviderNeutralSecurityComposition` remains the sole route injection seam and
is unchanged. Test-only dependency injection proves safe and unsafe control
routes can resolve through the store-backed provider while the existing exact
Origin and `X-CSRF-Token` checks remain in force. Browser and workload
transports remain non-interchangeable.

No provider or store is installed by default. Import, startup, health, and
protected-request behavior remain unchanged: health is 200 and every protected
operation is a bounded 503 with no filesystem, database, WAL, provider, or
network side effect. This package adds no runtime bundle, application factory,
route, dependency, configuration, cookie issuance, login/logout endpoint,
provider integration, credential, migration, deployment, or live data access.

## Failure and privacy boundary

The authoritative database contains digests and bounded pseudonymous metadata,
never raw session or CSRF material. Resolve and lifecycle conflicts do not
distinguish absence, malformed evidence, expiry, revocation, stale state, or
digest collision. Through the existing composition, invalid evidence is a
bounded generic 401 and locked, corrupt, or unavailable SQLite is a bounded
generic 503. SQL, database paths, digests, principals, scopes, timing facts, and
raw exception text are not returned by the route boundary.

## Verification

Hermetic tests cover exact empty initialization and exact reopen; rejection of
partial, drifted, colliding, and unknown schema state without repair;
registration and duplicate handling; read-only resolution; lifetime and origin
policy; immutable one-time digest allocation; rotate-back and post-rotation
registration rejection; bounded touch; atomic dual-digest rotation; terminal revocation;
optimistic stale-version and concurrent mutation behavior; restart preservation
of active, touched, rotated, expired, revoked, and allocated-digest state;
malformed timestamp and clock-arithmetic overflow handling; provider fault mapping;
test-only safe/unsafe route composition; browser/workload separation; and the
unchanged 29-operation, 28-protected, 11-unsafe inventory and default 503 matrix.

## Residual live controls

This is a disposable SQLite concurrency and durability reference, not a live or
production session system. A separate R3 decision must still cover real IdP/MFA
lifecycle, cryptographic raw-material generation and custody, cookie attributes,
session fixation, live logout and invalidation delivery, origin/proxy/TLS
configuration, monitoring and incident response, privacy/legal controls,
deployment, recovery, data handling, and cost/exposure limits.

## Rollback

Before merge, close the draft pull request and retain its private branch. After
a separately governed merge, revert the exact merge through a private pull
request and one CI cycle. All browser-session databases in this decision are
disposable `tmp_path` synthetic files; there is no live-state recovery action.
