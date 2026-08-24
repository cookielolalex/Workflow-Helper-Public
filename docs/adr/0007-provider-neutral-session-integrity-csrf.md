# ADR 0007: Provider-neutral synthetic session integrity and anti-CSRF seam

- Status: Accepted for bounded synthetic evidence
- Date: 2026-08-17
- Decision class: R2 material reversible
- Exact implementation baseline: `40208f464ba2bd75ca85f0386caef2feac9c560a`

## Context

The private `/v1/control/**` surface already fails closed without an installed
authenticated principal and service. It did not yet have an independent,
server-supplied session-lifecycle contract or route-side anti-CSRF precondition.
CORS is useful browser defense in depth, but it is not authentication, session
integrity, or a CSRF defense by itself.

The legacy `/v1/sessions/**` and `/v1/internal/sessions/**` surfaces use
separate development bearer/worker-token seams. They are intentionally excluded
from this decision. Consequently, this ADR is not a whole-application or
production-complete session-security claim.

## Decision

Install one shared dependency from application composition on every current
router under `/v1/control`. The dependency runs before route service/store
dependencies and requires both:

1. the existing exact `AuthenticatedPrincipal`; and
2. an immutable `SessionSecurityContext` returned by a server-supplied
   `SessionSecurityContextProvider` protocol.

There is no default provider. Missing provider installation returns one bounded
503. Provider failures return the same bounded 503. Invalid, expired, revoked,
stale, forged, or principal-mismatched context returns one generic bounded
rejection without provider or lifecycle detail.

The context binds the exact pseudonymous subject, exact roles, and exact
tenant/workspace scope; SHA-256 digest of an opaque session identifier; current
and active session generation; ordered UTC issuance, authentication, last-seen,
idle-expiry, and absolute-expiry timestamps; explicit revocation state;
server-classified browser-cookie transport; exact canonical HTTPS browser
origin; and only a SHA-256 digest of the current CSRF material.

All fields are revalidated after provider output. The synthetic policy caps
absolute lifetime at eight hours, idle lifetime at thirty minutes, and tolerated
issuance clock skew at sixty seconds. Authentication and last-seen evidence may
not be future-dated. The session generation must exactly equal the provider's
current active generation.

Safe methods (`GET`, `HEAD`, and `OPTIONS`) require a valid session
context. Unsafe methods (`POST`, `PUT`, `PATCH`, and `DELETE`) also
require exactly one canonical HTTPS `Origin` equal to the server-supplied
allowed origin and exactly one `X-CSRF-Token` header. The presented token is
canonical bounded base64url material containing exactly 256 bits. It is hashed
with SHA-256 and compared with the provider digest using a constant-time
comparison. Raw token material is never accepted, returned, persisted, audited,
or logged by this seam. This validation seam does not persist either digest.
ADR 0011's separate, explicitly constructed lifecycle authority persists only
the two canonical digests and bounded metadata; it never receives raw material.

A token present only in a cookie, URL, query, path, or body is ignored and
cannot satisfy the guard. Missing, duplicate, blank, malformed, oversized,
wrong, case-changed, or stale token evidence fails before route service/store
access. Origin matching is exact; null, HTTP, credentials, paths, default-port
ambiguity, wrong ports, suffixes, subdomains, wildcards, substring matches, case
normalization, and trailing-dot ambiguity are rejected.

`X-CSRF-Token` is added to the existing explicit CORS allowed-header list.
Origins and methods are not broadened. CORS remains defense in depth and is not
the anti-CSRF enforcement mechanism.

## Durable synthetic lifecycle reference

ADR 0011 adds the separate component-local `SQLiteBrowserSessionStore` and an
explicit store-backed provider. Registration, read-only resolve, bounded touch,
atomic dual-digest rotation, terminal revocation, optimistic concurrency, and
restart/reopen behavior are now authoritative in that hermetic reference. A
prior identifier digest no longer resolves after rotation, prior CSRF material
fails the unchanged request guard, and explicit revocation fails immediately.
The immutable allocation history prevents any prior identifier or CSRF digest
from being registered or rotated back into active authority.

The store is not installed by default and adds no issuance, cookies, routes,
configuration, provider integration, live database, or production claim. The
runtime bundle and all live lifecycle controls remain separately gated.

## Preserved invariants

This package does not change route source, request/response schemas, persistence
or migrations, RBAC, tenant/workspace authorization, exclusive steward roles,
global lease cap of three, 1,800-second maximum lease TTL, audit, retention,
dataset approval, or one-way safety semantics. Default authentication and
service fail-closed behavior remains. No test or development bypass exists for
`/v1/control/**`.

## Residual R3 controls

Before any live or production use, a separate R3 decision and enhanced controls
must cover at least:

- real IdP and MFA lifecycle integration;
- secure session issuance, renewal, and live logout/invalidation delivery, plus
  a production-authoritative durable session store;
- cookie name, host/domain/path, `Secure`, `HttpOnly`, `SameSite`, expiry,
  and session-fixation controls;
- live origin/domain/proxy/TLS configuration and trusted-forwarding policy;
- cryptographic entropy generation, secret handling, key rotation, and
  credential ownership;
- monitoring, alerts, bounded audit evidence, incident ownership, containment,
  and tested recovery;
- privacy notice, consent, access, retention, deletion, and legal/third-party
  prerequisites;
- deployment, canary, cost/data/exposure caps, rollback, and authoritative
  post-deployment verification.

Reusable CSRF evidence does not prevent replay after theft of the authenticated
session and its current CSRF material. This package does not satisfy the
canonical live session/CSRF gate and does not authorize live identities, real
data, credentials, provider calls, Site/Drive data-plane mutation, release, or
deployment.

## Rollback and stop triggers

Before integration, close the draft PR and retain or discard the private branch.
After a separately authorized integration, revert through a reviewed PR while
preserving evidence.

Stop if exact baseline or merge base changes, a non-allowlisted path is needed,
a weak/ambiguous origin comparison or non-constant digest comparison appears,
provider/session/token detail leaks, guard-before-store ordering cannot be
proved, any existing invariant or test regresses, or any real provider, cookie,
credential, configuration, data, deployment, permission, billing, or external
exposure becomes necessary.

## Consequences

The control plane gains one explicit provider-neutral fail-closed contract and
route-wide synthetic enforcement point. Successful live use remains impossible
until the R3 controls above are separately designed, reviewed, implemented, and
verified.
