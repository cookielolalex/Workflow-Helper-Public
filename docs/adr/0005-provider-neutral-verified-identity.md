# ADR 0005: Provider-neutral verified identity contract

- Status: Accepted for synthetic code-only development
- Date: 2026-08-17
- Decision class: R1, routine reversible private feature-branch change

## Context

The control plane already accepts an immutable `AuthenticatedPrincipal`, but its
default dependency deliberately returns HTTP 503. A future server composition
needs a narrow seam between a reviewed identity provider integration and that
principal. The seam must not trust identity, groups, roles, or an MFA flag from
HTTP request material, and this checkpoint must not connect to a real provider.

## Decision

Add a provider-neutral contract with:

- immutable, bounded evidence containing one exact lowercase pseudonymous subject;
- typed authentication assurance and supported authentication methods that require
  at least two distinct factor categories;
- a server-supplied `Authenticator` protocol with no default implementation;
- a bounded server-owned allowlist that compares group identifiers exactly and
  case-sensitively and maps only to existing `ControlRole` enum values; and
- validation both when evidence/mappings are constructed and again after the
  authenticator returns, before an `AuthenticatedPrincipal` is created.

Unknown, duplicate, wildcard, substring, case-changed, empty, unbounded, or
unsupported evidence fails closed. Empty, duplicate, ambiguous, zero-role, or
non-`ControlRole` mappings fail closed. The canonical `AuthenticatedPrincipal`
constructor remains the final invariant check, including exclusive
`retention_steward` and `safety_steward` identities.

`get_authenticated_principal` is unchanged and therefore continues to return a
bounded HTTP 503 until a separately reviewed server composition explicitly
installs an authenticator and mapping.

## Consequences

This creates a hermetic contract and synthetic test seam only. It does not
implement or authorize SSO, OAuth/OIDC, HTTP token parsing, provider SDKs,
credentials, external configuration, real user data, production identity,
deployment, or live-pilot access. A later provider integration must separately
verify issuer, audience, signature, freshness, session state, MFA semantics,
group provenance, credential handling, logging/redaction, and incident/rollback
controls before it may supply this contract.
