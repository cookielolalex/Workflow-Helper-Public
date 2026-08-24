# ADR 0004: Synthetic authenticated control boundary

## Status

Accepted for a synthetic-only, local development slice.

## Context

The durable SQLite control store needs a narrow service boundary before any
future operational use. Direct request fields must never select the worker or
reviewer identity, authorization must be server-side and least-privilege, and
an accepted state mutation must not commit without immutable actor/action
evidence.

This decision does not authorize live identity, real data, capture, deployment,
or access to any external provider.

## Decision

Add a frozen pseudonymous principal with only three exact, case-sensitive roles:
`deterministic_worker`, `reviewer`, and `audit_reader`. The worker may register,
acquire, heartbeat, and complete jobs; the reviewer may append and read review
events; the audit reader may only read audit events. There are no wildcards,
role normalization, implied permissions, or roleless permissions.

Every new route depends on an authentication dependency that returns a bounded
503 by default. Tests may explicitly inject hermetic principals and a local
service. There is no header-trusted identity, bearer-token implementation,
secret, environment bypass, or development bypass in this boundary. Request
models omit actor and owner fields and reject extra fields. The service always
uses the authenticated subject as `owner_id` or `actor_id`.

Accepted mutations append an `accepted` audit event inside the same SQLite
`BEGIN IMMEDIATE` transaction as the state mutation, including idempotent
success paths. Authenticated authorization denials append standalone `denied`
evidence where the audit store is available. Audit events contain a bounded
correlation identifier, optional semantic idempotency key, pseudonymous
subject, exact sorted roles, enumerated action, target, result, and UTC
timestamp. Update and delete triggers make audit evidence append-only. No audit
mutation route exists.

The routes expose only synthetic jobs, leases, completions, reviews, and audit
evidence under `/v1/control`. They have no Drive, network, cloud, Site, capture,
live-identity, or real-data path.

## Consequences and mandatory later gates

This is code-boundary evidence, not production authentication. Any move toward
private operational or live use is a later R3 decision and must independently
design, implement, and review all of the following:

- real SSO and MFA with a trusted identity provider;
- tenant isolation and object-level access controls;
- CSRF and session controls;
- production secret creation, storage, rotation, and revocation;
- live identity lifecycle, audit retention, incident response, and recovery.

Until those gates pass, the default-unavailable dependency remains correct and
the boundary remains synthetic-only. It must not be connected to Drive,
network/cloud providers, Site hosting, capture, live workstations, live users,
or real data.
