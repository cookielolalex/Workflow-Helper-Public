# ADR 0013: Scope-bound synthetic artifact evidence

- Status: accepted for synthetic code-boundary evidence
- Date: 2026-08-18
- Scope: in-process artifact metadata authorization; no provider activation

## Context

ADR 0012 introduced a sealed no-network artifact oracle. Its ticket
registrations and test receipts were indexed only by the caller-visible object
key, and its queue evidence was deduplicated only by session UUID and object
key. The legacy session store correctly authorizes an exact tenant/workspace and
capture owner before calling the gateway, but that store authorization was not
part of the gateway's evidence identity.

Separate valid stores can legitimately contain the same public session UUID,
SHA-256 digest, package size, and therefore the same external object key. Under
the prior indexing, a registration or receipt created for one authorized scope
or capture owner could satisfy verification and queue evidence for another.
The public key cannot itself prove authorization.

## Decision

Add one frozen exact `ArtifactAuthority` value containing:

- one exact `TenantWorkspaceScope`; and
- one exact bounded pseudonymous capture-owner subject.

Every `ArtifactGateway` operation requires this value explicitly: ticket
registration, synthetic test-receipt recording, verification, and enqueue.
Missing values, invalid contents, and subclasses fail closed. Routes construct
the authority only from the already-authorized request's `authorization.scope`
and `authorization.principal.subject`, after the exact scoped/owned store read.
No request body, path, query, header, or `SessionRecord` field can supply or
override artifact authority.

`NoNetworkArtifactGateway` indexes registrations and receipts by
`(ArtifactAuthority, object_key)`. Its queue evidence is also keyed and
deduplicated by that pair and records the authority, exact UUID, and public key.
The queue record also retains the bounded digest and size already established
by the receipt. Verification requires the same authority and exact object key,
UUID, SHA-256 digest, and size established by the registration and receipt. A wrong authority
is rejected before receipt, verification-state, or queue mutation. Repeating
the same operation under the same authority remains idempotent.

The external object-key syntax is unchanged:

```text
sessions/{uuid}/packages/{sha256}.zip
```

`AwsGateway` accepts and validates the exact authority argument only to preserve
the common interface. It does not incorporate the value into provider keys,
requests, messages, or metadata. Existing S3/LocalStack behavior remains
compatibility and rollback evidence; this decision makes no claim of
provider-visible namespace isolation and does not activate any provider.

## Error and ordering properties

Handler order remains authorization, exact scoped/owned store read, then
gateway. Wrong-scope or wrong-owner store lookups retain the bounded generic
`404` behavior and do not reach the gateway. A wrong authority at the synthetic
gateway retains the existing bounded conflict or unavailable mapping; responses
do not reveal tenant, workspace, owner, UUID, digest, size, or internal map
state. Receipt failure occurs before the store is marked uploaded, and enqueue
failure occurs without adding queue evidence.

## Consequences and exclusions

Two sealed synthetic bundles with separate stores and a shared no-network
gateway may now reuse identical UUID/digest/size metadata without satisfying or
deduplicating each other's evidence. The same isolation applies to two capture
owners in one tenant/workspace. Exact same-authority replay remains stable.

This changes no contract, schema, SQL, migration, runtime-bundle shape,
dependency, configuration, workflow, infrastructure, worker model, capture
agent, Windows harness, public key, or privacy boundary. It introduces no
network access, credentials, signed URLs, payload bytes, real data, deployment,
release, provider activation, permissions, public sharing, recurring cost, or
live-readiness claim. Recording remains disabled by default, and Drive-first
storage authority is unchanged.

Before merge, rollback is to close the private draft PR and retain its branch
for audit. After merge, rollback requires a separately governed private revert
PR restoring the prior blobs and passing the full required validation. There is
no data, migration, provider, or infrastructure recovery step.
