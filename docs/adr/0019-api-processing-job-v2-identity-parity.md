# ADR 0019: Dormant API ProcessingJobV2 payload identity parity

- Status: accepted for dormant synthetic integration evidence
- Date: 2026-08-19
- Decision class: R2, material reversible private code change
- Scope: API-local models and payload identity only; no route or runtime wiring

## Context

The frozen ProcessingJobV2 payload-digest contract already has a worker implementation
and cross-language golden vectors. The API needs an independently implemented identity
mechanism so a future, separately governed control-plane writer can bind the exact
admitted payload without importing worker code. Sharing runtime model classes would
blur ownership and permit structurally similar or mutated values to cross a trust
boundary without API admission.

The payload contract and its checked-in vectors remain the sole identity authority.
This decision does not revise schemas, infer identity from storage metadata, or make
an API or worker implementation authoritative over the contract.

## Decision

Add API-local `ArtifactProvider`, `ArtifactRole`, `ArtifactRef`, and `ProcessingJobV2`
types. The two Pydantic models are frozen and reject additional fields. They preserve
the frozen structural bounds: exact version `2.0`, UUID identities, provider and role
enums, bounded file/revision/MIME strings, lowercase SHA-256, and an integer artifact
size from zero through 512 MiB. Integral JSON floats converge to the corresponding
integer; booleans, strings, fractions, and non-finite values do not.

Add one dormant API identity module. It accepts only the exact API
`ProcessingJobV2` and exact nested API `ArtifactRef`, verifies their exact field and
runtime scalar types, and creates one independently validated defensive snapshot.
Package admission then requires provider `s3` or `google_drive`, role `raw_package`,
MIME type `application/zip`, and a size from one through 512 MiB. Dicts, worker
models, subclasses, impostors, missing or additional fields, forged scalar types,
and invalid package semantics fail before hashing.

The admitted snapshot is normalized to exactly the eleven semantic values named by
`contracts/processing-job-v2-payload-digest-v1.md`. UUIDs become lowercase hyphenated
text. Other strings retain their exact Unicode scalar sequence, including whitespace,
case, controls, and NFC/NFD distinctions; unpaired surrogates fail closed. A restricted
RFC 8785 serializer emits only the required object/string/integer subset and prefixes
the canonical bytes with:

```text
workflow-helper\0processing-job-v2\0payload-digest\0sha256-jcs-v1\0
```

The only scheme is
`workflow-helper.processing-job-v2.payload.sha256-jcs.v1`. Every public rejection,
including poisoned internal serialization or hashing failures, is the same
`ValueError("payload digest rejected")` without input values, partial bytes, digest,
or exception cause. The implementation performs no resolver, store, provider,
network, filesystem, environment, logging, queue, callback, or runtime operation.

API and worker code intentionally remain independent. Root parity tests bind both
implementations to the frozen canonical bytes, preimages, and golden digests
`5a5653b89eb071a70b9b861b65358bd062b83ee978962ea8041b9ca3affad1c7` and
`6370158c3d21bf6a4e5c62f0297fa12e5bdc518fa4d2c324f46527f70d9d39a1`.
A built-in-only Node reproduction provides a third mechanism over those same frozen
vectors.

## Authority separation

Payload `session_id` is payload identity only. It never supplies tenant, workspace,
principal, capture owner, or artifact authority. ADR 0018 remains the exclusive
capture-authority seam: an authenticated server-derived tenant/workspace scope plus
the exact session UUID resolves the stored registration owner. No payload field,
worker identity, lease owner, machine/project metadata, object key, or request value
can replace that durable authority.

Result identity remains independently domain-separated under the frozen result
contract and worker result-manifest mechanism. ADR 0017 control-identity sidecars,
the existing control ledger, leases, fencing, completion, and historical opaque
digests are unchanged. Composing payload, capture, result, or control identity into a
runtime write requires a later governed decision.

## Dormancy, privacy, and rollback

Nothing imports this module from routes, dependencies, application factories,
runtime bundles, worker entrypoints, configuration, Compose, or infrastructure.
It opens no database or provider, discovers no credential or environment value,
accepts no payload bytes, logs no identifiers, invokes no capture, and creates no
deployment or recurring resource. All verification data is synthetic and checked in.
Added spend and real/customer/personal/raw-data exposure remain zero.

Before runtime adoption, rollback is deletion of the API identity module, its two
test files, and this ADR plus removal of the four API-local model definitions. No
schema, vector, stored record, provider artifact, database, or deployment recovery is
required.

## Consequences

- API admission owns an immutable local snapshot without worker imports.
- Contract vectors, rather than either runtime, detect semantic drift.
- Generic rejection preserves the privacy boundary on malformed or hostile values.
- Capture, result, and control authority remain separate and dormant.
- Any route, writer, default import, provider integration, persistence, activation,
  or production claim requires a separate decision and verification package.
