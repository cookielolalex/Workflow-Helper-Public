# ADR 0016: Candidate-skill internal-coherence admission

Status: Accepted

## Context

The candidate-skill 1.0 schema constrains individual fields but cannot express
all relationships between its arrays. A structurally valid candidate could use
duplicate input or parameter names, number ordered actions inconsistently with
their array order, or reference a parameter that is not declared. Such content
is ambiguous and must not reach the authoritative approval boundary.

## Decision

Add a pure, dependency-free validator in
`workflow_api.candidate_skill_semantics`. It runs in the existing bounded
candidate admission path immediately after complete structural contract
validation and before digest construction, request validation, control-service
access, review or audit mutation, or creation of the SQLite coordination lock.

For every structurally admitted candidate, the validator requires:

- ordered-action `sequence` values to be exactly `1..N` in array order;
- input names to be unique;
- parameter names to be unique; and
- every ordered-action parameter reference to match one declared parameter.

Exact string equality defines name identity. Empty parameter declarations and
empty per-action parameter-reference arrays remain valid. Structural admission
continues to provide the fixed collection and content bounds, so the coherence
pass is linear in already bounded candidate content and performs no I/O or
mutation.

## Consequences

Incoherent candidates fail closed before any observable downstream effect in
both approval and approval-state reads. Existing coherent version 1.0 fixtures,
canonical digest behavior, forged inline approval handling, replay and
concurrency controls, changed-content conflicts, scope isolation, and SQLite
restart persistence are unchanged. No schema, fixture, producer, extraction,
route, provider, session, artifact, UI, runtime default, dependency, workflow,
lockfile, or data-store change is introduced.

Rejection is additive and reversible: remove the coherence module, its tests,
this ADR, and its single call from candidate admission. Existing authority
records require no migration or rollback.
