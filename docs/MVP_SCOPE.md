# Lean MVP scope

## Implemented synthetic vertical slice

The default API image and module-global application remain inert and fail
closed. An explicitly guarded development-only Compose command can instead
construct the sealed no-network synthetic runtime. That runtime currently
provides:

- the canonical rich synthetic session package and versioned contracts;
- the default deterministic v2 worker path and durable timeline readback;
- deterministic candidate derivation marked `observed` and `unreviewed`;
- authenticated, server-only dashboard, session, and v2 timeline views; and
- a bounded synthetic review action whose decision is durably recorded.

The active development slice uses six component-local SQLite stores and an
in-memory, no-network S3 oracle. PostgreSQL, LocalStack, S3, and SQS remain
compatibility or rollback surfaces; they are not the active application stores
or transport for this sealed slice. No live provider is connected.

## Deferred behind explicit approval and interfaces

- Production authentication, identity-provider integration, device enrollment,
  RBAC operations, and live audit deployment
- AI/model-assisted labeling or candidate extraction
- Live-provider and production review workflows
- Real screen capture, a user-visible recording pilot, AutoCAD plug-in capture,
  and DWG-safe snapshot integration
- Production PostgreSQL repositories and migrations, resumable multipart
  upload, live S3/Drive adapters, compute deployment, and operational alerting

These deferrals do not describe the synthetic slice as unauthenticated or
review-inert: its fixed development identities, scoped proofs, candidate
publication, and durable review are implemented and fail closed. They confer no
production or live-data authority.

## Checkpoint acceptance criteria

1. Contracts and canonical examples validate structurally and semantically.
2. The guarded smoke path proves register -> upload receipt -> default v2
   processing -> durable timeline -> candidate visible -> authenticated review
   -> durable empty unreviewed queue after an independent runtime reopen.
3. The dashboard exposes exactly the canonical synthetic session, its detail,
   v2 timeline and segments, and the bounded candidate-review route without
   exposing raw credentials or candidate identifiers.
4. Repository validation and the relevant API, worker, web, root, and
   infrastructure checks are green. Public GitHub Actions run `32766238604`
   completed `9/9` jobs successfully.
5. Recording remains disabled by default, the default application remains
   inert, and no secret or real customer or employee artifact is present.

## Further work

This document does not authorize the next milestone. Under Decision 200, each
new implementation step requires a separate SP dispatch and may not
self-authorize from this scope description. The current result is not evidence
of Windows capture readiness, live-pilot readiness, production readiness, or
live-provider readiness. Any such step remains separately governed and must
preserve synthetic-only operation, recording-off defaults, no real data, no
model calls, no new spend, and no deployment unless explicitly approved.
