# Workflow Helper Course-Correction Record

> **PROPOSED/HISTORICAL PLANNING INPUT — NOT AN EXECUTABLE WORK ORDER OR REPOSITORY AUTHORITY.**

**Reconciled:** 2026-08-25  
**Basis:** advisor proposal reconciled with canonical governance and current private-main truth  
**Scope:** planning history, activation governance, safety invariants, and advisory verification

## 1. Authority and precedence

This record does not authorize a branch, commit, pull request, merge, provider,
credential, live resource, real-data operation, capture capability, deployment,
spend, permission change, cleanup, or destructive action. Repository work requires
a separate bounded SP dispatch.

When sources differ, authority is resolved in this order:

1. canonical Google Drive governance, recorded decisions, outcomes, and dispatches;
2. the repository's applicable `AGENTS.md` instructions;
3. `docs/PRIVACY_BOUNDARY.md`;
4. `docs/ARCHITECTURE.md` for reconciled implementation truth; and
5. each file under `docs/adr/` according to that ADR's own recorded status.

ADR filenames currently span 0001–0019. That numbering range does **not** mean
every ADR is accepted or active. Each ADR's status and any later canonical
supersession control independently. This record neither reserves an ADR number nor
changes an ADR's status.

If this record conflicts with a higher-precedence source, the higher-precedence
source wins and the affected action remains stopped pending reconciliation.

## 2. Reconciled current outcome

The course correction's activation prerequisite has been achieved through bounded
packages P2, P4, P3a, and P3b:

- **P2 complete:** an explicit development server constructs the sealed synthetic
  no-network runtime. The default image command and module-global application remain
  inert and fail closed.
- **P4 complete:** one rich canonical synthetic package is the cross-component
  fixture, and the default worker queue loop processes it through v2 deterministically.
- **P3a complete:** deterministic repeated-command evidence produces one observed,
  unreviewed candidate only after durable v2 timeline completion. Publication,
  discovery, and review authority remain scoped to the exact sealed bundle.
- **P3b complete:** the guarded synthetic Compose runtime seeds the canonical package,
  exposes a redacted server-only candidate-review page, records one bounded review
  action, and proves durable state through an independent runtime opener.

The P1 reachability smoke now proves, with synthetic data only:

`register → upload receipt → timeline → candidate visible → review durably recorded`

This is development evidence, not a production-readiness claim. The activated slice
uses explicit synthetic proofs, recording remains off, and no live credential,
network provider, employee/client data, model call, or recurring spend is involved.
PostgreSQL and LocalStack remain compatibility topology, not application authority for
this slice.

There is no GCS gateway or activated GCS authority. No live Google Drive data-plane
adapter, production identity stack, ChatGPT Site deployment, or live capture path is
implemented. Provider selection, GCS evaluation, real capture, and a live pilot remain
deferred and separately governed.

## 3. P1 activation rule

Every feature PR must either be reachable through a sanctioned entrypoint (the
guarded Compose development runtime, the synthetic pilot harness, or the web) or name
one exact follow-up PR that activates it, and that activation PR must be next in that
work stream. A work stream may have at most one dormant layer. Later feature PRs
extend the end-to-end smoke at the earliest newly reachable boundary.

Reachability evidence should be deterministic, synthetic, and fail closed. A feature
that cannot yet extend a sanctioned entrypoint is incomplete unless its one exact next
activation PR is named and remains next in that stream.

## 4. P5 consolidation freeze

The consolidation freeze has fulfilled its role as an activation prerequisite: P2,
P4, P3a, and P3b landed without adding another unconstrained store, schema, identity
module, or parallel dormant product path.

This outcome grants **no** authority to delete code, refs, branches, stores, schemas,
history, or provider compatibility paths. It also grants no authority for source/store
consolidation. Any destructive cleanup is a separate bounded dispatch and requires the
owner's explicit approval. Non-destructive consolidation proposals still require
caller evidence, rollback, and independent verification.

## 5. Non-negotiable invariants

These remain advisory hard constraints for any future bounded dispatch:

1. Recording stays disabled by default. Consent and capture configuration remain
   false/off, and the disabled recorder remains the default implementation.
2. Uncertain identity, authority, scope, integrity, or runtime state fails closed. No
   default credential, header-trusted identity, wildcard authority, or control-plane
   development bypass is introduced.
3. Credentials, signed URLs, private repository URLs, client drawings, employee data,
   and other real data do not enter source, fixtures, logs, artifacts, or planning
   records.
4. Breaking contract changes create a new schema version; stored meaning is not
   silently changed.
5. Observed behavior is not human approval. An `approved` candidate requires durable
   human-approval evidence.
6. Artifact identity remains provider ID, immutable revision, SHA-256, exact size,
   MIME type, and role. Names and folders are not identity or workflow state.
7. Package object keys retain `sessions/{uuid}/packages/{sha256}.zip` semantics.
8. Existing bounds remain: 512 MiB package, 900-second ticket TTL, three active
   leases, 30-minute lease TTL, 14-day raw-retention target, analysis concurrency one,
   no automatic provider fallback, and no automatic API-key analysis fallback.
9. No new recurring spend or live resource is inferred from this planning record.
10. Synthetic fixtures remain deterministic, recording-off, and free of real data.

## 6. Forbidden actions and stop conditions

This record does not support any of the following:

- new synthetic security machinery, proof schemes, digest authorities, sealed types,
  or identity modules without a separately governed need;
- a live Drive/GCS data plane, OAuth flow, provider credential discovery, Site
  deployment, or billable cloud call;
- enabling a real recording, CAD telemetry, drawing snapshot, or workstation capture
  path;
- worker model/API calls or weakening the serialized analysis boundary;
- an additional queue system, silent provider fallback, or ungoverned store/schema;
- weakening append-only evidence, exact-scope predicates, immutable publication,
  generic bounded failure responses, caps, retention controls, or inert defaults;
- placing provider-specific headers or types outside the authorized gateway boundary;
- real credentials, real data, new spend, screen capture, broader OAuth scopes,
  production permissions, live deployment, or a changed fail-closed default; or
- deletion, branch/ref pruning, history replacement, repository replacement, or other
  destructive cleanup without an exact owner-approved destructive dispatch.

A future package stops on a verified regression, authority ambiguity, semantic schema
change, privacy-boundary conflict, live-provider requirement, or unavailable evidence
needed for its readiness claim. A genuinely unavailable platform is recorded as
`PLATFORM_UNVERIFIED`; it is never silently treated as `PASS` or `FAIL`.

## 7. Advisory verification matrix

The applicable matrix is evidence guidance for a separately dispatched package, not a
command from this record. A verified `FAIL` blocks that package. Every skipped row has
an explicit applicability or platform reason.

| Surface | Advisory check |
| --- | --- |
| Repository contracts and safety | `python scripts/validate.py` |
| API | `cd apps/api && ruff check src tests && pytest` |
| Worker | `cd apps/worker && ruff check src tests && pytest` |
| Cross-component slice | `pytest tests` from the repository root with both packages available |
| Web | `cd apps/web && npm run typecheck && npm run build` |
| Infrastructure | `cd infra && npm run build && npm run synth` plus the applicable dependency audit |
| Capture agent | restore, build, and `dotnet test` on an authorized .NET/Windows surface |
| Guarded Compose slice | `scripts/dev-runtime-smoke.sh` with Docker Compose available |
| Windows pilot | the synthetic pilot harness on an authorized Windows surface |

Results are recorded as `PASS`, `FAIL`, or `PLATFORM_UNVERIFIED`, with exact command,
head/tree provenance, and bounded evidence. Platform-unverified evidence cannot support
a claim that depends on that platform.

## 8. Reconciled historical program map

The advisor's old numbered phases are retained only as historical intent:

| Historical increment | Reconciled status |
| --- | --- |
| Truth reconciliation | Superseded by current repository truth and this advisory record; no phase-per-session rule survives. |
| Storage decision package | Deferred; Drive-first intended authority remains unless canonical governance records a different decision. |
| Runnable development stack | Activation objective completed through P2 and P3b while preserving the inert default application. |
| First knowledge slice | Synthetic objective completed through P4, P3a, and P3b: rich package, v2 timeline, candidate, visibility, and durable review. |
| Conditional GCS adapter | Not activated; GCS/provider decision remains deferred. |
| Capture signal upgrade | Not activated; live telemetry, snapshots, and recording remain absent. |
| Live pilot gate | Not activated; identity, consent, legal/platform authority, retention proof, incident ownership, billing controls, and one-workstation limits remain future gates. |

The old “one phase per session” and imperative work-order language are historical and
non-governing. Current progression uses the P1 activation rule, one bounded dispatch at
a time, exact scope, independent verification, rollback evidence, and canonical SP
governance.

## 9. Interpretation

This document records why the project shifted from accumulating dormant inventory to
shipping one reachable synthetic knowledge slice. It is useful when evaluating a
future proposal, but it cannot activate that proposal. Current repository truth comes
from the exact private-main tree and higher-precedence canonical records; future work
begins only through a new bounded dispatch.
