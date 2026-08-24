# ADR 0012: Sealed provider-neutral synthetic runtime bundle

- Status: accepted for synthetic code-boundary evidence
- Date: 2026-08-18
- Scope: in-process, no-network, no raw payload, no live readiness claim

## Context

The repository already has provider-neutral verified identity, durable workload
proof claims in `SQLiteLegacySessionStore`, a digest-only browser lifecycle,
`ControlService`, and `SafetyControlService`. They intentionally had no runtime
installation. Independent dependency overrides could not prove that every route
shared one authority or that an upload lifecycle could succeed without an
external artifact provider.

The default application must remain import-safe and health-only usable. No
environment, `.env`, path, existing database, SDK/client, provider, credential,
real origin, network, deployment, release, or default-provider fallback may be
introduced.

## Decision

Add exact final `SealedSyntheticRuntimeBundle` and `create_app(bundle=None)`.
The bundle accepts only preconstructed exact instances of:

- `ProviderNeutralSecurityComposition`;
- the identical `SQLiteLegacySessionStore` exposed by that composition;
- `SQLiteBrowserSessionStore`;
- the identical exact `StoreBackedBrowserSessionProviderFactory` installed in
  the composition, whose exposed store is that browser store;
- exact `ControlService` and `SafetyControlService` singletons;
- an exact, env-file-disabled `Settings` snapshot with every field explicitly
  supplied; and
- exact `NoNetworkArtifactGateway`.

Subclasses, missing collaborators, split stores/factories, non-synthetic or
implicit settings, live origins/endpoints, and gateway limit mismatches are
rejected before collaborator methods. Dependency roots are thin adapters over
the installed bundle and repeatedly return the same objects by identity.

`create_app()` installs no bundle, configures zero CORS origins, and does not
call settings/environment/path/provider/client/database code. Health returns
`200`; protected routes fail closed with bounded `503`. `create_app(bundle)`
creates a separate app, installs the bundle atomically, and uses only the
bundle's canonical HTTPS reserved-`.example` origins. It never mutates the
module-global app.

All request-validation errors use one constant bounded body. Route error mapping
is:

| Condition | Status |
| --- | ---: |
| invalid identity, browser session, or workload proof | 401 |
| authenticated but forbidden action | 403 |
| scoped resource absence | 404 |
| state, idempotency, or receipt conflict | 409 |
| invalid submitted shape/value | 422 |
| operational provider/store/service/oracle failure | 503 |

Bodies do not echo submitted values or expose raw cookies, tokens, credentials,
payloads, principals/scopes, SQL/paths, digests, signed URLs, or exception text.

## Synthetic artifact oracle

`NoNetworkArtifactGateway` is a deterministic in-memory metadata oracle. Ticket
creation registers only canonical object key, SHA-256 digest, and exact size and
returns an inert `https://uploads.synthetic.example` PUT target with deterministic
required digest/size headers and bounded expiry. A test-only receipt method
accepts those three metadata fields and no bytes. Verification succeeds only
when ticket registration, receipt, object key, digest, size, and durable session
registration match exactly. Queueing records only `(session_id, object_key)` and
has no external effect.

The handler order remains authorization/proof claim, scoped durable read, then
oracle. Upload completion verifies outside a store transaction, then durably
marks/events, then records queue evidence. Replay and invalid identity/session
stop before handlers and the oracle. Missing/wrong receipt cannot mark uploaded
or queue.

## Settings and caps

The explicit snapshot requires `environment=synthetic`; unique canonical HTTPS
reserved-`.example` origins; raw retention of 1–14 days; ticket TTL of 1–900
seconds; package limit of 1–512 MiB; positive bounded metadata/chunk/spool sizes;
no AWS endpoint, presign endpoint, or queue URL; and inert reserved labels only.
The bundle constructor accepts no path, environment name, provider config,
secret, or live origin.

## Consequences and exclusions

This provides a hermetic composition and end-to-end metadata proof while the
default remains inert. It does not issue credentials/cookies, accept raw upload
bytes, sign URLs, construct SDK clients, open sockets/files, connect providers,
use existing/real databases, migrate data, process real data, deploy, release,
change permissions, flip a default, or establish live/provider/deployment
readiness. Drive-first storage authority is unchanged; the AWS adapter and
LocalStack tests remain compatibility/rollback evidence outside this runtime.

Before merge, rollback is to close the draft PR and retain the private branch.
After merge, rollback requires a separately governed private revert PR plus CI.
The in-memory oracle and synthetic temporary databases contain no material data
and require no recovery.

Any live IdP/workload provider, origin/domain/proxy, credential, cookie issuance,
Drive/AWS connection, durable production database, real data, permission,
deployment, release, cost, monitoring, or readiness claim is a separate R3
package. It must satisfy governance enhanced audits, least privilege, consent,
retention, incident ownership, caps, rollback, and authoritative readback before
execution.
