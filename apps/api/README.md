# Workflow Helper API upload contract

The API uses separate S3 endpoints for two different network contexts:

- `AWS_ENDPOINT_URL` is used by the API container for S3 and SQS SDK calls.
- `AWS_S3_PRESIGNED_ENDPOINT_URL` is used only when producing the URL returned
  to the capture client. For Docker Desktop development it should be
  `http://localhost:4566`, while the internal endpoint remains
  `http://localstack:4566`.

`POST /v1/sessions/{session_id}/upload-url` returns every header that must be
sent with the PUT in `required_headers`. This includes the exact content length,
the base64 SHA-256 S3 checksum, hash metadata, and `If-None-Match: *`. The raw
key is content addressed:

`sessions/{session_id}/packages/{package_sha256}.zip`

Upload finalization verifies the S3 provider checksum, exact object length,
streamed content digest, and the bounded root `metadata.json`. Package metadata
must follow the session contract and its identity fields must match the
registration before the job is queued.

If queue submission returns `503`, the client retries the same upload-finalization
request. The API re-verifies the identical content-addressed package and retries
enqueueing while the session remains `uploaded`; later workflow states are not
requeued by this callback.

Workers complete processing through
`POST /v1/internal/sessions/{session_id}/processing-completion`. The callback is
idempotent by its deterministic 64-character SHA-256 `idempotency_key`. Clients
read the persisted result from `GET /v1/sessions/{session_id}/timeline`.

The legacy static control-plane bearer and `X-Workflow-Worker-Token` are not
authentication mechanisms in development, test, or production. Every session
route fails closed by default because this repository deliberately composes no
real provider. A later governed composition must install provider-neutral,
request-scoped providers without putting raw credentials in validated context.

Reviewer `GET` requests reuse the verified identity contract and browser-session
validator. They may list, read, and fetch timelines only in the exact tenant and
workspace supplied by that trusted context. Capture `POST` requests require an
exact `capture_uploader` workload context and bind registration, presigning, and
upload completion to its scope and owner subject. Processing completion requires
an exact `deterministic_worker` context in the same stored scope. Workload proof
decisions bind principal, role, audience, transport, method, canonical path, raw
body SHA-256, UTC freshness, generation/revocation, and one-time replay status.

Session UUIDs remain globally unique. The repository stores scope and capture
owner privately, returns generic absence across boundaries, and does not permit
the same UUID to coexist in different scopes. Object keys remain
`sessions/{session_id}/packages/{package_sha256}.zip`.

The compressed package and presign TTL have immutable maxima of 512 MiB and 900
seconds; configuration may only lower them. The metadata limit defaults to 1 MiB
and may also be lowered.

## Sealed synthetic runtime bundle

`create_app()` is inert: it creates a health-only-usable application with zero
CORS origins, performs no environment, `.env`, filesystem, SQLite/WAL, SDK,
provider, gateway, service, or network discovery, and returns bounded `503`
responses from every protected surface. `GET /health` remains available.

`create_app(bundle)` accepts only one exact `SealedSyntheticRuntimeBundle`. The
bundle contains preconstructed singleton security composition, legacy store,
digest-only browser store and its exact store-backed factory, control service,
safety service, an explicit env-file-disabled synthetic `Settings` snapshot,
and `NoNetworkArtifactGateway`. Dependency adapters return those same objects by
identity; no default or fallback construction exists. CORS comes only from the
bundle's canonical HTTPS reserved-`.example` origins.

The no-network gateway is an in-process synthetic metadata oracle. It creates
an inert `https://uploads.synthetic.example` ticket, records only canonical
object key/SHA-256/size registration and receipt metadata, verifies an exact
receipt, and records session/object-key queue evidence. It accepts and stores no
payload bytes, constructs no client, signs no URL, and performs no file or
network I/O. Missing or wrong receipts fail before durable upload marking and
queue evidence.

Status boundaries are generic and bounded: invalid identity, browser session,
or workload proof is `401`; forbidden action is `403`; scoped absence is `404`;
state/receipt conflict is `409`; invalid input is `422`; and operational store,
service, provider, or oracle failure is `503`. Validation bodies never include
submitted values, field details, credentials, principals, paths, SQL, or
digests.

This bundle is synthetic-only, in-process, and no-network. It is not live
provider wiring, deployment configuration, a release, readiness evidence, or a
production identity/data path. Live origins, providers, credentials, existing
databases, real data, permissions, deployment, and default flips require a
separate R3 decision and its enhanced gates. Before merge, rollback is to close
the draft PR and retain the private branch. After merge, rollback requires a
separately governed private revert PR plus CI.
