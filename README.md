# Workflow Helper

Privacy-conscious CAD workflow capture and knowledge extraction for expert
AutoCAD sessions.

This repository contains a synthetic activation MVP. Its bounded development
vertical slice is:

1. detect an approved AutoCAD foreground window;
2. create a local, versioned session package;
3. register and upload the package;
4. queue deterministic processing;
5. produce a compact timeline and a deterministic candidate;
6. publish that candidate only after durable timeline completion; and
7. display and review the redacted candidate through the guarded development
   web route.

> **Important:** This is synthetic development software, not production capture
> software. Recording is disabled by default. Do not deploy it to employee
> workstations until consent, allowlists, retention, access controls, and a
> security review are complete.

## Repository map

| Path | Purpose |
| --- | --- |
| `apps/capture-agent` | Windows/.NET foreground detection and session packaging |
| `apps/api` | FastAPI session, upload, review, and authenticated synthetic control-plane APIs |
| `apps/worker` | Deterministic v2 preprocessing and synthetic candidate production |
| `apps/web` | Next.js management dashboard and session viewer |
| `contracts` | Versioned JSON contracts shared across components |
| `infra` | AWS compatibility scaffold retained for LocalStack/S3 rollback tests |
| `docs` | Architecture, privacy boundary, ADRs, and MVP scope |
| `scripts` | Dependency-light validation and bounded synthetic test harnesses |

## Local development

Prerequisites:

- Python 3.12+
- Node.js 22+
- .NET 8 SDK on Windows for the capture agent
- Docker Compose (optional, for the guarded synthetic development runtime)

```bash
cp .env.example .env
docker compose up --build
```

Then open:

- Web UI: `http://localhost:3000`
- API health: `http://localhost:8000/health`
- LocalStack: `http://localhost:4566`

Compose has one explicitly guarded, synthetic end-to-end development slice.
Its `api` command override starts `workflow_api.dev_server`, which rejects
non-development environments, ambient live-provider credentials, non-fresh
data directories, and malformed synthetic proof material before constructing
the sealed no-network bundle. A one-shot seed submits the canonical synthetic
package, runs the default v2 worker path, and publishes a deterministic
candidate only after timeline completion. The `/candidate-review` page renders
a redacted queue and submits one same-origin synthetic review action.

This activation does not change the image default: `workflow_api.main:app`
still installs no runtime bundle, performs no discovery, and leaves protected
routes fail closed. PostgreSQL and LocalStack remain compatibility services in
the Compose topology; the activated slice uses six component-local SQLite
stores and an in-memory S3 oracle instead. The ordinary dashboard and session
detail pages still mask API failures as empty or not found, so only the bounded
candidate-review smoke is development-readiness evidence.

Run the dependency-light checks with:

```bash
python scripts/validate.py
```

For the bounded generated-data-only Windows/LocalStack compatibility pilot,
follow [`docs/WINDOWS_SYNTHETIC_PILOT.md`](docs/WINDOWS_SYNTHETIC_PILOT.md).
That compatibility harness is separate from the guarded candidate-review
slice. The latter is exercised by `scripts/dev-runtime-smoke.sh`; it never
enables or exercises real capture and does not connect to Google Drive, use
live credentials, or contact any billable cloud service.

## Safety defaults

- Recording is opt-in through configuration and uses a no-op recorder in this
  checkpoint.
- Only an allowlisted process name (`acad`) can start a normal session.
- Session metadata uses pseudonymous machine IDs.
- No permanent cloud or AI-provider credentials belong in the agent or repo.
- Google Drive is the intended artifact system of record for the future live
  design; LocalStack/S3 is retained only as explicit compatibility/rollback.
- The control plane exposes artifact references, not unrestricted storage access.
- Observed behavior and human-approved drafting rules are different states.

## Current implementation boundary

The repository contains persistent synthetic SQLite reference stores, a
fail-closed authenticated service boundary, provider-neutral artifact contracts,
a no-network artifact oracle, and a serialized analysis boundary. These are not
installed by the module-global application or the default image command. A
sealed synthetic bundle can be constructed explicitly and passed to a
separately created `create_app(bundle)` instance for hermetic tests. The guarded
Compose development command also constructs that exact no-network bundle and
uses its durable SQLite stores for the synthetic seed/review slice. The unused
`InMemorySessionRepository` is not route storage, and the durable
`SQLiteLegacySessionStore` is reachable only through an explicitly constructed
bundle.

These development controls do not authorize or implement production identity,
a live Google Drive adapter, employee capture, real-data processing, a
PostgreSQL-backed control plane, or Site deployment. Google Drive remains the
intended future artifact authority. S3/LocalStack remains compatibility and
rollback evidence only; there is no automatic provider fallback.

The highest-risk live integrations remain behind explicit gates: real screen
capture, AutoCAD command telemetry, DWG snapshotting, organization-owned Drive
identity/scopes, production authentication/SSO, real-data retention enforcement,
and AI labeling on selected evidence.

## Status

Synthetic activation foundation with recording disabled by default. See
`docs/MVP_SCOPE.md`, `docs/ARCHITECTURE.md`, and the accepted ADRs for current
acceptance criteria and deferred live-pilot work.
