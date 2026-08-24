# Workflow Helper

Privacy-conscious CAD workflow capture and knowledge extraction for expert
AutoCAD sessions.

This repository contains a lean MVP scaffold.
The intended vertical slice is:

1. detect an approved AutoCAD foreground window;
2. create a local, versioned session package;
3. register and upload the package;
4. queue deterministic processing;
5. produce a compact timeline and keyframe manifest; and
6. display session status in a web control plane.

> **Important:** This is an implementation scaffold, not production capture
> software. Recording is disabled by default. Do not deploy it to employee
> workstations until consent, allowlists, retention, access controls, and a
> security review are complete.

## Repository map

| Path | Purpose |
| --- | --- |
| `apps/capture-agent` | Windows/.NET foreground detection and session packaging |
| `apps/api` | FastAPI session, upload, review, and authenticated synthetic control-plane APIs |
| `apps/worker` | Deterministic preprocessing worker scaffold |
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
- Docker Compose (optional, for building and starting the current scaffold)

```bash
cp .env.example .env
docker compose up --build
```

Then open:

- Web UI: `http://localhost:3000`
- API health: `http://localhost:8000/health`
- LocalStack: `http://localhost:4566`

This is not currently an end-to-end development stack. Compose starts
PostgreSQL, LocalStack, the default API, the worker, and the web app, but the
default API intentionally installs no runtime bundle. It serves `GET /health`
with `environment=unconfigured`; `/docs`, `/redoc`, and `/openapi.json` return
`404`; and protected routes fail closed with bounded `503` responses.
PostgreSQL is health-checked and persisted by Compose but is not connected to
the API or worker. The web app currently converts API failures into an empty
dashboard or a not-found session page, so an empty display is not evidence that
the API session plane is available. An explicit unavailable/error UI belongs to
Phase 1.

Run the dependency-light checks with:

```bash
python scripts/validate.py
```

For the bounded generated-data-only Windows/LocalStack compatibility pilot,
follow [`docs/WINDOWS_SYNTHETIC_PILOT.md`](docs/WINDOWS_SYNTHETIC_PILOT.md).
That harness describes the intended compatibility flow but cannot currently
reach `PASS` with the default Compose API because the required synthetic
authentication/runtime composition is not installed. It never enables or
exercises real capture and does not connect to Google Drive or any billable
cloud service.

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
a no-network artifact oracle, and a serialized analysis boundary. These are
code and test components, not the default runtime. A sealed synthetic bundle
can be constructed explicitly and passed to a separately created
`create_app(bundle)` instance for hermetic tests; Compose and the module-global
API do not construct or install it. The unused `InMemorySessionRepository` is
also not default route storage, and the durable `SQLiteLegacySessionStore` is
only reachable through an explicitly constructed bundle.

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

Synthetic/code-only foundation with recording disabled by default. See
`docs/MVP_SCOPE.md`, `docs/ARCHITECTURE.md`, and the accepted ADRs for current
acceptance criteria and deferred live-pilot work.

<!-- staged public verification trigger -->
