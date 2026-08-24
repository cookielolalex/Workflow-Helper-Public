# Controlled Windows synthetic pilot

This harness is intended to exercise the smallest safe local compatibility
vertical slice on one controlled Windows host:

generated package → API registration → presigned LocalStack upload → SQS →
worker → processed timeline → API and web readback.

It never detects a window, opens a recording, reads a drawing, accepts an input
file, calls Google Drive, or invokes model analysis. LocalStack/S3 is used only
as the repository's explicit synthetic compatibility/rollback oracle; Google
Drive remains the intended artifact system of record for the future live design.

The current default Compose runtime cannot complete that flow. The API starts
the module-global `create_app()` without the sealed synthetic runtime bundle or
browser/workload authentication composition. Its health response is
`environment=unconfigured`, while the harness requires `development`; all
protected session-plane routes return bounded `503`. Consequently `PASS` is not
expected from the current tree. This document records the intended compatibility
procedure and its safety boundaries; it is not successful pilot evidence.

The normal agent defaults remain unchanged: `CaptureEnabled=false`,
`ConsentAcknowledged=false`, `Upload.Enabled=false`, and
`DisabledCaptureRecorder`. The one-shot `--synthetic-pilot` route is separate
from the hosted capture worker and fails unless capture and consent remain false,
upload is explicitly enabled for that process, the API is credential-free and
loopback-only, and the output directory is visibly synthetic.

## Prerequisites

- Windows 11 or Windows Server with PowerShell 7+
- .NET 8 SDK
- Docker Desktop using Linux containers and Docker Compose v2
- ports 3000, 4566, and 8000 available locally
- a fresh checkout with no real drawings, recordings, identifiers, or secrets

Create the ignored development environment file from the checked template:

```powershell
Copy-Item .env.example .env
```

Do not add real credentials. The harness requires the checked LocalStack
endpoints and `test` AWS placeholders. It also refuses either of the optional
newer authentication credentials, whether inherited by the shell or placed in
`.env`:

- `CONTROL_PLANE_BEARER_TOKEN`
- `WORKFLOW_WORKER_TOKEN`

The harness intentionally does **not** learn to send those credentials. A future
authenticated pilot must be designed and approved separately instead of quietly
turning this synthetic compatibility check into a credential-bearing workflow.

No deployed or billable service is used. The run must use generated synthetic
data only, and its platform status remains `PLATFORM_UNVERIFIED` until a future
authorized composition completes the checks on a controlled Windows host.

## Current runtime blockers

- `docker compose` starts PostgreSQL, but the API and worker do not connect to
  it. The named volume is not session-plane persistence.
- `InMemorySessionRepository` exists in source but is unused by the routes; API
  restarts do not install or clear it.
- `SQLiteLegacySessionStore` is the durable session-plane reference used by an
  explicitly constructed security composition. The default API does not create
  it.
- `SealedSyntheticRuntimeBundle` can be passed only to a separately created
  `create_app(bundle)`. Compose starts `workflow_api.main:app`, which has no
  bundle, and the harness does not construct one or issue the required identity,
  browser-session, CSRF, or workload-proof evidence.
- The web app converts the unavailable API into an empty or not-found response,
  so its current HTML cannot prove session-plane readback. Phase 1 owns an
  explicit unavailable/error state.

## Run

From the repository root:

```powershell
pwsh -File scripts/windows-synthetic-pilot.ps1
```

The harness stops the worker; starts/rebuilds PostgreSQL and LocalStack;
force-recreates the default API and web containers; checks that the synthetic
queue has no visible, in-flight, or delayed messages; and then attempts the
fixed generated-package flow. In the current tree it fails at the API health
expectation before registration. Even if that health expectation were relaxed,
registration would receive `503` because the session-plane bundle and
authentication evidence are absent.

Do not reinterpret the unused in-memory repository, the separately constructible
SQLite store, or the uninstalled sealed bundle as working Compose persistence or
authentication. Remediation and a newly authorized controlled-Windows run are
required before `PASS` can be expected.

It writes ordered machine-readable evidence to:

```text
pilot-evidence/windows-synthetic-pilot.json
```

`result` can be `PASS` only when every named check passes; that result is not
expected with the current default runtime. The generated session ID,
events, timestamps, and package content are fixed, so the package digest and
expected timeline are repeatable. The temporary synthetic package is removed at
the end. If the queue is not empty, the harness fails rather than deleting
unknown local data.

For a nonempty synthetic queue or stale LocalStack container, explicitly reset
this local-only stack, then rerun the whole harness:

```powershell
docker compose down
pwsh -File scripts/windows-synthetic-pilot.ps1
```

`docker compose down` does not remove the named PostgreSQL volume. Do not add
`--volumes`; the pilot does not need to delete database data.

To stop the local stack after reviewing the evidence:

```powershell
docker compose down
```

## Future acceptance and manual check

Only after the missing synthetic runtime/authentication composition is
implemented and the harness produces a genuine `PASS`, open this URL in a
browser on the controlled Windows host:

```text
http://localhost:3000/sessions/d6d9e5b7-c9bc-4eb1-ae4a-1a14ed5b1350
```

Visually confirm the page shows a processed session and the
`AutoCAD command: SYNTHETIC_LINE` timeline item. The harness verifies the
server-rendered HTTP content, but it cannot honestly attest what a human sees in
the local browser.

Repository CI can build and unit-test the one-shot route, but it does not prove
this complete Windows + Docker Desktop harness has run. Do not mark the
controlled-Windows pilot complete until a suitable host produces PASS evidence
and the browser check is recorded.

This technical run does not satisfy the privacy pilot checklist, approve real
capture, test a visible recording indicator, create a Drive data plane, or
authorize workstation deployment. Keep all capture settings false until the
separate live-pilot prerequisites are satisfied.
