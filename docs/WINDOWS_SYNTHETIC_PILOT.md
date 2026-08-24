# Controlled Windows synthetic pilot

This document describes a legacy compatibility harness for one controlled
Windows host:

generated package → API registration → presigned LocalStack upload → SQS →
worker → v1 processed timeline → API and web readback.

It is not the repository's currently verified guarded development slice. The
legacy harness has no recorded `PASS`, remains `PLATFORM_UNVERIFIED`, and is not
expected to pass on the current tree.

## Current runtime truth

Compose now explicitly overrides the API command to run
`workflow_api.dev_server`. That entrypoint requires the exact synthetic proof
inputs and a fresh absolute data directory, constructs the sealed no-network
runtime bundle, and works with the canonical seed. The default image command
and module-global application remain inert and fail closed; the Compose override
does not change those defaults.

The dashboard and session-detail pages use guarded server-only credentials.
They distinguish an unavailable session plane from a genuine empty or not-found
result. Their current behavior is verified by the separate
`scripts/dev-runtime-smoke.sh` acceptance path, which exercises the canonical
rich package, default v2 processing, candidate visibility, and durable synthetic
review.

Public GitHub Actions run `32767406213` completed `9/9` jobs successfully. That
run validates the guarded Compose development smoke. It does **not** validate
this legacy Windows + Docker Desktop + LocalStack/SQS harness and is not a
controlled-Windows pilot result.

## Why the legacy harness does not match the current runtime

The existing `scripts/windows-synthetic-pilot.ps1` has not been adapted to the
current sealed runtime:

- It does not supply the current capture, worker, and reviewer proof material or
  the browser-session and CSRF evidence required by protected operations.
- It sends credential-free requests to protected session-plane routes.
- It expects the obsolete three-event package and an
  `AutoCAD command: SYNTHETIC_LINE` timeline item rather than the canonical rich
  synthetic package.
- It expects a v1 `timeline.json` artifact in S3 and the LocalStack/SQS worker
  path, while the guarded acceptance path uses the default v2 processing flow
  and sealed no-network runtime.

Changing the legacy script into an active harness requires a separate
authorization and bounded implementation dispatch. This document does not
authorize that work, and `scripts/windows-synthetic-pilot.ps1` remains
unchanged.

## Safety boundary

The harness and current guarded smoke are synthetic-only. Neither detects a
window, opens a recording, reads a drawing, accepts an input drawing, invokes a
model, connects Google Drive or another live provider, deploys capture software,
or creates recurring spend. The normal capture settings remain disabled and the
recorder remains a no-op.

No deployed or billable service is authorized. No real drawing, customer or
employee data, credential, provider connection, model call, live capture,
workstation deployment, or privacy-pilot approval may be inferred from either
path.

## Legacy platform prerequisites

Any future separately authorized attempt still requires:

- one controlled Windows 11 or Windows Server host;
- PowerShell 7+ and the .NET 8 SDK;
- Docker Desktop using Linux containers and Docker Compose v2;
- the required local ports; and
- a fresh checkout containing no real drawings, recordings, identifiers, or
  secrets.

The human browser check also remains necessary because a script cannot attest
what a reviewer actually sees. These requirements have not been executed or
verified here.

## Historical invocation and evidence boundary

The unadapted command is:

```powershell
pwsh -File scripts/windows-synthetic-pilot.ps1
```

It writes intended evidence to:

```text
pilot-evidence/windows-synthetic-pilot.json
```

Do not treat invoking the command, CI success for another smoke path, or a
server-rendered HTTP response as a legacy pilot `PASS`. A genuine result would
require every harness check plus the controlled-host human browser review to be
recorded after the script is separately authorized and brought into agreement
with the current runtime.

This technical harness does not satisfy the privacy pilot checklist, approve
real capture, test a visible recording indicator, create a Drive data plane, or
authorize workstation deployment. Keep recording and capture disabled until all
separate live-pilot prerequisites are explicitly approved.
