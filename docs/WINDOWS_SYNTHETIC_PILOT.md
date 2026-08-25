# Controlled Windows synthetic pilot

This document defines the sanctioned generated-data-only pilot for one
controlled Windows host. It is a synthetic integration gate, not the live
privacy pilot and not a deployment path for the capture agent. The entrypoint
is:

```powershell
pwsh -NoProfile -File scripts/windows-synthetic-pilot.ps1
```

The command drives the sealed synthetic runtime and does not reimplement API,
worker, review, or export behavior in PowerShell. The controlled outcome is the
canonical rich synthetic package passing through upload receipt, v2 timeline,
candidate review, terminal human approval, approved catalog/export, and an
independent durable reopen.

The current repository status is `PLATFORM_BLOCKED`: no controlled-host run or
human browser sign-off is asserted by source checkout or CI. A full run may
report `PASS` only after every automated check and the explicit human gate
succeed. A completed CI preflight is never a full pilot result.

## Safety boundary

Both modes are synthetic-only and recording-absent. The canonical fixture has
`recording: null` and no recording artifact. Neither mode detects a live
window, opens a recorder, reads a drawing, accepts an input drawing, invokes a
model, connects Google Drive or another live provider, uses live credentials,
deploys capture software, or creates spend. Committed capture, consent, and
upload defaults must remain `false`, and the normal recorder registration must
remain the disabled no-op.

The script rejects ambient Google, AWS, and other live-provider credential
sources. It creates fresh capture, worker, reviewer, browser-session, and CSRF
proof material for each run, a uniquely named Compose project, and fresh
temporary runtime state. On success or failure it removes only that project's
containers/volumes and its own temporary proof/state paths.

No real drawing, customer or employee data, provider credential, live capture,
recording, model call, deployment, permission change, or privacy-pilot approval
is authorized by this harness.

## Preflight-only check

Run the same non-Docker, no-network check used by the existing Windows
capture-agent CI job:

```powershell
pwsh -NoProfile -File scripts/windows-synthetic-pilot.ps1 -PreflightOnly
```

`-PreflightOnly` does not launch Docker or Compose, start the runtime, contact a
network, or perform provider activity. It fails closed unless all of these are
true:

- the host is Windows with supported PowerShell and .NET expectations;
- committed capture, consent, and upload defaults are `false`;
- `DisabledCaptureRecorder` is the normal-mode recorder;
- the canonical fixture is bounded, recording-free, contains exactly eight
  lifecycle events, and carries the four-command
  `LINE -> TRIM -> LINE -> TRIM` sequence;
- the evidence target is the bounded local
  `pilot-evidence/windows-synthetic-pilot.json` location; and
- no prohibited ambient credential or provider configuration is present.

Preflight validates prerequisites and safety invariants only. It does not prove
Docker, the sealed runtime, upload or processing, browser rendering, human
review, terminal approval, catalog/export safety, or durability. Its success
means only that the host and fixtures are eligible for a separately gated full
run; it must not be recorded as pilot `PASS`.

## Full pilot prerequisites

Use a fresh checkout of the frozen candidate branch on one controlled Windows
11 or Windows Server host with:

- PowerShell 7+ and the .NET 8 SDK;
- Docker Desktop using Linux containers and Docker Compose v2;
- the local API and web ports used by the harness available for the bounded
  synthetic run;
- no real drawings, recordings, employee/client identifiers, or secrets in the
  checkout or environment; and
- a human reviewer present to inspect the browser surfaces.

Do not create a handwritten `.env` or add credentials. The script generates a
private temporary Compose environment and rejects ambient Google/AWS/provider
sources before starting anything. Internal Compose traffic is test traffic
between the sealed services; no live provider endpoint is permitted.

## Controlled run

From the repository root:

```powershell
pwsh -NoProfile -File scripts/windows-synthetic-pilot.ps1
```

The script starts a unique, fresh instance of the existing Compose topology and
then verifies the product through the sanctioned surfaces:

1. The sealed runtime accepts the canonical recording-absent package, registers
   it, and records the upload receipt.
2. The v2 timeline reports exactly eight meaningful operations (the eight
   lifecycle events) and four ordered operation segments.
3. The browser-visible candidate is redacted and shows only the observed
   `LINE -> TRIM -> LINE -> TRIM` without proof values, raw identifiers,
   digests, or private server evidence.
4. The operator opens the printed browser URLs, checks the timeline and review
   surfaces, and explicitly confirms the human review gate in the prompt.
5. The existing review route records one terminal approval only after that
   confirmation.
6. The approved catalog exposes one observed workflow and its bounded JSON
   export contains only the safe allowlisted fields—no identifiers, digests,
   proof material, or private evidence.
7. A separate no-port reopen verifies the approved record from durable state;
   the result cannot depend on an in-process object or a still-running port.
8. Cleanup removes only the unique project, volumes, and temporary state made
   by this run.

The run fails if the human confirmation is absent or negative. HTTP success,
server-rendered text, preflight, or CI alone cannot substitute for that
confirmation.

## Evidence and cleanup

The default evidence file is:

```text
pilot-evidence/windows-synthetic-pilot.json
```

It is local and untracked. Do not add it to Git. Evidence is redacted and
records only bounded check results, the controlled-host classification, and the
human-confirmation outcome; it must not contain runtime proof values,
browser-session or CSRF material, raw UUIDs, digests, object keys, private
server evidence, package bytes, or other run identifiers.

The script cleans only its uniquely named Compose project, volumes, and
temporary state. If cleanup itself fails, the pilot records a scoped-cleanup
failure; stop and inspect the controlled host rather than running broad Docker
cleanup or prune commands.

## Result classification

A full pass requires every automated check plus the recorded human browser
confirmation. Before that controlled-host evidence exists, the integration
gate remains `PLATFORM_BLOCKED`, even when preflight and repository CI pass.
`PLATFORM_BLOCKED` is a controlled-host/human-review gate, not evidence that
the synthetic checks failed and not permission to infer a pilot pass.

This harness still does not satisfy the live privacy pilot checklist, test a
visible recording indicator, create a Drive data plane, or authorize employee
workstation deployment. Keep recording and capture disabled until all separate
live-pilot prerequisites are approved.

## Rollback

Restore the exact frozen baseline blobs in a normal forward commit:

- script: `0abe4330e1fc24d5c33e5c7e5ccf351e6e63093b`
- this document: `1ebe688c28ceb3562e84240d8a3373e0c8c9ce82`
- `README.md`: `358d927b1d2114b66d4757d154045c87357dc94c`
- `.github/workflows/ci.yml`:
  `9c64ef3e8365c8038600715c48454e9539682218`
