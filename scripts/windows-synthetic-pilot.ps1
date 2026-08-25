[CmdletBinding()]
param(
    [string]$EvidencePath = "pilot-evidence/windows-synthetic-pilot.json",
    [int]$TimeoutSeconds = 180,
    [switch]$PreflightOnly
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$canonicalSessionId = "d6d9e5b7-c9bc-4eb1-ae4a-1a14ed5b1350"
$expectedEvidencePath = [IO.Path]::GetFullPath(
    (Join-Path $repoRoot "pilot-evidence/windows-synthetic-pilot.json"))
$resolvedEvidencePath = if ([IO.Path]::IsPathRooted($EvidencePath)) {
    [IO.Path]::GetFullPath($EvidencePath)
} else {
    [IO.Path]::GetFullPath((Join-Path $repoRoot $EvidencePath))
}
if (-not [string]::Equals(
        $resolvedEvidencePath,
        $expectedEvidencePath,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw "EvidencePath must remain pilot-evidence/windows-synthetic-pilot.json"
}

$forbiddenProviderSources = @(
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_PROFILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONFIG_FILE",
    "AWS_CA_BUNDLE",
    "AWS_SDK_LOAD_CONFIG",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT",
    "AWS_EC2_METADATA_SERVICE_ENDPOINT_MODE",
    "BOTO_CONFIG",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_OAUTH_ACCESS_TOKEN",
    "GOOGLE_CREDENTIALS",
    "GOOGLE_AUTHENTICATION",
    "GOOGLE_EXTERNAL_ACCOUNT_AUDIENCE",
    "GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE",
    "GOOGLE_EXTERNAL_ACCOUNT_IMPERSONATED_EMAIL",
    "GOOGLE_WORKLOAD_IDENTITY_PROVIDER",
    "GOOGLE_CLOUD_PROJECT",
    "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
    "CLOUDSDK_CONFIG",
    "GCE_METADATA_HOST",
    "GCE_METADATA_IP",
    "AWS_ENDPOINT_URL",
    "AWS_S3_PRESIGNED_ENDPOINT_URL",
    "PROCESSING_QUEUE_URL"
)

$checks = [ordered]@{
    windows_powershell_dotnet = "NOT_RUN"
    safety_defaults = "NOT_RUN"
    canonical_fixture = "NOT_RUN"
    fail_closed_configuration = "NOT_RUN"
    evidence_boundary = "NOT_RUN"
    docker_tooling = "NOT_RUN"
    sealed_runtime = "NOT_RUN"
    upload_receipt = "NOT_RUN"
    v2_timeline = "NOT_RUN"
    redacted_candidate = "NOT_RUN"
    human_browser_confirmation = "NOT_RUN"
    approval_terminal_outcome = "NOT_RUN"
    approved_catalog_export = "NOT_RUN"
    independent_durable_reopen = "NOT_RUN"
    scoped_cleanup = "NOT_RUN"
}
$evidence = [ordered]@{
    schema_version = "2.0"
    pilot_mode = if ($PreflightOnly) { "preflight-only" } else { "controlled-synthetic" }
    result = "FAIL"
    recording_included = $false
    human_browser_confirmed = $false
    checks = $checks
    error = $null
}

$currentCheck = "windows_powershell_dotnet"
$tempRoot = $null
$composePrefix = $null
$runtimeStarted = $false
$finalExitCode = 1

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$ArgumentList
    )
    $output = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { $_.ToString() })
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$FilePath failed with exit code $exitCode"
    }
    return $output
}

function Invoke-Compose {
    param([Parameter(Mandatory = $true)][string[]]$ArgumentList)
    if ($null -eq $script:composePrefix) {
        throw "Compose was not configured"
    }
    return Invoke-CheckedCommand "docker" ($script:composePrefix + $ArgumentList)
}

function New-HexProof {
    return [Convert]::ToHexString(
        [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    ).ToLowerInvariant()
}

function New-UrlSafeProof {
    $value = [Convert]::ToBase64String(
        [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    )
    return $value.TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function Get-FreeLoopbackPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally {
        $listener.Stop()
    }
}

function Assert-NoAmbientProviderSources {
    foreach ($name in $script:forbiddenProviderSources) {
        $value = [Environment]::GetEnvironmentVariable(
            $name,
            [EnvironmentVariableTarget]::Process)
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            throw "Ambient provider configuration is forbidden: $name"
        }
    }
}

function Assert-SafeSurface {
    param(
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)][string[]]$PrivateValues,
        [switch]$ForbidIdentifiers
    )
    if ($Content.Length -gt 1048576) {
        throw "Synthetic surface exceeded its bound"
    }
    foreach ($value in $PrivateValues) {
        if (-not [string]::IsNullOrEmpty($value) -and $Content.Contains($value)) {
            throw "Synthetic surface exposed private proof material"
        }
    }
    foreach ($name in @("publication_key", "review_target_id", "reason_code", "sha256")) {
        if ($Content.Contains($name)) {
            throw "Synthetic surface exposed private server evidence"
        }
    }
    if ($Content -match "(?i)candidate-(publication|skill):") {
        throw "Synthetic surface exposed a raw candidate identifier"
    }
    if ($ForbidIdentifiers) {
        if ($Content -match "(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b") {
            throw "Synthetic surface exposed a UUID"
        }
        if ($Content -match "(?i)\b[a-f0-9]{64}\b") {
            throw "Synthetic surface exposed a digest"
        }
    }
}

function Invoke-BoundedWebRequest {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [ValidateSet("GET", "POST")][string]$Method = "GET",
        [hashtable]$Headers = @{},
        [string]$Body = "",
        [string]$ContentType = "",
        [int]$MaximumRedirection = 5
    )
    $arguments = @{
        Uri = $Uri
        Method = $Method
        Headers = $Headers
        TimeoutSec = 10
        UseBasicParsing = $true
        MaximumRedirection = $MaximumRedirection
        SkipHttpErrorCheck = $true
    }
    if ($Method -eq "POST") {
        $arguments.Body = $Body
        $arguments.ContentType = $ContentType
    }
    $response = Invoke-WebRequest @arguments
    if ($response.RawContentLength -gt 1048576) {
        throw "Synthetic HTTP response exceeded its bound"
    }
    return $response
}

function Wait-ForHealth {
    param([Parameter(Mandatory = $true)][string]$Uri)
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($script:TimeoutSeconds)
    do {
        try {
            $response = Invoke-BoundedWebRequest -Uri $Uri
            if ($response.StatusCode -eq 200) {
                $payload = $response.Content | ConvertFrom-Json
                if (
                    $payload.status -eq "ok" -and
                    $payload.service -eq "workflow-helper-api" -and
                    $payload.environment -eq "synthetic"
                ) {
                    return
                }
            }
        } catch {
            # The bounded local runtime may still be starting.
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "Timed out waiting for the sealed synthetic runtime"
}

function Write-BoundedEvidence {
    $evidenceDirectory = Split-Path -Parent $script:resolvedEvidencePath
    if ($evidenceDirectory) {
        New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
    }
    $json = $script:evidence | ConvertTo-Json -Depth 6
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 32768) {
        throw "Pilot evidence exceeded its bound"
    }
    Set-Content -LiteralPath $script:resolvedEvidencePath -Value $json -Encoding utf8
    Write-Output $json
}

try {
    Push-Location $repoRoot

    if ($env:OS -ne "Windows_NT") {
        throw "This controlled pilot must run on Windows"
    }
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        throw "PowerShell 7 or later is required"
    }
    if (-not (Get-Command "dotnet" -ErrorAction SilentlyContinue)) {
        throw "The .NET SDK is required"
    }
    $dotnetVersion = (Invoke-CheckedCommand "dotnet" @("--version") | Select-Object -Last 1).Trim()
    $parsedDotnetVersion = $null
    if (
        -not [Version]::TryParse($dotnetVersion.Split("-")[0], [ref]$parsedDotnetVersion) -or
        $parsedDotnetVersion.Major -lt 8
    ) {
        throw ".NET 8 or later is required"
    }
    Assert-NoAmbientProviderSources
    $checks.windows_powershell_dotnet = "PASS"

    $currentCheck = "safety_defaults"
    $settings = Get-Content -LiteralPath (
        Join-Path $repoRoot "apps/capture-agent/appsettings.json"
    ) -Raw | ConvertFrom-Json
    if (
        $settings.Capture.CaptureEnabled -ne $false -or
        $settings.Capture.ConsentAcknowledged -ne $false -or
        $settings.Upload.Enabled -ne $false
    ) {
        throw "Committed capture, consent, and upload defaults must remain false"
    }
    $program = Get-Content -LiteralPath (
        Join-Path $repoRoot "apps/capture-agent/Program.cs"
    ) -Raw
    if (-not $program.Contains("AddSingleton<ICaptureRecorder, DisabledCaptureRecorder>")) {
        throw "DisabledCaptureRecorder must remain the normal-mode recorder"
    }
    $checks.safety_defaults = "PASS"

    $currentCheck = "canonical_fixture"
    $fixturePath = Join-Path $repoRoot "contracts/examples/session.json"
    $fixtureFile = Get-Item -LiteralPath $fixturePath
    if ($fixtureFile.LinkType -or $fixtureFile.Length -le 0 -or $fixtureFile.Length -gt 1048576) {
        throw "Canonical fixture must be a bounded regular file"
    }
    $fixture = Get-Content -LiteralPath $fixturePath -Raw | ConvertFrom-Json
    $commands = @(
        $fixture.cad_events |
            Where-Object { $_.event_type -eq "cad_command" } |
            ForEach-Object { $_.command_name }
    )
    if (
        $fixture.schema_version -ne "1.0" -or
        $fixture.recording -ne $null -or
        @($fixture.cad_events).Count -ne 8 -or
        @($fixture.input_artifacts).Count -ne 1 -or
        @($fixture.output_artifacts).Count -ne 1 -or
        ($commands -join ",") -ne "LINE,TRIM,LINE,TRIM"
    ) {
        throw "Canonical rich fixture shape is invalid"
    }
    $checks.canonical_fixture = "PASS"

    $currentCheck = "fail_closed_configuration"
    $composeText = Get-Content -LiteralPath (
        Join-Path $repoRoot "docker-compose.yml"
    ) -Raw
    foreach ($required in @(
        'command: ["python", "-m", "workflow_api.dev_server"]',
        'WORKFLOW_DEV_CAPTURE_PROOF: ${WORKFLOW_DEV_CAPTURE_PROOF:-}',
        'WORKFLOW_DEV_WORKER_PROOF: ${WORKFLOW_DEV_WORKER_PROOF:-}',
        'WORKFLOW_DEV_REVIEWER_PROOF: ${WORKFLOW_DEV_REVIEWER_PROOF:-}',
        'WORKFLOW_DEV_REVIEWER_SESSION: ${WORKFLOW_DEV_REVIEWER_SESSION:-}',
        'WORKFLOW_DEV_REVIEWER_CSRF: ${WORKFLOW_DEV_REVIEWER_CSRF:-}',
        './contracts/examples/session.json:/workspace/session.json:ro',
        './scripts/dev-runtime-seed.py:/workspace/dev-runtime-seed.py:ro'
    )) {
        if (-not $composeText.Contains($required)) {
            throw "Sealed Compose fail-closed configuration drifted"
        }
    }
    $checks.fail_closed_configuration = "PASS"

    $currentCheck = "evidence_boundary"
    $evidenceRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot "pilot-evidence")) +
        [IO.Path]::DirectorySeparatorChar
    if (
        -not $resolvedEvidencePath.StartsWith(
            $evidenceRoot,
            [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($resolvedEvidencePath) -ne
            "windows-synthetic-pilot.json"
    ) {
        throw "Pilot evidence path is outside its local bound"
    }
    $checks.evidence_boundary = "PASS"

    if ($PreflightOnly) {
        $checks.scoped_cleanup = "PASS"
        $evidence.result = "PASS"
        $finalExitCode = 0
        return
    }

    $currentCheck = "docker_tooling"
    if (-not (Get-Command "docker" -ErrorAction SilentlyContinue)) {
        throw "Docker Desktop is required for the full pilot"
    }
    Invoke-CheckedCommand "docker" @("info") | Out-Null
    Invoke-CheckedCommand "docker" @("compose", "version") | Out-Null
    $checks.docker_tooling = "PASS"

    $captureProof = New-HexProof
    $workerProof = New-HexProof
    $reviewerProof = New-HexProof
    $reviewerSession = New-UrlSafeProof
    $reviewerCsrf = New-UrlSafeProof
    $privateValues = @(
        $captureProof,
        $workerProof,
        $reviewerProof,
        $reviewerSession,
        $reviewerCsrf
    )

    $tempRoot = Join-Path ([IO.Path]::GetTempPath()) (
        "workflow-helper-win-pilot-{0}-{1}" -f $PID, [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tempRoot | Out-Null
    $runtimeEnv = Join-Path $tempRoot "runtime.env"
    $apiPort = Get-FreeLoopbackPort
    do {
        $webPort = Get-FreeLoopbackPort
    } while ($webPort -eq $apiPort)
    $projectName = (
        "workflow-helper-win-pilot-{0}-{1}" -f
            $PID,
            [Guid]::NewGuid().ToString("N").Substring(0, 12)
    ).ToLowerInvariant()
    $runtimeLines = @(
        "WORKFLOW_COMPOSE_ENV_FILE=$runtimeEnv",
        "WORKFLOW_API_PORT=$apiPort",
        "WORKFLOW_WEB_PORT=$webPort",
        "ENVIRONMENT=development",
        "LOG_LEVEL=INFO",
        "AWS_REGION=ap-northeast-1",
        "RAW_BUCKET=workflow-helper-raw-dev",
        "PROCESSED_BUCKET=workflow-helper-processed-dev",
        "RAW_RETENTION_DAYS=14",
        "WORKFLOW_DEV_DATA_DIR=/var/lib/workflow-helper/runtime",
        "WORKFLOW_DEV_CAPTURE_PROOF=$captureProof",
        "WORKFLOW_DEV_WORKER_PROOF=$workerProof",
        "WORKFLOW_DEV_REVIEWER_PROOF=$reviewerProof",
        "WORKFLOW_DEV_REVIEWER_SESSION=$reviewerSession",
        "WORKFLOW_DEV_REVIEWER_CSRF=$reviewerCsrf"
    )
    Set-Content -LiteralPath $runtimeEnv -Value $runtimeLines -Encoding utf8
    $composePrefix = @(
        "compose",
        "--env-file", $runtimeEnv,
        "--file", (Join-Path $repoRoot "docker-compose.yml"),
        "--project-name", $projectName
    )

    $currentCheck = "sealed_runtime"
    # Mark the scoped project as started before Compose is invoked so a
    # partially-created project is still removed if startup fails.
    $runtimeStarted = $true
    Invoke-Compose @("up", "--detach", "--wait", "--wait-timeout", "180", "web") |
        Out-Null
    $apiBase = "http://127.0.0.1:$apiPort"
    $webBase = "http://127.0.0.1:$webPort"
    Wait-ForHealth "$apiBase/health"
    $checks.sealed_runtime = "PASS"

    $currentCheck = "upload_receipt"
    $seedLogs = Invoke-Compose @("logs", "--no-color", "seed")
    if (($seedLogs -join [Environment]::NewLine) -notmatch "synthetic candidate seed complete") {
        throw "Canonical seed did not complete its upload receipt and processing chain"
    }
    $checks.upload_receipt = "PASS"

    $currentCheck = "v2_timeline"
    $sessionResponse = Invoke-BoundedWebRequest (
        "$webBase/sessions/$canonicalSessionId")
    if ($sessionResponse.StatusCode -ne 200) {
        throw "Synthetic session page was unavailable"
    }
    $sessionHtml = [string]$sessionResponse.Content
    foreach ($required in @(
        "Meaningful operations",
        "8 meaningful operations from 8 observed events.",
        "Deterministic operation segments",
        "Segment 1",
        "Segment 4",
        "Commands: LINE",
        "Commands: TRIM",
        "Review candidates"
    )) {
        if (-not $sessionHtml.Contains($required)) {
            throw "Synthetic v2 timeline evidence was incomplete"
        }
    }
    Assert-SafeSurface -Content $sessionHtml -PrivateValues $privateValues
    $checks.v2_timeline = "PASS"

    $currentCheck = "redacted_candidate"
    $candidateResponse = Invoke-BoundedWebRequest "$webBase/candidate-review"
    if ($candidateResponse.StatusCode -ne 200) {
        throw "Synthetic candidate review page was unavailable"
    }
    $candidateHtml = [string]$candidateResponse.Content
    foreach ($required in @(
        "Candidate review queue",
        "Candidates awaiting review",
        "Candidate 1",
        "LINE → TRIM → LINE → TRIM",
        "observed / unreviewed",
        "Approve"
    )) {
        if (-not $candidateHtml.Contains($required)) {
            throw "Redacted candidate evidence was incomplete"
        }
    }
    Assert-SafeSurface -Content $candidateHtml -PrivateValues $privateValues -ForbidIdentifiers
    $checks.redacted_candidate = "PASS"

    $currentCheck = "human_browser_confirmation"
    $sessionUrl = "$webBase/sessions/$canonicalSessionId"
    $candidateUrl = "$webBase/candidate-review"
    Write-Host ""
    Write-Host "Human confirmation is mandatory for this controlled pilot."
    Write-Host "Review the timeline in the browser: $sessionUrl"
    Write-Host "Review the redacted candidate in the browser: $candidateUrl"
    try {
        Start-Process -FilePath $sessionUrl | Out-Null
        Start-Process -FilePath $candidateUrl | Out-Null
    } catch {
        Write-Warning "The browser could not be opened automatically; use the printed URLs."
    }
    $confirmation = Read-Host (
        'Type exactly "APPROVE SYNTHETIC PILOT" only after both browser surfaces are visible and correct')
    if ($confirmation -cne "APPROVE SYNTHETIC PILOT") {
        throw "Human browser confirmation was not recorded"
    }
    $evidence.human_browser_confirmed = $true
    $checks.human_browser_confirmation = "PASS"

    $currentCheck = "approval_terminal_outcome"
    $approvalArguments = @{
        Uri = "$webBase/candidate-review/action"
        Method = "POST"
        Headers = @{ Origin = $webBase }
        Body = "ordinal=1&action=approve"
        ContentType = "application/x-www-form-urlencoded"
        MaximumRedirection = 0
    }
    $approvalResponse = Invoke-BoundedWebRequest @approvalArguments
    if (
        $approvalResponse.StatusCode -ne 303 -or
        -not [string]::IsNullOrEmpty([string]$approvalResponse.Content)
    ) {
        throw "Synthetic approval action did not return the fixed bodyless redirect"
    }
    $outcomeResponse = Invoke-BoundedWebRequest "$webBase/candidate-review"
    if ($outcomeResponse.StatusCode -ne 200) {
        throw "Approved terminal outcome was unavailable"
    }
    $outcomeHtml = [string]$outcomeResponse.Content
    foreach ($required in @(
        "No candidates awaiting review.",
        "Review outcomes",
        "Outcome 1",
        "LINE → TRIM → LINE → TRIM",
        "approved",
        "No reason code"
    )) {
        if (-not $outcomeHtml.Contains($required)) {
            throw "Approved terminal outcome evidence was incomplete"
        }
    }
    Assert-SafeSurface -Content $outcomeHtml -PrivateValues $privateValues -ForbidIdentifiers
    $checks.approval_terminal_outcome = "PASS"

    $currentCheck = "approved_catalog_export"
    $catalogResponse = Invoke-BoundedWebRequest "$webBase/approved-workflows"
    if ($catalogResponse.StatusCode -ne 200) {
        throw "Approved workflow catalog was unavailable"
    }
    $catalogHtml = [string]$catalogResponse.Content
    foreach ($required in @(
        "Approved workflows",
        "Approved workflow 1",
        "LINE → TRIM → LINE → TRIM",
        "observed / approved",
        "Download JSON"
    )) {
        if (-not $catalogHtml.Contains($required)) {
            throw "Approved workflow catalog evidence was incomplete"
        }
    }
    Assert-SafeSurface -Content $catalogHtml -PrivateValues $privateValues -ForbidIdentifiers

    $downloadResponse = Invoke-BoundedWebRequest (
        "$webBase/approved-workflows/download?ordinal=1")
    if ($downloadResponse.StatusCode -ne 200) {
        throw "Approved workflow export was unavailable"
    }
    $downloadText = [string]$downloadResponse.Content
    $downloadBytes = [Text.Encoding]::UTF8.GetBytes($downloadText)
    if (
        $downloadBytes.Length -gt 65536 -or
        -not $downloadText.EndsWith([char]10)
    ) {
        throw "Approved workflow export was not bounded"
    }
    Assert-SafeSurface -Content $downloadText -PrivateValues $privateValues -ForbidIdentifiers
    $downloadPayload = $downloadText | ConvertFrom-Json
    $downloadKeys = @($downloadPayload.PSObject.Properties.Name | Sort-Object)
    $expectedKeys = @(
        "approval_status",
        "command_sequence",
        "decided_at",
        "occurrence_count",
        "provenance",
        "schema",
        "version"
    )
    if (
        ($downloadKeys -join ",") -ne ($expectedKeys -join ",") -or
        $downloadPayload.schema -ne "workflow-helper.approved-workflow" -or
        $downloadPayload.version -ne "1.0" -or
        (@($downloadPayload.command_sequence) -join ",") -ne
            "LINE,TRIM,LINE,TRIM" -or
        $downloadPayload.occurrence_count -ne 4 -or
        $downloadPayload.provenance -ne "observed" -or
        $downloadPayload.approval_status -ne "approved" -or
        [string]::IsNullOrWhiteSpace([string]$downloadPayload.decided_at)
    ) {
        throw "Approved workflow export schema was invalid"
    }
    $checks.approved_catalog_export = "PASS"

    $currentCheck = "independent_durable_reopen"
    $independentVerifier = @'
import os
import runpy
from datetime import UTC, datetime

from workflow_api import dev_server

seed = runpy.run_path("/workspace/dev-runtime-seed.py")
driver = seed["_ASGIDriver"](dev_server.open_existing_app())
headers = seed["_reviewer_headers"]()
queue = driver.request(
    "GET",
    "/v1/control/candidate-publications/review-queue",
    headers=headers,
)
outcomes = driver.request(
    "GET",
    "/v1/control/candidate-publications/review-outcomes",
    headers=headers,
)
queue_payload = queue.json()
outcome_payload = outcomes.json()
items = outcome_payload.get("items")
item = items[0] if isinstance(items, list) and len(items) == 1 else None
if (
    queue.status != 200
    or queue_payload != {"items": [], "count": 0}
    or outcomes.status != 200
    or not isinstance(outcome_payload, dict)
    or set(outcome_payload) != {"items", "count"}
    or outcome_payload.get("count") != 1
    or not isinstance(item, dict)
    or set(item) != {
        "command_sequence",
        "occurrence_count",
        "provenance",
        "review_status",
        "reason_code",
        "decided_at_us",
    }
    or item.get("command_sequence") != ["LINE", "TRIM", "LINE", "TRIM"]
    or item.get("occurrence_count") != 4
    or item.get("provenance") != "observed"
    or item.get("review_status") != "approved"
    or item.get("reason_code") is not None
    or type(item.get("decided_at_us")) is not int
    or item["decided_at_us"] <= 0
):
    raise SystemExit("independent approved workflow verification failed")
expected = (
    datetime.fromtimestamp(item["decided_at_us"] / 1_000_000, tz=UTC)
    .isoformat(timespec="milliseconds")
    .replace("+00:00", "Z")
)
if expected != os.environ.get("EXPECTED_DECIDED_AT"):
    raise SystemExit("independent approved decision time verification failed")
print("synthetic approved workflow durability verified")
'@
    $reopenOutput = Invoke-Compose @(
        "run", "--rm", "--no-deps", "-T",
        "-e", "EXPECTED_DECIDED_AT=$($downloadPayload.decided_at)",
        "seed", "python", "-c", $independentVerifier
    )
    if (
        @($reopenOutput | Where-Object {
            $_.Trim() -eq "synthetic approved workflow durability verified"
        }).Count -ne 1
    ) {
        throw "Independent durable reopen evidence was not exact"
    }
    $checks.independent_durable_reopen = "PASS"

    $evidence.result = "PASS"
    $finalExitCode = 0
} catch {
    if ($checks.Contains($currentCheck)) {
        $checks[$currentCheck] = "FAIL"
    }
    $evidence.error = "Check failed: $currentCheck"
    Write-Warning $_.Exception.Message
} finally {
    if ($runtimeStarted -and $null -ne $composePrefix) {
        try {
            Invoke-Compose @("down", "--volumes", "--remove-orphans") | Out-Null
            $checks.scoped_cleanup = "PASS"
        } catch {
            $checks.scoped_cleanup = "FAIL"
            $evidence.result = "FAIL"
            $evidence.error = "Check failed: scoped_cleanup"
            $finalExitCode = 1
            Write-Warning "Scoped Compose cleanup failed"
        }
    } elseif ($PreflightOnly) {
        $checks.scoped_cleanup = "PASS"
    }
    if ($null -ne $tempRoot -and (Test-Path -LiteralPath $tempRoot)) {
        try {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force
        } catch {
            $checks.scoped_cleanup = "FAIL"
            $evidence.result = "FAIL"
            $evidence.error = "Check failed: scoped_cleanup"
            $finalExitCode = 1
            Write-Warning "Scoped temporary-state cleanup failed"
        }
    }
    Pop-Location -ErrorAction SilentlyContinue
    Write-BoundedEvidence
}

exit $finalExitCode
