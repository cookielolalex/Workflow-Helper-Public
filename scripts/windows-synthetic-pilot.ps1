[CmdletBinding()]
param(
    [string]$EvidencePath = "pilot-evidence/windows-synthetic-pilot.json",
    [int]$TimeoutSeconds = 120
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$syntheticOutput = Join-Path ([IO.Path]::GetTempPath()) (
    "workflow-helper-synthetic-pilot-{0}-{1}" -f $PID, [Guid]::NewGuid().ToString("N"))
$sessionId = "d6d9e5b7-c9bc-4eb1-ae4a-1a14ed5b1350"
$checks = [ordered]@{
    safety_defaults = "NOT_RUN"
    local_tooling = "NOT_RUN"
    local_compose = "NOT_RUN"
    api_health = "NOT_RUN"
    queue_baseline = "NOT_RUN"
    package_register_upload = "NOT_RUN"
    queue_enqueue = "NOT_RUN"
    worker_timeline = "NOT_RUN"
    localstack_artifact = "NOT_RUN"
    api_readback = "NOT_RUN"
    web_readback = "NOT_RUN"
}
$evidence = [ordered]@{
    schema_version = "1.1"
    pilot_mode = "generated-synthetic-only"
    result = "FAIL"
    session_id = $sessionId
    package_sha256 = $null
    package_size_bytes = $null
    recording_included = $false
    checks = $checks
    error = $null
    residual_manual_step = "Open the session URL in a browser on the controlled Windows host and visually confirm the rendered timeline; this script verifies HTTP content but cannot attest human-visible rendering."
}
$currentCheck = "safety_defaults"

function Invoke-CheckedCommand {
    param([string]$FilePath, [string[]]$ArgumentList)
    $output = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { $_.ToString() })
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE`: $($output -join ' ')"
    }
    return $output
}

function Read-DevelopmentEnvironment {
    param([string]$Path)
    $values = @{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#")) { continue }
        $separator = $trimmed.IndexOf("=")
        if ($separator -gt 0) {
            $values[$trimmed.Substring(0, $separator)] = $trimmed.Substring($separator + 1)
        }
    }
    return $values
}

function Assert-NoControlCredentials {
    param([hashtable]$Development)
    foreach ($name in @("CONTROL_PLANE_BEARER_TOKEN", "WORKFLOW_WORKER_TOKEN")) {
        $fileValue = if ($Development.ContainsKey($name)) { $Development[$name] } else { $null }
        $processValue = [Environment]::GetEnvironmentVariable($name)
        if (-not [string]::IsNullOrWhiteSpace($fileValue) -or
            -not [string]::IsNullOrWhiteSpace($processValue)) {
            throw "$name must be unset for the credential-free synthetic pilot"
        }
    }
}

function Wait-ForJson {
    param([string]$Uri, [scriptblock]$Accept)
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            $value = Invoke-RestMethod -Uri $Uri -TimeoutSec 5
            if (& $Accept $value) { return $value }
        } catch {
            # Startup and processing are intentionally polled to a fixed deadline.
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "Timed out waiting for $Uri"
}

function Wait-ForWebContent {
    param([string]$Uri, [string[]]$RequiredText)
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            $response = Invoke-WebRequest -Uri $Uri -TimeoutSec 5 -UseBasicParsing
            $allPresent = $response.StatusCode -eq 200
            foreach ($text in $RequiredText) {
                $allPresent = $allPresent -and $response.Content.Contains($text)
            }
            if ($allPresent) { return $response }
        } catch {
            # The web container and its API-backed route may become ready independently.
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "Timed out waiting for rendered content from $Uri"
}

function ConvertTo-NonNegativeQueueCount {
    param(
        [object]$Attributes,
        [string]$Name
    )
    if ($null -eq $Attributes) {
        throw "Queue evidence is missing the Attributes object"
    }
    $property = $Attributes.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        throw "Queue evidence is missing required attribute: $Name"
    }
    [long]$parsed = 0
    $valid = [long]::TryParse(
        $property.Value.ToString(),
        [Globalization.NumberStyles]::None,
        [Globalization.CultureInfo]::InvariantCulture,
        [ref]$parsed)
    if (-not $valid -or $parsed -lt 0) {
        throw "Queue evidence attribute must be a non-negative integer: $Name"
    }
    return $parsed
}

function Get-QueueDepth {
    param([string]$QueueUrl)
    $response = (Invoke-CheckedCommand "docker" @(
        "compose", "exec", "-T", "localstack", "awslocal", "sqs", "get-queue-attributes",
        "--queue-url", $QueueUrl, "--attribute-names",
        "ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible",
        "ApproximateNumberOfMessagesDelayed", "--output", "json"
    ) -join "`n") | ConvertFrom-Json
    if ($null -eq $response) {
        throw "Queue evidence response is empty"
    }
    $attributesProperty = $response.PSObject.Properties["Attributes"]
    if ($null -eq $attributesProperty -or $null -eq $attributesProperty.Value) {
        throw "Queue evidence response is missing the Attributes object"
    }
    $attributes = $attributesProperty.Value
    $visible = ConvertTo-NonNegativeQueueCount $attributes "ApproximateNumberOfMessages"
    $notVisible = ConvertTo-NonNegativeQueueCount `
        $attributes "ApproximateNumberOfMessagesNotVisible"
    $delayed = ConvertTo-NonNegativeQueueCount `
        $attributes "ApproximateNumberOfMessagesDelayed"
    return [PSCustomObject]@{
        Visible = $visible
        NotVisible = $notVisible
        Delayed = $delayed
        Total = $visible + $notVisible + $delayed
    }
}

function Wait-ForQueuedMessage {
    param([string]$QueueUrl)
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(15)
    do {
        $depth = Get-QueueDepth $QueueUrl
        if ($depth.Visible -ge 1) { return $depth.Visible }
        Start-Sleep -Seconds 1
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    throw "No processing message was visible while the worker was stopped"
}

$savedEnvironment = @{}
try {
    Push-Location $repoRoot

    if ($env:OS -ne "Windows_NT") {
        throw "This controlled pilot harness must run on Windows"
    }
    $settings = Get-Content "apps/capture-agent/appsettings.json" -Raw | ConvertFrom-Json
    if ($settings.Capture.CaptureEnabled -ne $false -or
        $settings.Capture.ConsentAcknowledged -ne $false -or
        $settings.Upload.Enabled -ne $false) {
        throw "Committed capture, consent, and upload defaults must all remain false"
    }
    $program = Get-Content "apps/capture-agent/Program.cs" -Raw
    if (-not $program.Contains("AddSingleton<ICaptureRecorder, DisabledCaptureRecorder>")) {
        throw "DisabledCaptureRecorder is not the normal-mode registration"
    }
    $checks.safety_defaults = "PASS"

    $currentCheck = "local_tooling"
    foreach ($command in @("dotnet", "docker")) {
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
            throw "Required local command is missing: $command"
        }
    }
    Invoke-CheckedCommand "dotnet" @("--version") | Out-Null
    Invoke-CheckedCommand "docker" @("info") | Out-Null
    Invoke-CheckedCommand "docker" @("compose", "version") | Out-Null
    $checks.local_tooling = "PASS"

    $currentCheck = "local_compose"
    if (-not (Test-Path ".env")) {
        throw "Missing .env; copy .env.example to .env without adding real credentials"
    }
    $development = Read-DevelopmentEnvironment ".env"
    Assert-NoControlCredentials $development
    $requiredLocalValues = [ordered]@{
        ENVIRONMENT = "development"
        AWS_ENDPOINT_URL = "http://localstack:4566"
        AWS_ACCESS_KEY_ID = "test"
        AWS_SECRET_ACCESS_KEY = "test"
        RAW_BUCKET = "workflow-helper-raw-dev"
        PROCESSED_BUCKET = "workflow-helper-processed-dev"
        PROCESSING_QUEUE_URL = "http://localstack:4566/000000000000/workflow-helper-processing"
    }
    foreach ($entry in $requiredLocalValues.GetEnumerator()) {
        if ($development[$entry.Key] -ne $entry.Value) {
            throw ".env must use the checked LocalStack development value for $($entry.Key)"
        }
    }
    if ($development.ContainsKey("AWS_S3_PRESIGNED_ENDPOINT_URL") -and
        $development["AWS_S3_PRESIGNED_ENDPOINT_URL"] -ne "http://localhost:4566") {
        throw ".env AWS_S3_PRESIGNED_ENDPOINT_URL must remain loopback when specified"
    }
    $renderedCompose = Invoke-CheckedCommand "docker" @("compose", "config")
    if (($renderedCompose -join "`n") -notmatch
        "AWS_S3_PRESIGNED_ENDPOINT_URL:\s+http://localhost:4566") {
        throw "Rendered API compose configuration must presign only for loopback LocalStack"
    }
    Invoke-CheckedCommand "docker" @("compose", "stop", "worker") | Out-Null
    Invoke-CheckedCommand "docker" @("compose", "up", "-d", "--build", "postgres", "localstack") | Out-Null
    Invoke-CheckedCommand "docker" @(
        "compose", "up", "-d", "--build", "--force-recreate", "api", "web"
    ) | Out-Null
    $checks.local_compose = "PASS"

    $currentCheck = "api_health"
    Wait-ForJson "http://localhost:8000/health" {
        param($value) $value.status -eq "ok" -and $value.environment -eq "development"
    } | Out-Null
    $checks.api_health = "PASS"

    $currentCheck = "queue_baseline"
    $queueUrl = (Invoke-CheckedCommand "docker" @(
        "compose", "exec", "-T", "localstack", "awslocal", "sqs", "get-queue-url",
        "--queue-name", "workflow-helper-processing", "--query", "QueueUrl", "--output", "text"
    ) | Select-Object -Last 1).Trim()
    $baseline = Get-QueueDepth $queueUrl
    if ($baseline.Total -ne 0) {
        throw "Synthetic LocalStack queue is not empty (visible, in-flight, or delayed); use a fresh controlled stack"
    }
    $checks.queue_baseline = "PASS"

    $currentCheck = "package_register_upload"
    if (Test-Path -LiteralPath $syntheticOutput) {
        Remove-Item -LiteralPath $syntheticOutput -Recurse -Force
    }
    foreach ($name in @(
        "Capture__CaptureEnabled",
        "Capture__ConsentAcknowledged",
        "Capture__OutputDirectory",
        "Upload__Enabled",
        "Upload__ApiBaseUrl"
    )) {
        $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name)
    }
    $env:Capture__CaptureEnabled = "false"
    $env:Capture__ConsentAcknowledged = "false"
    $env:Capture__OutputDirectory = $syntheticOutput
    $env:Upload__Enabled = "true"
    $env:Upload__ApiBaseUrl = "http://localhost:8000"
    $runnerOutput = @(& dotnet run --project "apps/capture-agent/WorkflowHelper.CaptureAgent.csproj" -- --synthetic-pilot 2>&1 |
        ForEach-Object { $_.ToString() })
    $runnerExitCode = $LASTEXITCODE
    $runnerJson = $runnerOutput |
        Where-Object { $_.Trim().StartsWith("{") -and $_.Trim().EndsWith("}") } |
        Select-Object -Last 1
    if (-not $runnerJson) {
        throw "Synthetic runner emitted no JSON evidence"
    }
    $runnerEvidence = $runnerJson | ConvertFrom-Json
    if ($runnerExitCode -ne 0 -or $runnerEvidence.Result -ne "PASS" -or
        $runnerEvidence.RecordingIncluded -ne $false) {
        throw "Synthetic package/register/upload runner failed: $($runnerEvidence.Error)"
    }
    $evidence.package_sha256 = $runnerEvidence.PackageSha256
    $evidence.package_size_bytes = $runnerEvidence.PackageSizeBytes
    $checks.package_register_upload = "PASS"

    $currentCheck = "queue_enqueue"
    Wait-ForQueuedMessage $queueUrl | Out-Null
    $checks.queue_enqueue = "PASS"

    $currentCheck = "worker_timeline"
    Invoke-CheckedCommand "docker" @("compose", "up", "-d", "--build", "worker") | Out-Null
    $session = Wait-ForJson "http://localhost:8000/v1/sessions/$sessionId" {
        param($value) $value.processing_status -eq "processed"
    }
    $timeline = Wait-ForJson "http://localhost:8000/v1/sessions/$sessionId/timeline" {
        param($value) $value.event_count -eq 3 -and $value.meaningful_event_count -eq 3
    }
    if ($timeline.timeline[1].summary -ne "AutoCAD command: SYNTHETIC_LINE") {
        throw "Processed timeline does not contain the deterministic synthetic command"
    }
    $checks.worker_timeline = "PASS"

    $currentCheck = "localstack_artifact"
    Invoke-CheckedCommand "docker" @(
        "compose", "exec", "-T", "localstack", "awslocal", "s3api", "head-object",
        "--bucket", "workflow-helper-processed-dev",
        "--key", "sessions/$sessionId/timeline.json"
    ) | Out-Null
    $checks.localstack_artifact = "PASS"

    $currentCheck = "api_readback"
    if ($session.review_status -ne "pending" -or
        $session.raw_object_key -notlike "sessions/$sessionId/packages/*.zip") {
        throw "API readback did not expose the expected processed synthetic session"
    }
    $checks.api_readback = "PASS"

    $currentCheck = "web_readback"
    Wait-ForWebContent "http://localhost:3000/sessions/$sessionId" @(
        $sessionId,
        "AutoCAD command: SYNTHETIC_LINE"
    ) | Out-Null
    $checks.web_readback = "PASS"
    $evidence.result = "PASS"
} catch {
    $checks[$currentCheck] = "FAIL"
    $evidence.error = $_.Exception.Message
} finally {
    foreach ($entry in $savedEnvironment.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value)
    }
    if (Test-Path -LiteralPath $syntheticOutput) {
        Remove-Item -LiteralPath $syntheticOutput -Recurse -Force
    }
    Pop-Location -ErrorAction SilentlyContinue
    $resolvedEvidencePath = if ([IO.Path]::IsPathRooted($EvidencePath)) {
        $EvidencePath
    } else {
        Join-Path $repoRoot $EvidencePath
    }
    $evidenceDirectory = Split-Path -Parent $resolvedEvidencePath
    if ($evidenceDirectory) {
        New-Item -ItemType Directory -Path $evidenceDirectory -Force | Out-Null
    }
    $json = $evidence | ConvertTo-Json -Depth 6
    Set-Content -LiteralPath $resolvedEvidencePath -Value $json -Encoding utf8
    Write-Output $json
}

if ($evidence.result -ne "PASS") { exit 1 }
