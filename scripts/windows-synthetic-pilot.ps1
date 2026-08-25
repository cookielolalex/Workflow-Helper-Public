[CmdletBinding()]
param(
    [switch]$PreflightOnly,
    [string]$EvidencePath = "pilot-evidence/windows-synthetic-pilot.json",
    [int]$TimeoutSeconds = 180
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$resolvedEvidencePath = [IO.Path]::GetFullPath((Join-Path $repoRoot "pilot-evidence/windows-synthetic-pilot.json"))
$maxHttpBytes = 2MB
$maxExportBytes = 64KB
$maxEvidenceBytes = 64KB
$sessionId = $null
$canonicalFixture = $null
$runtimeDirectory = $null
$runtimeEnvironment = $null
$composeProject = $null
$composeStarted = $false
$cleanupFailure = $false
$currentCheck = "preflight"
$proofs = @()

$checks = [ordered]@{
    preflight = "NOT_RUN"
    windows_powershell_dotnet = "NOT_RUN"
    safety_defaults = "NOT_RUN"
    canonical_fixture = "NOT_RUN"
    configuration_safety = "NOT_RUN"
    fail_closed_configuration = "NOT_RUN"
    evidence_boundary = "NOT_RUN"
    local_tooling = "NOT_RUN"
    docker_tooling = "NOT_RUN"
    compose_runtime = "NOT_RUN"
    sealed_runtime = "NOT_RUN"
    upload_receipt = "NOT_RUN"
    v2_timeline = "NOT_RUN"
    redacted_candidate = "NOT_RUN"
    browser_confirmation = "NOT_RUN"
    human_browser_confirmation = "NOT_RUN"
    terminal_approval = "NOT_RUN"
    approval_terminal_outcome = "NOT_RUN"
    approved_catalog = "NOT_RUN"
    approved_catalog_export = "NOT_RUN"
    safe_export = "NOT_RUN"
    independent_reopen = "NOT_RUN"
    independent_durable_reopen = "NOT_RUN"
    cleanup = "NOT_RUN"
    scoped_cleanup = "NOT_RUN"
}

$evidence = [ordered]@{
    schema_version = "2.0"
    pilot_mode = "generated-synthetic-only"
    result = if ($PreflightOnly) { "PREFLIGHT_FAIL" } else { "FAIL" }
    classification = "PLATFORM_BLOCKED"
    recording_included = $false
    human_browser_confirmation = "NOT_RUN"
    checks = $checks
    error = $null
}

function Throw-SafeFailure {
    param([string]$Message)
    throw $Message
}

function Get-ResolvedEvidencePath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        Throw-SafeFailure "Evidence path is required"
    }
    $candidate = if ([IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path $repoRoot $Path }
    $resolved = [IO.Path]::GetFullPath($candidate)
    $relative = [IO.Path]::GetRelativePath($repoRoot, $resolved)
    if (
        $relative -eq ".." -or
        $relative.StartsWith("..$([IO.Path]::DirectorySeparatorChar)") -or
        -not $relative.Equals("pilot-evidence/windows-synthetic-pilot.json", [StringComparison]::OrdinalIgnoreCase)
    ) {
        Throw-SafeFailure "Evidence must remain at the bounded local pilot-evidence path"
    }
    return $resolved
}

function Get-JsonFile {
    param(
        [string]$Path,
        [int]$MaximumBytes = 1MB
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Throw-SafeFailure "Required fixture is missing"
    }
    $file = Get-Item -LiteralPath $Path
    if ($file.LinkType -or $file.Length -le 0 -or $file.Length -gt $MaximumBytes) {
        Throw-SafeFailure "Required fixture exceeds its bounded size"
    }
    try {
        return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
    } catch {
        Throw-SafeFailure "Required fixture is not valid JSON"
    }
}

function Get-PropertyNames {
    param([object]$Value)

    if ($null -eq $Value) { return @() }
    return @($Value.PSObject.Properties | ForEach-Object { $_.Name })
}

function Assert-ExactPropertyNames {
    param(
        [object]$Value,
        [string[]]$Expected
    )

    $actual = @(Get-PropertyNames $Value | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    if (($actual -join ([char]31)) -ne ($wanted -join ([char]31))) {
        Throw-SafeFailure "Runtime response shape was not exact"
    }
}

function Get-CanonicalFixture {
    $sessionPath = Join-Path $repoRoot "contracts/examples/session.json"
    $v2Path = Join-Path $repoRoot "contracts/examples/processing-result-v2.json"
    $fixture = Get-JsonFile $sessionPath
    $v2 = Get-JsonFile $v2Path

    if ($null -eq $fixture -or $null -eq $v2) {
        Throw-SafeFailure "Canonical synthetic fixtures are unavailable"
    }
    Assert-ExactPropertyNames $fixture @(
        "schema_version", "session_id", "machine_id", "project_id", "started_at",
        "ended_at", "active_duration_seconds", "approved_process", "drawing_files",
        "input_artifacts", "output_artifacts", "recording", "cad_events",
        "idle_intervals", "processing_status", "review_status", "labels", "skills",
        "raw_expires_at"
    )
    Assert-ExactPropertyNames $v2 @(
        "schema_version", "session_id", "event_count", "meaningful_event_count",
        "timeline", "operation_segments", "keyframes", "warnings"
    )
    if (
        $fixture.schema_version -ne "1.0" -or
        [string]::IsNullOrWhiteSpace([string]$fixture.session_id) -or
        $fixture.project_id -ne $null -or
        $fixture.recording -ne $null -or
        $fixture.drawing_files.Count -ne 0 -or
        $fixture.input_artifacts.Count -ne 1 -or
        $fixture.output_artifacts.Count -ne 1 -or
        $fixture.cad_events.Count -ne 8
    ) {
        Throw-SafeFailure "Canonical package fixture is not recording-free and bounded"
    }
    try {
        [Guid]::Parse([string]$fixture.session_id) | Out-Null
    } catch {
        Throw-SafeFailure "Canonical package fixture has an invalid session identity"
    }

    $expectedEvents = @(
        "session_started",
        "drawing_opened",
        "cad_command",
        "cad_command",
        "cad_command",
        "cad_command",
        "drawing_saved",
        "session_ended"
    )
    $expectedCommands = @("LINE", "TRIM", "LINE", "TRIM")
    $commands = @()
    for ($index = 0; $index -lt $fixture.cad_events.Count; $index++) {
        $event = $fixture.cad_events[$index]
        if (
            $event.event_type -ne $expectedEvents[$index] -or
            $event.details.synthetic -ne $true
        ) {
            Throw-SafeFailure "Canonical package fixture event shape is invalid"
        }
        if ($event.event_type -eq "cad_command") {
            $commands += [string]$event.command_name
        }
    }
    if (($commands -join ([char]31)) -ne ($expectedCommands -join ([char]31))) {
        Throw-SafeFailure "Canonical package fixture command sequence is invalid"
    }

    if (
        $v2.schema_version -ne "2.0" -or
        [int]$v2.event_count -ne 8 -or
        [int]$v2.meaningful_event_count -ne 8 -or
        $v2.timeline.Count -ne 8 -or
        $v2.operation_segments.Count -ne 4 -or
        [string]$v2.session_id -ne [string]$fixture.session_id
    ) {
        Throw-SafeFailure "Canonical v2 fixture shape is invalid"
    }
    $segmentCommands = @()
    for ($index = 0; $index -lt $v2.operation_segments.Count; $index++) {
        $segment = $v2.operation_segments[$index]
        if (
            [int]$segment.sequence -ne ($index + 1) -or
            $segment.command_names.Count -ne 1 -or
            $segment.command_names[0] -ne $expectedCommands[$index]
        ) {
            Throw-SafeFailure "Canonical v2 operation segments are not ordered"
        }
        $segmentCommands += [string]$segment.command_names[0]
    }
    if (($segmentCommands -join ([char]31)) -ne ($expectedCommands -join ([char]31))) {
        Throw-SafeFailure "Canonical v2 operation sequence is invalid"
    }
    return $fixture
}

function Assert-SafetyDefaults {
    $settingsPath = Join-Path $repoRoot "apps/capture-agent/appsettings.json"
    $programPath = Join-Path $repoRoot "apps/capture-agent/Program.cs"
    $settings = Get-JsonFile $settingsPath
    if (
        $settings.Capture.CaptureEnabled -ne $false -or
        $settings.Capture.ConsentAcknowledged -ne $false -or
        $settings.Upload.Enabled -ne $false
    ) {
        Throw-SafeFailure "Committed capture, consent, and upload defaults must remain false"
    }
    if (-not (Test-Path -LiteralPath $programPath -PathType Leaf)) {
        Throw-SafeFailure "Capture-agent registration source is missing"
    }
    $program = Get-Content -LiteralPath $programPath -Raw -Encoding UTF8
    if (-not $program.Contains("AddSingleton<ICaptureRecorder, DisabledCaptureRecorder>")) {
        Throw-SafeFailure "DisabledCaptureRecorder is not the normal-mode registration"
    }
}

function Assert-ComposeConfiguration {
    $composePath = Join-Path $repoRoot "docker-compose.yml"
    if (-not (Test-Path -LiteralPath $composePath -PathType Leaf)) {
        Throw-SafeFailure "Synthetic Compose topology is missing"
    }
    $compose = Get-Content -LiteralPath $composePath -Raw -Encoding UTF8
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
        if (-not $compose.Contains($required)) {
            Throw-SafeFailure "Sealed Compose fail-closed configuration drifted"
        }
    }
    if (
        $compose -match 'AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GOOGLE_APPLICATION_CREDENTIALS' -or
        $compose -match 'https?://(?!localhost|127\.0\.0\.1|api:|web:)[^\s"'']+'
    ) {
        Throw-SafeFailure "Compose contains a live-provider or unsafe endpoint"
    }
}

function Get-EnvironmentValue {
    param([string]$Name)
    return [Environment]::GetEnvironmentVariable($Name, [EnvironmentVariableTarget]::Process)
}

function Assert-NoAmbientProviderConfiguration {
    $forbiddenNames = @(
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
        "AWS_ENDPOINT_URL",
        "AWS_S3_PRESIGNED_ENDPOINT_URL",
        "AWS_REGION",
        "PROCESSING_QUEUE_URL",
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
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_TENANT_ID",
        "AZURE_FEDERATED_TOKEN_FILE",
        "ARM_CLIENT_ID",
        "ARM_CLIENT_SECRET",
        "ARM_TENANT_ID",
        "MSI_ENDPOINT",
        "MSI_SECRET",
        "CODEX_API_KEY",
        "CONTROL_PLANE_BEARER_TOKEN",
        "WORKFLOW_WORKER_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "DATABASE_URL",
        "API_BASE_URL",
        "NEXT_PUBLIC_API_BASE_URL",
        "WORKFLOW_REVIEW_API_BASE_URL",
        "RAW_BUCKET",
        "PROCESSED_BUCKET",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "COMPOSE_FILE",
        "COMPOSE_PROJECT_NAME",
        "WORKFLOW_COMPOSE_ENV_FILE",
        "WORKFLOW_API_PORT",
        "WORKFLOW_WEB_PORT",
        "WORKFLOW_DEV_DATA_DIR",
        "WORKFLOW_DEV_CAPTURE_PROOF",
        "WORKFLOW_DEV_WORKER_PROOF",
        "WORKFLOW_DEV_REVIEWER_PROOF",
        "WORKFLOW_DEV_REVIEWER_SESSION",
        "WORKFLOW_DEV_REVIEWER_CSRF"
    )
    foreach ($name in $forbiddenNames) {
        $value = Get-EnvironmentValue $name
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            Throw-SafeFailure "Ambient provider or runtime configuration is present"
        }
    }
    foreach ($entry in Get-ChildItem Env:) {
        if (
            -not [string]::IsNullOrWhiteSpace([string]$entry.Value) -and
            $entry.Name -match "^(AWS_|GOOGLE_|GCP_|CLOUDSDK_|GCE_|AZURE_|ARM_|OPENAI_|ANTHROPIC_)"
        ) {
            Throw-SafeFailure "Ambient provider or runtime configuration is present"
        }
    }

    $environmentFiles = @(Get-ChildItem -LiteralPath $repoRoot -Filter ".env*" -File -Force -ErrorAction SilentlyContinue)
    foreach ($file in $environmentFiles) {
        if ($file.Name -in @(".env.example", ".env.template")) { continue }
        $path = $file.FullName
        if ($file.LinkType -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Throw-SafeFailure "Environment configuration file is unsafe"
        }
        foreach ($line in Get-Content -LiteralPath $path -Encoding UTF8) {
            $trimmed = $line.Trim()
            if (-not $trimmed -or $trimmed.StartsWith("#")) { continue }
            $separator = $trimmed.IndexOf("=")
            if ($separator -le 0) { continue }
            $name = $trimmed.Substring(0, $separator).Trim()
            if ($forbiddenNames -contains $name) {
                $value = $trimmed.Substring($separator + 1).Trim().Trim('"').Trim("'")
                if (-not [string]::IsNullOrWhiteSpace($value)) {
                    Throw-SafeFailure "Ambient provider or runtime configuration is present"
                }
            }
        }
    }
}

function Assert-HostExpectations {
    if ($env:OS -ne "Windows_NT") {
        Throw-SafeFailure "This controlled pilot harness must run on Windows"
    }
    if (
        $null -eq $PSVersionTable -or
        $PSVersionTable.PSEdition -ne "Core" -or
        [int]$PSVersionTable.PSVersion.Major -lt 7
    ) {
        Throw-SafeFailure "PowerShell 7 or newer is required"
    }
    if ([Environment]::Version.Major -lt 8) {
        Throw-SafeFailure ".NET 8 or newer is required"
    }
    $dotnet = Get-Command "dotnet" -ErrorAction SilentlyContinue
    if ($null -eq $dotnet) {
        Throw-SafeFailure ".NET SDK is required"
    }
    $dotnetOutput = @(& $dotnet.Source "--version" 2>$null | ForEach-Object { $_.ToString().Trim() })
    if ($LASTEXITCODE -ne 0 -or $dotnetOutput.Count -ne 1) {
        Throw-SafeFailure ".NET SDK version could not be verified"
    }
    try {
        $dotnetVersion = [Version]$dotnetOutput[0]
    } catch {
        Throw-SafeFailure ".NET SDK version could not be verified"
    }
    if ($dotnetVersion.Major -lt 8) {
        Throw-SafeFailure ".NET 8 or newer is required"
    }
}

function Invoke-CheckedCommand {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [switch]$ReturnOutput
    )
    $output = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { $_.ToString() })
    if ($LASTEXITCODE -ne 0) {
        Throw-SafeFailure "A local synthetic command failed"
    }
    if ($ReturnOutput) { return ,$output }
}

function Get-FreeTcpPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    } finally {
        $listener.Stop()
    }
}

function New-SyntheticMaterial {
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function New-RuntimeEnvironment {
    param(
        [string]$Path,
        [string]$DataPath,
        [int]$ApiPort,
        [int]$WebPort,
        [string]$CaptureProof,
        [string]$WorkerProof,
        [string]$ReviewerProof,
        [string]$ReviewerSession,
        [string]$ReviewerCsrf
    )
    $lines = @(
        "WORKFLOW_COMPOSE_ENV_FILE=$Path",
        "WORKFLOW_API_PORT=$ApiPort",
        "WORKFLOW_WEB_PORT=$WebPort",
        "ENVIRONMENT=development",
        "LOG_LEVEL=INFO",
        "API_BASE_URL=http://api:8000",
        "DATABASE_URL=",
        "AWS_REGION=region.synthetic.example",
        "RAW_BUCKET=raw.synthetic.example",
        "PROCESSED_BUCKET=processed.synthetic.example",
        "RAW_RETENTION_DAYS=14",
        "WORKFLOW_DEV_DATA_DIR=$DataPath",
        "WORKFLOW_DEV_CAPTURE_PROOF=$CaptureProof",
        "WORKFLOW_DEV_WORKER_PROOF=$WorkerProof",
        "WORKFLOW_DEV_REVIEWER_PROOF=$ReviewerProof",
        "WORKFLOW_DEV_REVIEWER_SESSION=$ReviewerSession",
        "WORKFLOW_DEV_REVIEWER_CSRF=$ReviewerCsrf",
        "MAX_METADATA_SIZE_BYTES=1048576",
        "MAX_PACKAGE_SIZE_BYTES=536870912",
        "UPLOAD_SPOOL_MEMORY_BYTES=8388608",
        "UPLOAD_STREAM_CHUNK_BYTES=1048576"
    )
    $text = ($lines -join [Environment]::NewLine) + [Environment]::NewLine
    $bytes = [Text.Encoding]::UTF8.GetBytes($text)
    if ($bytes.Length -gt 32KB) {
        Throw-SafeFailure "Synthetic Compose environment exceeds its bound"
    }
    [IO.File]::WriteAllText($Path, $text, [Text.UTF8Encoding]::new($false))
}

function Invoke-Compose {
    param(
        [string[]]$Arguments,
        [switch]$ReturnOutput
    )
    $base = @(
        "compose",
        "--env-file", $runtimeEnvironment,
        "--file", (Join-Path $repoRoot "docker-compose.yml"),
        "--project-name", $composeProject
    )
    return Invoke-CheckedCommand "docker" ($base + $Arguments) -ReturnOutput:$ReturnOutput
}

function Get-HttpResponse {
    param(
        [string]$Uri,
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        [string]$Body = $null,
        [string]$ContentType = $null
    )
    $parameters = @{
        Uri = $Uri
        Method = $Method
        Headers = $Headers
        TimeoutSec = [Math]::Max(5, [Math]::Min(30, $TimeoutSeconds))
        MaximumRedirection = 0
        UseBasicParsing = $true
        SkipHttpErrorCheck = $true
    }
    if ($null -ne $Body) { $parameters.Body = $Body }
    if ($null -ne $ContentType) { $parameters.ContentType = $ContentType }
    try {
        $response = Invoke-WebRequest @parameters
    } catch {
        Throw-SafeFailure "Synthetic HTTP request failed"
    }
    $bodyBytes = [Text.Encoding]::UTF8.GetBytes([string]$response.Content)
    if ($bodyBytes.Length -gt $maxHttpBytes) {
        Throw-SafeFailure "Synthetic HTTP response exceeded its bound"
    }
    return $response
}

function Convert-ResponseJson {
    param([object]$Response)
    try {
        return ($Response.Content | ConvertFrom-Json)
    } catch {
        Throw-SafeFailure "Synthetic HTTP response was not valid JSON"
    }
}

function Get-ApiJson {
    param(
        [string]$Base,
        [string]$Path,
        [hashtable]$Headers
    )
    $response = Get-HttpResponse -Uri ($Base + $Path) -Headers $Headers
    if ($response.StatusCode -ne 200) {
        Throw-SafeFailure "Synthetic API read failed"
    }
    return Convert-ResponseJson $response
}

function Wait-ForApiJson {
    param(
        [string]$Base,
        [string]$Path,
        [hashtable]$Headers,
        [scriptblock]$Accept
    )
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            $response = Get-HttpResponse -Uri ($Base + $Path) -Headers $Headers
            if ($response.StatusCode -eq 200) {
                $value = Convert-ResponseJson $response
                if (& $Accept $value) { return $value }
            }
        } catch {
            # Startup and deterministic processing are polled to a fixed bound.
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    Throw-SafeFailure "Synthetic API did not reach the expected state"
}

function Wait-ForHealth {
    param([string]$Uri)
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            $response = Get-HttpResponse -Uri $Uri
            if ($response.StatusCode -eq 200) {
                $value = Convert-ResponseJson $response
                if (
                    $value.status -eq "ok" -and
                    $value.service -eq "workflow-helper-api" -and
                    $value.environment -eq "synthetic"
                ) {
                    return
                }
            }
        } catch {
            # The bounded synthetic topology may still be starting.
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    Throw-SafeFailure "Synthetic API health did not reach the expected state"
}

function Wait-ForSeedCompletion {
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            $logs = Invoke-Compose @("logs", "--no-color", "seed") -ReturnOutput
            if (($logs -join [Environment]::NewLine) -match "synthetic candidate seed complete") {
                return
            }
        } catch {
            # The one-shot seed may not have emitted its bounded completion line yet.
        }
        Start-Sleep -Seconds 2
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    Throw-SafeFailure "Synthetic seed did not complete its bounded lifecycle"
}

function Get-WebVisibleText {
    param([string]$Html)
    $withoutHidden = [Regex]::Replace($Html, "(?is)<(script|style)\b.*?</\1>", "")
    $withoutTags = [Regex]::Replace($withoutHidden, "(?is)<[^>]*>", " ")
    return ([Net.WebUtility]::HtmlDecode($withoutTags) -replace "\s+", " ").Trim()
}

function Assert-RedactedSurface {
    param(
        [string]$Text,
        [switch]$AllowSessionId,
        [switch]$SkipIdentifierCheck
    )
    foreach ($proof in $proofs) {
        if (-not [string]::IsNullOrEmpty($proof) -and $Text.Contains($proof)) {
            Throw-SafeFailure "A browser surface exposed runtime proof material"
        }
    }
    foreach ($privateName in @(
        "publication_key", "review_target_id", "reason_code", "artifact_ref",
        "raw_object_key", "processing_completion_id", "source_event_id"
    )) {
        if ($Text.Contains($privateName)) {
            Throw-SafeFailure "A browser surface exposed private server evidence"
        }
    }
    if ([Regex]::IsMatch($Text, "candidate-(?:publication|skill):", [RegexOptions]::IgnoreCase)) {
        Throw-SafeFailure "A browser surface exposed a raw candidate identifier"
    }
    if (-not $SkipIdentifierCheck) {
        foreach ($match in [Regex]::Matches($Text, "\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", [RegexOptions]::IgnoreCase)) {
            if (-not $AllowSessionId -or $match.Value -ne $sessionId) {
                Throw-SafeFailure "A browser surface exposed a raw identifier"
            }
        }
        if ([Regex]::IsMatch($Text, "\b[a-f0-9]{64}\b", [RegexOptions]::IgnoreCase)) {
            Throw-SafeFailure "A browser surface exposed a digest"
        }
    }
}

function Get-ReviewerHeaders {
    return @{
        "Cookie" = "workflow_session=$($proofs[3])"
        "Origin" = "https://review.synthetic.example"
        "X-Workflow-Dev-Reviewer-Proof" = $proofs[2]
    }
}

function Assert-CanonicalTimeline {
    param([object]$Timeline)
    if (
        $Timeline.schema_version -ne "2.0" -or
        [int]$Timeline.event_count -ne 8 -or
        [int]$Timeline.meaningful_event_count -ne 8 -or
        $Timeline.timeline.Count -ne 8 -or
        $Timeline.operation_segments.Count -ne 4
    ) {
        Throw-SafeFailure "The processed v2 timeline did not meet the exact bound"
    }
    $expected = @("LINE", "TRIM", "LINE", "TRIM")
    for ($index = 0; $index -lt 4; $index++) {
        $segment = $Timeline.operation_segments[$index]
        if (
            [int]$segment.sequence -ne ($index + 1) -or
            $segment.command_names.Count -ne 1 -or
            [string]$segment.command_names[0] -ne $expected[$index]
        ) {
            Throw-SafeFailure "The processed v2 operation segments were not exact"
        }
    }
    $commandEvents = @($Timeline.timeline | Where-Object { $_.event_type -eq "cad_command" })
    if ($commandEvents.Count -ne 4) {
        Throw-SafeFailure "The processed v2 timeline command evidence was not exact"
    }
    $commands = @($commandEvents | ForEach-Object { ([string]$_.summary -replace ".*: ", "") })
    if (($commands -join ([char]31)) -ne "LINE$([char]31)TRIM$([char]31)LINE$([char]31)TRIM") {
        Throw-SafeFailure "The processed v2 command sequence was not exact"
    }
}

function Assert-ReviewQueueItem {
    param([object]$Queue)
    if ($null -eq $Queue -or [int]$Queue.count -ne 1 -or $Queue.items.Count -ne 1) {
        Throw-SafeFailure "The synthetic candidate queue did not contain one item"
    }
    $item = $Queue.items[0]
    Assert-ExactPropertyNames $item @(
        "publication_key", "review_target_id", "command_sequence",
        "occurrence_count", "provenance", "review_status", "finalized_at_us"
    )
    if (
        ($item.command_sequence -join ([char]31)) -ne "LINE$([char]31)TRIM$([char]31)LINE$([char]31)TRIM" -or
        [int]$item.occurrence_count -ne 4 -or
        [string]$item.provenance -ne "observed" -or
        [string]$item.review_status -ne "unreviewed"
    ) {
        Throw-SafeFailure "The synthetic candidate evidence was not the redacted observed sequence"
    }
    return $item
}

function Assert-ApprovedOutcome {
    param([object]$Outcomes)
    if ($null -eq $Outcomes -or [int]$Outcomes.count -ne 1 -or $Outcomes.items.Count -ne 1) {
        Throw-SafeFailure "The approved outcome catalog did not contain one item"
    }
    $item = $Outcomes.items[0]
    Assert-ExactPropertyNames $item @(
        "command_sequence", "occurrence_count", "provenance",
        "review_status", "reason_code", "decided_at_us"
    )
    if (
        ($item.command_sequence -join ([char]31)) -ne "LINE$([char]31)TRIM$([char]31)LINE$([char]31)TRIM" -or
        [int]$item.occurrence_count -ne 4 -or
        [string]$item.provenance -ne "observed" -or
        [string]$item.review_status -ne "approved" -or
        $null -ne $item.reason_code -or
        [int64]$item.decided_at_us -le 0
    ) {
        Throw-SafeFailure "The synthetic terminal approval was not exact"
    }
    return $item
}

function Assert-SafeExport {
    param([object]$Response)
    if ($Response.StatusCode -ne 200) {
        Throw-SafeFailure "Approved workflow export was unavailable"
    }
    $raw = [Text.Encoding]::UTF8.GetBytes([string]$Response.Content)
    $exportText = [Text.Encoding]::UTF8.GetString($raw)
    if ($raw.Length -gt $maxExportBytes -or -not $exportText.EndsWith([Environment]::NewLine)) {
        Throw-SafeFailure "Approved workflow export exceeded its bound"
    }
    if ($Response.Headers["Content-Type"] -ne "application/json; charset=utf-8") {
        Throw-SafeFailure "Approved workflow export content type was not exact"
    }
    if ($Response.Headers["Content-Disposition"] -ne 'attachment; filename="approved-workflow.json"') {
        Throw-SafeFailure "Approved workflow export disposition was not exact"
    }
    if ([int]$Response.Headers["Content-Length"] -ne $raw.Length) {
        Throw-SafeFailure "Approved workflow export length was not exact"
    }
    try { $payload = $Response.Content | ConvertFrom-Json } catch {
        Throw-SafeFailure "Approved workflow export was not valid JSON"
    }
    Assert-ExactPropertyNames $payload @(
        "schema", "version", "command_sequence", "occurrence_count",
        "provenance", "approval_status", "decided_at"
    )
    if (
        $payload.schema -ne "workflow-helper.approved-workflow" -or
        $payload.version -ne "1.0" -or
        ($payload.command_sequence -join ([char]31)) -ne "LINE$([char]31)TRIM$([char]31)LINE$([char]31)TRIM" -or
        [int]$payload.occurrence_count -ne 4 -or
        $payload.provenance -ne "observed" -or
        $payload.approval_status -ne "approved" -or
        [string]::IsNullOrWhiteSpace([string]$payload.decided_at)
    ) {
        Throw-SafeFailure "Approved workflow export schema was not the safe allowlist"
    }
    Assert-RedactedSurface ([string]$Response.Content)
    return $payload
}

function Invoke-Preflight {
    $resolvedEvidence = Get-ResolvedEvidencePath $EvidencePath
    if ($TimeoutSeconds -lt 30 -or $TimeoutSeconds -gt 900) {
        Throw-SafeFailure "TimeoutSeconds is outside its bounded range"
    }
    Assert-HostExpectations
    Assert-ComposeConfiguration
    Assert-SafetyDefaults
    $script:canonicalFixture = Get-CanonicalFixture
    $script:sessionId = [string]$canonicalFixture.session_id
    Assert-NoAmbientProviderConfiguration
    $checks.windows_powershell_dotnet = "PASS"
    $checks.safety_defaults = "PASS"
    $checks.canonical_fixture = "PASS"
    $checks.configuration_safety = "PASS"
    $checks.fail_closed_configuration = "PASS"
    $checks.evidence_boundary = "PASS"
    $checks.preflight = "PASS"
    return $resolvedEvidence
}

function Assert-SafeEvidenceDestination {
    param([string]$ResolvedPath)

    $reparsePoint = [IO.FileAttributes]::ReparsePoint
    $rootItem = Get-Item -LiteralPath $repoRoot -Force -ErrorAction Stop
    if (
        $rootItem.LinkType -or
        (($rootItem.Attributes -band $reparsePoint) -ne 0)
    ) {
        Throw-SafeFailure "Evidence repository root is a link or reparse point"
    }

    $directory = Split-Path -Parent $ResolvedPath
    $directoryItem = Get-Item -LiteralPath $directory -Force -ErrorAction SilentlyContinue
    if ($null -eq $directoryItem) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
        $directoryItem = Get-Item -LiteralPath $directory -Force -ErrorAction SilentlyContinue
    }
    if (
        $null -eq $directoryItem -or
        -not $directoryItem.PSIsContainer -or
        $directoryItem.LinkType -or
        (($directoryItem.Attributes -band $reparsePoint) -ne 0)
    ) {
        Throw-SafeFailure "Evidence parent directory is unsafe"
    }

    $existingFile = Get-Item -LiteralPath $ResolvedPath -Force -ErrorAction SilentlyContinue
    if ($null -eq $existingFile) { return }
    if (
        $existingFile -isnot [IO.FileInfo] -or
        $existingFile.LinkType -or
        (($existingFile.Attributes -band $reparsePoint) -ne 0)
    ) {
        Throw-SafeFailure "Evidence destination is a link or reparse point"
    }

    $hardlinkTool = Get-Command "fsutil.exe" -ErrorAction SilentlyContinue
    if ($null -eq $hardlinkTool) {
        Throw-SafeFailure "Evidence hardlink status could not be verified"
    }
    $hardlinkLines = @(& $hardlinkTool.Source "hardlink" "list" $ResolvedPath 2>&1 |
        ForEach-Object { $_.ToString().Trim() } |
        Where-Object { $_ })
    if ($LASTEXITCODE -ne 0 -or $hardlinkLines.Count -ne 1) {
        Throw-SafeFailure "Evidence destination is hardlinked or could not be verified"
    }
    Throw-SafeFailure "Evidence destination already exists"
}

function Write-RedactedEvidence {
    param([string]$ResolvedPath)
    $json = $evidence | ConvertTo-Json -Depth 8 -Compress
    $jsonBytes = [Text.Encoding]::UTF8.GetBytes($json + [Environment]::NewLine)
    if ($jsonBytes.Length -gt $maxEvidenceBytes) {
        Throw-SafeFailure "Pilot evidence exceeded its bound"
    }
    foreach ($proof in $proofs) {
        if (-not [string]::IsNullOrEmpty($proof) -and $json.Contains($proof)) {
            Throw-SafeFailure "Pilot evidence contained runtime proof material"
        }
    }
    if (
        [Regex]::IsMatch($json, "\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", [RegexOptions]::IgnoreCase) -or
        [Regex]::IsMatch($json, "\b[a-f0-9]{64}\b", [RegexOptions]::IgnoreCase) -or
        [Regex]::IsMatch($json, "candidate-(?:publication|skill):", [RegexOptions]::IgnoreCase) -or
        $json.Contains("object_key") -or
        $json.Contains("review_target_id") -or
        $json.Contains("publication_key")
    ) {
        Throw-SafeFailure "Pilot evidence was not redacted"
    }
    Assert-SafeEvidenceDestination $ResolvedPath
    [IO.File]::WriteAllBytes($ResolvedPath, $jsonBytes)
    Write-Output $json
}

function Invoke-IndependentApprovedReopen {
    param([string]$ExpectedDecidedAt)
    $code = @'
import runpy
import os
from datetime import UTC, datetime
from workflow_api import dev_server
seed = runpy.run_path("/workspace/dev-runtime-seed.py")
driver = seed["_ASGIDriver"]
app = dev_server.open_existing_app()
driver = driver(app)
headers = seed["_reviewer_headers"]()
queue = driver.request("GET", "/v1/control/candidate-publications/review-queue", headers=headers)
outcomes = driver.request("GET", "/v1/control/candidate-publications/review-outcomes", headers=headers)
queue_payload = queue.json()
outcome_payload = outcomes.json()
item = outcome_payload.get("items", [None])[0] if isinstance(outcome_payload, dict) else None
if (queue.status != 200 or queue_payload != {"items": [], "count": 0} or outcomes.status != 200 or
    not isinstance(outcome_payload, dict) or set(outcome_payload) != {"items", "count"} or
    outcome_payload.get("count") != 1 or not isinstance(item, dict) or
    set(item) != {"command_sequence", "occurrence_count", "provenance", "review_status", "reason_code", "decided_at_us"} or
    item.get("command_sequence") != ["LINE", "TRIM", "LINE", "TRIM"] or
    item.get("occurrence_count") != 4 or item.get("provenance") != "observed" or
    item.get("review_status") != "approved" or item.get("reason_code") is not None or
    type(item.get("decided_at_us")) is not int or item.get("decided_at_us") <= 0):
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
    $output = Invoke-Compose @(
        "run", "--rm", "--no-deps", "-T",
        "-e", "EXPECTED_DECIDED_AT=$ExpectedDecidedAt",
        "seed", "python", "-c", $code
    ) -ReturnOutput
    $lines = @($output | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($lines.Count -ne 1 -or $lines[0] -ne "synthetic approved workflow durability verified") {
        Throw-SafeFailure "Independent durable reopen was not exact"
    }
}

try {
    $resolvedEvidencePath = Invoke-Preflight

    if ($PreflightOnly) {
        $evidence.result = "PREFLIGHT_PASS"
        $evidence.classification = "PLATFORM_BLOCKED"
        Write-Output (([ordered]@{
            result = $evidence.result
            classification = $evidence.classification
            checks = $checks
        }) | ConvertTo-Json -Depth 5 -Compress)
    } else {
        $currentCheck = "local_tooling"
        if ($null -eq (Get-Command "docker" -ErrorAction SilentlyContinue)) {
            Throw-SafeFailure "Docker is required for the full synthetic pilot"
        }
        $null = Invoke-CheckedCommand "docker" @("info") -ReturnOutput
        $null = Invoke-CheckedCommand "docker" @("--version") -ReturnOutput
        $null = Invoke-CheckedCommand "docker" @("compose", "version") -ReturnOutput
        $checks.local_tooling = "PASS"
        $checks.docker_tooling = "PASS"

        $runTag = [Guid]::NewGuid().ToString("N")
        $composeProject = ("workflow-win-{0}-{1}" -f $PID, $runTag.Substring(0, 12)).ToLowerInvariant()
        if ($composeProject -notmatch "^[a-z0-9][a-z0-9_-]{0,62}$") {
            Throw-SafeFailure "Synthetic Compose project name was unsafe"
        }
        $runtimeDirectory = Join-Path ([IO.Path]::GetTempPath()) (
            "workflow-helper-windows-synthetic-pilot-{0}-{1}" -f $PID, $runTag)
        New-Item -ItemType Directory -Path $runtimeDirectory -Force | Out-Null
        $runtimeEnvironment = Join-Path $runtimeDirectory "compose.env"
        $dataPath = "/var/lib/workflow-helper/$runTag"
        $apiPort = Get-FreeTcpPort
        $webPort = Get-FreeTcpPort
        if ($apiPort -eq $webPort) { $webPort = Get-FreeTcpPort }
        $captureProof = New-SyntheticMaterial
        $workerProof = New-SyntheticMaterial
        $reviewerProof = New-SyntheticMaterial
        $reviewerSession = New-SyntheticMaterial
        $reviewerCsrf = New-SyntheticMaterial
        $proofs = @($captureProof, $workerProof, $reviewerProof, $reviewerSession, $reviewerCsrf)
        if (@($proofs | Select-Object -Unique).Count -ne 5) {
            Throw-SafeFailure "Synthetic proof material was not distinct"
        }
        New-RuntimeEnvironment -Path $runtimeEnvironment -DataPath $dataPath -ApiPort $apiPort -WebPort $webPort -CaptureProof $captureProof -WorkerProof $workerProof -ReviewerProof $reviewerProof -ReviewerSession $reviewerSession -ReviewerCsrf $reviewerCsrf

        $currentCheck = "compose_runtime"
        # The project is considered owned before startup so a partial Compose
        # failure is still cleaned up by the unique-project teardown.
        $composeStarted = $true
        $null = Invoke-Compose @("config", "--quiet") -ReturnOutput
        $null = Invoke-Compose @("up", "-d", "--build", "--force-recreate", "api", "seed", "web") -ReturnOutput
        $checks.compose_runtime = "PASS"
        $checks.sealed_runtime = "PASS"

        $apiBase = "http://127.0.0.1:$apiPort"
        $webBase = "http://127.0.0.1:$webPort"
        Wait-ForHealth "$apiBase/health"
        $reviewHeaders = Get-ReviewerHeaders
        $currentCheck = "upload_receipt"
        Wait-ForSeedCompletion
        $session = Wait-ForApiJson $apiBase "/v1/sessions/$sessionId" $reviewHeaders {
            param($value)
            return ([string]$value.processing_status -eq "processed")
        }
        if (
            [string]$session.raw_object_key -notmatch "^sessions/$sessionId/packages/[a-f0-9]{64}\.zip$" -or
            [int64]$session.package_size_bytes -le 0 -or
            $session.recording -ne $null
        ) {
            Throw-SafeFailure "Canonical upload receipt was not visible in the processed session"
        }
        $checks.upload_receipt = "PASS"

        $currentCheck = "v2_timeline"
        $timeline = Get-ApiJson $apiBase "/v1/sessions/$sessionId/timeline" $reviewHeaders
        Assert-CanonicalTimeline $timeline
        $checks.v2_timeline = "PASS"

        $currentCheck = "redacted_candidate"
        $candidateResponse = Get-HttpResponse -Uri "$webBase/candidate-review"
        if ($candidateResponse.StatusCode -ne 200) {
            Throw-SafeFailure "Synthetic candidate review page was unavailable"
        }
        $candidateHtml = [string]$candidateResponse.Content
        $candidateText = Get-WebVisibleText $candidateHtml
        foreach ($label in @(
            "Candidate review queue", "Candidate 1", "LINE → TRIM → LINE → TRIM",
            "4", "observed / unreviewed", "Approve", "Start review"
        )) {
            if (-not $candidateText.Contains($label)) {
                Throw-SafeFailure "Redacted candidate browser evidence was incomplete"
            }
        }
        Assert-RedactedSurface $candidateHtml
        $queue = Get-ApiJson $apiBase "/v1/control/candidate-publications/review-queue" $reviewHeaders
        $null = Assert-ReviewQueueItem $queue
        $checks.redacted_candidate = "PASS"

        $currentCheck = "browser_confirmation"
        $sessionPage = Get-HttpResponse -Uri "$webBase/sessions/$sessionId"
        if ($sessionPage.StatusCode -ne 200) {
            Throw-SafeFailure "Synthetic session browser page was unavailable"
        }
        $sessionText = Get-WebVisibleText ([string]$sessionPage.Content)
        foreach ($label in @(
            "Meaningful operations", "8 meaningful operations from 8 observed events.",
            "Deterministic operation segments", "Segment 1", "Segment 4",
            "Commands: LINE", "Commands: TRIM", "Review candidates"
        )) {
            if (-not $sessionText.Contains($label)) {
                Throw-SafeFailure "Synthetic v2 timeline browser evidence was incomplete"
            }
        }
        Assert-RedactedSurface ([string]$sessionPage.Content) -SkipIdentifierCheck
        Write-Output "Open these URLs in the controlled browser and inspect the timeline and candidate review surfaces:"
        Write-Output "$webBase/sessions/$sessionId"
        Write-Output "$webBase/candidate-review"
        try {
            Start-Process -FilePath "$webBase/sessions/$sessionId" | Out-Null
            Start-Process -FilePath "$webBase/candidate-review" | Out-Null
        } catch {
            Write-Warning "The browser could not be opened automatically; use the printed URLs."
        }
        $humanConfirmation = Read-Host "Type HUMAN-CONFIRMED after the browser-visible synthetic review is verified"
        if ($humanConfirmation -cne "HUMAN-CONFIRMED") {
            Throw-SafeFailure "Human browser confirmation was not provided"
        }
        $evidence.human_browser_confirmation = "PASS"
        $checks.browser_confirmation = "PASS"
        $checks.human_browser_confirmation = "PASS"

        $currentCheck = "terminal_approval"
        $actionHeaders = @{
            "Host" = "127.0.0.1:$webPort"
            "Origin" = "http://127.0.0.1:$webPort"
        }
        $approvalResponse = Get-HttpResponse -Uri "$webBase/candidate-review/action" -Method "POST" -Headers $actionHeaders -Body "ordinal=1&action=approve" -ContentType "application/x-www-form-urlencoded"
        if (
            $approvalResponse.StatusCode -ne 303 -or
            [string]$approvalResponse.Content -ne "" -or
            $approvalResponse.Headers["Location"] -ne "/candidate-review"
        ) {
            Throw-SafeFailure "Terminal approval route did not return the fixed bodyless redirect"
        }
        $checks.terminal_approval = "PASS"
        $checks.approval_terminal_outcome = "PASS"

        $currentCheck = "approved_catalog"
        $approvedQueueResponse = Get-HttpResponse -Uri "$webBase/candidate-review"
        $approvedQueueText = Get-WebVisibleText ([string]$approvedQueueResponse.Content)
        if (-not $approvedQueueText.Contains("No candidates awaiting review.")) {
            Throw-SafeFailure "Terminal approval did not empty the active review queue"
        }
        $catalogResponse = Get-HttpResponse -Uri "$webBase/approved-workflows"
        $catalogText = Get-WebVisibleText ([string]$catalogResponse.Content)
        foreach ($label in @(
            "Approved workflows", "Approved workflow 1", "LINE → TRIM → LINE → TRIM",
            "observed / approved", "Download JSON"
        )) {
            if (-not $catalogText.Contains($label)) {
                Throw-SafeFailure "Approved catalog browser evidence was incomplete"
            }
        }
        Assert-RedactedSurface ([string]$approvedQueueResponse.Content)
        Assert-RedactedSurface ([string]$catalogResponse.Content)
        $outcomes = Get-ApiJson $apiBase "/v1/control/candidate-publications/review-outcomes" $reviewHeaders
        $approvedOutcome = Assert-ApprovedOutcome $outcomes
        $checks.approved_catalog = "PASS"
        $checks.approved_catalog_export = "PASS"

        $currentCheck = "safe_export"
        $downloadHeaders = @{ "Host" = "127.0.0.1:$webPort" }
        $downloadResponse = Get-HttpResponse -Uri "$webBase/approved-workflows/download?ordinal=1" -Headers $downloadHeaders
        $downloadPayload = Assert-SafeExport $downloadResponse
        $parsedDecision = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse(
            [string]$downloadPayload.decided_at,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::RoundtripKind,
            [ref]$parsedDecision
        )) {
            Throw-SafeFailure "Approved export decision evidence was not a timestamp"
        }
        $checks.safe_export = "PASS"

        $currentCheck = "independent_reopen"
        $null = Invoke-Compose @("stop", "api", "web") -ReturnOutput
        Invoke-IndependentApprovedReopen ([string]$downloadPayload.decided_at)
        $checks.independent_reopen = "PASS"
        $checks.independent_durable_reopen = "PASS"
        $evidence.result = "PASS"
        $evidence.classification = "CONTROLLED_HOST_SYNTHETIC_PASS"
    }
} catch {
    $checks[$currentCheck] = "FAIL"
    if ($PreflightOnly) {
        $evidence.result = "PREFLIGHT_FAIL"
    } else {
        $evidence.result = "FAIL"
    }
    $evidence.error = "bounded check failed: $currentCheck"
    Write-Warning "Synthetic Windows pilot did not pass the bounded check: $currentCheck"
} finally {
    if (-not $PreflightOnly -and $composeStarted) {
        try {
            $null = Invoke-Compose @("down", "--volumes", "--remove-orphans") -ReturnOutput
            $checks.cleanup = "PASS"
            $checks.scoped_cleanup = "PASS"
        } catch {
            $cleanupFailure = $true
            $checks.cleanup = "FAIL"
            if ($evidence.result -eq "PASS") { $evidence.result = "FAIL" }
            $evidence.error = "bounded cleanup failed"
            $checks.scoped_cleanup = "FAIL"
            Write-Warning "Synthetic cleanup failed for the unique Compose project; no broad cleanup was attempted."
        }
    } elseif (-not $PreflightOnly) {
        $checks.cleanup = "PASS"
        $checks.scoped_cleanup = "PASS"
    }
    if (-not $PreflightOnly -and $null -ne $runtimeDirectory -and (Test-Path -LiteralPath $runtimeDirectory)) {
        try {
            Remove-Item -LiteralPath $runtimeDirectory -Recurse -Force
        } catch {
            $cleanupFailure = $true
            $checks.cleanup = "FAIL"
            if ($evidence.result -eq "PASS") { $evidence.result = "FAIL" }
            $evidence.error = "bounded temporary-state cleanup failed"
            $checks.scoped_cleanup = "FAIL"
            Write-Warning "Synthetic temporary-state cleanup failed; no unrelated path was removed."
        }
    }

    if (-not $PreflightOnly) {
        try {
            Write-RedactedEvidence $resolvedEvidencePath
        } catch {
            $evidence.result = "FAIL"
            $evidence.error = "bounded evidence write failed"
            Write-Warning "Synthetic pilot evidence could not be written to the bounded local path."
        }
    }
}

if ($PreflightOnly) {
    if ($evidence.result -ne "PREFLIGHT_PASS") { exit 1 }
    exit 0
}
if ($evidence.result -ne "PASS" -or $cleanupFailure) { exit 1 }
exit 0
