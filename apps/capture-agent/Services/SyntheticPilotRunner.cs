using Microsoft.Extensions.Options;
using WorkflowHelper.CaptureAgent.Configuration;
using WorkflowHelper.CaptureAgent.Domain;

namespace WorkflowHelper.CaptureAgent.Services;

public sealed record SyntheticPilotEvidence(
    string SchemaVersion,
    string PilotMode,
    string Result,
    Guid SessionId,
    string? PackageSha256,
    long? PackageSizeBytes,
    bool RecordingIncluded,
    string? Error);

/// <summary>
/// A bounded one-shot route for the controlled pilot. It never resolves the
/// detector, recorder, worker, or coordinator and never accepts an input file.
/// </summary>
public sealed class SyntheticPilotRunner(
    ISessionPackageWriter packageWriter,
    ISessionUploadClient uploadClient,
    IOptions<CaptureOptions> captureOptions,
    IOptions<UploadOptions> uploadOptions)
{
    internal static readonly Guid PilotSessionId =
        Guid.Parse("d6d9e5b7-c9bc-4eb1-ae4a-1a14ed5b1350");
    internal static readonly Guid BeforeArtifactId =
        Guid.Parse("44444444-4444-4444-8444-444444444444");
    internal static readonly Guid AfterArtifactId =
        Guid.Parse("55555555-5555-4555-8555-555555555555");
    private static readonly DateTimeOffset StartedAt =
        new(2026, 8, 17, 0, 0, 0, TimeSpan.Zero);

    public async Task<SyntheticPilotEvidence> RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            ValidateSafetyBoundary(captureOptions.Value, uploadOptions.Value);
            var session = CreateSyntheticSession();
            var package = await packageWriter.WriteAsync(
                session,
                recordingPath: null,
                cancellationToken);
            await uploadClient.UploadAsync(package, cancellationToken);
            return Evidence(
                "PASS",
                package.Sha256,
                package.SizeBytes,
                error: null);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return Evidence(
                "FAIL",
                packageSha256: null,
                packageSizeBytes: null,
                error: exception.Message);
        }
    }

    internal static CaptureSession CreateSyntheticSession()
    {
        var endedAt = StartedAt.AddSeconds(60);
        return new CaptureSession(
            PilotSessionId,
            "1.0",
            "synthetic-pilot-machine",
            StartedAt,
            endedAt,
            60,
            "acad",
            WindowFingerprint: null,
            CadEvents:
            [
                new CadEvent(
                    Guid.Parse("f74d30dd-9945-4291-8ae9-95658379b335"),
                    StartedAt,
                    "session_started",
                    "agent",
                    null,
                    null,
                    SyntheticDetails()),
                new CadEvent(
                    Guid.Parse("1e6e2db8-c50a-4cd2-b122-381e3f20640f"),
                    StartedAt.AddSeconds(5),
                    "drawing_opened",
                    "autocad",
                    null,
                    "synthetic-drawing-001",
                    SyntheticDetails()),
                new CadEvent(
                    Guid.Parse("9ef08077-1fd0-468c-bf68-1f8f1ef23c4e"),
                    StartedAt.AddSeconds(20),
                    "cad_command",
                    "autocad",
                    "LINE",
                    "synthetic-drawing-001",
                    SyntheticDetails()),
                new CadEvent(
                    Guid.Parse("7482f72e-0b68-4535-bf65-f234a460e376"),
                    StartedAt.AddSeconds(35),
                    "cad_command",
                    "autocad",
                    "TRIM",
                    "synthetic-drawing-001",
                    SyntheticDetails()),
                new CadEvent(
                    Guid.Parse("a21f79d6-cb3c-41c4-b5f0-1f0a883fde45"),
                    StartedAt.AddSeconds(50),
                    "drawing_saved",
                    "autocad",
                    null,
                    "synthetic-drawing-001",
                    SyntheticDetails()),
                new CadEvent(
                    Guid.Parse("3cb65614-3f9d-4e19-bac1-133fbdda9a54"),
                    endedAt,
                    "session_ended",
                    "agent",
                    null,
                    null,
                    SyntheticDetails()),
            ],
            InputArtifacts:
            [
                new CaptureArtifact(
                    BeforeArtifactId,
                    "input",
                    "synthetic-before.json",
                    "37c13fc0765424f6d94fa90c04aac1f03dfb693ec91c0b5e9083de465fadec30",
                    36,
                    null),
            ],
            OutputArtifacts:
            [
                new CaptureArtifact(
                    AfterArtifactId,
                    "output",
                    "synthetic-after.json",
                    "797d708b02d246269d7a774480ee876feb5c885e033c6b5de5475f8b40cdb4b7",
                    35,
                    null),
            ]);
    }

    private static Dictionary<string, object?> SyntheticDetails() =>
        new() { ["synthetic"] = true };

    internal static void ValidateSafetyBoundary(
        CaptureOptions capture,
        UploadOptions upload)
    {
        if (capture.CaptureEnabled || capture.ConsentAcknowledged)
        {
            throw new InvalidOperationException(
                "Synthetic pilot requires CaptureEnabled=false and ConsentAcknowledged=false");
        }
        if (!upload.Enabled)
        {
            throw new InvalidOperationException(
                "Synthetic pilot requires explicit Upload__Enabled=true");
        }
        if (!upload.ApiBaseUrl.IsLoopback ||
            upload.ApiBaseUrl.UserInfo.Length != 0 ||
            upload.ApiBaseUrl.Scheme is not ("http" or "https"))
        {
            throw new InvalidOperationException(
                "Synthetic pilot API must be an HTTP(S) loopback endpoint without credentials");
        }
        if (string.IsNullOrWhiteSpace(capture.OutputDirectory))
        {
            throw new InvalidOperationException(
                "Synthetic pilot output directory must contain 'synthetic-pilot'");
        }
        var canonicalOutputDirectory = Path.GetFullPath(capture.OutputDirectory);
        var outputDirectoryName = Path.GetFileName(
            Path.TrimEndingDirectorySeparator(canonicalOutputDirectory));
        if (!outputDirectoryName.Contains(
            "synthetic-pilot",
            StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "Synthetic pilot output directory must contain 'synthetic-pilot'");
        }
    }

    private static SyntheticPilotEvidence Evidence(
        string result,
        string? packageSha256,
        long? packageSizeBytes,
        string? error) =>
        new(
            "1.0",
            "generated-synthetic-only",
            result,
            PilotSessionId,
            packageSha256,
            packageSizeBytes,
            RecordingIncluded: false,
            error);
}
