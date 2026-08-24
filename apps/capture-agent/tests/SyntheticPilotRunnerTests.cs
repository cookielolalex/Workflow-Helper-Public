using Microsoft.Extensions.Options;
using WorkflowHelper.CaptureAgent.Configuration;
using WorkflowHelper.CaptureAgent.Domain;
using WorkflowHelper.CaptureAgent.Services;
using Xunit;

namespace WorkflowHelper.CaptureAgent.Tests;

public sealed class SyntheticPilotRunnerTests
{
    [Fact]
    public async Task GeneratesBoundedPackageWithoutRecordingAndUploadsIt()
    {
        var writer = new RecordingPackageWriter();
        var uploader = new RecordingUploadClient();
        var runner = CreateRunner(writer, uploader);

        var evidence = await runner.RunAsync(CancellationToken.None);

        Assert.Equal("PASS", evidence.Result);
        Assert.False(evidence.RecordingIncluded);
        Assert.Null(writer.RecordingPath);
        Assert.NotNull(writer.Session);
        Assert.Equal(SyntheticPilotRunner.PilotSessionId, writer.Session.SessionId);
        Assert.Equal("synthetic-pilot-machine", writer.Session.MachineId);
        Assert.Null(writer.Session.WindowFingerprint);
        Assert.Equal(3, writer.Session.CadEvents.Count);
        Assert.All(writer.Session.CadEvents, value =>
        {
            Assert.True(value.Details.TryGetValue("synthetic", out var marker));
            Assert.True(marker is true);
        });
        Assert.Same(writer.Package, uploader.Package);
    }

    [Fact]
    public async Task FailsClosedBeforeWritingWhenUploadIsDisabled()
    {
        var writer = new RecordingPackageWriter();
        var runner = CreateRunner(
            writer,
            new RecordingUploadClient(),
            uploadEnabled: false);

        var evidence = await runner.RunAsync(CancellationToken.None);

        Assert.Equal("FAIL", evidence.Result);
        Assert.NotNull(evidence.Error);
        Assert.Contains("Upload__Enabled=true", evidence.Error);
        Assert.Null(writer.Session);
    }

    [Theory]
    [InlineData("https://example.com")]
    [InlineData("http://user:password@localhost:8000")]
    public async Task RejectsNonLoopbackOrCredentialBearingApi(string apiBaseUrl)
    {
        var writer = new RecordingPackageWriter();
        var runner = CreateRunner(
            writer,
            new RecordingUploadClient(),
            apiBaseUrl: apiBaseUrl);

        var evidence = await runner.RunAsync(CancellationToken.None);

        Assert.Equal("FAIL", evidence.Result);
        Assert.Null(writer.Session);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task RefusesToRunIfEitherCaptureGateIsEnabled(
        bool captureEnabled,
        bool consentAcknowledged)
    {
        var writer = new RecordingPackageWriter();
        var runner = new SyntheticPilotRunner(
            writer,
            new RecordingUploadClient(),
            Options.Create(new CaptureOptions
            {
                CaptureEnabled = captureEnabled,
                ConsentAcknowledged = consentAcknowledged,
                OutputDirectory = "synthetic-pilot-output",
            }),
            Options.Create(new UploadOptions
            {
                Enabled = true,
                ApiBaseUrl = new Uri("http://localhost:8000"),
            }));

        var evidence = await runner.RunAsync(CancellationToken.None);

        Assert.Equal("FAIL", evidence.Result);
        Assert.Null(writer.Session);
    }

    [Theory]
    [InlineData("ordinary-output")]
    [InlineData("synthetic-pilot-output/../ordinary-output")]
    public async Task RejectsOutputWithoutMarkerAfterCanonicalization(string outputDirectory)
    {
        var writer = new RecordingPackageWriter();
        var runner = CreateRunner(
            writer,
            new RecordingUploadClient(),
            outputDirectory: outputDirectory);

        var evidence = await runner.RunAsync(CancellationToken.None);

        Assert.Equal("FAIL", evidence.Result);
        Assert.NotNull(evidence.Error);
        Assert.Contains("synthetic-pilot", evidence.Error);
        Assert.Null(writer.Session);
    }

    private static SyntheticPilotRunner CreateRunner(
        RecordingPackageWriter writer,
        RecordingUploadClient uploader,
        bool uploadEnabled = true,
        string apiBaseUrl = "http://localhost:8000",
        string outputDirectory = "synthetic-pilot-output") =>
        new(
            writer,
            uploader,
            Options.Create(new CaptureOptions
            {
                CaptureEnabled = false,
                ConsentAcknowledged = false,
                OutputDirectory = outputDirectory,
            }),
            Options.Create(new UploadOptions
            {
                Enabled = uploadEnabled,
                ApiBaseUrl = new Uri(apiBaseUrl),
            }));

    private sealed class RecordingPackageWriter : ISessionPackageWriter
    {
        public CaptureSession? Session { get; private set; }
        public string? RecordingPath { get; private set; }
        public PackageDescriptor? Package { get; private set; }

        public Task<PackageDescriptor> WriteAsync(
            CaptureSession session,
            string? recordingPath,
            CancellationToken cancellationToken)
        {
            Session = session;
            RecordingPath = recordingPath;
            var package = new PackageDescriptor(
                session.SessionId,
                "synthetic-pilot-output/package.zip",
                new string('a', 64),
                123,
                session);
            Package = package;
            return Task.FromResult(package);
        }
    }

    private sealed class RecordingUploadClient : ISessionUploadClient
    {
        public PackageDescriptor? Package { get; private set; }

        public Task UploadAsync(
            PackageDescriptor package,
            CancellationToken cancellationToken)
        {
            Package = package;
            return Task.CompletedTask;
        }
    }
}
