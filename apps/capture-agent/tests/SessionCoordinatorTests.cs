using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using WorkflowHelper.CaptureAgent.Configuration;
using WorkflowHelper.CaptureAgent.Domain;
using WorkflowHelper.CaptureAgent.Services;
using Xunit;

namespace WorkflowHelper.CaptureAgent.Tests;

public sealed class SessionCoordinatorTests
{
    private static readonly ApprovedWindowContext ApprovedWindow =
        new(42, "acad", "synthetic-window");

    [Fact]
    public async Task ForegroundLossPausesAndReturnResumesBeforeStop()
    {
        var fixture = new CoordinatorFixture(foregroundGraceSeconds: 5);

        fixture.Detector.Current = ApprovedWindow;
        await fixture.Coordinator.TickAsync(CancellationToken.None);
        fixture.Clock.Advance(TimeSpan.FromSeconds(1));
        fixture.Detector.Current = null;
        await fixture.Coordinator.TickAsync(CancellationToken.None);

        Assert.Equal(["start", "pause"], fixture.Recorder.Actions);
        Assert.Null(fixture.UploadClient.Uploaded);

        fixture.Clock.Advance(TimeSpan.FromSeconds(1));
        fixture.Detector.Current = ApprovedWindow;
        await fixture.Coordinator.TickAsync(CancellationToken.None);
        fixture.Clock.Advance(TimeSpan.FromSeconds(2));
        await fixture.Coordinator.FinishActiveSessionAsync(CancellationToken.None);

        Assert.Equal(["start", "pause", "resume", "stop"], fixture.Recorder.Actions);
        Assert.Null(fixture.PackageWriter.RecordingPath);
        var uploaded = Assert.IsType<PackageDescriptor>(fixture.UploadClient.Uploaded);
        var finished = uploaded.Session;
        Assert.Equal(3, finished.ActiveDurationSeconds);
        Assert.Equal(
            ["session_started", "session_paused", "session_resumed", "session_ended"],
            finished.CadEvents.Select(value => value.EventType));
    }

    [Fact]
    public async Task ForegroundLossPausesImmediatelyButGraceKeepsLogicalSessionAlive()
    {
        var fixture = new CoordinatorFixture(foregroundGraceSeconds: 5);
        fixture.Detector.Current = ApprovedWindow;
        await fixture.Coordinator.TickAsync(CancellationToken.None);

        fixture.Clock.Advance(TimeSpan.FromSeconds(1));
        fixture.Detector.Current = null;
        await fixture.Coordinator.TickAsync(CancellationToken.None);
        fixture.Clock.Advance(TimeSpan.FromSeconds(3));
        await fixture.Coordinator.TickAsync(CancellationToken.None);

        Assert.Equal(["start", "pause"], fixture.Recorder.Actions);
        Assert.Null(fixture.UploadClient.Uploaded);

        fixture.Clock.Advance(TimeSpan.FromSeconds(2));
        await fixture.Coordinator.TickAsync(CancellationToken.None);

        Assert.Equal(["start", "pause", "stop"], fixture.Recorder.Actions);
        var uploaded = Assert.IsType<PackageDescriptor>(fixture.UploadClient.Uploaded);
        Assert.Single(
            uploaded.Session.CadEvents,
            value => value.EventType == "session_paused");
    }

    [Fact]
    public async Task DisabledRecorderPauseResumeAndStopRemainNoOps()
    {
        var recorder = new DisabledCaptureRecorder(NullLogger<DisabledCaptureRecorder>.Instance);
        var session = CaptureSession.Start(
            "machine-synthetic",
            ApprovedWindow,
            DateTimeOffset.Parse("2026-08-16T04:00:00Z"));

        await recorder.StartAsync(session, CancellationToken.None);
        await recorder.PauseAsync(CancellationToken.None);
        await recorder.ResumeAsync(CancellationToken.None);
        var artifact = await recorder.StopAsync(CancellationToken.None);

        Assert.Null(artifact);
    }

    [Fact]
    public async Task FinishedRecordingPathIsPassedToPackageWriterBeforeUpload()
    {
        var fixture = new CoordinatorFixture(foregroundGraceSeconds: 5);
        var recordingPath = Path.Combine("synthetic-root", "capture.synthetic");
        fixture.Recorder.StopResult = recordingPath;
        fixture.Detector.Current = ApprovedWindow;

        await fixture.Coordinator.TickAsync(CancellationToken.None);
        await fixture.Coordinator.FinishActiveSessionAsync(CancellationToken.None);

        Assert.Equal(recordingPath, fixture.PackageWriter.RecordingPath);
        Assert.NotNull(fixture.UploadClient.Uploaded);
        Assert.Equal(
            fixture.PackageWriter.WrittenPackage,
            fixture.UploadClient.Uploaded);
    }

    [Fact]
    public async Task PackageFailureRetriesFinishedSessionWithoutSecondStopOrEndEvent()
    {
        var fixture = new CoordinatorFixture(foregroundGraceSeconds: 5);
        fixture.Recorder.StopResult = Path.Combine("synthetic-root", "capture.synthetic");
        fixture.PackageWriter.Failures.Enqueue(
            new InvalidDataException("synthetic package failure"));
        fixture.Detector.Current = ApprovedWindow;

        await fixture.Coordinator.TickAsync(CancellationToken.None);
        await Assert.ThrowsAsync<InvalidDataException>(
            () => fixture.Coordinator.FinishActiveSessionAsync(CancellationToken.None));
        fixture.Clock.Advance(TimeSpan.FromSeconds(30));
        await fixture.Coordinator.FinishActiveSessionAsync(CancellationToken.None);

        Assert.Equal(1, fixture.Recorder.StopCount);
        Assert.Equal(2, fixture.PackageWriter.Calls.Count);
        Assert.Same(
            fixture.PackageWriter.Calls[0].Session,
            fixture.PackageWriter.Calls[1].Session);
        Assert.All(fixture.PackageWriter.Calls, call =>
        {
            Assert.Equal(fixture.Recorder.StopResult, call.RecordingPath);
            Assert.Single(
                call.Session.CadEvents,
                value => value.EventType == "session_ended");
        });
        Assert.Single(fixture.UploadClient.Packages);
    }

    [Fact]
    public async Task PackageCancellationRetriesWithoutSecondStop()
    {
        var fixture = new CoordinatorFixture(foregroundGraceSeconds: 5);
        fixture.Recorder.StopResult = Path.Combine(
            "synthetic-root",
            "cancelled-package.synthetic");
        fixture.PackageWriter.Failures.Enqueue(
            new OperationCanceledException("synthetic package cancellation"));
        fixture.Detector.Current = ApprovedWindow;

        await fixture.Coordinator.TickAsync(CancellationToken.None);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => fixture.Coordinator.FinishActiveSessionAsync(CancellationToken.None));
        await fixture.Coordinator.FinishActiveSessionAsync(CancellationToken.None);

        Assert.Equal(1, fixture.Recorder.StopCount);
        Assert.Equal(2, fixture.PackageWriter.Calls.Count);
        Assert.Same(
            fixture.PackageWriter.Calls[0].Session,
            fixture.PackageWriter.Calls[1].Session);
        Assert.All(fixture.PackageWriter.Calls, call =>
        {
            Assert.Equal(fixture.Recorder.StopResult, call.RecordingPath);
            Assert.Single(
                call.Session.CadEvents,
                value => value.EventType == "session_ended");
        });
        var uploaded = Assert.Single(fixture.UploadClient.Packages);
        Assert.Same(fixture.PackageWriter.WrittenPackage, uploaded);
    }

    [Fact]
    public async Task UploadFailureRetriesExactCachedPackageWithoutRebuildOrStop()
    {
        var fixture = new CoordinatorFixture(foregroundGraceSeconds: 5);
        fixture.UploadClient.Failures.Enqueue(
            new HttpRequestException("synthetic upload failure"));
        fixture.Detector.Current = ApprovedWindow;

        await fixture.Coordinator.TickAsync(CancellationToken.None);
        await Assert.ThrowsAsync<HttpRequestException>(
            () => fixture.Coordinator.FinishActiveSessionAsync(CancellationToken.None));
        await fixture.Coordinator.FinishActiveSessionAsync(CancellationToken.None);

        Assert.Equal(1, fixture.Recorder.StopCount);
        var write = Assert.Single(fixture.PackageWriter.Calls);
        Assert.Single(
            write.Session.CadEvents,
            value => value.EventType == "session_ended");
        Assert.Null(write.RecordingPath);
        Assert.Equal(2, fixture.UploadClient.Packages.Count);
        Assert.Same(
            fixture.UploadClient.Packages[0],
            fixture.UploadClient.Packages[1]);
        Assert.Same(
            fixture.PackageWriter.WrittenPackage,
            fixture.UploadClient.Packages[1]);
        Assert.Same(write.Session, fixture.UploadClient.Packages[1].Session);
    }

    [Fact]
    public async Task UploadCancellationRetriesExactCachedPackageWithoutRebuild()
    {
        var fixture = new CoordinatorFixture(foregroundGraceSeconds: 5);
        fixture.UploadClient.Failures.Enqueue(
            new OperationCanceledException("synthetic upload cancellation"));
        fixture.Detector.Current = ApprovedWindow;

        await fixture.Coordinator.TickAsync(CancellationToken.None);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => fixture.Coordinator.FinishActiveSessionAsync(CancellationToken.None));
        await fixture.Coordinator.FinishActiveSessionAsync(CancellationToken.None);

        Assert.Equal(1, fixture.Recorder.StopCount);
        var write = Assert.Single(fixture.PackageWriter.Calls);
        Assert.Single(
            write.Session.CadEvents,
            value => value.EventType == "session_ended");
        Assert.Null(write.RecordingPath);
        Assert.Equal(2, fixture.UploadClient.Packages.Count);
        Assert.Same(
            fixture.UploadClient.Packages[0],
            fixture.UploadClient.Packages[1]);
        Assert.Same(
            fixture.PackageWriter.WrittenPackage,
            fixture.UploadClient.Packages[1]);
        Assert.Same(write.Session, fixture.UploadClient.Packages[1].Session);
    }

    [Fact]
    public async Task TickDrainsPendingUploadBeforeStartingNextSession()
    {
        var fixture = new CoordinatorFixture(foregroundGraceSeconds: 5);
        fixture.UploadClient.Failures.Enqueue(
            new HttpRequestException("synthetic first upload failure"));
        fixture.Detector.Current = ApprovedWindow;

        await fixture.Coordinator.TickAsync(CancellationToken.None);
        await Assert.ThrowsAsync<HttpRequestException>(
            () => fixture.Coordinator.FinishActiveSessionAsync(CancellationToken.None));
        await fixture.Coordinator.TickAsync(CancellationToken.None);

        Assert.Equal(2, fixture.Recorder.StartCount);
        Assert.Equal(1, fixture.Recorder.StopCount);
        var write = Assert.Single(fixture.PackageWriter.Calls);
        Assert.Single(
            write.Session.CadEvents,
            value => value.EventType == "session_ended");
        Assert.Null(write.RecordingPath);
        Assert.Equal(2, fixture.UploadClient.Packages.Count);
        Assert.Same(
            fixture.UploadClient.Packages[0],
            fixture.UploadClient.Packages[1]);
        Assert.Same(write.Session, fixture.UploadClient.Packages[1].Session);
        Assert.Equal(
            [
                "recorder:start",
                "recorder:stop",
                "writer:write",
                "upload:upload",
                "upload:upload",
                "recorder:start",
            ],
            fixture.Timeline);
    }

    private sealed class CoordinatorFixture
    {
        public CoordinatorFixture(int foregroundGraceSeconds)
        {
            Recorder = new RecordingSpy(Timeline);
            PackageWriter = new PackageWriterSpy(Timeline);
            UploadClient = new UploadClientSpy(Timeline);
            var options = Options.Create(new CaptureOptions
            {
                MachinePseudonym = "machine-synthetic",
                ForegroundGraceSeconds = foregroundGraceSeconds,
            });
            Coordinator = new SessionCoordinator(
                Detector,
                Recorder,
                PackageWriter,
                UploadClient,
                options,
                Clock,
                NullLogger<SessionCoordinator>.Instance);
        }

        public List<string> Timeline { get; } = [];
        public MutableWindowDetector Detector { get; } = new();
        public RecordingSpy Recorder { get; }
        public PackageWriterSpy PackageWriter { get; }
        public UploadClientSpy UploadClient { get; }
        public AdjustableTimeProvider Clock { get; } = new(
            DateTimeOffset.Parse("2026-08-16T04:00:00Z"));
        public SessionCoordinator Coordinator { get; }
    }

    private sealed class MutableWindowDetector : IApprovedWindowDetector
    {
        public ApprovedWindowContext? Current { get; set; }
        public ApprovedWindowContext? GetApprovedForegroundWindow() => Current;
    }

    private sealed class RecordingSpy(List<string> timeline) : ICaptureRecorder
    {
        public List<string> Actions { get; } = [];
        public string? StopResult { get; set; }
        public int StartCount { get; private set; }
        public int StopCount { get; private set; }

        public Task StartAsync(CaptureSession session, CancellationToken cancellationToken)
        {
            Actions.Add("start");
            StartCount++;
            timeline.Add("recorder:start");
            return Task.CompletedTask;
        }

        public Task PauseAsync(CancellationToken cancellationToken)
        {
            Actions.Add("pause");
            return Task.CompletedTask;
        }

        public Task ResumeAsync(CancellationToken cancellationToken)
        {
            Actions.Add("resume");
            return Task.CompletedTask;
        }

        public Task<string?> StopAsync(CancellationToken cancellationToken)
        {
            Actions.Add("stop");
            StopCount++;
            timeline.Add("recorder:stop");
            return Task.FromResult(StopResult);
        }
    }

    private sealed class PackageWriterSpy(List<string> timeline) : ISessionPackageWriter
    {
        public Queue<Exception> Failures { get; } = [];
        public List<(CaptureSession Session, string? RecordingPath)> Calls { get; } = [];
        public string? RecordingPath { get; private set; }
        public PackageDescriptor? WrittenPackage { get; private set; }

        public Task<PackageDescriptor> WriteAsync(
            CaptureSession session,
            string? recordingPath,
            CancellationToken cancellationToken)
        {
            RecordingPath = recordingPath;
            Calls.Add((session, recordingPath));
            timeline.Add("writer:write");
            if (Failures.Count > 0)
            {
                throw Failures.Dequeue();
            }
            var package = new PackageDescriptor(
                session.SessionId,
                "synthetic-package.zip",
                new string('a', 64),
                128,
                session);
            WrittenPackage = package;
            return Task.FromResult(package);
        }
    }

    private sealed class UploadClientSpy(List<string> timeline) : ISessionUploadClient
    {
        public Queue<Exception> Failures { get; } = [];
        public List<PackageDescriptor> Packages { get; } = [];
        public PackageDescriptor? Uploaded => Packages.LastOrDefault();

        public Task UploadAsync(PackageDescriptor package, CancellationToken cancellationToken)
        {
            Packages.Add(package);
            timeline.Add("upload:upload");
            if (Failures.Count > 0)
            {
                throw Failures.Dequeue();
            }
            return Task.CompletedTask;
        }
    }

    private sealed class AdjustableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;

        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan duration) => _now += duration;
    }
}
