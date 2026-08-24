using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WorkflowHelper.CaptureAgent.Configuration;
using WorkflowHelper.CaptureAgent.Domain;
using WorkflowHelper.CaptureAgent.Services;
using Xunit;

namespace WorkflowHelper.CaptureAgent.Tests;

public sealed class CaptureWorkerTests
{
    private static readonly ApprovedWindowContext ApprovedWindow =
        new(42, "acad", "synthetic-worker-window");

    [Fact]
    public async Task UploadFailureRetriesCachedDescriptorAndLoopContinues()
    {
        var delay = new ControlledDelay(completedCallsBeforeBlocking: 2);
        var fixture = new WorkerFixture(delay.DelayAsync);
        fixture.Detector.Enqueue(ApprovedWindow, null, null);
        fixture.Recorder.StopResult = "synthetic/worker-recording.bin";
        fixture.UploadClient.Failures.Enqueue(
            new HttpRequestException("synthetic upload failure"));
        var worker = fixture.CreateWorker();

        await worker.StartAsync(CancellationToken.None);
        await delay.Blocked.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(3, fixture.Detector.CallCount);
        Assert.Equal(1, fixture.Recorder.StopCount);
        var write = Assert.Single(fixture.PackageWriter.Calls);
        Assert.Equal(fixture.Recorder.StopResult, write.RecordingPath);
        Assert.Single(
            write.Session.CadEvents,
            value => value.EventType == "session_ended");
        Assert.Equal(2, fixture.UploadClient.Packages.Count);
        Assert.Same(
            fixture.UploadClient.Packages[0],
            fixture.UploadClient.Packages[1]);
        Assert.Same(fixture.PackageWriter.WrittenPackage, fixture.UploadClient.Packages[1]);
        Assert.Contains(
            fixture.Logger.Entries,
            entry => entry.Level == LogLevel.Warning &&
                entry.Exception is HttpRequestException);

        await StopWithinAsync(worker);
    }

    [Fact]
    public async Task PackageFailureRebuildsOnlyAndDoesNotStopOrEndAgain()
    {
        var delay = new ControlledDelay(completedCallsBeforeBlocking: 2);
        var fixture = new WorkerFixture(delay.DelayAsync);
        fixture.Detector.Enqueue(ApprovedWindow, null, null);
        fixture.PackageWriter.Failures.Enqueue(
            new InvalidDataException("synthetic package failure"));
        var worker = fixture.CreateWorker();

        await worker.StartAsync(CancellationToken.None);
        await delay.Blocked.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(3, fixture.Detector.CallCount);
        Assert.Equal(1, fixture.Recorder.StopCount);
        Assert.Equal(2, fixture.PackageWriter.Calls.Count);
        Assert.Same(
            fixture.PackageWriter.Calls[0].Session,
            fixture.PackageWriter.Calls[1].Session);
        Assert.All(fixture.PackageWriter.Calls, call => Assert.Single(
            call.Session.CadEvents,
            value => value.EventType == "session_ended"));
        Assert.Single(fixture.UploadClient.Packages);
        Assert.Contains(
            fixture.Logger.Entries,
            entry => entry.Level == LogLevel.Warning &&
                entry.Exception is InvalidDataException);

        await StopWithinAsync(worker);
    }

    [Fact]
    public async Task NextSessionStartsOnlyAfterPendingUploadSucceeds()
    {
        var delay = new ControlledDelay(completedCallsBeforeBlocking: 2);
        var fixture = new WorkerFixture(delay.DelayAsync);
        fixture.Detector.Enqueue(ApprovedWindow, null, ApprovedWindow);
        fixture.UploadClient.Failures.Enqueue(
            new HttpRequestException("synthetic pending upload"));
        var worker = fixture.CreateWorker();

        await worker.StartAsync(CancellationToken.None);
        await delay.Blocked.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(2, fixture.Recorder.StartCount);
        Assert.Equal(
            [
                "detector",
                "recorder:start",
                "delay",
                "detector",
                "recorder:pause",
                "recorder:stop",
                "writer",
                "upload",
                "delay",
                "upload",
                "detector",
                "recorder:start",
                "delay",
            ],
            fixture.Timeline);

        await StopWithinAsync(worker);
    }

    [Fact]
    public async Task RecoveryDelayIsMinimumBoundedAndStoppingCancelsWithoutHang()
    {
        var delay = new ControlledDelay(completedCallsBeforeBlocking: 1);
        var fixture = new WorkerFixture(delay.DelayAsync, pollIntervalMilliseconds: 0);
        fixture.Detector.Enqueue(ApprovedWindow, null);
        fixture.UploadClient.Failures.Enqueue(
            new HttpRequestException("synthetic retry delay"));
        var worker = fixture.CreateWorker();

        await worker.StartAsync(CancellationToken.None);
        await delay.Blocked.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(
            [TimeSpan.FromMilliseconds(1), TimeSpan.FromMilliseconds(1)],
            delay.Delays);
        await StopWithinAsync(worker);
        Assert.Equal(2, fixture.UploadClient.Packages.Count);
        Assert.Same(
            fixture.UploadClient.Packages[0],
            fixture.UploadClient.Packages[1]);
    }

    [Fact]
    public async Task RecoveryDelayIsUpperBoundedForPathologicalPollInterval()
    {
        var delay = new ControlledDelay(completedCallsBeforeBlocking: 1);
        var fixture = new WorkerFixture(
            delay.DelayAsync,
            pollIntervalMilliseconds: int.MaxValue);
        fixture.Detector.Enqueue(ApprovedWindow, null);
        fixture.UploadClient.Failures.Enqueue(
            new HttpRequestException("synthetic upper-bound retry delay"));
        var worker = fixture.CreateWorker();

        await worker.StartAsync(CancellationToken.None);
        await delay.Blocked.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(
            [TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(30)],
            delay.Delays);
        await StopWithinAsync(worker);
        Assert.Equal(2, fixture.UploadClient.Packages.Count);
    }

    [Fact]
    public async Task DetectorFaultPropagatesOutOfWorkerLoop()
    {
        var fixture = new WorkerFixture(static (_, _) => Task.CompletedTask);
        fixture.Detector.Failure = new InvalidOperationException("synthetic detector fault");
        var worker = fixture.CreateWorker();

        var exception = await ObserveFailureAsync<InvalidOperationException>(worker);

        Assert.Equal("synthetic detector fault", exception.Message);
    }

    [Fact]
    public async Task RecorderFaultPropagatesOutOfWorkerLoop()
    {
        var fixture = new WorkerFixture(static (_, _) => Task.CompletedTask);
        fixture.Detector.Enqueue(ApprovedWindow);
        fixture.Recorder.StartFailure = new ArgumentException("synthetic recorder fault");
        var worker = fixture.CreateWorker();

        var exception = await ObserveFailureAsync<ArgumentException>(worker);

        Assert.Equal("synthetic recorder fault", exception.Message);
    }

    [Fact]
    public async Task ProgrammerFaultFromDelayPropagatesOutOfWorkerLoop()
    {
        var fixture = new WorkerFixture(
            static (_, _) => throw new NotSupportedException("synthetic programmer fault"));
        fixture.Detector.Enqueue((ApprovedWindowContext?)null);
        var worker = fixture.CreateWorker();

        var exception = await ObserveFailureAsync<NotSupportedException>(worker);

        Assert.Equal("synthetic programmer fault", exception.Message);
    }

    [Fact]
    public async Task ShutdownFailureIsLoggedWithoutMaskingPrimaryWorkerFault()
    {
        var fixture = new WorkerFixture(
            static (_, _) => throw new InvalidOperationException("synthetic primary fault"));
        fixture.Detector.Enqueue(ApprovedWindow);
        fixture.Recorder.StopFailure = new IOException("synthetic shutdown failure");
        var worker = fixture.CreateWorker();

        var exception = await ObserveFailureAsync<InvalidOperationException>(worker);

        Assert.Equal("synthetic primary fault", exception.Message);
        Assert.Contains(
            fixture.Logger.Entries,
            entry => entry.Level == LogLevel.Error &&
                entry.Exception is IOException shutdown &&
                shutdown.Message == "synthetic shutdown failure" &&
                entry.Message.Contains("preserving the primary worker fault"));
    }

    [Fact]
    public async Task NormalStoppingCancellationCompletesNormally()
    {
        var delay = new ControlledDelay(completedCallsBeforeBlocking: 0);
        var fixture = new WorkerFixture(delay.DelayAsync);
        fixture.Detector.Enqueue((ApprovedWindowContext?)null);
        var worker = fixture.CreateWorker();

        await worker.StartAsync(CancellationToken.None);
        await delay.Blocked.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await StopWithinAsync(worker);

        Assert.DoesNotContain(
            fixture.Logger.Entries,
            entry => entry.Level == LogLevel.Error);
        Assert.True(worker.ExecuteTask?.IsCompletedSuccessfully is true);
    }

    [Fact]
    public async Task ShutdownFailureWithoutPrimaryPropagates()
    {
        var delay = new ControlledDelay(completedCallsBeforeBlocking: 0);
        var fixture = new WorkerFixture(delay.DelayAsync);
        fixture.Detector.Enqueue(ApprovedWindow);
        fixture.Recorder.StopFailure = new IOException("synthetic finalization fault");
        var worker = fixture.CreateWorker();

        await worker.StartAsync(CancellationToken.None);
        await delay.Blocked.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var exception = await StopAndObserveFailureAsync<IOException>(worker);

        Assert.Equal("synthetic finalization fault", exception.Message);
        Assert.Contains(
            fixture.Logger.Entries,
            entry => entry.Level == LogLevel.Error &&
                entry.Exception is IOException);
    }

    private static async Task StopWithinAsync(CaptureWorker worker)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await worker.StopAsync(timeout.Token);
        if (worker.ExecuteTask is not null)
        {
            await worker.ExecuteTask.WaitAsync(timeout.Token);
        }
    }

    private static async Task<TException> ObserveFailureAsync<TException>(
        CaptureWorker worker) where TException : Exception
    {
        var startError = await Record.ExceptionAsync(
            () => worker.StartAsync(CancellationToken.None));
        if (startError is not null)
        {
            return Assert.IsType<TException>(startError);
        }

        var task = Assert.IsAssignableFrom<Task>(worker.ExecuteTask);
        return await Assert.ThrowsAsync<TException>(
            () => task.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    private static async Task<TException> StopAndObserveFailureAsync<TException>(
        CaptureWorker worker) where TException : Exception
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var stopError = await Record.ExceptionAsync(() => worker.StopAsync(timeout.Token));
        if (stopError is not null)
        {
            return Assert.IsType<TException>(stopError);
        }

        var task = Assert.IsAssignableFrom<Task>(worker.ExecuteTask);
        return await Assert.ThrowsAsync<TException>(() => task.WaitAsync(timeout.Token));
    }

    private sealed class WorkerFixture
    {
        public WorkerFixture(
            Func<TimeSpan, CancellationToken, Task> delayAsync,
            int pollIntervalMilliseconds = 7)
        {
            Timeline = [];
            Detector = new SequenceDetector(Timeline);
            Recorder = new RecorderSpy(Timeline);
            PackageWriter = new PackageWriterSpy(Timeline);
            UploadClient = new UploadClientSpy(Timeline);
            Logger = new ListLogger<CaptureWorker>();
            DelayAsync = async (delay, cancellationToken) =>
            {
                Timeline.Add("delay");
                await delayAsync(delay, cancellationToken);
            };
            Options = Microsoft.Extensions.Options.Options.Create(new CaptureOptions
            {
                CaptureEnabled = true,
                ConsentAcknowledged = true,
                MachinePseudonym = "machine-synthetic-worker",
                PollIntervalMilliseconds = pollIntervalMilliseconds,
                ForegroundGraceSeconds = 0,
            });
            Coordinator = new SessionCoordinator(
                Detector,
                Recorder,
                PackageWriter,
                UploadClient,
                Options,
                new FixedTimeProvider(DateTimeOffset.Parse("2026-08-17T04:00:00Z")),
                new ListLogger<SessionCoordinator>());
        }

        public List<string> Timeline { get; }
        public SequenceDetector Detector { get; }
        public RecorderSpy Recorder { get; }
        public PackageWriterSpy PackageWriter { get; }
        public UploadClientSpy UploadClient { get; }
        public ListLogger<CaptureWorker> Logger { get; }
        public Func<TimeSpan, CancellationToken, Task> DelayAsync { get; }
        public IOptions<CaptureOptions> Options { get; }
        public SessionCoordinator Coordinator { get; }

        public CaptureWorker CreateWorker() => new(
            Coordinator,
            Options,
            Logger,
            DelayAsync,
            TimeSpan.FromSeconds(1));
    }

    private sealed class SequenceDetector(List<string> timeline) : IApprovedWindowDetector
    {
        private readonly Queue<ApprovedWindowContext?> _values = [];

        public Exception? Failure { get; set; }
        public int CallCount { get; private set; }

        public void Enqueue(params ApprovedWindowContext?[] values)
        {
            foreach (var value in values)
            {
                _values.Enqueue(value);
            }
        }

        public ApprovedWindowContext? GetApprovedForegroundWindow()
        {
            timeline.Add("detector");
            CallCount++;
            if (Failure is not null)
            {
                throw Failure;
            }
            return _values.Count == 0 ? null : _values.Dequeue();
        }
    }

    private sealed class RecorderSpy(List<string> timeline) : ICaptureRecorder
    {
        public Exception? StartFailure { get; set; }
        public Exception? StopFailure { get; set; }
        public string? StopResult { get; set; }
        public int StartCount { get; private set; }
        public int StopCount { get; private set; }

        public Task StartAsync(CaptureSession session, CancellationToken cancellationToken)
        {
            timeline.Add("recorder:start");
            StartCount++;
            return StartFailure is null
                ? Task.CompletedTask
                : Task.FromException(StartFailure);
        }

        public Task PauseAsync(CancellationToken cancellationToken)
        {
            timeline.Add("recorder:pause");
            return Task.CompletedTask;
        }

        public Task ResumeAsync(CancellationToken cancellationToken)
        {
            timeline.Add("recorder:resume");
            return Task.CompletedTask;
        }

        public Task<string?> StopAsync(CancellationToken cancellationToken)
        {
            timeline.Add("recorder:stop");
            StopCount++;
            return StopFailure is null
                ? Task.FromResult(StopResult)
                : Task.FromException<string?>(StopFailure);
        }
    }

    private sealed class PackageWriterSpy(List<string> timeline) : ISessionPackageWriter
    {
        public Queue<Exception> Failures { get; } = [];
        public List<(CaptureSession Session, string? RecordingPath)> Calls { get; } = [];
        public PackageDescriptor? WrittenPackage { get; private set; }

        public Task<PackageDescriptor> WriteAsync(
            CaptureSession session,
            string? recordingPath,
            CancellationToken cancellationToken)
        {
            timeline.Add("writer");
            Calls.Add((session, recordingPath));
            if (Failures.Count > 0)
            {
                return Task.FromException<PackageDescriptor>(Failures.Dequeue());
            }
            var package = new PackageDescriptor(
                session.SessionId,
                "synthetic-worker-package.zip",
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

        public Task UploadAsync(PackageDescriptor package, CancellationToken cancellationToken)
        {
            timeline.Add("upload");
            Packages.Add(package);
            return Failures.Count == 0
                ? Task.CompletedTask
                : Task.FromException(Failures.Dequeue());
        }
    }

    private sealed class ControlledDelay(int completedCallsBeforeBlocking)
    {
        public List<TimeSpan> Delays { get; } = [];
        public TaskCompletionSource<bool> Blocked { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            Delays.Add(delay);
            if (Delays.Count <= completedCallsBeforeBlocking)
            {
                return Task.CompletedTask;
            }
            Blocked.TrySetResult(true);
            return Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class ListLogger<T> : ILogger<T>
    {
        public List<LogEntry> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Entries.Add(new LogEntry(logLevel, exception, formatter(state, exception)));
        }
    }

    private sealed record LogEntry(LogLevel Level, Exception? Exception, string Message);
}
