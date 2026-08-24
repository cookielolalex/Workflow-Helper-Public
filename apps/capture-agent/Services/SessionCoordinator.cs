using Microsoft.Extensions.Options;
using WorkflowHelper.CaptureAgent.Configuration;
using WorkflowHelper.CaptureAgent.Domain;

namespace WorkflowHelper.CaptureAgent.Services;

internal sealed class PendingSessionFinalizationException(
    Guid sessionId,
    Exception innerException) : Exception(
        $"Pending session {sessionId:D} could not be finalized.",
        innerException)
{
    public Guid SessionId { get; } = sessionId;
}

public sealed class SessionCoordinator(
    IApprovedWindowDetector windowDetector,
    ICaptureRecorder recorder,
    ISessionPackageWriter packageWriter,
    ISessionUploadClient uploadClient,
    IOptions<CaptureOptions> options,
    TimeProvider timeProvider,
    ILogger<SessionCoordinator> logger)
{
    private readonly CaptureOptions _options = options.Value;
    private CaptureSession? _activeSession;
    private DateTimeOffset? _lastApprovedForegroundAt;
    private bool _recorderPaused;
    private CaptureSession? _pendingFinishedSession;
    private string? _pendingRecordingPath;
    private PackageDescriptor? _pendingPackage;

    public async Task TickAsync(CancellationToken cancellationToken)
    {
        if (_pendingFinishedSession is not null)
        {
            await FinalizeFromTickAsync(cancellationToken);
        }

        var approvedWindow = windowDetector.GetApprovedForegroundWindow();
        var now = timeProvider.GetUtcNow();
        if (approvedWindow is not null)
        {
            _lastApprovedForegroundAt = now;
            if (_activeSession is null)
            {
                _activeSession = CaptureSession.Start(
                    _options.MachinePseudonym,
                    approvedWindow,
                    now);
                await recorder.StartAsync(_activeSession, cancellationToken);
                logger.LogInformation("Logical CAD session {SessionId} started", _activeSession.SessionId);
            }
            else if (_recorderPaused)
            {
                await recorder.ResumeAsync(cancellationToken);
                _activeSession = _activeSession.Resume(now);
                _recorderPaused = false;
                logger.LogInformation("Logical CAD session {SessionId} resumed", _activeSession.SessionId);
            }
            return;
        }

        if (_activeSession is null || _lastApprovedForegroundAt is null)
        {
            return;
        }
        if (!_recorderPaused)
        {
            await recorder.PauseAsync(cancellationToken);
            _activeSession = _activeSession.Pause(now);
            _recorderPaused = true;
            logger.LogInformation(
                "Logical CAD session {SessionId} paused on approved foreground loss",
                _activeSession.SessionId);
        }
        if (now - _lastApprovedForegroundAt <
            TimeSpan.FromSeconds(_options.ForegroundGraceSeconds))
        {
            return;
        }

        await FinalizeFromTickAsync(cancellationToken);
    }

    private async Task FinalizeFromTickAsync(CancellationToken cancellationToken)
    {
        try
        {
            await FinishActiveSessionAsync(cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (_pendingFinishedSession is not null)
        {
            throw new PendingSessionFinalizationException(
                _pendingFinishedSession!.SessionId,
                exception);
        }
    }

    public async Task FinishActiveSessionAsync(CancellationToken cancellationToken)
    {
        if (_pendingFinishedSession is null)
        {
            if (_activeSession is null)
            {
                return;
            }

            var recordingPath = await recorder.StopAsync(cancellationToken);
            _pendingFinishedSession = _activeSession.Finish(timeProvider.GetUtcNow());
            _pendingRecordingPath = recordingPath;
            _pendingPackage = null;
            _activeSession = null;
            _lastApprovedForegroundAt = null;
            _recorderPaused = false;
        }

        var finishedSession = _pendingFinishedSession ??
            throw new InvalidOperationException("Pending session state was lost.");
        var package = _pendingPackage;
        if (package is null)
        {
            package = await packageWriter.WriteAsync(
                finishedSession,
                _pendingRecordingPath,
                cancellationToken);
            _pendingPackage = package;
        }
        await uploadClient.UploadAsync(package, cancellationToken);

        var completedSessionId = finishedSession.SessionId;
        _pendingFinishedSession = null;
        _pendingRecordingPath = null;
        _pendingPackage = null;
        logger.LogInformation("Logical CAD session {SessionId} packaged", completedSessionId);
    }
}
