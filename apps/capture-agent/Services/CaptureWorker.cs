using Microsoft.Extensions.Options;
using WorkflowHelper.CaptureAgent.Configuration;

namespace WorkflowHelper.CaptureAgent.Services;

public sealed class CaptureWorker : BackgroundService
{
    private const int MaximumPollDelayMilliseconds = 30_000;
    private static readonly TimeSpan DefaultShutdownFinalizationTimeout =
        TimeSpan.FromSeconds(30);

    private readonly SessionCoordinator _coordinator;
    private readonly CaptureOptions _options;
    private readonly ILogger<CaptureWorker> _logger;
    private readonly Func<TimeSpan, CancellationToken, Task> _delayAsync;
    private readonly TimeSpan _shutdownFinalizationTimeout;

    public CaptureWorker(
        SessionCoordinator coordinator,
        IOptions<CaptureOptions> options,
        ILogger<CaptureWorker> logger)
        : this(
            coordinator,
            options,
            logger,
            static (delay, cancellationToken) => Task.Delay(delay, cancellationToken),
            DefaultShutdownFinalizationTimeout)
    {
    }

    internal CaptureWorker(
        SessionCoordinator coordinator,
        IOptions<CaptureOptions> options,
        ILogger<CaptureWorker> logger,
        Func<TimeSpan, CancellationToken, Task> delayAsync,
        TimeSpan shutdownFinalizationTimeout)
    {
        if (shutdownFinalizationTimeout <= TimeSpan.Zero ||
            shutdownFinalizationTimeout == Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(
                nameof(shutdownFinalizationTimeout),
                "Shutdown finalization timeout must be finite and positive.");
        }

        _coordinator = coordinator;
        _options = options.Value;
        _logger = logger;
        _delayAsync = delayAsync;
        _shutdownFinalizationTimeout = shutdownFinalizationTimeout;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.CaptureEnabled || !_options.ConsentAcknowledged)
        {
            _logger.LogWarning(
                "Capture agent is inert: CaptureEnabled and ConsentAcknowledged must both be true");
            return;
        }
        if (string.IsNullOrWhiteSpace(_options.MachinePseudonym) ||
            _options.MachinePseudonym.Length < 8 ||
            _options.MachinePseudonym == "machine-demo-change-me")
        {
            _logger.LogError("A non-default pseudonymous machine ID is required");
            return;
        }

        Exception? primaryError = null;
        try
        {
            var pollDelay = TimeSpan.FromMilliseconds(
                Math.Clamp(
                    _options.PollIntervalMilliseconds,
                    1,
                    MaximumPollDelayMilliseconds));
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await _coordinator.TickAsync(stoppingToken);
                }
                catch (PendingSessionFinalizationException exception)
                {
                    _logger.LogWarning(
                        exception.InnerException ?? exception,
                        "Pending session {SessionId} finalization failed; retrying after {Delay}",
                        exception.SessionId,
                        pollDelay);
                }

                await _delayAsync(pollDelay, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal service shutdown.
        }
        catch (Exception exception)
        {
            primaryError = exception;
            throw;
        }
        finally
        {
            try
            {
                using var finalizationTimeout = new CancellationTokenSource(
                    _shutdownFinalizationTimeout);
                await _coordinator.FinishActiveSessionAsync(finalizationTimeout.Token);
            }
            catch (Exception secondaryError)
            {
                if (primaryError is null)
                {
                    try
                    {
                        _logger.LogError(
                            secondaryError,
                            "Session finalization failed during service shutdown");
                    }
                    catch
                    {
                        // Preserve the shutdown finalization failure over logging.
                    }
                    throw;
                }

                try
                {
                    _logger.LogError(
                        secondaryError,
                        "Session finalization also failed while preserving the primary worker fault");
                }
                catch
                {
                    // A logging provider failure must not replace the primary worker fault.
                }
            }
        }
    }
}
