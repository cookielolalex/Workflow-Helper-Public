using WorkflowHelper.CaptureAgent.Domain;

namespace WorkflowHelper.CaptureAgent.Services;

public interface ICaptureRecorder
{
    Task StartAsync(CaptureSession session, CancellationToken cancellationToken);
    Task PauseAsync(CancellationToken cancellationToken);
    Task ResumeAsync(CancellationToken cancellationToken);
    Task<string?> StopAsync(CancellationToken cancellationToken);
}

public sealed class DisabledCaptureRecorder(
    ILogger<DisabledCaptureRecorder> logger) : ICaptureRecorder
{
    public Task StartAsync(CaptureSession session, CancellationToken cancellationToken)
    {
        logger.LogInformation(
            "Session {SessionId} started with recording disabled by the scaffold safety default",
            session.SessionId);
        return Task.CompletedTask;
    }

    public Task PauseAsync(CancellationToken cancellationToken)
    {
        logger.LogInformation("Logical session paused; real recording remains disabled");
        return Task.CompletedTask;
    }

    public Task ResumeAsync(CancellationToken cancellationToken)
    {
        logger.LogInformation("Logical session resumed; real recording remains disabled");
        return Task.CompletedTask;
    }

    public Task<string?> StopAsync(CancellationToken cancellationToken) =>
        Task.FromResult<string?>(null);
}
