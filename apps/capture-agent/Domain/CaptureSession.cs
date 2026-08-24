namespace WorkflowHelper.CaptureAgent.Domain;

public sealed record CaptureSession(
    Guid SessionId,
    string SchemaVersion,
    string MachineId,
    DateTimeOffset StartedAt,
    DateTimeOffset? EndedAt,
    int ActiveDurationSeconds,
    string ApprovedProcess,
    string? WindowFingerprint,
    IReadOnlyList<CadEvent> CadEvents,
    IReadOnlyList<CaptureArtifact>? InputArtifacts = null,
    IReadOnlyList<CaptureArtifact>? OutputArtifacts = null)
{
    public static CaptureSession Start(
        string machineId,
        ApprovedWindowContext context,
        DateTimeOffset startedAt)
    {
        return new CaptureSession(
            Guid.NewGuid(),
            "1.0",
            machineId,
            startedAt,
            null,
            0,
            context.ProcessName,
            context.WindowFingerprint,
            [CadEvent.Create("session_started", startedAt)]);
    }

    public CaptureSession Pause(DateTimeOffset occurredAt) =>
        this with
        {
            CadEvents = CadEvents.Append(CadEvent.Create("session_paused", occurredAt)).ToArray(),
        };

    public CaptureSession Resume(DateTimeOffset occurredAt) =>
        this with
        {
            CadEvents = CadEvents.Append(CadEvent.Create("session_resumed", occurredAt)).ToArray(),
        };

    public CaptureSession Finish(DateTimeOffset endedAt)
    {
        var events = CadEvents.Append(CadEvent.Create("session_ended", endedAt)).ToArray();
        return this with
        {
            EndedAt = endedAt,
            ActiveDurationSeconds = CalculateActiveDurationSeconds(events),
            CadEvents = events,
        };
    }

    private static int CalculateActiveDurationSeconds(IReadOnlyList<CadEvent> events)
    {
        DateTimeOffset? activeSince = null;
        var activeDuration = TimeSpan.Zero;
        foreach (var cadEvent in events)
        {
            if (cadEvent.EventType is "session_started" or "session_resumed")
            {
                activeSince = cadEvent.OccurredAt;
            }
            else if ((cadEvent.EventType is "session_paused" or "session_ended") &&
                activeSince is not null)
            {
                activeDuration += cadEvent.OccurredAt - activeSince.Value;
                activeSince = null;
            }
        }
        return Math.Max(0, (int)activeDuration.TotalSeconds);
    }
}

public sealed record CadEvent(
    Guid EventId,
    DateTimeOffset OccurredAt,
    string EventType,
    string Source,
    string? CommandName,
    string? DrawingRef,
    IReadOnlyDictionary<string, object?> Details)
{
    public static CadEvent Create(string eventType, DateTimeOffset occurredAt) =>
        new(Guid.NewGuid(), occurredAt, eventType, "agent", null, null,
            new Dictionary<string, object?>());
}

public sealed record CaptureArtifact(
    Guid ArtifactId,
    string Kind,
    string FileName,
    string Sha256,
    long SizeBytes,
    string? StorageKey);

public sealed record ApprovedWindowContext(
    int ProcessId,
    string ProcessName,
    string? WindowFingerprint);
