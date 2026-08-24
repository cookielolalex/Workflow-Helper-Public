namespace WorkflowHelper.CaptureAgent.Configuration;

public sealed class CaptureOptions
{
    public const string SectionName = "Capture";

    public bool CaptureEnabled { get; init; }
    public bool ConsentAcknowledged { get; init; }
    public string[] ApprovedProcessNames { get; init; } = ["acad"];
    public string MachinePseudonym { get; init; } = string.Empty;
    public int PollIntervalMilliseconds { get; init; } = 1_000;
    public int ForegroundGraceSeconds { get; init; } = 5;
    public string OutputDirectory { get; init; } = "capture-data";
    public long MaxRecordingSizeBytes { get; init; } = 256L * 1024 * 1024;
}
