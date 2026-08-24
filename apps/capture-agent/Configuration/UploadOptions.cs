namespace WorkflowHelper.CaptureAgent.Configuration;

public sealed class UploadOptions
{
    public const string SectionName = "Upload";

    public Uri ApiBaseUrl { get; init; } = new("http://localhost:8000");
    public bool Enabled { get; init; }
    public long MaxPackageSizeBytes { get; init; } = 512L * 1024 * 1024;
}
