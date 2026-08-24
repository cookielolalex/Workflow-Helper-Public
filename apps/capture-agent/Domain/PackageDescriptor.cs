namespace WorkflowHelper.CaptureAgent.Domain;

public sealed record PackageDescriptor(
    Guid SessionId,
    string FilePath,
    string Sha256,
    long SizeBytes,
    CaptureSession Session);
