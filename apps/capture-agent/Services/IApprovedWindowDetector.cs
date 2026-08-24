using WorkflowHelper.CaptureAgent.Domain;

namespace WorkflowHelper.CaptureAgent.Services;

public interface IApprovedWindowDetector
{
    ApprovedWindowContext? GetApprovedForegroundWindow();
}
