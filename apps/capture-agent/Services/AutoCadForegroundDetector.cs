using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using WorkflowHelper.CaptureAgent.Configuration;
using WorkflowHelper.CaptureAgent.Domain;

namespace WorkflowHelper.CaptureAgent.Services;

public sealed class AutoCadForegroundDetector(
    IOptions<CaptureOptions> options,
    ILogger<AutoCadForegroundDetector> logger) : IApprovedWindowDetector
{
    private readonly HashSet<string> _approvedProcesses = new(
        options.Value.ApprovedProcessNames,
        StringComparer.OrdinalIgnoreCase);

    public ApprovedWindowContext? GetApprovedForegroundWindow()
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        var windowHandle = GetForegroundWindow();
        if (windowHandle == IntPtr.Zero)
        {
            return null;
        }

        _ = GetWindowThreadProcessId(windowHandle, out var processId);
        try
        {
            using var process = Process.GetProcessById((int)processId);
            if (!_approvedProcesses.Contains(process.ProcessName))
            {
                return null;
            }

            // Persist only a one-way fingerprint; window titles may contain client names or paths.
            var title = process.MainWindowTitle;
            var fingerprint = string.IsNullOrWhiteSpace(title)
                ? null
                : Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(title))).ToLowerInvariant();
            return new ApprovedWindowContext(process.Id, process.ProcessName, fingerprint);
        }
        catch (ArgumentException)
        {
            return null;
        }
        catch (InvalidOperationException exception)
        {
            logger.LogDebug(exception, "Foreground process exited before inspection");
            return null;
        }
    }

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr windowHandle, out uint processId);
}
