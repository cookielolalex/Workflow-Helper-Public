using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace WorkflowHelper.CaptureAgent.Services;

internal interface IRecordingSourceOpener
{
    FileStream OpenRead(string sourcePath, string outputDirectory, long maxSizeBytes);
}

internal sealed class WindowsRecordingSourceOpener : IRecordingSourceOpener
{
    private const uint GenericRead = 0x80000000;
    private const uint FileShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagSequentialScan = 0x08000000;
    private const uint FileTypeDisk = 0x0001;

    public FileStream OpenRead(
        string sourcePath,
        string outputDirectory,
        long maxSizeBytes)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new InvalidDataException(
                "Recording source validation is only available on Windows.");
        }

        var handle = CreateFile(
            sourcePath,
            GenericRead,
            FileShareRead,
            IntPtr.Zero,
            OpenExisting,
            FileFlagOpenReparsePoint | FileFlagSequentialScan,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new InvalidDataException(
                "Recording file could not be opened safely.",
                new Win32Exception(error));
        }

        try
        {
            if (GetFileType(handle) != FileTypeDisk)
            {
                throw new InvalidDataException("Recording must be a normal disk file.");
            }
            if (!GetFileInformationByHandle(handle, out var information))
            {
                throw WindowsValidationFailure(
                    "Recording handle information could not be verified.");
            }
            if ((information.FileAttributes &
                    (FileAttributes.Directory |
                        FileAttributes.ReparsePoint |
                        FileAttributes.Device)) != 0)
            {
                throw new InvalidDataException("Recording must be a regular file.");
            }
            if (information.NumberOfLinks != 1)
            {
                throw new InvalidDataException(
                    "Recording file must have exactly one filesystem link.");
            }

            var sizeBytes = ((long)information.FileSizeHigh << 32) |
                information.FileSizeLow;
            if (sizeBytes <= 0)
            {
                throw new InvalidDataException("Recording file is empty.");
            }
            if (sizeBytes > maxSizeBytes)
            {
                throw new InvalidDataException(
                    "Recording file exceeds the configured size limit.");
            }

            var requestedPath = Path.GetFullPath(sourcePath);
            var requestedRoot = Path.GetPathRoot(requestedPath) ?? string.Empty;
            if (requestedPath.AsSpan(requestedRoot.Length).Contains(':'))
            {
                throw new InvalidDataException(
                    "Recording must not be an alternate data stream.");
            }
            var finalPath = Path.GetFullPath(GetFinalPath(handle));
            if (!PathEquals(finalPath, requestedPath) ||
                !IsBeneath(finalPath, Path.GetFullPath(outputDirectory)))
            {
                throw new InvalidDataException(
                    "Recording handle resolved outside its approved path.");
            }

            return new FileStream(
                handle,
                FileAccess.Read,
                bufferSize: 81_920,
                isAsync: false);
        }
        catch (InvalidDataException)
        {
            handle.Dispose();
            throw;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or
                ArgumentException or NotSupportedException or OverflowException)
        {
            handle.Dispose();
            throw new InvalidDataException(
                "Recording handle could not be verified.",
                exception);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static string GetFinalPath(SafeFileHandle handle)
    {
        var capacity = 512;
        while (true)
        {
            var buffer = new StringBuilder(capacity);
            var length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
            if (length == 0)
            {
                throw WindowsValidationFailure(
                    "Recording final path could not be verified.");
            }
            if (length < buffer.Capacity)
            {
                return NormalizeExtendedPath(buffer.ToString());
            }
            capacity = checked((int)length + 1);
        }
    }

    private static string NormalizeExtendedPath(string path)
    {
        const string uncPrefix = @"\\?\UNC\";
        const string extendedPrefix = @"\\?\";
        if (path.StartsWith(uncPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return @"\\" + path[uncPrefix.Length..];
        }
        return path.StartsWith(extendedPrefix, StringComparison.OrdinalIgnoreCase)
            ? path[extendedPrefix.Length..]
            : path;
    }

    private static bool IsBeneath(string candidate, string root)
    {
        var prefix = Path.EndsInDirectorySeparator(root)
            ? root
            : root + Path.DirectorySeparatorChar;
        return candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase);
    }

    private static bool PathEquals(string first, string second) =>
        string.Equals(first, second, StringComparison.OrdinalIgnoreCase);

    private static InvalidDataException WindowsValidationFailure(string message) =>
        new(message, new Win32Exception(Marshal.GetLastWin32Error()));

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true,
        CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetFileType(SafeFileHandle file);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

    [DllImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW",
        SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        StringBuilder filePath,
        uint filePathLength,
        uint flags);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public FileAttributes FileAttributes;
        public FILETIME CreationTime;
        public FILETIME LastAccessTime;
        public FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }
}
