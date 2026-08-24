using System.IO.Compression;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using WorkflowHelper.CaptureAgent.Configuration;
using WorkflowHelper.CaptureAgent.Domain;

namespace WorkflowHelper.CaptureAgent.Services;

public interface ISessionPackageWriter
{
    Task<PackageDescriptor> WriteAsync(
        CaptureSession session,
        string? recordingPath,
        CancellationToken cancellationToken);
}

public sealed class SessionPackageWriter : ISessionPackageWriter
{
    private const int BufferSize = 81_920;
    private const string RecordingFileName = "recording.bin";
    private const string RecordingPackagePath = "recordings/recording.bin";

    private static readonly DateTimeOffset ZipTimestamp =
        new(1980, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly Encoding Utf8WithoutBom = new UTF8Encoding(false);
    private static readonly JsonSerializerOptions MetadataJsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = true,
    };
    private static readonly JsonSerializerOptions EventJsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = false,
    };

    private readonly string _outputDirectory;
    private readonly long _maxRecordingSizeBytes;
    private readonly IRecordingSourceOpener _recordingSourceOpener;

    public SessionPackageWriter(IOptions<CaptureOptions> options)
        : this(options, new WindowsRecordingSourceOpener())
    {
    }

    internal SessionPackageWriter(
        IOptions<CaptureOptions> options,
        IRecordingSourceOpener recordingSourceOpener)
    {
        _outputDirectory = Path.GetFullPath(options.Value.OutputDirectory);
        _maxRecordingSizeBytes = options.Value.MaxRecordingSizeBytes;
        _recordingSourceOpener = recordingSourceOpener;
    }

    public async Task<PackageDescriptor> WriteAsync(
        CaptureSession session,
        string? recordingPath,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(_outputDirectory);

        var attemptId = Guid.NewGuid().ToString("N");
        var packagePath = Path.Combine(_outputDirectory, $"{session.SessionId:D}.zip");
        var temporaryPackage = Path.Combine(
            _outputDirectory,
            $".{session.SessionId:D}.{attemptId}.zip.tmp");
        string? workDirectory = null;
        FileStream? source = null;
        FileStream? stagedRecording = null;
        Exception? primaryError = null;

        try
        {
            object? recording = null;
            if (recordingPath is not null)
            {
                var sourcePath = ValidateRecordingSourcePath(recordingPath);
                source = _recordingSourceOpener.OpenRead(
                    sourcePath,
                    _outputDirectory,
                    _maxRecordingSizeBytes);
                EnsureNoReparsePoints(sourcePath, expectFile: true);
                ValidateOpenedSource(source);

                workDirectory = Path.Combine(
                    _outputDirectory,
                    $".{session.SessionId:D}.{attemptId}.work");
                Directory.CreateDirectory(workDirectory);
                var stagedPath = Path.Combine(
                    workDirectory,
                    "recordings",
                    RecordingFileName);
                stagedRecording = await StageRecordingAsync(
                    source,
                    stagedPath,
                    cancellationToken);
                var recordingDescriptor = await DescribeStagedRecordingAsync(
                    stagedRecording,
                    cancellationToken);
                recording = new
                {
                    artifact_id = CreateRecordingArtifactId(
                        session.SessionId,
                        recordingDescriptor.Sha256),
                    kind = "recording",
                    file_name = RecordingFileName,
                    sha256 = recordingDescriptor.Sha256,
                    size_bytes = recordingDescriptor.SizeBytes,
                    storage_key = RecordingPackagePath,
                };
            }

            var metadata = new
            {
                schema_version = session.SchemaVersion,
                session_id = session.SessionId,
                machine_id = session.MachineId,
                project_id = (string?)null,
                started_at = session.StartedAt,
                ended_at = session.EndedAt,
                active_duration_seconds = session.ActiveDurationSeconds,
                approved_process = session.ApprovedProcess,
                drawing_files = Array.Empty<object>(),
                input_artifacts = Array.Empty<object>(),
                output_artifacts = Array.Empty<object>(),
                recording,
                cad_events = session.CadEvents,
                idle_intervals = Array.Empty<object>(),
                processing_status = "local",
                review_status = "not_ready",
                labels = Array.Empty<object>(),
                skills = Array.Empty<string>(),
                raw_expires_at = (DateTimeOffset?)null,
            };
            var metadataBytes = Utf8WithoutBom.GetBytes(WithFinalLf(
                JsonSerializer.Serialize(metadata, MetadataJsonOptions)));
            var eventBytes = Utf8WithoutBom.GetBytes(WithFinalLf(string.Join(
                "\n",
                session.CadEvents.Select(value =>
                    JsonSerializer.Serialize(value, EventJsonOptions)))));

            var packageIdentity = await CreatePackageAsync(
                temporaryPackage,
                metadataBytes,
                eventBytes,
                stagedRecording,
                cancellationToken);
            File.Move(temporaryPackage, packagePath, overwrite: true);
            return new PackageDescriptor(
                session.SessionId,
                packagePath,
                packageIdentity.Sha256,
                packageIdentity.SizeBytes,
                session);
        }
        catch (Exception exception)
        {
            primaryError = exception;
            throw;
        }
        finally
        {
            Exception? cleanupError = null;
            cleanupError = await DisposeCapturingAsync(stagedRecording, cleanupError);
            cleanupError = await DisposeCapturingAsync(source, cleanupError);
            cleanupError = DeleteFileCapturing(temporaryPackage, cleanupError);
            if (workDirectory is not null)
            {
                cleanupError = DeleteDirectoryCapturing(workDirectory, cleanupError);
            }
            if (primaryError is null && cleanupError is not null)
            {
                ExceptionDispatchInfo.Capture(cleanupError).Throw();
            }
        }
    }

    private string ValidateRecordingSourcePath(string recordingPath)
    {
        if (_maxRecordingSizeBytes <= 0)
        {
            throw new InvalidDataException(
                $"{nameof(CaptureOptions.MaxRecordingSizeBytes)} must be greater than zero.");
        }
        if (string.IsNullOrWhiteSpace(recordingPath))
        {
            throw new InvalidDataException("Recording path is empty.");
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(recordingPath);
        }
        catch (Exception exception) when (
            exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new InvalidDataException("Recording path is invalid.", exception);
        }

        var outputPrefix = Path.EndsInDirectorySeparator(_outputDirectory)
            ? _outputDirectory
            : _outputDirectory + Path.DirectorySeparatorChar;
        var comparison = OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
        if (!fullPath.StartsWith(outputPrefix, comparison))
        {
            throw new InvalidDataException(
                "Recording must be beneath the configured output directory.");
        }

        EnsureNoReparsePoints(fullPath, expectFile: true);
        return fullPath;
    }

    private void ValidateOpenedSource(FileStream source)
    {
        long length;
        try
        {
            length = source.Length;
        }
        catch (Exception exception) when (
            exception is IOException or NotSupportedException or ObjectDisposedException)
        {
            throw new InvalidDataException(
                "Recording handle length could not be verified.",
                exception);
        }
        if (length <= 0)
        {
            throw new InvalidDataException("Recording file is empty.");
        }
        if (length > _maxRecordingSizeBytes)
        {
            throw new InvalidDataException("Recording file exceeds the configured size limit.");
        }
    }

    private async Task<FileStream> StageRecordingAsync(
        FileStream source,
        string destinationPath,
        CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(destinationPath)!);
        var destination = new FileStream(
            destinationPath,
            new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.ReadWrite,
                Share = FileShare.None,
                BufferSize = BufferSize,
                Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
            });
        try
        {
            source.Position = 0;
            var expectedLength = source.Length;
            var buffer = new byte[BufferSize];
            long totalBytes = 0;
            while (true)
            {
                var bytesRead = await source.ReadAsync(buffer, cancellationToken);
                if (bytesRead == 0)
                {
                    break;
                }
                if (totalBytes > _maxRecordingSizeBytes - bytesRead)
                {
                    throw new InvalidDataException(
                        "Recording file exceeds the configured size limit.");
                }
                await destination.WriteAsync(
                    buffer.AsMemory(0, bytesRead),
                    cancellationToken);
                totalBytes += bytesRead;
            }
            await destination.FlushAsync(cancellationToken);
            if (totalBytes != expectedLength || source.Length != expectedLength)
            {
                throw new InvalidDataException("Recording file changed while staging.");
            }
            destination.Position = 0;
            return destination;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            try
            {
                await destination.DisposeAsync();
            }
            catch
            {
                // Preserve the source or staging failure as the primary error.
            }
            throw new InvalidDataException("Recording file could not be staged.", exception);
        }
        catch
        {
            try
            {
                await destination.DisposeAsync();
            }
            catch
            {
                // Preserve the staging or cancellation failure as the primary error.
            }
            throw;
        }
    }

    private static async Task<RecordingDescriptor> DescribeStagedRecordingAsync(
        FileStream staged,
        CancellationToken cancellationToken)
    {
        staged.Position = 0;
        var sha256 = Convert.ToHexString(
                await SHA256.HashDataAsync(staged, cancellationToken))
            .ToLowerInvariant();
        var sizeBytes = staged.Length;
        staged.Position = 0;
        return new RecordingDescriptor(sha256, sizeBytes);
    }

    private static async Task<PackageIdentity> CreatePackageAsync(
        string destinationPath,
        byte[] metadata,
        byte[] events,
        FileStream? stagedRecording,
        CancellationToken cancellationToken)
    {
        FileStream? destination = null;
        Exception? primaryError = null;
        try
        {
            destination = new FileStream(
                destinationPath,
                new FileStreamOptions
                {
                    Mode = FileMode.CreateNew,
                    Access = FileAccess.ReadWrite,
                    Share = FileShare.Read,
                    BufferSize = BufferSize,
                    Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
                });
            var archive = new ZipArchive(
                destination,
                ZipArchiveMode.Create,
                leaveOpen: true,
                entryNameEncoding: Encoding.UTF8);
            Exception? archiveError = null;
            try
            {
                await WriteBytesEntryAsync(
                    archive,
                    "metadata.json",
                    metadata,
                    cancellationToken);
                await WriteBytesEntryAsync(
                    archive,
                    "events.jsonl",
                    events,
                    cancellationToken);
                if (stagedRecording is not null)
                {
                    stagedRecording.Position = 0;
                    await WriteStreamEntryAsync(
                        archive,
                        RecordingPackagePath,
                        stagedRecording,
                        cancellationToken);
                    stagedRecording.Position = 0;
                }
            }
            catch (Exception exception)
            {
                archiveError = exception;
                throw;
            }
            finally
            {
                try
                {
                    archive.Dispose();
                }
                catch when (archiveError is not null)
                {
                    // Preserve a write or cancellation failure over archive finalization.
                }
            }

            await destination.FlushAsync(cancellationToken);
            destination.Position = 0;
            var sha256 = Convert.ToHexString(
                    await SHA256.HashDataAsync(destination, cancellationToken))
                .ToLowerInvariant();
            return new PackageIdentity(sha256, destination.Length);
        }
        catch (Exception exception)
        {
            primaryError = exception;
            throw;
        }
        finally
        {
            if (destination is not null)
            {
                try
                {
                    await destination.DisposeAsync();
                }
                catch when (primaryError is not null)
                {
                    // Preserve the package creation or cancellation failure.
                }
            }
        }
    }

    private static async Task WriteBytesEntryAsync(
        ZipArchive archive,
        string name,
        ReadOnlyMemory<byte> contents,
        CancellationToken cancellationToken)
    {
        var entry = CreateDeterministicEntry(archive, name);
        var stream = entry.Open();
        Exception? primaryError = null;
        try
        {
            await stream.WriteAsync(contents, cancellationToken);
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
                await stream.DisposeAsync();
            }
            catch when (primaryError is not null)
            {
                // Preserve the entry write or cancellation failure.
            }
        }
    }

    private static async Task WriteStreamEntryAsync(
        ZipArchive archive,
        string name,
        Stream contents,
        CancellationToken cancellationToken)
    {
        var entry = CreateDeterministicEntry(archive, name);
        var stream = entry.Open();
        Exception? primaryError = null;
        try
        {
            await contents.CopyToAsync(stream, BufferSize, cancellationToken);
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
                await stream.DisposeAsync();
            }
            catch when (primaryError is not null)
            {
                // Preserve the entry copy or cancellation failure.
            }
        }
    }

    private static ZipArchiveEntry CreateDeterministicEntry(
        ZipArchive archive,
        string name)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.NoCompression);
        entry.LastWriteTime = ZipTimestamp;
        entry.ExternalAttributes = 0;
        return entry;
    }

    private static string WithFinalLf(string value)
    {
        var normalized = value.Replace("\r\n", "\n", StringComparison.Ordinal)
            .Replace('\r', '\n');
        return normalized.EndsWith('\n') ? normalized : normalized + '\n';
    }

    private static void EnsureNoReparsePoints(string fullPath, bool expectFile)
    {
        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrEmpty(root))
        {
            throw new InvalidDataException("Recording path has no filesystem root.");
        }

        var components = fullPath[root.Length..].Split(
            [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
            StringSplitOptions.RemoveEmptyEntries);
        var current = root;
        for (var index = 0; index < components.Length; index++)
        {
            current = Path.Combine(current, components[index]);
            try
            {
                var attributes = File.GetAttributes(current);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    throw new InvalidDataException(
                        "Recording path contains a reparse point or symbolic link.");
                }

                var isLast = index == components.Length - 1;
                if ((!isLast || !expectFile) &&
                    (attributes & FileAttributes.Directory) == 0)
                {
                    throw new InvalidDataException(
                        "Recording path contains a non-directory component.");
                }

                FileSystemInfo pathInfo = isLast && expectFile
                    ? new FileInfo(current)
                    : new DirectoryInfo(current);
                if (pathInfo.LinkTarget is not null)
                {
                    throw new InvalidDataException(
                        "Recording path contains a reparse point or symbolic link.");
                }
            }
            catch (InvalidDataException)
            {
                throw;
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException)
            {
                throw new InvalidDataException(
                    "Recording path components could not be verified.",
                    exception);
            }
        }
    }

    private static Guid CreateRecordingArtifactId(Guid sessionId, string recordingSha256)
    {
        var identityBytes = Encoding.UTF8.GetBytes($"{sessionId:D}:{recordingSha256}");
        var uuidCharacters = Convert.ToHexString(
                SHA256.HashData(identityBytes).AsSpan(0, 16))
            .ToLowerInvariant()
            .ToCharArray();
        uuidCharacters[12] = '8';
        uuidCharacters[16] = '8';
        var hexadecimalId = new string(uuidCharacters);
        return Guid.ParseExact(
            $"{hexadecimalId[..8]}-{hexadecimalId[8..12]}-" +
            $"{hexadecimalId[12..16]}-{hexadecimalId[16..20]}-" +
            hexadecimalId[20..],
            "D");
    }

    private static async Task<Exception?> DisposeCapturingAsync(
        FileStream? stream,
        Exception? existingError)
    {
        if (stream is null)
        {
            return existingError;
        }
        try
        {
            await stream.DisposeAsync();
        }
        catch (Exception exception)
        {
            return existingError ?? exception;
        }
        return existingError;
    }

    private static Exception? DeleteFileCapturing(string path, Exception? existingError)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception exception)
        {
            return existingError ?? exception;
        }
        return existingError;
    }

    private static Exception? DeleteDirectoryCapturing(string path, Exception? existingError)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (Exception exception)
        {
            return existingError ?? exception;
        }
        return existingError;
    }

    private sealed record RecordingDescriptor(string Sha256, long SizeBytes);
    private sealed record PackageIdentity(string Sha256, long SizeBytes);
}
