using System.ComponentModel;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using WorkflowHelper.CaptureAgent.Configuration;
using WorkflowHelper.CaptureAgent.Domain;
using WorkflowHelper.CaptureAgent.Services;
using Xunit;

namespace WorkflowHelper.CaptureAgent.Tests;

public sealed class SessionPackageWriterTests
{
    private static readonly byte[] SyntheticRecording =
        Encoding.UTF8.GetBytes("generated-synthetic-recording-v1");

    [Fact]
    public async Task NullRecordingProducesMetadataNullAndNoRecordingEntry()
    {
        using var fixture = new PackageWriterFixture();

        var package = await fixture.Writer.WriteAsync(
            SyntheticSession(),
            null,
            CancellationToken.None);

        using var archive = ZipFile.OpenRead(package.FilePath);
        Assert.Equal(
            ["events.jsonl", "metadata.json"],
            archive.Entries.Select(value => value.FullName).OrderBy(value => value));
        using var metadata = await ReadMetadataAsync(archive);
        Assert.Equal(JsonValueKind.Null, metadata.RootElement.GetProperty("recording").ValueKind);
    }

    [Fact]
    public async Task NullRecordingIgnoresDisabledRecordingSizeLimit()
    {
        using var fixture = new PackageWriterFixture(maxRecordingSizeBytes: 0);

        var package = await fixture.Writer.WriteAsync(
            SyntheticSession(),
            null,
            CancellationToken.None);

        using var archive = ZipFile.OpenRead(package.FilePath);
        using var metadata = await ReadMetadataAsync(archive);
        Assert.Equal(JsonValueKind.Null, metadata.RootElement.GetProperty("recording").ValueKind);
    }

    [Fact]
    public async Task RecordingEntryAndMetadataExactlyDescribeSyntheticBytes()
    {
        using var fixture = new PackageWriterFixture();
        var sourcePath = fixture.WriteRecording(
            Path.Combine("recorder", "private-looking-source.synthetic"),
            SyntheticRecording);
        var expectedHash = Convert.ToHexString(SHA256.HashData(SyntheticRecording))
            .ToLowerInvariant();

        var package = await fixture.Writer.WriteAsync(
            SyntheticSession(),
            sourcePath,
            CancellationToken.None);

        using var archive = ZipFile.OpenRead(package.FilePath);
        Assert.Equal(
            ["events.jsonl", "metadata.json", "recordings/recording.bin"],
            archive.Entries.Select(value => value.FullName).OrderBy(value => value));
        var recordingEntry = Assert.Single(
            archive.Entries,
            value => value.FullName == "recordings/recording.bin");
        await using (var stream = recordingEntry.Open())
        using (var memory = new MemoryStream())
        {
            await stream.CopyToAsync(memory);
            Assert.Equal(SyntheticRecording, memory.ToArray());
        }

        using var metadata = await ReadMetadataAsync(archive);
        var recording = metadata.RootElement.GetProperty("recording");
        Assert.Equal(
            ["artifact_id", "file_name", "kind", "sha256", "size_bytes", "storage_key"],
            recording.EnumerateObject()
                .Select(value => value.Name)
                .OrderBy(value => value));
        Assert.Equal("recording", recording.GetProperty("kind").GetString());
        Assert.Equal("recording.bin", recording.GetProperty("file_name").GetString());
        Assert.Equal(expectedHash, recording.GetProperty("sha256").GetString());
        Assert.Matches("^[a-f0-9]{64}$", recording.GetProperty("sha256").GetString()!);
        Assert.Equal(SyntheticRecording.LongLength, recording.GetProperty("size_bytes").GetInt64());
        Assert.Equal(
            "recordings/recording.bin",
            recording.GetProperty("storage_key").GetString());
        Assert.True(Guid.TryParse(recording.GetProperty("artifact_id").GetString(), out _));
        Assert.DoesNotContain("private-looking", await ReadEntryTextAsync(archive, "metadata.json"));
    }

    [Fact]
    public async Task NonNullMetadataSatisfiesCheckedInSessionContract()
    {
        using var fixture = new PackageWriterFixture();
        var sourcePath = fixture.WriteRecording("contract.synthetic", SyntheticRecording);
        var package = await fixture.Writer.WriteAsync(
            SyntheticSession(),
            sourcePath,
            CancellationToken.None);

        using var archive = ZipFile.OpenRead(package.FilePath);
        using var metadata = await ReadMetadataAsync(archive);
        var contractPath = ContractBackedMetadataAssertions.FindContract(
            "contracts/session.schema.json");

        ContractBackedMetadataAssertions.AssertValid(metadata.RootElement, contractPath);
    }

    [Fact]
    public async Task ArtifactIdentityIsDeterministicForSameSessionAndBytes()
    {
        var session = SyntheticSession();
        string firstArtifactId;
        string secondArtifactId;
        using (var first = new PackageWriterFixture())
        {
            var path = first.WriteRecording("first.synthetic", SyntheticRecording);
            var package = await first.Writer.WriteAsync(session, path, CancellationToken.None);
            using var archive = ZipFile.OpenRead(package.FilePath);
            using var metadata = await ReadMetadataAsync(archive);
            firstArtifactId = metadata.RootElement.GetProperty("recording")
                .GetProperty("artifact_id").GetString()!;
        }
        using (var second = new PackageWriterFixture())
        {
            var path = second.WriteRecording(
                Path.Combine("different", "name.synthetic"),
                SyntheticRecording);
            var package = await second.Writer.WriteAsync(session, path, CancellationToken.None);
            using var archive = ZipFile.OpenRead(package.FilePath);
            using var metadata = await ReadMetadataAsync(archive);
            secondArtifactId = metadata.RootElement.GetProperty("recording")
                .GetProperty("artifact_id").GetString()!;
        }

        Assert.Equal(firstArtifactId, secondArtifactId);
        Assert.True(Guid.TryParse(firstArtifactId, out _));
        Assert.Equal('8', firstArtifactId[14]);
        Assert.Contains(firstArtifactId[19], "89ab");
    }

    [Fact]
    public async Task CompleteZipIsByteIdenticalAcrossDelayAndDistinctOutputRoots()
    {
        var session = SyntheticSession();
        var fixedSourceTime = DateTime.Parse(
            "2026-08-16T04:00:00Z",
            null,
            System.Globalization.DateTimeStyles.AdjustToUniversal);
        byte[] firstZip;
        byte[] firstMetadata;
        byte[] firstRecording;
        PackageDescriptor firstPackage;
        using (var first = new PackageWriterFixture())
        {
            var path = first.WriteRecording("first-source.synthetic", SyntheticRecording);
            File.SetLastWriteTimeUtc(path, fixedSourceTime);
            firstPackage = await first.Writer.WriteAsync(session, path, CancellationToken.None);
            firstZip = await File.ReadAllBytesAsync(firstPackage.FilePath);
            using var archive = ZipFile.OpenRead(firstPackage.FilePath);
            Assert.Equal(
                ["metadata.json", "events.jsonl", "recordings/recording.bin"],
                archive.Entries.Select(value => value.FullName));
            firstMetadata = await ReadEntryBytesAsync(archive, "metadata.json");
            firstRecording = await ReadEntryBytesAsync(archive, "recordings/recording.bin");
        }

        await Task.Delay(TimeSpan.FromMilliseconds(2200));

        using var second = new PackageWriterFixture();
        var secondPath = second.WriteRecording(
            Path.Combine("different", "second-source.synthetic"),
            SyntheticRecording);
        File.SetLastWriteTimeUtc(secondPath, fixedSourceTime);
        var secondPackage = await second.Writer.WriteAsync(
            session,
            secondPath,
            CancellationToken.None);
        var secondZip = await File.ReadAllBytesAsync(secondPackage.FilePath);
        using var secondArchive = ZipFile.OpenRead(secondPackage.FilePath);

        Assert.Equal(firstZip, secondZip);
        Assert.Equal(firstPackage.Sha256, secondPackage.Sha256);
        Assert.Equal(firstPackage.SizeBytes, secondPackage.SizeBytes);
        Assert.Equal(firstMetadata, await ReadEntryBytesAsync(secondArchive, "metadata.json"));
        Assert.Equal(
            firstRecording,
            await ReadEntryBytesAsync(secondArchive, "recordings/recording.bin"));
    }

    [Fact]
    public async Task OutsideRootRecordingIsRejected()
    {
        using var fixture = new PackageWriterFixture();
        var outsideDirectory = Path.Combine(
            Path.GetTempPath(),
            $"workflow-helper-outside-{Guid.NewGuid():N}");
        Directory.CreateDirectory(outsideDirectory);
        var outsidePath = Path.Combine(outsideDirectory, "outside.synthetic");
        await File.WriteAllBytesAsync(outsidePath, SyntheticRecording);
        try
        {
            await AssertWriteFailsAsync(fixture.Writer, outsidePath);
        }
        finally
        {
            Directory.Delete(outsideDirectory, true);
        }
    }

    [Fact]
    public async Task TraversalThatResolvesOutsideRootIsRejected()
    {
        using var fixture = new PackageWriterFixture();
        var outsidePath = Path.Combine(
            Path.GetDirectoryName(fixture.OutputDirectory)!,
            $"outside-{Guid.NewGuid():N}.synthetic");
        await File.WriteAllBytesAsync(outsidePath, SyntheticRecording);
        var traversalPath = Path.Combine(
            fixture.OutputDirectory,
            "inside",
            "..",
            "..",
            Path.GetFileName(outsidePath));
        try
        {
            await AssertWriteFailsAsync(fixture.Writer, traversalPath);
        }
        finally
        {
            File.Delete(outsidePath);
        }
    }

    [WindowsHardLinkFact]
    public async Task WindowsSameVolumeOutsideFileAndInsideHardLinkAreRejected()
    {
        using var fixture = new PackageWriterFixture();
        var outsidePath = Path.Combine(
            Path.GetDirectoryName(fixture.OutputDirectory)!,
            $"outside-hard-link-{Guid.NewGuid():N}.synthetic");
        await File.WriteAllBytesAsync(outsidePath, SyntheticRecording);
        var insideLink = Path.Combine(fixture.OutputDirectory, "inside-hard-link.synthetic");
        try
        {
            await AssertWriteFailsAsync(fixture.Writer, outsidePath);
            if (!NativeMethods.CreateHardLink(insideLink, outsidePath, IntPtr.Zero))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "Windows same-volume hard-link primitive is unavailable.");
            }

            await AssertWriteFailsAsync(fixture.Writer, insideLink);
            Assert.Empty(Directory.EnumerateFiles(fixture.OutputDirectory, "*.zip"));
            Assert.Empty(Directory.EnumerateFiles(fixture.OutputDirectory, "*.tmp"));
            Assert.Empty(Directory.EnumerateDirectories(fixture.OutputDirectory, ".*.work"));
        }
        finally
        {
            File.Delete(outsidePath);
        }
    }

    [Fact]
    public async Task MissingRecordingIsRejected()
    {
        using var fixture = new PackageWriterFixture();
        var missingPath = Path.Combine(fixture.OutputDirectory, "missing.synthetic");

        await AssertWriteFailsAsync(fixture.Writer, missingPath);
    }

    [Fact]
    public async Task DirectoryRecordingIsRejected()
    {
        using var fixture = new PackageWriterFixture();
        var directoryPath = Path.Combine(fixture.OutputDirectory, "directory.synthetic");
        Directory.CreateDirectory(directoryPath);

        await AssertWriteFailsAsync(fixture.Writer, directoryPath);
    }

    [SymbolicLinkFact]
    public async Task SymbolicLinkRecordingIsRejectedWhenSupported()
    {
        using var fixture = new PackageWriterFixture();
        var targetPath = fixture.WriteRecording("target.synthetic", SyntheticRecording);
        var linkPath = Path.Combine(fixture.OutputDirectory, "link.synthetic");
        File.CreateSymbolicLink(linkPath, targetPath);

        await AssertWriteFailsAsync(fixture.Writer, linkPath);
    }

    [SymbolicLinkFact]
    public async Task SymbolicLinkDirectoryComponentIsRejectedWhenSupported()
    {
        using var fixture = new PackageWriterFixture();
        var targetDirectory = Path.Combine(fixture.OutputDirectory, "real-directory");
        Directory.CreateDirectory(targetDirectory);
        var targetPath = Path.Combine(targetDirectory, "intermediate.synthetic");
        await File.WriteAllBytesAsync(targetPath, SyntheticRecording);
        var linkDirectory = Path.Combine(fixture.OutputDirectory, "linked-directory");
        Directory.CreateSymbolicLink(linkDirectory, targetDirectory);

        await AssertWriteFailsAsync(
            fixture.Writer,
            Path.Combine(linkDirectory, "intermediate.synthetic"));
    }

    [Fact]
    public async Task EmptyRecordingIsRejected()
    {
        using var fixture = new PackageWriterFixture();
        var path = fixture.WriteRecording("empty.synthetic", []);

        await AssertWriteFailsAsync(fixture.Writer, path);
    }

    [Fact]
    public async Task OversizeRecordingIsRejected()
    {
        using var fixture = new PackageWriterFixture(maxRecordingSizeBytes: 4);
        var path = fixture.WriteRecording("oversize.synthetic", [1, 2, 3, 4, 5]);

        await AssertWriteFailsAsync(fixture.Writer, path);
    }

    [Fact]
    public async Task OpenedSourceLengthMutationDuringStagingIsRejected()
    {
        var opener = new DelegateRecordingSourceOpener(
            path => new LengthMutatingFileStream(path));
        using var fixture = new PackageWriterFixture(recordingSourceOpener: opener);
        var path = fixture.WriteRecording("mutating-source.synthetic", SyntheticRecording);

        await AssertWriteFailsAsync(fixture.Writer, path);
    }

    [WindowsFact]
    public async Task WindowsValidatedSourceHandlePreventsReplacementAndDelete()
    {
        using var fixture = new PackageWriterFixture();
        var sourcePath = fixture.WriteRecording("retained-source.synthetic", SyntheticRecording);
        var replacementPath = fixture.WriteRecording(
            "replacement.synthetic",
            Encoding.UTF8.GetBytes("synthetic-replacement-bytes"));
        var opener = new WindowsRecordingSourceOpener();

        await using var source = opener.OpenRead(
            sourcePath,
            fixture.OutputDirectory,
            1024 * 1024);

        Assert.ThrowsAny<IOException>(() => File.Delete(sourcePath));
        var replacementError = Record.Exception(
            () => File.Move(replacementPath, sourcePath, overwrite: true));
        Assert.True(
            replacementError is IOException or UnauthorizedAccessException,
            $"Expected Windows to block replacement, but got {replacementError?.GetType().Name ?? "no error"}.");
        var actual = new byte[checked((int)source.Length)];
        await source.ReadExactlyAsync(actual);
        Assert.Equal(SyntheticRecording, actual);
    }

    [WindowsFact]
    public async Task PrivateStagedFileCannotBeOverwrittenOrDeletedDuringPackaging()
    {
        var blockingSource = new BlockingReadFileStreamFactory();
        using var fixture = new PackageWriterFixture(recordingSourceOpener: blockingSource);
        var sourcePath = fixture.WriteRecording("blocking-source.synthetic", SyntheticRecording);
        var packaging = fixture.Writer.WriteAsync(
            SyntheticSession(),
            sourcePath,
            CancellationToken.None);

        await blockingSource.FirstReadStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var workDirectory = Assert.Single(
            Directory.EnumerateDirectories(fixture.OutputDirectory, ".*.work"));
        var stagedPath = Path.Combine(workDirectory, "recordings", "recording.bin");
        try
        {
            Assert.ThrowsAny<IOException>(
                () => File.Open(stagedPath, FileMode.Open, FileAccess.Write, FileShare.ReadWrite));
            Assert.ThrowsAny<IOException>(() => File.Delete(stagedPath));
        }
        finally
        {
            blockingSource.AllowReadToContinue.TrySetResult(true);
        }

        var package = await packaging;
        Assert.True(File.Exists(package.FilePath));
    }

    [Fact]
    public async Task StaleRecordingFromEarlierWriteIsExcludedWhenRetryHasNoRecording()
    {
        using var fixture = new PackageWriterFixture();
        var session = SyntheticSession();
        var path = fixture.WriteRecording("first.synthetic", SyntheticRecording);
        _ = await fixture.Writer.WriteAsync(session, path, CancellationToken.None);
        var legacyWorkDirectory = Path.Combine(
            fixture.OutputDirectory,
            session.SessionId.ToString("D"));
        Directory.CreateDirectory(Path.Combine(legacyWorkDirectory, "recordings"));
        await File.WriteAllBytesAsync(
            Path.Combine(legacyWorkDirectory, "recordings", "recording.bin"),
            Encoding.UTF8.GetBytes("stale-synthetic-recording"));
        await File.WriteAllTextAsync(
            Path.Combine(legacyWorkDirectory, "stale-marker.txt"),
            "stale-synthetic-marker");

        var retriedPackage = await fixture.Writer.WriteAsync(
            session,
            null,
            CancellationToken.None);

        using var archive = ZipFile.OpenRead(retriedPackage.FilePath);
        Assert.DoesNotContain(
            archive.Entries,
            value => value.FullName == "recordings/recording.bin");
        Assert.DoesNotContain(
            archive.Entries,
            value => value.FullName == "stale-marker.txt");
        using var metadata = await ReadMetadataAsync(archive);
        Assert.Equal(JsonValueKind.Null, metadata.RootElement.GetProperty("recording").ValueKind);
    }

    [Fact]
    public async Task FailedRecordingCanBeRepairedAndRetried()
    {
        using var fixture = new PackageWriterFixture();
        var path = fixture.WriteRecording("retry.synthetic", []);
        await AssertWriteFailsAsync(fixture.Writer, path);
        await File.WriteAllBytesAsync(path, SyntheticRecording);

        var package = await fixture.Writer.WriteAsync(
            SyntheticSession(),
            path,
            CancellationToken.None);

        using var archive = ZipFile.OpenRead(package.FilePath);
        var entry = Assert.Single(
            archive.Entries,
            value => value.FullName == "recordings/recording.bin");
        Assert.Equal(SyntheticRecording.LongLength, entry.Length);
    }

    private static CaptureSession SyntheticSession() => new(
        Guid.Parse("3265ca4f-a470-42d2-bd0d-24894d7109b2"),
        "1.0",
        "machine-synthetic",
        DateTimeOffset.Parse("2026-08-16T04:00:00Z"),
        DateTimeOffset.Parse("2026-08-16T04:00:04Z"),
        4,
        "acad",
        "synthetic-window",
        [
            new CadEvent(
                Guid.Parse("53eadbb8-e039-4b4c-9cf6-4054945e42d6"),
                DateTimeOffset.Parse("2026-08-16T04:00:00Z"),
                "session_started",
                "agent",
                null,
                null,
                new Dictionary<string, object?>()),
        ]);

    private static async Task<JsonDocument> ReadMetadataAsync(ZipArchive archive)
    {
        var text = await ReadEntryTextAsync(archive, "metadata.json");
        return JsonDocument.Parse(text);
    }

    private static async Task<string> ReadEntryTextAsync(
        ZipArchive archive,
        string entryName)
    {
        var entry = Assert.Single(archive.Entries, value => value.FullName == entryName);
        using var reader = new StreamReader(entry.Open(), Encoding.UTF8);
        return await reader.ReadToEndAsync();
    }

    private static async Task<byte[]> ReadEntryBytesAsync(
        ZipArchive archive,
        string entryName)
    {
        var entry = Assert.Single(archive.Entries, value => value.FullName == entryName);
        await using var stream = entry.Open();
        using var memory = new MemoryStream();
        await stream.CopyToAsync(memory);
        return memory.ToArray();
    }

    private static async Task AssertWriteFailsAsync(
        SessionPackageWriter writer,
        string recordingPath)
    {
        await Assert.ThrowsAsync<InvalidDataException>(
            () => writer.WriteAsync(
                SyntheticSession(),
                recordingPath,
                CancellationToken.None));
    }

    private sealed class PackageWriterFixture : IDisposable
    {
        public PackageWriterFixture(
            long maxRecordingSizeBytes = 1024 * 1024,
            IRecordingSourceOpener? recordingSourceOpener = null)
        {
            OutputDirectory = Path.Combine(
                Path.GetTempPath(),
                $"workflow-helper-recording-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(OutputDirectory);
            var options = Options.Create(new CaptureOptions
            {
                OutputDirectory = OutputDirectory,
                MaxRecordingSizeBytes = maxRecordingSizeBytes,
            });
            Writer = recordingSourceOpener is null
                ? new SessionPackageWriter(options)
                : new SessionPackageWriter(options, recordingSourceOpener);
        }

        public string OutputDirectory { get; }
        public SessionPackageWriter Writer { get; }

        public string WriteRecording(string relativePath, byte[] contents)
        {
            var path = Path.Combine(OutputDirectory, relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllBytes(path, contents);
            return path;
        }

        public void Dispose()
        {
            if (Directory.Exists(OutputDirectory))
            {
                Directory.Delete(OutputDirectory, true);
            }
        }
    }

    private static class NativeMethods
    {
        [DllImport("Kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateHardLink(
            string newFileName,
            string existingFileName,
            IntPtr securityAttributes);
    }

    private sealed class DelegateRecordingSourceOpener(
        Func<string, FileStream> open) : IRecordingSourceOpener
    {
        public FileStream OpenRead(
            string sourcePath,
            string outputDirectory,
            long maxSizeBytes) => open(sourcePath);
    }

    private sealed class LengthMutatingFileStream(string path) : FileStream(
        path,
        FileMode.Open,
        FileAccess.ReadWrite,
        FileShare.Read,
        bufferSize: 4096,
        FileOptions.Asynchronous)
    {
        private bool _mutated;

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            var bytesRead = await base.ReadAsync(buffer, cancellationToken);
            if (!_mutated && bytesRead > 0)
            {
                SetLength(Length + 1);
                _mutated = true;
            }
            return bytesRead;
        }
    }

    private sealed class BlockingReadFileStreamFactory : IRecordingSourceOpener
    {
        public TaskCompletionSource<bool> FirstReadStarted { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource<bool> AllowReadToContinue { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public FileStream OpenRead(
            string sourcePath,
            string outputDirectory,
            long maxSizeBytes) => new BlockingReadFileStream(
                sourcePath,
                FirstReadStarted,
                AllowReadToContinue);
    }

    private sealed class BlockingReadFileStream(
        string path,
        TaskCompletionSource<bool> firstReadStarted,
        TaskCompletionSource<bool> allowReadToContinue) : FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            bufferSize: 4096,
            FileOptions.Asynchronous)
    {
        private bool _blocked;

        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            if (!_blocked)
            {
                _blocked = true;
                firstReadStarted.TrySetResult(true);
                await allowReadToContinue.Task.WaitAsync(cancellationToken);
            }
            return await base.ReadAsync(buffer, cancellationToken);
        }
    }
}

public sealed class WindowsHardLinkFactAttribute : FactAttribute
{
    public WindowsHardLinkFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
        {
            Skip = "Requires the Windows same-volume hard-link primitive.";
            return;
        }

        var root = Path.Combine(
            Path.GetTempPath(),
            $"workflow-helper-hard-link-capability-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(root);
            var target = Path.Combine(root, "target");
            File.WriteAllText(target, "synthetic");
            if (!CreateHardLink(
                Path.Combine(root, "link"),
                target,
                IntPtr.Zero))
            {
                Skip = $"Windows hard-link primitive unavailable: Win32 " +
                    $"error {Marshal.GetLastWin32Error()}.";
            }
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }

    [DllImport("Kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateHardLink(
        string newFileName,
        string existingFileName,
        IntPtr securityAttributes);
}

public sealed class SymbolicLinkFactAttribute : FactAttribute
{
    public SymbolicLinkFactAttribute()
    {
        var root = Path.Combine(
            Path.GetTempPath(),
            $"workflow-helper-symlink-capability-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(root);
            var fileTarget = Path.Combine(root, "file-target");
            File.WriteAllText(fileTarget, "synthetic");
            File.CreateSymbolicLink(Path.Combine(root, "file-link"), fileTarget);
            var directoryTarget = Path.Combine(root, "directory-target");
            Directory.CreateDirectory(directoryTarget);
            Directory.CreateSymbolicLink(
                Path.Combine(root, "directory-link"),
                directoryTarget);
        }
        catch (Exception exception) when (
            exception is PlatformNotSupportedException or UnauthorizedAccessException or IOException)
        {
            Skip = $"Filesystem symbolic-link primitive unavailable: {exception.GetType().Name}.";
        }
        finally
        {
            if (Directory.Exists(root))
            {
                Directory.Delete(root, recursive: true);
            }
        }
    }
}

public sealed class WindowsFactAttribute : FactAttribute
{
    public WindowsFactAttribute()
    {
        if (!OperatingSystem.IsWindows())
        {
            Skip = "Requires Windows file-sharing semantics.";
        }
    }
}
