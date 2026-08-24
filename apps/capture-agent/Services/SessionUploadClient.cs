using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Extensions.Options;
using WorkflowHelper.CaptureAgent.Configuration;
using WorkflowHelper.CaptureAgent.Domain;

[assembly: InternalsVisibleTo("WorkflowHelper.CaptureAgent.Tests")]

namespace WorkflowHelper.CaptureAgent.Services;

public interface ISessionUploadClient
{
    Task UploadAsync(PackageDescriptor package, CancellationToken cancellationToken);
}

public sealed class SessionUploadClient : ISessionUploadClient
{
    private const int CompletionMaxAttempts = 3;
    private static readonly TimeSpan CompletionBaseRetryDelay = TimeSpan.FromMilliseconds(100);
    private static readonly TimeSpan CompletionMaxRetryDelay = TimeSpan.FromSeconds(5);

    private readonly HttpClient _httpClient;
    private readonly UploadOptions _options;
    private readonly ILogger<SessionUploadClient> _logger;
    private readonly Func<TimeSpan, CancellationToken, Task> _delayAsync;
    private readonly Func<DateTimeOffset> _utcNow;

    public SessionUploadClient(
        HttpClient httpClient,
        IOptions<UploadOptions> options,
        ILogger<SessionUploadClient> logger)
        : this(
            httpClient,
            options,
            logger,
            static (delay, cancellationToken) => Task.Delay(delay, cancellationToken),
            static () => DateTimeOffset.UtcNow)
    {
    }

    internal SessionUploadClient(
        HttpClient httpClient,
        IOptions<UploadOptions> options,
        ILogger<SessionUploadClient> logger,
        Func<TimeSpan, CancellationToken, Task> delayAsync,
        Func<DateTimeOffset> utcNow)
    {
        _httpClient = httpClient;
        _options = options.Value;
        _logger = logger;
        _delayAsync = delayAsync;
        _utcNow = utcNow;
    }

    public async Task UploadAsync(PackageDescriptor package, CancellationToken cancellationToken)
    {
        if (!_options.Enabled)
        {
            _logger.LogInformation("Upload disabled; package retained at {Path}", package.FilePath);
            return;
        }
        if (package.SizeBytes <= 0 || package.SizeBytes > _options.MaxPackageSizeBytes)
        {
            throw new InvalidOperationException(
                $"Package size must be between 1 and {_options.MaxPackageSizeBytes} bytes");
        }

        var session = package.Session;
        var createPayload = new
        {
            schema_version = session.SchemaVersion,
            session_id = session.SessionId,
            machine_id = session.MachineId,
            project_id = (string?)null,
            started_at = session.StartedAt,
            ended_at = session.EndedAt,
            active_duration_seconds = session.ActiveDurationSeconds,
            approved_process = session.ApprovedProcess,
            package_sha256 = package.Sha256,
            package_size_bytes = package.SizeBytes,
        };
        using var registration = await _httpClient.PostAsJsonAsync(
            new Uri(_options.ApiBaseUrl, "/v1/sessions"),
            createPayload,
            cancellationToken);
        if (registration.StatusCode == HttpStatusCode.Conflict)
        {
            await ReconcileExistingRegistrationAsync(package, cancellationToken);
        }
        else
        {
            registration.EnsureSuccessStatusCode();
        }

        using var uploadRequest = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(_options.ApiBaseUrl, $"/v1/sessions/{session.SessionId:D}/upload-url"));
        using var uploadResponse = await _httpClient.SendAsync(uploadRequest, cancellationToken);
        uploadResponse.EnsureSuccessStatusCode();
        using var uploadDocument = JsonDocument.Parse(
            await uploadResponse.Content.ReadAsStringAsync(cancellationToken));
        var uploadUrl = uploadDocument.RootElement.GetProperty("upload_url").GetString()
            ?? throw new InvalidOperationException("API returned no upload URL");
        var objectKey = uploadDocument.RootElement.GetProperty("object_key").GetString()
            ?? throw new InvalidOperationException("API returned no object key");
        var requiredHeaders = uploadDocument.RootElement.GetProperty("required_headers")
            .EnumerateObject()
            .ToDictionary(value => value.Name, value => value.Value.GetString()
                ?? throw new InvalidOperationException("API returned a non-string required header"),
                StringComparer.OrdinalIgnoreCase);
        ValidateRequiredHeaders(package, requiredHeaders);

        await using var packageStream = File.OpenRead(package.FilePath);
        using var content = new StreamContent(packageStream);
        using var putRequest = new HttpRequestMessage(HttpMethod.Put, uploadUrl)
        {
            Content = content,
        };
        foreach (var (name, value) in requiredHeaders)
        {
            if (name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
                name.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
            {
                content.Headers.Remove(name);
                if (!content.Headers.TryAddWithoutValidation(name, value))
                {
                    throw new InvalidOperationException($"Could not apply signed content header {name}");
                }
            }
            else if (!putRequest.Headers.TryAddWithoutValidation(name, value))
            {
                throw new InvalidOperationException($"Could not apply signed request header {name}");
            }
        }
        using var putResponse = await _httpClient.SendAsync(putRequest, cancellationToken);
        if (putResponse.StatusCode == HttpStatusCode.PreconditionFailed)
        {
            _logger.LogInformation(
                "Package object already exists for session {SessionId}; verifying through completion",
                session.SessionId);
        }
        else
        {
            putResponse.EnsureSuccessStatusCode();
        }

        await CompleteUploadAsync(session.SessionId, objectKey, cancellationToken);
    }

    private async Task ReconcileExistingRegistrationAsync(
        PackageDescriptor package,
        CancellationToken cancellationToken)
    {
        var session = package.Session;
        using var response = await _httpClient.GetAsync(
            new Uri(_options.ApiBaseUrl, $"/v1/sessions/{session.SessionId:D}"),
            cancellationToken);
        response.EnsureSuccessStatusCode();

        using var document = JsonDocument.Parse(
            await response.Content.ReadAsStringAsync(cancellationToken));
        var existing = document.RootElement;
        var mismatches = new List<string>();
        AddMismatch(
            mismatches,
            "schema_version",
            existing.GetProperty("schema_version").GetString() == session.SchemaVersion);
        AddMismatch(
            mismatches,
            "session_id",
            existing.GetProperty("session_id").GetGuid() == session.SessionId);
        AddMismatch(
            mismatches,
            "machine_id",
            existing.GetProperty("machine_id").GetString() == session.MachineId);
        AddMismatch(
            mismatches,
            "project_id",
            existing.GetProperty("project_id").ValueKind == JsonValueKind.Null);
        AddMismatch(
            mismatches,
            "started_at",
            existing.GetProperty("started_at").GetDateTimeOffset() == session.StartedAt);
        AddMismatch(
            mismatches,
            "ended_at",
            existing.GetProperty("ended_at").GetDateTimeOffset() == session.EndedAt);
        AddMismatch(
            mismatches,
            "active_duration_seconds",
            existing.GetProperty("active_duration_seconds").GetInt64() ==
                session.ActiveDurationSeconds);
        AddMismatch(
            mismatches,
            "approved_process",
            existing.GetProperty("approved_process").GetString() == session.ApprovedProcess);
        AddMismatch(
            mismatches,
            "package_sha256",
            existing.GetProperty("package_sha256").GetString() == package.Sha256);
        AddMismatch(
            mismatches,
            "package_size_bytes",
            existing.GetProperty("package_size_bytes").GetInt64() == package.SizeBytes);

        if (mismatches.Count != 0)
        {
            throw new InvalidOperationException(
                "Existing session registration does not match package identity: " +
                string.Join(", ", mismatches));
        }
    }

    private static void AddMismatch(
        ICollection<string> mismatches,
        string field,
        bool matches)
    {
        if (!matches)
        {
            mismatches.Add(field);
        }
    }

    private async Task CompleteUploadAsync(
        Guid sessionId,
        string objectKey,
        CancellationToken cancellationToken)
    {
        var completionUri = new Uri(
            _options.ApiBaseUrl,
            $"/v1/sessions/{sessionId:D}/uploaded");
        var completionPayload = new { object_key = objectKey };

        for (var attempt = 1; attempt <= CompletionMaxAttempts; attempt++)
        {
            HttpResponseMessage completion;
            try
            {
                completion = await _httpClient.PostAsJsonAsync(
                    completionUri,
                    completionPayload,
                    cancellationToken);
            }
            catch (HttpRequestException exception) when (
                attempt < CompletionMaxAttempts &&
                (exception.StatusCode is null ||
                    exception.StatusCode == HttpStatusCode.ServiceUnavailable) &&
                !IsCancellation(exception, cancellationToken))
            {
                var delay = GetBackoffDelay(attempt);
                _logger.LogWarning(
                    exception,
                    "Upload completion transport failure; retrying attempt {Attempt} of {MaxAttempts}",
                    attempt + 1,
                    CompletionMaxAttempts);
                await _delayAsync(delay, cancellationToken);
                continue;
            }

            using (completion)
            {
                if (completion.StatusCode != HttpStatusCode.ServiceUnavailable)
                {
                    completion.EnsureSuccessStatusCode();
                    return;
                }
                if (attempt == CompletionMaxAttempts)
                {
                    completion.EnsureSuccessStatusCode();
                }

                var delay = GetRetryDelay(completion, attempt, _utcNow());
                _logger.LogWarning(
                    "Upload completion returned 503; retrying attempt {Attempt} of {MaxAttempts} after {Delay}",
                    attempt + 1,
                    CompletionMaxAttempts,
                    delay);
                await _delayAsync(delay, cancellationToken);
            }
        }
    }

    private static bool IsCancellation(
        HttpRequestException exception,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return true;
        }

        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is OperationCanceledException)
            {
                return true;
            }
        }
        return false;
    }

    internal static TimeSpan GetRetryDelay(
        HttpResponseMessage response,
        int attempt,
        DateTimeOffset utcNow)
    {
        RetryConditionHeaderValue? retryAfter;
        try
        {
            retryAfter = response.Headers.RetryAfter;
        }
        catch (FormatException)
        {
            return GetBackoffDelay(attempt);
        }
        var requestedDelay = retryAfter?.Delta;
        if (requestedDelay is null && retryAfter?.Date is { } retryDate)
        {
            requestedDelay = retryDate - utcNow;
        }
        if (requestedDelay is { } delay)
        {
            return TimeSpan.FromMilliseconds(Math.Clamp(
                delay.TotalMilliseconds,
                TimeSpan.Zero.TotalMilliseconds,
                CompletionMaxRetryDelay.TotalMilliseconds));
        }
        return GetBackoffDelay(attempt);
    }

    private static TimeSpan GetBackoffDelay(int attempt)
    {
        var multiplier = 1 << Math.Min(Math.Max(attempt - 1, 0), 10);
        var delayMilliseconds = Math.Min(
            CompletionBaseRetryDelay.TotalMilliseconds * multiplier,
            CompletionMaxRetryDelay.TotalMilliseconds);
        return TimeSpan.FromMilliseconds(delayMilliseconds);
    }

    private static void ValidateRequiredHeaders(
        PackageDescriptor package,
        IReadOnlyDictionary<string, string> headers)
    {
        var expectedChecksum = Convert.ToBase64String(Convert.FromHexString(package.Sha256));
        var expected = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Length"] = package.SizeBytes.ToString(
                System.Globalization.CultureInfo.InvariantCulture),
            ["Content-Type"] = "application/zip",
            ["x-amz-checksum-sha256"] = expectedChecksum,
            ["x-amz-meta-sha256"] = package.Sha256,
            ["If-None-Match"] = "*",
        };
        foreach (var (name, value) in expected)
        {
            if (!headers.TryGetValue(name, out var actual) || actual != value)
            {
                throw new InvalidOperationException(
                    $"API required header {name} is missing or does not match the package");
            }
        }
    }
}
