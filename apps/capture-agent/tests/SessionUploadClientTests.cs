using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using WorkflowHelper.CaptureAgent.Configuration;
using WorkflowHelper.CaptureAgent.Domain;
using WorkflowHelper.CaptureAgent.Services;
using Xunit;

namespace WorkflowHelper.CaptureAgent.Tests;

public sealed class SessionUploadClientTests
{
    [Fact]
    public async Task UploadAppliesEveryApiSignedHeaderExactly()
    {
        await WithPackageAsync(async (package, checksum) =>
        {
            var handler = new UploadSequenceHandler(package, checksum);
            var client = CreateClient(handler, maxPackageSizeBytes: 1024);

            await client.UploadAsync(package, CancellationToken.None);

            var put = Assert.Single(handler.Requests, value => value.Method == HttpMethod.Put);
            Assert.Equal(await File.ReadAllBytesAsync(package.FilePath), put.Body);
            Assert.Equal(package.SizeBytes.ToString(), put.Headers["Content-Length"]);
            Assert.Equal("application/zip", put.Headers["Content-Type"]);
            Assert.Equal(checksum, put.Headers["x-amz-checksum-sha256"]);
            Assert.Equal(package.Sha256, put.Headers["x-amz-meta-sha256"]);
            Assert.Equal("*", put.Headers["If-None-Match"]);
        });
    }

    [Fact]
    public async Task OversizedPackageFailsBeforeRegistration()
    {
        var bytes = Encoding.UTF8.GetBytes("too large");
        var handler = new UploadSequenceHandler(Package("unused.zip", bytes), "unused");
        var client = CreateClient(handler, maxPackageSizeBytes: bytes.Length - 1);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.UploadAsync(Package("unused.zip", bytes), CancellationToken.None));

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task RegistrationConflictWithExactRemoteIdentityContinuesUpload()
    {
        await WithPackageAsync(async (package, checksum) =>
        {
            var handler = new ConflictRecoveryHandler(
                package,
                checksum,
                [Respond(HttpStatusCode.Conflict)],
                [Respond(HttpStatusCode.OK)]);
            var client = CreateClient(handler);

            await client.UploadAsync(package, CancellationToken.None);

            Assert.Single(handler.Requests, request =>
                request.Method == HttpMethod.Get &&
                request.RequestUri.EndsWith($"/v1/sessions/{package.SessionId:D}"));
            var put = Assert.Single(handler.Requests, request => request.Method == HttpMethod.Put);
            Assert.Equal("*", put.Headers["If-None-Match"]);
            Assert.Single(CompletionRequests(handler.Requests));
        });
    }

    [Fact]
    public async Task RegistrationConflictWithMismatchedRemoteIdentityFailsClosed()
    {
        await WithPackageAsync(async (package, checksum) =>
        {
            var handler = new ConflictRecoveryHandler(
                package,
                checksum,
                [Respond(HttpStatusCode.Conflict)],
                [Respond(HttpStatusCode.OK)],
                remoteSha256: new string('f', 64));
            var client = CreateClient(handler);

            await Assert.ThrowsAsync<InvalidOperationException>(
                () => client.UploadAsync(package, CancellationToken.None));

            Assert.DoesNotContain(
                handler.Requests,
                request => request.RequestUri.EndsWith("/upload-url"));
            Assert.DoesNotContain(handler.Requests, request => request.Method == HttpMethod.Put);
        });
    }

    [Fact]
    public async Task CompleteClientRetryNeverOverwritesPersistedWinner()
    {
        await WithPackageAsync(async (package, checksum) =>
        {
            var handler = new ConflictRecoveryHandler(
                package,
                checksum,
                [Respond(HttpStatusCode.Created), Respond(HttpStatusCode.Conflict)],
                [
                    Throw(new HttpRequestException(
                        "synthetic response loss after object persistence")),
                    Respond(HttpStatusCode.PreconditionFailed),
                ]);
            var client = CreateClient(handler);

            await Assert.ThrowsAsync<HttpRequestException>(
                () => client.UploadAsync(package, CancellationToken.None));
            await client.UploadAsync(package, CancellationToken.None);

            var puts = handler.Requests
                .Where(request => request.Method == HttpMethod.Put)
                .ToList();
            var expectedBody = await File.ReadAllBytesAsync(package.FilePath);
            Assert.Equal(2, puts.Count);
            Assert.All(puts, request => Assert.Equal("*", request.Headers["If-None-Match"]));
            Assert.All(puts, request => Assert.Equal(expectedBody, request.Body));
            Assert.Single(handler.Requests, request =>
                request.Method == HttpMethod.Get &&
                request.RequestUri.EndsWith($"/v1/sessions/{package.SessionId:D}"));
            Assert.Single(CompletionRequests(handler.Requests));
        });
    }

    [Fact]
    public async Task CompletionRetries503WithIdenticalCallbackOnly()
    {
        await WithPackageAsync(async (package, checksum) =>
        {
            var handler = new UploadSequenceHandler(
                package,
                checksum,
                [Respond(HttpStatusCode.ServiceUnavailable), Respond(HttpStatusCode.Accepted)]);
            var delays = new List<TimeSpan>();
            var client = CreateClient(handler, delayAsync: RecordDelays(delays));

            await client.UploadAsync(package, CancellationToken.None);

            var callbacks = CompletionRequests(handler);
            Assert.Equal(2, callbacks.Count);
            Assert.Equal(callbacks[0].RequestUri, callbacks[1].RequestUri);
            Assert.Equal(callbacks[0].Body, callbacks[1].Body);
            Assert.Equal(
                $"http://api:8000/v1/sessions/{package.SessionId:D}/uploaded",
                callbacks[0].RequestUri);
            using var payload = JsonDocument.Parse(callbacks[0].Body);
            Assert.Equal(
                $"sessions/{package.SessionId:D}/packages/{package.Sha256}.zip",
                payload.RootElement.GetProperty("object_key").GetString());
            Assert.Equal(new[] { TimeSpan.FromMilliseconds(100) }, delays);
            Assert.Single(handler.Requests, request =>
                request.Method == HttpMethod.Post && request.RequestUri.EndsWith("/v1/sessions"));
            Assert.Single(handler.Requests, request => request.RequestUri.EndsWith("/upload-url"));
            Assert.Single(handler.Requests, request => request.Method == HttpMethod.Put);
        });
    }

    [Fact]
    public async Task CompletionStopsAfterThree503Responses()
    {
        await WithPackageAsync(async (package, checksum) =>
        {
            var handler = new UploadSequenceHandler(
                package,
                checksum,
                [
                    Respond(HttpStatusCode.ServiceUnavailable),
                    Respond(HttpStatusCode.ServiceUnavailable),
                    Respond(HttpStatusCode.ServiceUnavailable),
                ]);
            var delays = new List<TimeSpan>();
            var client = CreateClient(handler, delayAsync: RecordDelays(delays));

            var exception = await Assert.ThrowsAsync<HttpRequestException>(
                () => client.UploadAsync(package, CancellationToken.None));

            Assert.Equal(HttpStatusCode.ServiceUnavailable, exception.StatusCode);
            Assert.Equal(3, CompletionRequests(handler).Count);
            Assert.Equal(
                new[] { TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(200) },
                delays);
        });
    }

    [Fact]
    public async Task CompletionDoesNotRetryNon503ClientError()
    {
        await WithPackageAsync(async (package, checksum) =>
        {
            var handler = new UploadSequenceHandler(
                package,
                checksum,
                [Respond(HttpStatusCode.BadRequest)]);
            var delays = new List<TimeSpan>();
            var client = CreateClient(handler, delayAsync: RecordDelays(delays));

            var exception = await Assert.ThrowsAsync<HttpRequestException>(
                () => client.UploadAsync(package, CancellationToken.None));

            Assert.Equal(HttpStatusCode.BadRequest, exception.StatusCode);
            Assert.Single(CompletionRequests(handler));
            Assert.Empty(delays);
        });
    }

    [Fact]
    public async Task CompletionRecoversFromTransientTransportFailure()
    {
        await WithPackageAsync(async (package, checksum) =>
        {
            var handler = new UploadSequenceHandler(
                package,
                checksum,
                [Throw(new HttpRequestException("synthetic transport failure")),
                    Respond(HttpStatusCode.Accepted)]);
            var delays = new List<TimeSpan>();
            var client = CreateClient(handler, delayAsync: RecordDelays(delays));

            await client.UploadAsync(package, CancellationToken.None);

            var callbacks = CompletionRequests(handler);
            Assert.Equal(2, callbacks.Count);
            Assert.Equal(callbacks[0].RequestUri, callbacks[1].RequestUri);
            Assert.Equal(callbacks[0].Body, callbacks[1].Body);
            Assert.Equal(new[] { TimeSpan.FromMilliseconds(100) }, delays);
        });
    }

    [Fact]
    public async Task CompletionRecoversFromTransportExceptionWith503Status()
    {
        await WithPackageAsync(async (package, checksum) =>
        {
            var unavailable = new HttpRequestException(
                "synthetic service unavailable",
                null,
                HttpStatusCode.ServiceUnavailable);
            var handler = new UploadSequenceHandler(
                package,
                checksum,
                [Throw(unavailable), Respond(HttpStatusCode.Accepted)]);
            var delays = new List<TimeSpan>();
            var client = CreateClient(handler, delayAsync: RecordDelays(delays));

            await client.UploadAsync(package, CancellationToken.None);

            Assert.Equal(2, CompletionRequests(handler).Count);
            Assert.Equal(new[] { TimeSpan.FromMilliseconds(100) }, delays);
        });
    }

    [Fact]
    public async Task CompletionDoesNotRetryTransportExceptionWithNon503Status()
    {
        await WithPackageAsync(async (package, checksum) =>
        {
            var badRequest = new HttpRequestException(
                "synthetic client failure",
                null,
                HttpStatusCode.BadRequest);
            var handler = new UploadSequenceHandler(
                package,
                checksum,
                [Throw(badRequest)]);
            var delays = new List<TimeSpan>();
            var client = CreateClient(handler, delayAsync: RecordDelays(delays));

            var exception = await Assert.ThrowsAsync<HttpRequestException>(
                () => client.UploadAsync(package, CancellationToken.None));

            Assert.Equal(HttpStatusCode.BadRequest, exception.StatusCode);
            Assert.Single(CompletionRequests(handler));
            Assert.Empty(delays);
        });
    }

    [Fact]
    public async Task CompletionDoesNotRetryCancellationWrappedByTransportException()
    {
        await WithPackageAsync(async (package, checksum) =>
        {
            var cancellation = new OperationCanceledException("synthetic cancellation");
            var handler = new UploadSequenceHandler(
                package,
                checksum,
                [Throw(new HttpRequestException("transport cancellation", cancellation))]);
            var delays = new List<TimeSpan>();
            var client = CreateClient(handler, delayAsync: RecordDelays(delays));

            await Assert.ThrowsAsync<HttpRequestException>(
                () => client.UploadAsync(package, CancellationToken.None));

            Assert.Single(CompletionRequests(handler));
            Assert.Empty(delays);
        });
    }

    [Fact]
    public async Task CompletionCancellationDuringDelayPreventsAnotherCallback()
    {
        await WithPackageAsync(async (package, checksum) =>
        {
            var handler = new UploadSequenceHandler(
                package,
                checksum,
                [Respond(HttpStatusCode.ServiceUnavailable), Respond(HttpStatusCode.Accepted)]);
            using var cancellation = new CancellationTokenSource();
            Task CancelDelay(TimeSpan _, CancellationToken cancellationToken)
            {
                cancellation.Cancel();
                return Task.FromCanceled(cancellationToken);
            }
            var client = CreateClient(handler, delayAsync: CancelDelay);

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => client.UploadAsync(package, cancellation.Token));

            Assert.Single(CompletionRequests(handler));
        });
    }

    [Fact]
    public async Task CompletionHonorsBoundedRetryAfterDeltaAndDate()
    {
        await WithPackageAsync(async (package, checksum) =>
        {
            var now = DateTimeOffset.Parse("2026-08-16T04:00:00Z");
            var handler = new UploadSequenceHandler(
                package,
                checksum,
                [
                    Respond503WithRetryAfter(new RetryConditionHeaderValue(TimeSpan.FromSeconds(2))),
                    Respond503WithRetryAfter(new RetryConditionHeaderValue(now.AddSeconds(3))),
                    Respond(HttpStatusCode.Accepted),
                ]);
            var delays = new List<TimeSpan>();
            var client = CreateClient(
                handler,
                delayAsync: RecordDelays(delays),
                utcNow: () => now);

            await client.UploadAsync(package, CancellationToken.None);

            Assert.Equal(new[] { TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(3) }, delays);
        });
    }

    [Fact]
    public async Task CompletionClampsRetryAfterToBounds()
    {
        await WithPackageAsync(async (package, checksum) =>
        {
            var now = DateTimeOffset.Parse("2026-08-16T04:00:00Z");
            var handler = new UploadSequenceHandler(
                package,
                checksum,
                [
                    Respond503WithRetryAfter(new RetryConditionHeaderValue(TimeSpan.FromSeconds(10))),
                    Respond503WithRetryAfter(new RetryConditionHeaderValue(now.AddSeconds(-1))),
                    Respond(HttpStatusCode.Accepted),
                ]);
            var delays = new List<TimeSpan>();
            var client = CreateClient(
                handler,
                delayAsync: RecordDelays(delays),
                utcNow: () => now);

            await client.UploadAsync(package, CancellationToken.None);

            Assert.Equal(
                new[] { TimeSpan.FromSeconds(5), TimeSpan.Zero },
                delays);
        });
    }

    [Fact]
    public void CompletionFallsBackWhenRetryAfterIsMalformed()
    {
        using var response = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
        response.Headers.TryAddWithoutValidation("Retry-After", "not-a-delay");

        var delay = SessionUploadClient.GetRetryDelay(
            response,
            attempt: 1,
            DateTimeOffset.Parse("2026-08-16T04:00:00Z"));

        Assert.Equal(TimeSpan.FromMilliseconds(100), delay);
    }

    private static SessionUploadClient CreateClient(
        HttpMessageHandler handler,
        long maxPackageSizeBytes = 1024,
        Func<TimeSpan, CancellationToken, Task>? delayAsync = null,
        Func<DateTimeOffset>? utcNow = null) =>
        new(
            new HttpClient(handler),
            Options.Create(new UploadOptions
            {
                Enabled = true,
                ApiBaseUrl = new Uri("http://api:8000"),
                MaxPackageSizeBytes = maxPackageSizeBytes,
            }),
            NullLogger<SessionUploadClient>.Instance,
            delayAsync ?? (static (_, _) => Task.CompletedTask),
            utcNow ?? (static () => DateTimeOffset.UtcNow));

    private static Func<TimeSpan, CancellationToken, Task> RecordDelays(
        ICollection<TimeSpan> delays) =>
        (delay, _) =>
        {
            delays.Add(delay);
            return Task.CompletedTask;
        };

    private static async Task WithPackageAsync(
        Func<PackageDescriptor, string, Task> test)
    {
        var bytes = Encoding.UTF8.GetBytes("synthetic package bytes");
        var path = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid():D}.zip");
        await File.WriteAllBytesAsync(path, bytes);
        try
        {
            await test(Package(path, bytes), Convert.ToBase64String(SHA256.HashData(bytes)));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static PackageDescriptor Package(string path, byte[] bytes)
    {
        var startedAt = DateTimeOffset.Parse("2026-08-16T04:00:00Z");
        var session = CaptureSession.Start(
            "machine-synthetic",
            new ApprovedWindowContext(42, "acad", "synthetic-window"),
            startedAt).Finish(startedAt.AddSeconds(1));
        return new PackageDescriptor(
            session.SessionId,
            path,
            Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),
            bytes.Length,
            session);
    }

    private static List<CapturedRequest> CompletionRequests(UploadSequenceHandler handler) =>
        CompletionRequests(handler.Requests);

    private static List<CapturedRequest> CompletionRequests(
        IEnumerable<CapturedRequest> requests) =>
        requests
            .Where(request => request.RequestUri.EndsWith("/uploaded"))
            .ToList();

    private static Func<HttpResponseMessage> Respond(HttpStatusCode statusCode) =>
        () => new HttpResponseMessage(statusCode);

    private static Func<HttpResponseMessage> Respond503WithRetryAfter(
        RetryConditionHeaderValue retryAfter) =>
        () =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);
            response.Headers.RetryAfter = retryAfter;
            return response;
        };

    private static Func<HttpResponseMessage> Throw(Exception exception) =>
        () => throw exception;

    private sealed record CapturedRequest(
        HttpMethod Method,
        string RequestUri,
        IReadOnlyDictionary<string, string> Headers,
        byte[] Body);

    private sealed class ConflictRecoveryHandler : HttpMessageHandler
    {
        private readonly PackageDescriptor _package;
        private readonly string _checksum;
        private readonly Queue<Func<HttpResponseMessage>> _registrationOutcomes;
        private readonly Queue<Func<HttpResponseMessage>> _putOutcomes;
        private readonly string _remoteSha256;

        public ConflictRecoveryHandler(
            PackageDescriptor package,
            string checksum,
            IEnumerable<Func<HttpResponseMessage>> registrationOutcomes,
            IEnumerable<Func<HttpResponseMessage>> putOutcomes,
            string? remoteSha256 = null)
        {
            _package = package;
            _checksum = checksum;
            _registrationOutcomes = new Queue<Func<HttpResponseMessage>>(
                registrationOutcomes);
            _putOutcomes = new Queue<Func<HttpResponseMessage>>(putOutcomes);
            _remoteSha256 = remoteSha256 ?? package.Sha256;
        }

        public List<CapturedRequest> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var allHeaders = request.Content is null
                ? request.Headers.AsEnumerable()
                : request.Headers.Concat(request.Content.Headers);
            var headers = allHeaders.ToDictionary(
                value => value.Key,
                value => string.Join(",", value.Value),
                StringComparer.OrdinalIgnoreCase);
            var body = request.Content is null
                ? []
                : await request.Content.ReadAsByteArrayAsync(cancellationToken);
            Requests.Add(new CapturedRequest(
                request.Method,
                request.RequestUri?.AbsoluteUri ?? string.Empty,
                headers,
                body));

            var path = request.RequestUri?.AbsolutePath ?? string.Empty;
            if (request.Method == HttpMethod.Post && path == "/v1/sessions")
            {
                return _registrationOutcomes.Dequeue()();
            }
            if (request.Method == HttpMethod.Get &&
                path == $"/v1/sessions/{_package.SessionId:D}")
            {
                var session = _package.Session;
                var json = JsonSerializer.Serialize(new
                {
                    schema_version = session.SchemaVersion,
                    session_id = session.SessionId,
                    machine_id = session.MachineId,
                    project_id = (string?)null,
                    started_at = session.StartedAt,
                    ended_at = session.EndedAt,
                    active_duration_seconds = session.ActiveDurationSeconds,
                    approved_process = session.ApprovedProcess,
                    package_sha256 = _remoteSha256,
                    package_size_bytes = _package.SizeBytes,
                });
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(json, Encoding.UTF8, "application/json"),
                };
            }
            if (path.EndsWith("/upload-url"))
            {
                var json = JsonSerializer.Serialize(new
                {
                    upload_url = "http://localstack:4566/upload",
                    object_key =
                        $"sessions/{_package.SessionId:D}/packages/{_package.Sha256}.zip",
                    required_headers = new Dictionary<string, string>
                    {
                        ["Content-Length"] = _package.SizeBytes.ToString(),
                        ["Content-Type"] = "application/zip",
                        ["x-amz-checksum-sha256"] = _checksum,
                        ["x-amz-meta-sha256"] = _package.Sha256,
                        ["If-None-Match"] = "*",
                    },
                });
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(json, Encoding.UTF8, "application/json"),
                };
            }
            if (request.Method == HttpMethod.Put)
            {
                return _putOutcomes.Dequeue()();
            }
            if (path.EndsWith("/uploaded"))
            {
                return new HttpResponseMessage(HttpStatusCode.Accepted);
            }
            throw new InvalidOperationException(
                $"Unexpected synthetic request {request.Method} {path}");
        }
    }

    private sealed class UploadSequenceHandler : HttpMessageHandler
    {
        private readonly PackageDescriptor _package;
        private readonly string _checksum;
        private readonly Queue<Func<HttpResponseMessage>> _completionOutcomes;

        public UploadSequenceHandler(
            PackageDescriptor package,
            string checksum,
            IEnumerable<Func<HttpResponseMessage>>? completionOutcomes = null)
        {
            _package = package;
            _checksum = checksum;
            _completionOutcomes = new Queue<Func<HttpResponseMessage>>(
                completionOutcomes ?? [Respond(HttpStatusCode.Accepted)]);
        }

        public List<CapturedRequest> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var allHeaders = request.Content is null
                ? request.Headers.AsEnumerable()
                : request.Headers.Concat(request.Content.Headers);
            var headers = allHeaders
                .ToDictionary(value => value.Key, value => string.Join(",", value.Value),
                    StringComparer.OrdinalIgnoreCase);
            var body = request.Content is null
                ? []
                : await request.Content.ReadAsByteArrayAsync(cancellationToken);
            Requests.Add(new CapturedRequest(
                request.Method,
                request.RequestUri?.AbsoluteUri ?? string.Empty,
                headers,
                body));

            if (request.RequestUri?.AbsolutePath.EndsWith("/upload-url") == true)
            {
                var json = JsonSerializer.Serialize(new
                {
                    upload_url = "http://localstack:4566/upload",
                    object_key = $"sessions/{_package.SessionId:D}/packages/{_package.Sha256}.zip",
                    required_headers = new Dictionary<string, string>
                    {
                        ["Content-Length"] = _package.SizeBytes.ToString(),
                        ["Content-Type"] = "application/zip",
                        ["x-amz-checksum-sha256"] = _checksum,
                        ["x-amz-meta-sha256"] = _package.Sha256,
                        ["If-None-Match"] = "*",
                    },
                });
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(json, Encoding.UTF8, "application/json"),
                };
            }
            if (request.RequestUri?.AbsolutePath.EndsWith("/uploaded") == true)
            {
                return _completionOutcomes.Dequeue()();
            }
            return new HttpResponseMessage(
                request.Method == HttpMethod.Post
                    ? HttpStatusCode.Accepted
                    : HttpStatusCode.OK);
        }
    }
}
