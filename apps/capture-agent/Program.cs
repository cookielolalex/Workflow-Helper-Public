using WorkflowHelper.CaptureAgent.Configuration;
using WorkflowHelper.CaptureAgent.Services;
using System.Text.Json;

var syntheticPilotRequested = args.Length == 1 && args[0] == "--synthetic-pilot";
if (!syntheticPilotRequested && args.Contains("--synthetic-pilot", StringComparer.Ordinal))
{
    Console.Error.WriteLine("--synthetic-pilot must be the only command-line argument");
    return 2;
}

// Do not offer the sentinel flag to the command-line configuration provider:
// it is an exact route selector, not a key awaiting a value.
var builder = Host.CreateApplicationBuilder(
    syntheticPilotRequested ? Array.Empty<string>() : args);
builder.Services.Configure<CaptureOptions>(builder.Configuration.GetSection(CaptureOptions.SectionName));
builder.Services.Configure<UploadOptions>(builder.Configuration.GetSection(UploadOptions.SectionName));
builder.Services.AddHttpClient<ISessionUploadClient, SessionUploadClient>();
builder.Services.AddSingleton<ISessionPackageWriter, SessionPackageWriter>();

if (syntheticPilotRequested)
{
    builder.Services.AddSingleton<SyntheticPilotRunner>();
    using var pilotHost = builder.Build();
    var evidence = await pilotHost.Services
        .GetRequiredService<SyntheticPilotRunner>()
        .RunAsync(CancellationToken.None);
    Console.WriteLine(JsonSerializer.Serialize(evidence));
    return evidence.Result == "PASS" ? 0 : 1;
}

builder.Services.AddWindowsService(options => options.ServiceName = "Workflow Helper Capture Agent");
builder.Services.AddSingleton<IApprovedWindowDetector, AutoCadForegroundDetector>();
builder.Services.AddSingleton<ICaptureRecorder, DisabledCaptureRecorder>();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<SessionCoordinator>();
builder.Services.AddHostedService<CaptureWorker>();

await builder.Build().RunAsync();
return 0;
