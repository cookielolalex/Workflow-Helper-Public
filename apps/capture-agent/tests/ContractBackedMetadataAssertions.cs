using System.Text.Json;
using System.Text.RegularExpressions;
using Xunit;

namespace WorkflowHelper.CaptureAgent.Tests;

internal static class ContractBackedMetadataAssertions
{
    public static string FindContract(string relativePath)
    {
        foreach (var start in new[] { AppContext.BaseDirectory, Directory.GetCurrentDirectory() })
        {
            for (var directory = new DirectoryInfo(start);
                directory is not null;
                directory = directory.Parent)
            {
                var candidate = Path.Combine(directory.FullName, relativePath);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }
        throw new FileNotFoundException(
            $"Could not locate checked-in contract {relativePath} from the test runtime.");
    }

    public static void AssertValid(JsonElement metadata, string sessionContractPath)
    {
        using var sessionContract = JsonDocument.Parse(File.ReadAllText(sessionContractPath));
        var schema = sessionContract.RootElement;
        Assert.Equal("1.0", schema.GetProperty("properties")
            .GetProperty("schema_version").GetProperty("const").GetString());
        AssertObjectShape(metadata, schema);

        var properties = schema.GetProperty("properties");
        AssertString(metadata, properties, "schema_version");
        AssertString(metadata, properties, "session_id");
        AssertString(metadata, properties, "machine_id");
        AssertNullableString(metadata, properties, "project_id");
        AssertString(metadata, properties, "started_at");
        AssertString(metadata, properties, "ended_at");
        AssertInteger(metadata, properties, "active_duration_seconds");
        AssertString(metadata, properties, "approved_process");
        AssertEnum(metadata, properties, "processing_status");
        AssertEnum(metadata, properties, "review_status");
        AssertNullableDateTime(metadata, "raw_expires_at");

        foreach (var arrayName in new[]
        {
            "drawing_files",
            "input_artifacts",
            "output_artifacts",
            "cad_events",
            "idle_intervals",
            "labels",
            "skills",
        })
        {
            Assert.Equal(JsonValueKind.Array, metadata.GetProperty(arrayName).ValueKind);
        }

        var recording = metadata.GetProperty("recording");
        Assert.Equal(JsonValueKind.Object, recording.ValueKind);
        var artifactSchema = schema.GetProperty("$defs").GetProperty("artifact");
        AssertObjectShape(recording, artifactSchema);
        var artifactProperties = artifactSchema.GetProperty("properties");
        AssertString(recording, artifactProperties, "artifact_id");
        AssertEnum(recording, artifactProperties, "kind");
        AssertString(recording, artifactProperties, "file_name");
        AssertString(recording, artifactProperties, "sha256");
        AssertInteger(recording, artifactProperties, "size_bytes");
        AssertNullableString(recording, artifactProperties, "storage_key");

        var eventReference = properties.GetProperty("cad_events")
            .GetProperty("items").GetProperty("$ref").GetString();
        Assert.False(string.IsNullOrWhiteSpace(eventReference));
        var eventContractPath = Path.Combine(
            Path.GetDirectoryName(sessionContractPath)!,
            eventReference!);
        using var eventContract = JsonDocument.Parse(File.ReadAllText(eventContractPath));
        foreach (var cadEvent in metadata.GetProperty("cad_events").EnumerateArray())
        {
            AssertEvent(cadEvent, eventContract.RootElement);
        }
    }

    private static void AssertEvent(JsonElement value, JsonElement schema)
    {
        AssertObjectShape(value, schema);
        var properties = schema.GetProperty("properties");
        AssertString(value, properties, "event_id");
        AssertString(value, properties, "occurred_at");
        AssertEnum(value, properties, "event_type");
        AssertEnum(value, properties, "source");
        AssertNullableString(value, properties, "command_name");
        AssertNullableString(value, properties, "drawing_ref");
        Assert.Equal(JsonValueKind.Object, value.GetProperty("details").ValueKind);
    }

    private static void AssertObjectShape(JsonElement value, JsonElement schema)
    {
        Assert.Equal(JsonValueKind.Object, value.ValueKind);
        if (schema.TryGetProperty("additionalProperties", out var additionalProperties))
        {
            Assert.False(additionalProperties.GetBoolean());
            var allowed = schema.GetProperty("properties").EnumerateObject()
                .Select(property => property.Name)
                .ToHashSet(StringComparer.Ordinal);
            Assert.All(value.EnumerateObject(), property => Assert.Contains(property.Name, allowed));
        }
        foreach (var required in schema.GetProperty("required").EnumerateArray())
        {
            Assert.True(
                value.TryGetProperty(required.GetString()!, out _),
                $"Contract-required property {required.GetString()} was absent.");
        }
    }

    private static void AssertString(
        JsonElement value,
        JsonElement properties,
        string name)
    {
        var actual = value.GetProperty(name);
        var constraint = properties.GetProperty(name);
        Assert.Equal(JsonValueKind.String, actual.ValueKind);
        var text = actual.GetString()!;
        if (constraint.TryGetProperty("const", out var constant))
        {
            Assert.Equal(constant.GetString(), text);
        }
        if (constraint.TryGetProperty("minLength", out var minimumLength))
        {
            Assert.True(text.Length >= minimumLength.GetInt32());
        }
        if (constraint.TryGetProperty("maxLength", out var maximumLength))
        {
            Assert.True(text.Length <= maximumLength.GetInt32());
        }
        if (constraint.TryGetProperty("pattern", out var pattern))
        {
            Assert.Matches(new Regex(pattern.GetString()!), text);
        }
        if (constraint.TryGetProperty("format", out var format))
        {
            if (format.GetString() == "uuid")
            {
                Assert.True(Guid.TryParse(text, out _));
            }
            else if (format.GetString() == "date-time")
            {
                Assert.True(DateTimeOffset.TryParse(text, out _));
            }
        }
    }

    private static void AssertNullableString(
        JsonElement value,
        JsonElement properties,
        string name)
    {
        var actual = value.GetProperty(name);
        if (actual.ValueKind == JsonValueKind.Null)
        {
            return;
        }
        AssertString(value, properties, name);
    }

    private static void AssertNullableDateTime(JsonElement value, string name)
    {
        var actual = value.GetProperty(name);
        Assert.True(
            actual.ValueKind == JsonValueKind.Null ||
            (actual.ValueKind == JsonValueKind.String &&
                DateTimeOffset.TryParse(actual.GetString(), out _)));
    }

    private static void AssertInteger(
        JsonElement value,
        JsonElement properties,
        string name)
    {
        var actual = value.GetProperty(name);
        Assert.Equal(JsonValueKind.Number, actual.ValueKind);
        Assert.True(actual.TryGetInt64(out var integer));
        var constraint = properties.GetProperty(name);
        if (constraint.TryGetProperty("minimum", out var minimum))
        {
            Assert.True(integer >= minimum.GetInt64());
        }
    }

    private static void AssertEnum(
        JsonElement value,
        JsonElement properties,
        string name)
    {
        var actual = value.GetProperty(name);
        Assert.Equal(JsonValueKind.String, actual.ValueKind);
        var allowed = properties.GetProperty(name).GetProperty("enum")
            .EnumerateArray().Select(item => item.GetString());
        Assert.Contains(actual.GetString(), allowed);
    }
}
