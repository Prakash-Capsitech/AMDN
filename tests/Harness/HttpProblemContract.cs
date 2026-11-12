using System.Text.Json;
using Xunit;

namespace AMDN.Harness.Tests;

internal static class HttpProblemContract
{
    private static readonly JsonElement Components = JsonSerializer.Deserialize<JsonElement>(
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "openapi.json"))).GetProperty("components");

    public static void AssertResponse(HttpResponseMessage response, JsonElement body)
    {
        var status = (int)response.StatusCode;
        var contract = Components.GetProperty("responses").GetProperty("Error" + status);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var constraints = contract.GetProperty("content").GetProperty("application/problem+json")
            .GetProperty("schema").GetProperty("allOf")[1].GetProperty("properties");
        Assert.Equal(constraints.GetProperty("status").GetProperty("const").GetInt32(), body.GetProperty("status").GetInt32());
        Assert.Equal(status, body.GetProperty("status").GetInt32());
        Assert.Equal(constraints.GetProperty("code").GetProperty("const").GetString(), body.GetProperty("code").GetString());

        var problem = Components.GetProperty("schemas").GetProperty("Problem");
        var properties = problem.GetProperty("properties");
        Assert.Equal(JsonValueKind.Object, body.ValueKind);
        foreach (var required in problem.GetProperty("required").EnumerateArray())
            Assert.True(body.TryGetProperty(required.GetString()!, out _));
        Assert.False(problem.GetProperty("additionalProperties").GetBoolean());
        Assert.All(body.EnumerateObject(), field => Assert.True(properties.TryGetProperty(field.Name, out _)));
        foreach (var name in new[] { "type", "title", "code", "request_id" })
            Assert.Equal(JsonValueKind.String, body.GetProperty(name).ValueKind);
        Assert.True(Uri.TryCreate(body.GetProperty("type").GetString(), UriKind.Absolute, out _));
        Assert.InRange(body.GetProperty("title").GetString()!.Length,
            properties.GetProperty("title").GetProperty("minLength").GetInt32(),
            properties.GetProperty("title").GetProperty("maxLength").GetInt32());
        Assert.InRange(status, properties.GetProperty("status").GetProperty("minimum").GetInt32(),
            properties.GetProperty("status").GetProperty("maximum").GetInt32());
        Assert.Contains(body.GetProperty("code").GetString(),
            properties.GetProperty("code").GetProperty("enum").EnumerateArray().Select(value => value.GetString()));
        var id = body.GetProperty("request_id").GetString()!;
        Assert.Matches(Components.GetProperty("schemas").GetProperty("Id").GetProperty("pattern").GetString()!, id);
        Assert.True(Guid.TryParseExact(id, "D", out _));

        if (!contract.TryGetProperty("headers", out var headers)) return;
        foreach (var header in headers.EnumerateObject())
        {
            Assert.True(response.Headers.TryGetValues(header.Name, out var values));
            var value = Assert.Single(values);
            if (header.Value.GetProperty("schema").TryGetProperty("pattern", out var pattern))
                Assert.Matches(pattern.GetString()!, value);
        }
    }
}
