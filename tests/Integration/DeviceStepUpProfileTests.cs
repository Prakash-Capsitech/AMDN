using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Xunit;
using Xunit.Abstractions;

namespace AMDN.Integration.Tests;

public sealed class DeviceStepUpProfileTests(OidcFixture issuer, ITestOutputHelper output) : IClassFixture<OidcFixture>
{
    // The strict access-token profile applies even when no endpoint uses step-up.
    // Checking the real HTTP boundary rejects a policy-only validation mistake.
    [Theory]
    [InlineData("acr", "null")]
    [InlineData("acr", "42")]
    [InlineData("acr", "[]")]
    [InlineData("acr", "\"\"")]
    [InlineData("acr", "\"contains spaces\"")]
    [InlineData("auth_time", "null")]
    [InlineData("auth_time", "\"1\"")]
    [InlineData("auth_time", "[1]")]
    [InlineData("auth_time", "true")]
    [InlineData("auth_time", "1.5")]
    [InlineData("auth_time", "-1")]
    [InlineData("auth_time", "9223372036854775808")]
    public async Task DisabledStepUpStillRejectsMalformedOptionalSignedClaims(string name, string json)
    {
        await using var gateway = issuer.Gateway();
        using var client = gateway.CreateClient();
        var token = issuer.Token(payload => payload[name] = JsonSerializer.Deserialize<JsonElement>(json));
        using var request = Request(token);
        using var response = await client.SendAsync(request);
        output.WriteLine($"Step-up disabled; signed {name}={json}; GET /__test/token -> {(int)response.StatusCode}");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Bearer", response.Headers.WwwAuthenticate.Single().ToString());
    }

    [Theory]
    [InlineData("\"custom\":1,\"custom\":2")]
    [InlineData("\"custom\":1,\"custom\":1")]
    [InlineData("\"acr\":\"valid\",\"a\\u0063r\":\"valid\"")]
    public async Task DisabledStepUpRejectsDuplicateTopLevelClaimsIncludingUnknownAndEscapedNames(string members)
    {
        await using var gateway = issuer.Gateway();
        using var client = gateway.CreateClient();
        var token = issuer.Token(rawPayload: json => json[..^1] + "," + members + "}");
        using var request = Request(token);
        using var response = await client.SendAsync(request);
        output.WriteLine($"Step-up disabled; duplicate signed JSON members {members}; GET /__test/token -> {(int)response.StatusCode}");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task DisabledStepUpAcceptsMissingOptionalClaimsButStillValidatesAndPreservesPresentEvidence()
    {
        await using var gateway = issuer.Gateway();
        using var client = gateway.CreateClient();
        foreach (var scenario in new[] { "missing", "valid", "after-iat" })
        {
            var token = issuer.Token(payload =>
            {
                if (scenario == "missing") return;
                payload["acr"] = "urn:synthetic:verification";
                payload["auth_time"] = (long)payload["iat"] + (scenario == "after-iat" ? 1 : -1);
            });
            using var request = Request(token);
            using var response = await client.SendAsync(request);
            output.WriteLine($"Step-up disabled; {scenario} optional evidence; GET /__test/token -> {(int)response.StatusCode}");
            Assert.Equal(scenario == "after-iat" ? HttpStatusCode.Unauthorized : HttpStatusCode.OK, response.StatusCode);
            if (scenario == "valid")
            {
                using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                Assert.Equal("urn:synthetic:verification", body.RootElement.GetProperty("acr").GetString());
                Assert.True(long.TryParse(body.RootElement.GetProperty("auth_time").GetString(), out _));
            }
        }
    }

    private static HttpRequestMessage Request(string token)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/__test/token");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return request;
    }
}
