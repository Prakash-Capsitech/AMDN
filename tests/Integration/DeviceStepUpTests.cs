using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using AMDN.Identity.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Xunit;

namespace AMDN.Integration.Tests;

public sealed class DeviceStepUpTests(OidcFixture issuer) : IClassFixture<OidcFixture>
{
    private const string Acr = "urn:amdn:test:recent-user-verification";
    private static Dictionary<string, string?> Settings() => new()
    {
        ["Authentication:DeviceStepUp:Enabled"] = "true",
        ["Authentication:DeviceStepUp:AllowedAcrValues:0"] = Acr,
        ["Authentication:DeviceStepUp:MaximumAgeSeconds"] = "120"
    };

    [Theory]
    [InlineData("fresh", HttpStatusCode.NoContent)]
    [InlineData("boundary", HttpStatusCode.NoContent)]
    [InlineData("stale", HttpStatusCode.Forbidden)]
    [InlineData("future", HttpStatusCode.Forbidden)]
    [InlineData("no-acr", HttpStatusCode.Forbidden)]
    [InlineData("no-auth-time", HttpStatusCode.Forbidden)]
    [InlineData("wrong-acr", HttpStatusCode.Forbidden)]
    [InlineData("acr-case", HttpStatusCode.Forbidden)]
    [InlineData("amr-only", HttpStatusCode.Forbidden)]
    [InlineData("no-scope", HttpStatusCode.Forbidden)]
    [InlineData("scope-prefix", HttpStatusCode.Forbidden)]
    [InlineData("disabled", HttpStatusCode.Forbidden)]
    [InlineData("signature", HttpStatusCode.Unauthorized)]
    [InlineData("missing", HttpStatusCode.Unauthorized)]
    public async Task RealSignedTokensMustMeetExplicitRecentAuthenticationPolicy(string scenario, HttpStatusCode expected)
    {
        var clock = new TestClock();
        await using var gateway = issuer.Gateway(settings: scenario == "disabled" ? null : Settings(),
            configure: services => services.AddSingleton<TimeProvider>(clock));
        using var client = gateway.CreateClient();
        var now = clock.GetUtcNow().ToUnixTimeSeconds();
        var token = issuer.Token(payload =>
        {
            payload["scope"] = "postman.read device.manage";
            payload["acr"] = Acr;
            payload["auth_time"] = now - 10;
            switch (scenario)
            {
                case "boundary": payload["auth_time"] = now - 120; break;
                case "stale": payload["auth_time"] = now - 121; break;
                case "future": payload["auth_time"] = now + 1; payload["iat"] = now + 1; break;
                case "no-acr": payload.Remove("acr"); break;
                case "no-auth-time": payload.Remove("auth_time"); break;
                case "wrong-acr": payload["acr"] = Acr + ":stronger"; break;
                case "acr-case": payload["acr"] = Acr.ToUpperInvariant(); break;
                case "amr-only": payload.Remove("acr"); payload["amr"] = new[] { "mfa" }; break;
                case "no-scope": payload.Remove("scope"); break;
                case "scope-prefix": payload["scope"] = "device.manage.all"; break;
            }
        }, rogue: scenario == "signature");
        using var response = await Send(client, scenario == "missing" ? null : token);
        Assert.Equal(expected, response.StatusCode);
        if (expected is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized)
        {
            var body = await response.Content.ReadAsStringAsync();
            Assert.DoesNotContain(Acr, body);
            Assert.DoesNotContain(token, body);
        }
    }

    [Theory]
    [InlineData("acr", "null")]
    [InlineData("acr", "42")]
    [InlineData("acr", "[]")]
    [InlineData("acr", "[\"urn:amdn:test:recent-user-verification\"]")]
    [InlineData("acr", "\"\"")]
    [InlineData("acr", "\"acr with spaces\"")]
    [InlineData("auth_time", "null")]
    [InlineData("auth_time", "\"1\"")]
    [InlineData("auth_time", "[1]")]
    [InlineData("auth_time", "true")]
    [InlineData("auth_time", "1.5")]
    [InlineData("auth_time", "-1")]
    [InlineData("auth_time", "9223372036854775808")]
    public async Task MalformedSignedStepUpClaimsFailAuthentication(string name, string json)
    {
        await using var gateway = issuer.Gateway(settings: Settings());
        using var client = gateway.CreateClient();
        var token = issuer.Token(payload => payload[name] = JsonSerializer.Deserialize<JsonElement>(json));
        using var response = await Send(client, token, "/__test/token");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task AuthenticationTimeCannotFollowTokenIssueTime()
    {
        await using var gateway = issuer.Gateway(settings: Settings());
        using var client = gateway.CreateClient();
        var token = issuer.Token(payload => payload["auth_time"] = (long)payload["iat"] + 1);
        using var response = await Send(client, token, "/__test/token");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData("acr", "\"unapproved\"")]
    [InlineData("auth_time", "0")]
    [InlineData("scope", "\"postman.read\"")]
    public async Task DuplicateSignedClaimsCannotBeCollapsedToAConvenientValue(string name, string extra)
    {
        await using var gateway = issuer.Gateway(settings: Settings());
        using var client = gateway.CreateClient();
        foreach (var prepend in new[] { true, false })
        {
            var duplicate = JsonSerializer.Serialize(name) + ":" + extra;
            var token = issuer.Token(payload =>
            {
                payload["scope"] = "device.manage";
                payload["acr"] = Acr;
                payload["auth_time"] = (long)payload["iat"];
            }, rawPayload: json => prepend ? "{" + duplicate + "," + json[1..] : json[..^1] + "," + duplicate + "}");
            using var response = await Send(client, token);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }
    }

    [Fact]
    public async Task FreshnessIsRecheckedAndNeitherRenewalNorHeadersSupplyStepUp()
    {
        var clock = new TestClock();
        var authentication = clock.GetUtcNow().ToUnixTimeSeconds() - 119;
        await using var gateway = issuer.Gateway(settings: Settings(), configure: services => services.AddSingleton<TimeProvider>(clock));
        using var client = gateway.CreateClient();
        string Token() => issuer.Token(payload =>
        {
            payload["scope"] = "device.manage";
            payload["acr"] = Acr;
            payload["auth_time"] = authentication;
        });
        using var before = await Send(client, Token());
        Assert.Equal(HttpStatusCode.NoContent, before.StatusCode);
        clock.Advance(TimeSpan.FromSeconds(2));
        using var after = await Send(client, Token());
        Assert.Equal(HttpStatusCode.Forbidden, after.StatusCode);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/__test/device-step-up?acr=" + Acr + "&auth_time=" + authentication);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", issuer.Token(p => p["scope"] = "device.manage"));
        request.Headers.Add("X-Acr", Acr);
        request.Headers.Add("X-Auth-Time", authentication.ToString());
        using var spoof = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Forbidden, spoof.StatusCode);
    }

    [Fact]
    public async Task StepUpPreservesOnlyVerifiedEvidenceAndCannotAuthorizeDevicesOrDefaultRoutes()
    {
        await using var gateway = issuer.Gateway(settings: Settings());
        using var client = gateway.CreateClient();
        var token = issuer.Token(payload =>
        {
            payload["scope"] = "device.manage";
            payload["acr"] = Acr;
            payload["auth_time"] = (long)payload["iat"] - 1;
            payload["device_id"] = Guid.NewGuid().ToString();
            payload["tenant_id"] = Guid.NewGuid().ToString();
            payload["amr"] = new[] { "mfa" };
        });
        using var evidence = await Send(client, token, "/__test/token");
        var claims = await evidence.Content.ReadFromJsonAsync<Dictionary<string, string>>();
        Assert.Equal(new[] { "acr", "auth_time", "client_id", "iss", "scope", "sub" }, claims!.Keys.Order().ToArray());
        foreach (var path in new[] { "/__test/default", "/__test/fallback" })
        {
            using var denied = await Send(client, token, path);
            Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        }
        using var enrollment = new HttpRequestMessage(HttpMethod.Post, "/v1/devices");
        enrollment.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var unavailable = await client.SendAsync(enrollment);
        Assert.Equal(HttpStatusCode.NotFound, unavailable.StatusCode);
    }

    [Theory]
    [InlineData("disabled-values")]
    [InlineData("no-oidc")]
    [InlineData("no-acr")]
    [InlineData("duplicate-acr")]
    [InlineData("invalid-acr")]
    [InlineData("zero-age")]
    [InlineData("excessive-age")]
    public async Task PartialOrInvalidConfigurationFailsStartup(string scenario)
    {
        var settings = Settings();
        settings["Authentication:Oidc:Enabled"] = "true";
        settings["Authentication:Oidc:Issuer"] = issuer.Issuer;
        settings["Authentication:Oidc:Audience"] = OidcFixture.Audience;
        switch (scenario)
        {
            case "disabled-values": settings["Authentication:DeviceStepUp:Enabled"] = "false"; break;
            case "no-oidc":
                settings["Authentication:Oidc:Enabled"] = "false";
                settings["Authentication:Oidc:Issuer"] = "";
                settings["Authentication:Oidc:Audience"] = "";
                break;
            case "no-acr": settings.Remove("Authentication:DeviceStepUp:AllowedAcrValues:0"); break;
            case "duplicate-acr": settings["Authentication:DeviceStepUp:AllowedAcrValues:1"] = Acr; break;
            case "invalid-acr": settings["Authentication:DeviceStepUp:AllowedAcrValues:0"] = "mfa other"; break;
            case "zero-age": settings["Authentication:DeviceStepUp:MaximumAgeSeconds"] = "0"; break;
            case "excessive-age": settings["Authentication:DeviceStepUp:MaximumAgeSeconds"] = "901"; break;
        }
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { DisableDefaults = true });
        builder.Configuration.AddInMemoryCollection(settings);
        builder.Services.AddAmdnIdentityAuthentication(builder.Configuration);
        using var host = builder.Build();
        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => host.StartAsync());
        Assert.Equal(typeof(DeviceStepUpSettings), error.OptionsType);
    }

    private static async Task<HttpResponseMessage> Send(HttpClient client, string? token, string path = "/__test/device-step-up")
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request);
    }

    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset _now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan by) => _now += by;
    }
}
