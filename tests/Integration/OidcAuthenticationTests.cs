using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using AMDN.Identity.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AMDN.Integration.Tests;

public sealed class OidcAuthenticationTests : IClassFixture<OidcFixture>
{
    private readonly OidcFixture _issuer;
    public OidcAuthenticationTests(OidcFixture issuer) => _issuer = issuer;

    [Fact]
    public async Task RealHttpsDiscoveryValidatesSignatureAndKeepsOnlyExternalIdentity()
    {
        await using var gateway = _issuer.Gateway();
        using var client = gateway.CreateClient();
        var token = _issuer.Token(payload =>
        {
            payload["tenant_id"] = Guid.NewGuid().ToString();
            payload["user_id"] = Guid.NewGuid().ToString();
            payload["device_id"] = Guid.NewGuid().ToString();
            payload["role"] = "admin";
            payload["email"] = "synthetic@example.invalid";
        });
        using var response = await Send(client, token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var claims = await response.Content.ReadFromJsonAsync<Dictionary<string, string>>();
        Assert.Equal(new[] { "client_id", "iss", "scope", "sub" }, claims!.Keys.Order().ToArray());
        Assert.Equal(_issuer.Issuer, claims["iss"]);
        Assert.Equal("synthetic-alice", claims["sub"]);
        Assert.True(_issuer.DiscoveryRequests > 0);
        Assert.True(_issuer.KeyRequests > 0);
        var options = gateway.Services.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(IdentityAuthentication.Scheme);
        Assert.True(options.RequireHttpsMetadata);
        Assert.False(options.SaveToken);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("malformed")]
    [InlineData("signature")]
    [InlineData("tampered")]
    [InlineData("unsigned")]
    [InlineData("symmetric")]
    [InlineData("issuer")]
    [InlineData("audience")]
    [InlineData("audience-slash")]
    [InlineData("expired")]
    [InlineData("future")]
    [InlineData("no-exp")]
    [InlineData("no-sub")]
    [InlineData("empty-sub")]
    [InlineData("multiple-sub")]
    [InlineData("no-client")]
    [InlineData("no-jti")]
    [InlineData("no-iat")]
    [InlineData("future-iat")]
    [InlineData("string-iat")]
    [InlineData("array-scope")]
    [InlineData("invalid-scope")]
    [InlineData("numeric-sub")]
    [InlineData("id-token")]
    [InlineData("oversize")]
    public async Task InvalidAccessTokensFailWithGenericChallenge(string scenario)
    {
        await using var gateway = _issuer.Gateway();
        using var client = gateway.CreateClient();
        string? token = scenario switch
        {
            "missing" => null,
            "malformed" => "invalid.synthetic.token",
            "signature" => _issuer.Token(rogue: true),
            "tampered" => Tamper(_issuer.Token()),
            "issuer" => _issuer.Token(p => p["iss"] = "https://foreign.example.invalid"),
            "audience" => _issuer.Token(p => p["aud"] = "another-api"),
            "audience-slash" => _issuer.Token(p => p["aud"] = OidcFixture.Audience + "/"),
            "expired" => _issuer.Token(p => { p["exp"] = DateTimeOffset.UtcNow.AddMinutes(-2).ToUnixTimeSeconds(); p["nbf"] = DateTimeOffset.UtcNow.AddMinutes(-10).ToUnixTimeSeconds(); }),
            "future" => _issuer.Token(p => p["nbf"] = DateTimeOffset.UtcNow.AddMinutes(2).ToUnixTimeSeconds()),
            "no-exp" => _issuer.Token(p => p.Remove("exp")),
            "no-sub" => _issuer.Token(p => p.Remove("sub")),
            "empty-sub" => _issuer.Token(p => p["sub"] = " "),
            "multiple-sub" => _issuer.Token(p => p["sub"] = new[] { "alice", "bob" }),
            "no-client" => _issuer.Token(p => p.Remove("client_id")),
            "no-jti" => _issuer.Token(p => p.Remove("jti")),
            "no-iat" => _issuer.Token(p => p.Remove("iat")),
            "future-iat" => _issuer.Token(p => p["iat"] = DateTimeOffset.UtcNow.AddMinutes(2).ToUnixTimeSeconds()),
            "string-iat" => _issuer.Token(p => p["iat"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()),
            "array-scope" => _issuer.Token(p => p["scope"] = new[] { "postman.read" }),
            "invalid-scope" => _issuer.Token(p => p["scope"] = "postman.read\tinbox.read"),
            "numeric-sub" => _issuer.Token(p => p["sub"] = 42),
            "id-token" => _issuer.Token(type: "JWT"),
            "oversize" => new string('a', 17 * 1024),
            "unsigned" => Forge("none"),
            "symmetric" => Forge("HS256"),
            _ => throw new ArgumentException("Unknown case")
        };
        using var response = await Send(client, token);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("Bearer", response.Headers.WwwAuthenticate.Single().ToString());
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType!.MediaType);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("unauthenticated", body);
        Assert.DoesNotContain("synthetic-alice", body);
        Assert.DoesNotContain("IDX", body);
        if (token is not null) Assert.DoesNotContain(token, body);
    }

    [Theory]
    [InlineData("/__test/default")]
    [InlineData("/__test/fallback")]
    public async Task AuthenticationAloneCannotGrantApplicationAccess(string path)
    {
        await using var gateway = _issuer.Gateway();
        using var client = gateway.CreateClient();
        using var anonymous = await Send(client, null, path);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        using var authenticated = await Send(client, _issuer.Token(), path);
        Assert.Equal(HttpStatusCode.Forbidden, authenticated.StatusCode);
    }

    [Fact]
    public async Task HeadersAndQueryCannotEstablishIdentityOrSmuggleBearerToken()
    {
        await using var gateway = _issuer.Gateway();
        using var client = gateway.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/__test/token?access_token=" + _issuer.Token());
        request.Headers.Add("X-Tenant-Id", Guid.NewGuid().ToString());
        request.Headers.Add("X-User-Id", Guid.NewGuid().ToString());
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task DisabledConfigurationDeniesEvenValidTokensAndKeepsLivenessPublic()
    {
        await using var gateway = _issuer.Gateway(enabled: false);
        using var client = gateway.CreateClient();
        using var denied = await Send(client, _issuer.Token());
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);
        using var live = await client.GetAsync("/health/live");
        Assert.Equal(HttpStatusCode.OK, live.StatusCode);
        using var messages = await client.PostAsync("/v1/messages", null);
        Assert.Equal(HttpStatusCode.NotFound, messages.StatusCode);
    }

    [Theory]
    [InlineData("http://issuer.example.invalid", "amdn")]
    [InlineData("https://user@issuer.example.invalid", "amdn")]
    [InlineData("https://issuer.example.invalid?tenant=evil", "amdn")]
    [InlineData("https://issuer.example.invalid#fragment", "amdn")]
    [InlineData("https://issuer.example.invalid", "")]
    public async Task InvalidConfigurationFailsStartup(string issuer, string audience)
    {
        await using var gateway = _issuer.Gateway(issuer: issuer, audience: audience);
        Assert.Throws<OptionsValidationException>(() => gateway.CreateClient());
    }

    [Fact]
    public async Task UntrustedTlsCertificateFailsClosed()
    {
        await using var gateway = _issuer.Gateway(trustCertificate: false);
        using var client = gateway.CreateClient();
        using var response = await Send(client, _issuer.Token());
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task UnknownSigningKeyTriggersDiscoveryRefreshWithoutAcceptingForgedKeys()
    {
        await using var gateway = _issuer.Gateway();
        using var client = gateway.CreateClient();
        using var before = await Send(client, _issuer.Token());
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);
        var requests = _issuer.KeyRequests;
        _issuer.Rotate();
        var token = _issuer.Token();
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (true)
        {
            using var response = await Send(client, token);
            if (response.StatusCode == HttpStatusCode.OK) break;
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.True(DateTime.UtcNow < deadline, "New signing key was not refreshed within the bounded deadline.");
            await Task.Delay(100);
        }
        Assert.True(_issuer.KeyRequests > requests);
        using var forged = await Send(client, _issuer.Token(rogue: true));
        Assert.Equal(HttpStatusCode.Unauthorized, forged.StatusCode);
    }

    [Fact]
    public async Task DiscoveryCannotAdvertiseAnAdditionalTrustedIssuer()
    {
        _issuer.AdvertisedIssuer = "https://unexpected.example.invalid";
        try
        {
            await using var gateway = _issuer.Gateway();
            using var client = gateway.CreateClient();
            using var configuredIssuer = await Send(client, _issuer.Token());
            using var advertisedIssuer = await Send(client, _issuer.Token(p => p["iss"] = _issuer.AdvertisedIssuer));
            Assert.Equal(HttpStatusCode.Unauthorized, configuredIssuer.StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, advertisedIssuer.StatusCode);
        }
        finally { _issuer.AdvertisedIssuer = null; }
    }

    [Fact]
    public async Task UnavailableDiscoveryCannotAuthenticateOnColdStart()
    {
        await using var gateway = _issuer.Gateway(issuer: "https://127.0.0.1:1");
        using var client = gateway.CreateClient();
        using var response = await Send(client, _issuer.Token(p => p["iss"] = "https://127.0.0.1:1"));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private static async Task<HttpResponseMessage> Send(HttpClient client, string? token, string path = "/__test/token")
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request);
    }

    private static string Tamper(string token)
    {
        var parts = token.Split('.');
        var payload = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(Base64UrlEncoder.Decode(parts[1]))!;
        payload["sub"] = JsonSerializer.SerializeToElement("forged-subject");
        return parts[0] + "." + Base64UrlEncoder.Encode(JsonSerializer.Serialize(payload)) + "." + parts[2];
    }

    private string Forge(string algorithm)
    {
        var validPayload = _issuer.Token().Split('.')[1];
        var header = Base64UrlEncoder.Encode(JsonSerializer.Serialize(new { alg = algorithm, typ = "at+jwt", kid = "initial" }));
        return header + "." + validPayload + "." + (algorithm == "none" ? "" : Base64UrlEncoder.Encode(new byte[32]));
    }
}
