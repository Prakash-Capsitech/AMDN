using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using AMDN.Identity.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace AMDN.Integration.Tests;

// In-memory keys and a real loopback HTTPS discovery/JWKS service. Never installed or trusted globally.
public sealed class OidcFixture : IAsyncLifetime
{
    private readonly RSA _tlsKey = RSA.Create(2048);
    private readonly RSA _signingKey = RSA.Create(2048);
    private readonly RSA _rotatedKey = RSA.Create(2048);
    private X509Certificate2 _certificate = null!;
    private WebApplication _issuer = null!;
    private bool _rotated;
    public string Issuer => _issuer.Urls.Single();
    public const string Audience = "amdn-test-api";
    public int DiscoveryRequests;
    public int KeyRequests;
    public string? AdvertisedIssuer { get; set; }

    public async Task InitializeAsync()
    {
        var request = new CertificateRequest("CN=AMDN disposable OIDC test", _tlsKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(names.Build());
        _certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(server => server.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(_certificate)));
        _issuer = builder.Build();
        _issuer.MapGet("/.well-known/openid-configuration", () =>
        {
            Interlocked.Increment(ref DiscoveryRequests);
            return Results.Json(new { issuer = AdvertisedIssuer ?? Issuer, jwks_uri = Issuer + "/keys" });
        });
        _issuer.MapGet("/keys", () =>
        {
            Interlocked.Increment(ref KeyRequests);
            var key = (_rotated ? _rotatedKey : _signingKey).ExportParameters(false);
            return Results.Json(new
            {
                keys = new[] { new { kty = "RSA", kid = _rotated ? "rotated" : "initial", use = "sig", alg = "RS256",
                    n = Base64UrlEncoder.Encode(key.Modulus!), e = Base64UrlEncoder.Encode(key.Exponent!) } }
            });
        });
        await _issuer.StartAsync();
    }

    public void Rotate() => _rotated = true;

    public string Token(Action<Dictionary<string, object>>? change = null, string type = "at+jwt", bool rogue = false,
        Func<string, string>? rawPayload = null)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var payload = new Dictionary<string, object>
        {
            ["iss"] = Issuer,
            ["aud"] = Audience,
            ["sub"] = "synthetic-alice",
            ["client_id"] = "synthetic-client",
            ["jti"] = Guid.NewGuid().ToString("N"),
            ["iat"] = now,
            ["nbf"] = now - 1,
            ["exp"] = now + 300,
            ["scope"] = "postman.read inbox.read"
        };
        change?.Invoke(payload);
        // The rogue key is disposable too; it is never advertised in JWKS.
        using var foreign = RSA.Create(2048);
        var key = new RsaSecurityKey(rogue ? foreign : _rotated ? _rotatedKey : _signingKey)
        { KeyId = rogue ? "rogue" : _rotated ? "rotated" : "initial" };
        if (rawPayload is not null)
            return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(
                rawPayload(JsonSerializer.Serialize(payload)), new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
                new Dictionary<string, object> { ["typ"] = type });
        return new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(new SecurityTokenDescriptor
        {
            Claims = payload,
            TokenType = type,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
        });
    }

    public WebApplicationFactory<Program> Gateway(bool enabled = true, bool trustCertificate = true, string? issuer = null,
        Action<IServiceCollection>? configure = null, Dictionary<string, string?>? settings = null) =>
        Application<Program>(settings, false, enabled, trustCertificate, issuer, services =>
        {
            services.AddSingleton<IStartupFilter, ProbeEndpoints>();
            configure?.Invoke(services);
        });

    public WebApplicationFactory<T> Application<T>(Dictionary<string, string?>? settings = null, bool https = true,
        bool enabled = true, bool trustCertificate = true, string? issuer = null, Action<IServiceCollection>? configure = null) where T : class
    {
        var factory = new WebApplicationFactory<T>().WithWebHostBuilder(builder =>
        {
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Authentication:Oidc:Enabled"] = enabled.ToString(),
                ["Authentication:Oidc:Issuer"] = issuer ?? (enabled ? Issuer : ""),
                ["Authentication:Oidc:Audience"] = enabled ? Audience : ""
            }));
            if (settings is not null) builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(settings));
            builder.ConfigureLogging(logging => logging.ClearProviders());
            builder.ConfigureServices(services =>
            {
                configure?.Invoke(services);
                if (trustCertificate)
                {
                    services.PostConfigure<JwtBearerOptions>(IdentityAuthentication.Scheme, options =>
                    {
                        // Test-only trust of this exact ephemeral cert. HTTPS validation stays on.
                        options.BackchannelHttpHandler = new HttpClientHandler
                        {
                            AllowAutoRedirect = false,
                            ServerCertificateCustomValidationCallback = (_, certificate, _, _) =>
                                certificate is not null && certificate.RawData.AsSpan().SequenceEqual(_certificate.RawData)
                        };
                        // JwtBearer post-configuration has already built its transport. Rebuild
                        // only transport/config manager so it uses the pinned test certificate.
                        options.Backchannel = null!;
                        options.ConfigurationManager = null!;
                        new JwtBearerPostConfigureOptions().PostConfigure(IdentityAuthentication.Scheme, options);
                    });
                }
            });
        });
        factory.UseKestrel(options => options.Listen(IPAddress.Loopback, 0, listen => { if (https) listen.UseHttps(_certificate); }));
        return factory;
    }

    public HttpClient Client<T>(WebApplicationFactory<T> factory) where T : class
    {
        using var defaultClient = factory.CreateClient();
        return new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = false,
            ServerCertificateCustomValidationCallback = (_, certificate, _, _) =>
                certificate is not null && certificate.RawData.AsSpan().SequenceEqual(_certificate.RawData)
        })
        { BaseAddress = defaultClient.BaseAddress };
    }

    public async Task DisposeAsync()
    {
        await _issuer.DisposeAsync();
        _certificate.Dispose();
        _tlsKey.Dispose();
        _signingKey.Dispose();
        _rotatedKey.Dispose();
    }

    // These routes exist only in the test assembly, never the deployed Gateway.
    private sealed class ProbeEndpoints : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Map("/__test", probes =>
            {
                probes.UseRouting();
                probes.UseAuthentication();
                probes.UseAuthorization();
                probes.UseEndpoints(endpoints =>
                {
                    endpoints.MapGet("/token", (HttpContext context) => Results.Json(
                        context.User.Claims.ToDictionary(claim => claim.Type, claim => claim.Value)))
                        .RequireAuthorization(IdentityAuthentication.TokenValidatedPolicy);
                    endpoints.MapGet("/default", () => Results.NoContent()).RequireAuthorization();
                    endpoints.MapGet("/device-step-up", () => Results.NoContent()).RequireAuthorization(DeviceStepUp.Policy);
                    endpoints.MapGet("/fallback", () => Results.NoContent());
                });
            });
            next(app);
        };
    }
}
