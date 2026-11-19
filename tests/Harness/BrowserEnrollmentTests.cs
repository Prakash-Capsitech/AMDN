using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using AMDN.Infrastructure.Identity;
using AMDN.Integration.Tests;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Npgsql;
using Xunit;

namespace AMDN.Harness.Tests;

public sealed class BrowserEnrollmentTests(OidcFixture issuer) : IClassFixture<OidcFixture>
{
    private readonly RunState _state = RunState.Load();

    [Fact]
    public async Task ChromeWebAuthnCompletesEnrollmentReplacementRevocationAndExactProofRetry()
    {
        using var tls = RSA.Create(2048);
        var certificateRequest = new CertificateRequest("CN=AMDN disposable browser fixture", tls, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder(); names.AddDnsName("localhost"); certificateRequest.CertificateExtensions.Add(names.Build());
        using var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" }); builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(server => server.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(certificate)));
        await using var proxy = builder.Build();
        HttpClient? upstream = null;
        var observed = new ConcurrentQueue<(string Path, string Key, string Digest)>();
        proxy.MapGet("/__browser/", () => Results.Content("""
            <!doctype html><meta charset="utf-8"><title>AMDN disposable browser test</title>
            <script type="module">
            import { EnrollmentClient } from './enrollment.mjs';
            window.EnrollmentClient = EnrollmentClient;
            window.browserReady = true;
            </script>
            """, "text/html"));
        proxy.MapGet("/__browser/enrollment.mjs", () => Results.Text(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "browser", "enrollment.mjs")), "text/javascript"));
        proxy.MapPost("/v1/{**path}", async (HttpContext context) =>
        {
            using var body = new MemoryStream(); await context.Request.Body.CopyToAsync(body, context.RequestAborted);
            var bytes = body.ToArray();
            observed.Enqueue((context.Request.Path, context.Request.Headers["Idempotency-Key"].ToString(), Convert.ToHexString(SHA256.HashData(bytes))));
            using var request = new HttpRequestMessage(HttpMethod.Post, context.Request.Path + context.Request.QueryString)
            { Content = new ByteArrayContent(bytes) };
            request.Content.Headers.ContentType = new("application/json");
            foreach (var header in new[] { "Origin", "Authorization", "Idempotency-Key" }) request.Headers.TryAddWithoutValidation(header, context.Request.Headers[header].ToArray());
            using var response = await upstream!.SendAsync(request, context.RequestAborted);
            context.Response.StatusCode = (int)response.StatusCode;
            foreach (var header in new[] { "Cache-Control", "Retry-After", "WWW-Authenticate" })
                if (response.Headers.TryGetValues(header, out var values)) context.Response.Headers[header] = values.ToArray();
            context.Response.ContentType = response.Content.Headers.ContentType?.ToString();
            await response.Content.CopyToAsync(context.Response.Body, context.RequestAborted);
        });
        await proxy.StartAsync();
        var address = new UriBuilder(proxy.Urls.Single()) { Host = "localhost" }.Uri.GetLeftPart(UriPartial.Authority);
        var config = Guid.NewGuid(); var subject = Guid.NewGuid().ToString("N");
        await using var provisioning = IdentityDatabase.ProvisioningPool(_state.IdentityConnection("provisioner"));
        var provisioner = new IdentityProvisioner(provisioning);
        var member = await provisioner.EnsureMemberAsync(await provisioner.CreateTenantAsync(), issuer.Issuer, subject);
        await using var owner = new NpgsqlConnection(_state.IdentityConnection("migrator")); await owner.OpenAsync();
        await Sql(owner, "SET ROLE amdn_identity_owner");
        await Sql(owner, "SELECT amdn_identity.administer_device_configuration(@command,@id,0,'localhost',@origin,ARRAY['urn:amdn:test:strong'],900,true,'browser-fixture')",
            ("command", Guid.NewGuid()), ("id", config), ("origin", address));
        await Sql(owner, "SELECT amdn_identity.administer_device_grant(@command,@tenant,@user,@postman,'grant.issue',0,clock_timestamp()+interval '1 hour','browser-fixture')",
            ("command", Guid.NewGuid()), ("tenant", member.TenantId), ("user", member.UserId), ("postman", member.PostmanId));
        await using var gateway = issuer.Application<Program>(new Dictionary<string, string?>
        {
            ["Authentication:DeviceStepUp:Enabled"] = "true",
            ["Authentication:DeviceStepUp:AllowedAcrValues:0"] = "urn:amdn:test:strong",
            ["Authentication:DeviceStepUp:MaximumAgeSeconds"] = "120",
            ["EnrollmentApi:Enabled"] = "true",
            ["EnrollmentApi:ConnectionString"] = _state.IdentityConnection("enrollment"),
            ["EnrollmentApi:ConfigurationId"] = config.ToString(),
            ["EnrollmentApi:Origin"] = address,
            ["EnrollmentApi:MaximumPoolSize"] = "2",
            ["EnrollmentApi:RequestsPerMinute"] = "100",
            ["EnrollmentApi:ActorRequestsPerMinute"] = "100",
            ["EnrollmentApi:TenantRequestsPerMinute"] = "100",
            ["EnrollmentApi:MaximumConcurrentProofs"] = "1"
        });
        using var client = issuer.Client(gateway); upstream = client;
        var pin = Convert.ToBase64String(SHA256.HashData(tls.ExportSubjectPublicKeyInfo()));
        await using var chrome = await BrowserProbe.Start(pin);
        var authenticator = await AddAuthenticator(chrome);
        await chrome.Call("Page.navigate", new { url = address + "/__browser/" });
        for (var attempt = 0; attempt < 50; attempt++)
        {
            if ((await chrome.Evaluate("Boolean(window.browserReady)")).GetBoolean()) break;
            await Task.Delay(100);
        }
        Assert.True((await chrome.Evaluate("Boolean(window.browserReady)")).GetBoolean());
        var accessToken = issuer.Token(payload =>
        {
            payload["sub"] = subject; payload["scope"] = "device.manage"; payload["acr"] = "urn:amdn:test:strong";
            payload["auth_time"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        });
        // Tokens exist only in this disposable browser's memory and protocol message.
        var setup = JsonSerializer.Serialize(new { tenantId = member.TenantId, rpId = "localhost", token = accessToken });
        Assert.True((await chrome.Evaluate($$"""
            (() => {
              const settings = {{setup}};
              window.makeClient = () => new EnrollmentClient({ tenantId: settings.tenantId, rpId: settings.rpId, getAccessToken: async () => settings.token });
              const original = window.fetch.bind(window);
              window.loseProofResponse = false;
              window.fetch = async (...args) => {
                const response = await original(...args);
                if (window.loseProofResponse && String(args[0]).includes('/candidate-proof') && response.status === 200) {
                  window.loseProofResponse = false; await response.arrayBuffer(); throw new TypeError('Simulated lost response');
                }
                return response;
              };
              window.first = makeClient(); return true;
            })()
            """)).GetBoolean());
        Assert.Equal("awaiting_registration", await State(chrome, "await first.beginEnrollment({expectedIdentityVersion:1})"));
        Assert.Equal("awaiting_candidate_proof", await State(chrome, "await first.prove()"));
        Assert.Equal("unavailable", (await chrome.Evaluate("(async()=>{window.loseProofResponse=true;try{await first.prove();return 'unexpected'}catch(e){return e.code}})()")).GetString());
        Assert.Equal("completed", await State(chrome, "await first.retry()"));
        var firstDevice = (await chrome.Evaluate("first.state.snapshot.device_id")).GetGuid();
        var retries = observed.Where(item => item.Path.EndsWith("/candidate-proof", StringComparison.Ordinal)).ToArray();
        Assert.Equal(2, retries.Length); Assert.Equal(retries[0].Key, retries[1].Key); Assert.Equal(retries[0].Digest, retries[1].Digest);
        Assert.Equal(1L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_commands WHERE tenant_id=@tenant AND stage='candidate'", ("tenant", member.TenantId)));

        await Presence(chrome, authenticator, false); var candidate = await AddAuthenticator(chrome);
        Assert.Equal("awaiting_registration", await State(chrome, "await (window.replacement=makeClient()).beginEnrollment({expectedIdentityVersion:2,replaceDeviceId:first.state.snapshot.device_id})"));
        Assert.Equal("awaiting_candidate_proof", await State(chrome, "await replacement.prove()"));
        Assert.Equal("awaiting_current_proof", await State(chrome, "await replacement.prove()"));
        await Presence(chrome, candidate, false); await Presence(chrome, authenticator, true);
        Assert.Equal("completed", await State(chrome, "await replacement.prove()"));
        Assert.Equal("awaiting_revocation_proof", await State(chrome, "await (window.revocation=makeClient()).beginRevocation({expectedIdentityVersion:3,deviceId:replacement.state.snapshot.device_id})"));
        await Presence(chrome, authenticator, false);
        Assert.Equal("cancelled", (await chrome.Evaluate("(async()=>{const abort=new AbortController();setTimeout(()=>abort.abort(),100);try{await revocation.prove({signal:abort.signal});return 'unexpected'}catch(e){return e.code}})()")).GetString());
        Assert.Equal(0L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_commands WHERE tenant_id=@tenant AND stage='revocation'", ("tenant", member.TenantId)));
        await Presence(chrome, candidate, true);
        Assert.Equal("completed", await State(chrome, "await revocation.prove()"));
        Assert.False((await chrome.Evaluate("revocation.state.snapshot.messaging_ready")).GetBoolean());
        Assert.Equal(4L, await Sql(owner, "SELECT identity_version FROM amdn_identity.users WHERE tenant_id=@tenant", ("tenant", member.TenantId)));
        Assert.Equal(2L, await Sql(owner, "SELECT count(*) FROM amdn_identity.devices WHERE tenant_id=@tenant AND status='revoked'", ("tenant", member.TenantId)));
        Assert.Equal("revoked", await Sql(owner, "SELECT status FROM amdn_identity.devices WHERE tenant_id=@tenant AND device_id=@device", ("tenant", member.TenantId), ("device", firstDevice)));
    }

    private static async Task<string?> State(BrowserProbe chrome, string operation) =>
        (await chrome.Evaluate($"(async()=>{{try{{return ({operation}).state}}catch(e){{return 'error:'+e.code}}}})()")).GetString();
    private static async Task<string> AddAuthenticator(BrowserProbe chrome) => (await chrome.Call("WebAuthn.addVirtualAuthenticator", new
    {
        options = new { protocol = "ctap2", transport = "usb", hasResidentKey = false, hasUserVerification = true, isUserVerified = true, automaticPresenceSimulation = true }
    })).GetProperty("authenticatorId").GetString()!;
    private static Task Presence(BrowserProbe chrome, string authenticatorId, bool enabled) =>
        chrome.Call("WebAuthn.setAutomaticPresenceSimulation", new { authenticatorId, enabled });
    private static async Task<object?> Sql(NpgsqlConnection connection, string text, params (string, object)[] values)
    {
        await using var command = new NpgsqlCommand(text, connection);
        foreach (var (name, value) in values) command.Parameters.AddWithValue(name, value);
        return await command.ExecuteScalarAsync();
    }
}
