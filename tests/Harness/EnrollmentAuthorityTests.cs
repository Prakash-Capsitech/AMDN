using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using AMDN.Enrollment;
using AMDN.Identity.Authentication;
using AMDN.Infrastructure.Identity;
using AMDN.Integration.Tests;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Npgsql;
using Xunit;

namespace AMDN.Harness.Tests;

public sealed class EnrollmentAuthorityTests(OidcFixture issuer) : IClassFixture<OidcFixture>
{
    private const string Acr = "urn:amdn:test:strong";
    private readonly RunState _state = RunState.Load();
    private sealed record Member(Guid Tenant, Guid User, Guid Config, string Subject);

    [Fact]
    public async Task RealSignedPrincipalAndExecuteOnlyPoolCompleteEnrollmentAndRejectForeignActors()
    {
        var alice = await Setup(); var other = await Setup();
        await using var pool = EnrollmentDatabase.Pool(_state.IdentityConnection("enrollment"), 1);
        int backend;
        await using (var initial = await pool.OpenConnectionAsync()) backend = (int)(await Sql(initial, "SELECT pg_backend_pid()"))!;
        await using var gateway = App(alice.Config, pool);
        using var client = issuer.Client(gateway);
        using var key = new SyntheticWebAuthn();
        var begin = await Send(client, alice, "begin", "{}"u8.ToArray());
        AssertOutcome("ok", begin); var id = begin.GetProperty("ceremony_id").GetGuid();
        var registration = key.Response(Challenge(begin), true);
        AssertOutcome("forbidden", await Send(client, other, $"proof/{id}/registration", registration, tenant: alice.Tenant));
        AssertOutcome("not_found", await Send(client, other, $"proof/{id}/registration", registration));
        AssertOutcome("conflict", await Send(client, alice, $"proof/{id}/registration", registration, scenario: "different-client"));
        var candidate = await Send(client, alice, $"proof/{id}/registration", registration);
        AssertOutcome("ok", candidate);
        var proof = key.Response(Challenge(candidate), false); var replay = Guid.NewGuid().ToString("N");
        var complete = await Send(client, alice, $"proof/{id}/candidate", proof, replay: replay);
        Assert.Equal(2, complete.GetProperty("committed_identity_version").GetInt64());
        Assert.False(complete.GetProperty("messaging_ready").GetBoolean());
        AssertOutcome("ok", await Send(client, alice, $"proof/{id}/candidate", proof, replay: replay));
        await using var connection = await pool.OpenConnectionAsync();
        Assert.Equal(backend, await Sql(connection, "SELECT pg_backend_pid()"));
        Assert.Equal(DBNull.Value, await Sql(connection, "SELECT nullif(current_setting('amdn.tenant_id',true),'')"));
        Assert.Equal(DBNull.Value, await Sql(connection, "SELECT nullif(current_setting('amdn.user_id',true),'')"));
        Assert.Equal(DBNull.Value, await Sql(connection, "SELECT nullif(current_setting('amdn.configuration_id',true),'')"));
        Assert.Equal("harness_identity_enrollment", await Sql(connection, "SELECT current_user"));
    }

    [Theory]
    [InlineData("missing", 403)]
    [InlineData("signature", 403)]
    [InlineData("no-scope", 403)]
    [InlineData("scope-prefix", 403)]
    [InlineData("no-acr", 403)]
    [InlineData("no-auth-time", 403)]
    [InlineData("wrong-acr", 403)]
    [InlineData("old-step-up", 403)]
    [InlineData("expired-within-skew", 403)]
    [InlineData("oversize-client", 403)]
    [InlineData("forged-user-no-token", 403)]
    [InlineData("forged-user-no-scope", 403)]
    public async Task PrincipalMappingRequiresActualValidatedEvidenceAndStrictAuthority(string scenario, int status)
    {
        var member = await Setup();
        await using var pool = EnrollmentDatabase.Pool(_state.IdentityConnection("enrollment"), 1);
        await using var gateway = App(member.Config, pool); using var client = issuer.Client(gateway);
        using var response = await Request(client, member, "begin", "{}"u8.ToArray(), scenario: scenario);
        Assert.Equal((HttpStatusCode)status, response.StatusCode);
        await using var owner = await Owner();
        Assert.Equal(0L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_ceremonies WHERE tenant_id=@tenant", ("tenant", member.Tenant)));
    }

    [Theory]
    [InlineData("replace-user")]
    [InlineData("mutate-user")]
    public async Task MutableUserAndInjectedTenantHeadersCannotReplaceValidatedActorOrConfiguration(string scenario)
    {
        var member = await Setup(); var foreign = await Setup();
        await using var pool = EnrollmentDatabase.Pool(_state.IdentityConnection("enrollment"), 1);
        await using var gateway = App(member.Config, pool); using var client = issuer.Client(gateway);
        client.DefaultRequestHeaders.Add("X-Tenant-Id", foreign.Tenant.ToString());
        client.DefaultRequestHeaders.Add("Origin", "https://foreign.invalid");
        client.DefaultRequestHeaders.Add("X-Forwarded-Host", "foreign.invalid");
        var begin = await Send(client, member, "begin", "{}"u8.ToArray(), scenario: scenario);
        AssertOutcome("ok", begin);
        await using var owner = await Owner();
        Assert.Equal(member.Subject, await Sql(owner, "SELECT subject FROM amdn_identity.device_ceremonies WHERE ceremony_id=@id", ("id", begin.GetProperty("ceremony_id").GetGuid())));
        Assert.Equal("https://ceremony.invalid", await Sql(owner, "SELECT origin FROM amdn_identity.device_ceremonies WHERE ceremony_id=@id", ("id", begin.GetProperty("ceremony_id").GetGuid())));
        // Transport Origin checks remain a future route obligation; headers do not select database authority.
    }

    [Fact]
    public async Task CurrentGrantAndMembershipRevocationOverridePreviouslyValidTokenAndPoolReuse()
    {
        var alice = await Setup(); var bob = await Setup();
        await using var pool = EnrollmentDatabase.Pool(_state.IdentityConnection("enrollment"), 1);
        await using var gateway = App(alice.Config, pool); using var client = issuer.Client(gateway);
        var first = await Send(client, alice, "begin", "{}"u8.ToArray()); AssertOutcome("ok", first);
        await using var owner = await Owner();
        await Sql(owner, "UPDATE amdn_identity.device_management_grants SET status='revoked' WHERE tenant_id=@tenant", ("tenant", alice.Tenant));
        using var key = new SyntheticWebAuthn();
        AssertOutcome("forbidden", await Send(client, alice, $"proof/{first.GetProperty("ceremony_id").GetGuid()}/registration", key.Response(Challenge(first), true)));
        AssertOutcome("ok", await Send(client, bob, "begin", "{}"u8.ToArray()));
        await Sql(owner, "UPDATE amdn_identity.memberships SET status='suspended' WHERE tenant_id=@tenant", ("tenant", bob.Tenant));
        AssertOutcome("forbidden", await Send(client, bob, "begin", "{}"u8.ToArray()));
    }

    [Fact]
    public async Task ApplicationCredentialCannotReadWriteHelpersAssumeRolesOrForgeRlsAccess()
    {
        var member = await Setup();
        await using var pool = EnrollmentDatabase.Pool(_state.IdentityConnection("enrollment"), 1);
        await using var connection = await pool.OpenConnectionAsync();
        foreach (var table in new[] { "tenants", "users", "memberships", "postmen", "devices", "device_subjects", "device_configurations", "device_management_grants", "device_ceremonies", "device_challenges", "device_commands", "device_ceremony_audit" })
        {
            foreach (var sql in new[] { $"SELECT * FROM amdn_identity.{table}", $"DELETE FROM amdn_identity.{table}", $"INSERT INTO amdn_identity.{table} DEFAULT VALUES" })
                Assert.Equal("42501", (await Assert.ThrowsAsync<PostgresException>(() => Sql(connection, sql))).SqlState);
        }
        foreach (var role in new[] { "amdn_identity_owner", "amdn_identity_ceremony_executor", "amdn_identity_provisioner", "amdn_identity_runtime" })
            Assert.Equal("42501", (await Assert.ThrowsAsync<PostgresException>(() => Sql(connection, $"SET ROLE {role}"))).SqlState);
        Assert.Equal("42501", (await Assert.ThrowsAsync<PostgresException>(() => Sql(connection, "SELECT amdn_identity.ceremony_snapshot(gen_random_uuid())"))).SqlState);
        await using var transaction = await connection.BeginTransactionAsync();
        await Sql(connection, "SELECT set_config('amdn.tenant_id',@tenant,true),set_config('amdn.user_id',@user,true)", ("tenant", member.Tenant.ToString()), ("user", member.User.ToString()));
        Assert.Equal("42501", (await Assert.ThrowsAsync<PostgresException>(() => Sql(connection, "SELECT * FROM amdn_identity.devices"))).SqlState);
        await transaction.RollbackAsync();
    }

    [Fact]
    public async Task ExecutorIsScopedByRlsAndCannotModifyGrantAuthority()
    {
        var alice = await Setup(); var bob = await Setup();
        await using var owner = await Owner();
        await Sql(owner, "SET ROLE amdn_identity_ceremony_executor");
        await using var transaction = await owner.BeginTransactionAsync();
        Assert.Equal(0L, await Sql(owner, "SELECT count(*) FROM amdn_identity.users"));
        await Sql(owner, "SELECT set_config('amdn.tenant_id',@tenant,true),set_config('amdn.user_id',@user,true),set_config('amdn.issuer',@issuer,true),set_config('amdn.subject',@subject,true)",
            ("tenant", alice.Tenant.ToString()), ("user", alice.User.ToString()), ("issuer", issuer.Issuer), ("subject", alice.Subject));
        Assert.Equal(1L, await Sql(owner, "SELECT count(*) FROM amdn_identity.users"));
        Assert.Equal(0L, await Sql(owner, "SELECT count(*) FROM amdn_identity.users WHERE tenant_id=@tenant", ("tenant", bob.Tenant)));
        Assert.Equal(0L, await Sql(owner, "WITH changed AS (UPDATE amdn_identity.users SET identity_version=identity_version+1 WHERE tenant_id=@tenant RETURNING *) SELECT count(*) FROM changed", ("tenant", bob.Tenant)));
        Assert.Equal("42501", (await Assert.ThrowsAsync<PostgresException>(() => Sql(owner, "UPDATE amdn_identity.device_management_grants SET expires_at=expires_at+interval '1 hour'"))).SqlState);
        await transaction.RollbackAsync();
    }

    [Theory]
    [InlineData("runtime")]
    [InlineData("provisioner")]
    [InlineData("migrator")]
    public async Task EnrollmentPoolRejectsOtherCredentials(string role)
    {
        await using var pool = EnrollmentDatabase.Pool(_state.IdentityConnection(role));
        await Assert.ThrowsAsync<InvalidOperationException>(async () => { await using var connection = await pool.OpenConnectionAsync(); });
    }

    [Fact]
    public async Task PoolRejectsAccidentalColumnReadPrivilege()
    {
        await using var owner = await Owner();
        await Sql(owner, "GRANT SELECT(tenant_id) ON amdn_identity.tenants TO amdn_identity_enrollment");
        try
        {
            await using var pool = EnrollmentDatabase.Pool(_state.IdentityConnection("enrollment"));
            await Assert.ThrowsAsync<InvalidOperationException>(async () => { await using var connection = await pool.OpenConnectionAsync(); });
        }
        finally { await Sql(owner, "REVOKE SELECT(tenant_id) ON amdn_identity.tenants FROM amdn_identity_enrollment"); }
    }

    [Fact]
    public async Task MappedPrincipalCannotOutliveStricterApplicationStepUpDeadline()
    {
        var member = await Setup();
        await using var pool = EnrollmentDatabase.Pool(_state.IdentityConnection("enrollment"), 1);
        await using var gateway = App(member.Config, pool, maximumAge: 5); using var client = issuer.Client(gateway);
        // Token lives 300 seconds, database config allows 900; only the mapped
        // application's five-second bound can deny after this test-only wait.
        AssertOutcome("forbidden", await Send(client, member, "begin", "{}"u8.ToArray(), scenario: "expire-mapped"));
        await using var owner = await Owner();
        Assert.Equal(0L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_ceremonies WHERE tenant_id=@tenant", ("tenant", member.Tenant)));
    }

    private Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program> App(Guid configuration, NpgsqlDataSource pool, int maximumAge = 120) =>
        issuer.Application<Program>(settings: new Dictionary<string, string?>
        {
            ["Authentication:DeviceStepUp:Enabled"] = "true",
            ["Authentication:DeviceStepUp:AllowedAcrValues:0"] = Acr,
            ["Authentication:DeviceStepUp:MaximumAgeSeconds"] = maximumAge.ToString(System.Globalization.CultureInfo.InvariantCulture)
        }, configure: services =>
        {
            services.AddSingleton(new EnrollmentCommands(pool));
            services.AddSingleton(provider => new EnrollmentPrincipalMapper(new EnrollmentConfiguration(configuration, "https://ceremony.invalid"),
                provider.GetRequiredService<IOptions<DeviceStepUpSettings>>(), TimeProvider.System));
            services.AddSingleton<IStartupFilter, Probes>();
        });

    private sealed class Probes : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Map("/__enrollment", branch =>
            {
                branch.UseRouting(); branch.UseAuthentication(); branch.UseAuthorization();
                branch.UseEndpoints(endpoints => endpoints.MapPost("/{tenant:guid}/{action}/{id?}/{stage?}", async (HttpContext context, EnrollmentPrincipalMapper mapper, EnrollmentCommands commands) =>
                {
                    if (context.Request.Headers.ContainsKey("X-Test-Replace-User"))
                        context.User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("iss", "forged"), new Claim("sub", "forged"), new Claim("scope", "device.manage"), new Claim("acr", Acr) }, IdentityAuthentication.Scheme));
                    if (context.Request.Headers.ContainsKey("X-Test-Mutate-User"))
                    {
                        var identity = (ClaimsIdentity)context.User.Identity!;
                        foreach (var claim in identity.Claims.ToArray()) identity.RemoveClaim(claim);
                        identity.AddClaims(new[] { new Claim("iss", "forged"), new Claim("sub", "forged"), new Claim("scope", "device.manage") });
                    }
                    var principal = await mapper.FromRequestAsync(context, Guid.Parse((string)context.Request.RouteValues["tenant"]!));
                    if (principal is null) return Results.StatusCode(403);
                    if (context.Request.Headers.ContainsKey("X-Test-Expire-Mapped")) await Task.Delay(6000, context.RequestAborted);
                    using var buffer = new MemoryStream(); await context.Request.Body.CopyToAsync(buffer);
                    var body = buffer.ToArray(); var replay = context.Request.Headers["Idempotency-Key"].ToString();
                    var result = (string)context.Request.RouteValues["action"]! == "begin"
                        ? await commands.BeginAsync(principal, "enrollment", 1, null, replay, body, context.RequestAborted)
                        : await commands.CompleteAsync(principal, Guid.Parse((string)context.Request.RouteValues["id"]!), (string)context.Request.RouteValues["stage"]!, replay, body, context.RequestAborted);
                    return Results.Json(result);
                }).AllowAnonymous()); // Test-only mapper exercises missing-token rejection itself.
            });
            next(app);
        };
    }

    private async Task<Member> Setup()
    {
        await using var provisioning = IdentityDatabase.ProvisioningPool(_state.IdentityConnection("provisioner"));
        var service = new IdentityProvisioner(provisioning); var subject = Guid.NewGuid().ToString("N");
        var person = await service.EnsureMemberAsync(await service.CreateTenantAsync(), issuer.Issuer, subject);
        await using var owner = await Owner();
        var configuration = (Guid)(await Sql(owner, "INSERT INTO amdn_identity.device_configurations(rp_id,origin,allowed_acrs,maximum_age_seconds,enabled) VALUES('ceremony.invalid','https://ceremony.invalid',ARRAY['urn:amdn:test:strong'],900,true) RETURNING configuration_id"))!;
        await Sql(owner, "INSERT INTO amdn_identity.device_management_grants(tenant_id,user_id,postman_id,expires_at) VALUES(@tenant,@user,@postman,clock_timestamp()+interval '1 hour')",
            ("tenant", person.TenantId), ("user", person.UserId), ("postman", person.PostmanId));
        return new(person.TenantId, person.UserId, configuration, subject);
    }
    private async Task<NpgsqlConnection> Owner()
    {
        var connection = new NpgsqlConnection(_state.IdentityConnection("migrator")); await connection.OpenAsync();
        await Sql(connection, "SET ROLE amdn_identity_owner"); return connection;
    }
    private static async Task<object?> Sql(NpgsqlConnection connection, string sql, params (string, object)[] values)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        foreach (var (name, value) in values) command.Parameters.AddWithValue(name, value);
        return await command.ExecuteScalarAsync();
    }
    private async Task<HttpResponseMessage> Request(HttpClient client, Member member, string path, byte[] bytes, string scenario = "valid", Guid? tenant = null, string? replay = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"/__enrollment/{tenant ?? member.Tenant}/{path}");
        request.Headers.Add("Idempotency-Key", replay ?? Guid.NewGuid().ToString("N"));
        if (scenario is "replace-user" or "forged-user-no-token" or "forged-user-no-scope") request.Headers.Add("X-Test-Replace-User", "true");
        if (scenario == "mutate-user") request.Headers.Add("X-Test-Mutate-User", "true");
        if (scenario == "expire-mapped") request.Headers.Add("X-Test-Expire-Mapped", "true");
        if (scenario is not ("missing" or "forged-user-no-token"))
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", issuer.Token(payload =>
            {
                var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                payload["sub"] = member.Subject; payload["scope"] = "device.manage"; payload["acr"] = Acr; payload["auth_time"] = now - 10;
                switch (scenario)
                {
                    case "no-scope": case "forged-user-no-scope": payload["scope"] = "postman.read"; break;
                    case "scope-prefix": payload["scope"] = "device.manage.all"; break;
                    case "no-acr": payload.Remove("acr"); break;
                    case "no-auth-time": payload.Remove("auth_time"); break;
                    case "wrong-acr": payload["acr"] = "urn:unapproved"; break;
                    case "old-step-up": payload["auth_time"] = now - 121; break;
                    case "expired-within-skew": payload["iat"] = now - 60; payload["nbf"] = now - 60; payload["exp"] = now - 1; payload["auth_time"] = now - 60; break;
                    case "oversize-client": payload["client_id"] = new string('a', 257); break;
                    case "different-client": payload["client_id"] = "another-client"; break;
                    case "expire-mapped": payload["auth_time"] = now; break;
                }
            }, rogue: scenario == "signature"));
        request.Content = new ByteArrayContent(bytes); request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return await client.SendAsync(request);
    }
    private async Task<JsonElement> Send(HttpClient client, Member member, string path, byte[] body, string scenario = "valid", Guid? tenant = null, string? replay = null)
    {
        using var response = await Request(client, member, path, body, scenario, tenant, replay);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync()); return document.RootElement.Clone();
    }
    private static byte[] Challenge(JsonElement value) => Convert.FromHexString(value.GetProperty("challenge_hex").GetString()!);
    private static void AssertOutcome(string expected, JsonElement result) => Assert.Equal(expected, result.GetProperty("outcome").GetString());
}
