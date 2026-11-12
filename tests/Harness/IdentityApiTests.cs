using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using AMDN.Integration.Tests;
using AMDN.Provisioning;
using Microsoft.AspNetCore.Mvc.Testing;
using Npgsql;
using Xunit;

namespace AMDN.Harness.Tests;

public sealed class IdentityApiTests
{
    [Fact]
    public async Task ActualHttpsApisProvisionReplayAndReadOnlyTheSelectedOwner()
    {
        await using var api = await Api.Start();
        var key = Guid.NewGuid().ToString("N");
        var creates = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => api.Create(key)));
        Assert.All(creates, response => Assert.Equal(201, response.Status));
        var tenant = creates[0].Id("tenant_id");
        Assert.All(creates, response => Assert.Equal(tenant, response.Id("tenant_id")));
        var memberKey = Guid.NewGuid().ToString("N");
        var enrollments = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => api.Enroll(tenant, "alice", memberKey)));
        Assert.All(enrollments, response => Assert.Equal(201, response.Status));
        var postman = enrollments[0].Id("postman_id");
        Assert.All(enrollments, response => Assert.Equal(postman, response.Id("postman_id")));
        var owner = await api.Read("alice", tenant);
        Assert.Equal(200, owner.Status);
        Assert.Equal(postman, owner.Id("postman_id"));
        Assert.Equal("\"1\"", owner.ETag);
        Assert.Equal(new[] { "policy", "policy_version", "postman_id" }, owner.Json.EnumerateObject().Select(p => p.Name).Order().ToArray());
        Assert.True(owner.Json.GetProperty("policy").GetProperty("receive_enabled").GetBoolean());
        Assert.Equal(2L, await api.Admin("SELECT count(*) FROM amdn_identity.provisioning_audit WHERE actor_id=@actor"));
        Assert.Equal(2L, await api.Admin("SELECT count(*) FROM amdn_identity.provisioning_commands WHERE actor_id=@actor"));
        var changed = await api.Send(api.Operator, "POST", "/v1/tenants", api.OperatorToken(), "{\"display_name\": \"Synthetic\"}", key);
        Assert.Equal(409, changed.Status); // Different exact bytes, same semantic fields.
        Assert.Equal(404, (await api.Send(api.Owner, "POST", "/v1/tenants", api.OperatorToken(), "{}", key)).Status);
        Assert.Equal(404, (await api.Send(api.Operator, "GET", "/v1/postman?tenant_id=" + tenant, api.Token("alice"))).Status);
        Assert.Equal(400, (await api.Send(api.Owner, "GET", "/v1/postman", api.Token("alice"), tenantHeader: tenant)).Status);
        Assert.Equal(200, (await api.Send(api.Owner, "GET", "/v1/postman?tenant_id=" + tenant, api.Token("alice"), tenantHeader: Guid.NewGuid())).Status);
    }

    [Fact]
    public async Task ScopeMembershipAndCurrentObjectGrantAreAllRequired()
    {
        await using var api = await Api.Start();
        var tenant = (await api.Create()).Id("tenant_id");
        var other = (await api.Create()).Id("tenant_id");
        var alice = await api.Enroll(tenant, "alice");
        await api.Enroll(tenant, "ann");
        await api.Enroll(other, "bob");
        var secondAlice = await api.Enroll(other, "alice");
        Assert.NotEqual(alice.Id("postman_id"), secondAlice.Id("postman_id"));
        Assert.Equal(secondAlice.Id("postman_id"), (await api.Read("alice", other)).Id("postman_id"));
        Assert.Equal(404, (await api.Read("ann", other)).Status);
        Assert.Equal(404, (await api.Read("unknown", tenant)).Status);
        Assert.Equal(404, (await api.Read("alice", Guid.NewGuid())).Status);
        Assert.Equal(403, (await api.Read("alice", tenant, "postman.read.other")).Status);
        Assert.Equal(403, (await api.Read("alice", tenant, "")).Status);
        Assert.Equal(401, (await api.Send(api.Owner, "GET", "/v1/postman?tenant_id=" + tenant, null)).Status);
        Assert.Equal(401, (await api.Send(api.Owner, "GET", "/v1/postman?tenant_id=" + tenant, api.Oidc.Token(rogue: true))).Status);
        // Provider authority claims do not alter the selected owner's object.
        var forged = api.Oidc.Token(claims => { claims["sub"] = "alice"; claims["tenant_id"] = other; claims["role"] = "platform-admin"; claims["postman_id"] = secondAlice.Id("postman_id"); });
        Assert.Equal(alice.Id("postman_id"), (await api.Send(api.Owner, "GET", "/v1/postman?tenant_id=" + tenant, forged)).Id("postman_id"));
        await api.Admin("UPDATE amdn_identity.owner_grants SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=@tenant", tenant);
        Assert.Equal(404, (await api.Read("alice", tenant)).Status);
        await api.Admin("UPDATE amdn_identity.owner_grants SET expires_at=NULL,status='revoked' WHERE tenant_id=@tenant", tenant);
        Assert.Equal(201, (await api.Enroll(tenant, "alice")).Status);
        Assert.Equal(404, (await api.Read("alice", tenant)).Status); // Registration must not restore revoked authority.
        Assert.Equal(200, (await api.Read("alice", other)).Status);
        await api.Admin("UPDATE amdn_identity.memberships SET status='revoked' WHERE tenant_id=@tenant AND subject='alice'", other);
        Assert.Equal(404, (await api.Read("alice", other)).Status);
    }

    [Fact]
    public async Task PlatformAuthorityCannotComeFromScopesOrTenantOwnershipAndReplayRechecksRevocation()
    {
        await using var api = await Api.Start();
        var key = Guid.NewGuid().ToString("N");
        var tenant = (await api.Create(key)).Id("tenant_id");
        await api.Enroll(tenant, "alice");
        var ordinary = api.Token("alice", "tenant.provision membership.provision postman.read");
        Assert.Equal(403, (await api.Send(api.Operator, "POST", "/v1/tenants", ordinary, "{\"display_name\":\"Synthetic\"}", Guid.NewGuid().ToString("N"))).Status);
        Assert.Equal(403, (await api.Send(api.Operator, "POST", "/v1/tenants", api.Token(api.Subject, "postman.read"), "{\"display_name\":\"Synthetic\"}", key)).Status);
        await using var other = await Api.Start();
        Assert.Equal(404, (await other.Enroll(tenant, "intruder")).Status);
        await api.Admin("UPDATE amdn_identity.platform_grants SET status='revoked' WHERE actor_id=@actor");
        Assert.Equal(403, (await api.Create(key)).Status);
        Assert.Equal(403, (await api.Enroll(tenant, "another")).Status);
        Assert.Equal(2L, await api.Admin("SELECT count(*) FROM amdn_identity.provisioning_audit WHERE actor_id=@actor"));
    }

    [Fact]
    public async Task ConcurrentCommandsRespectDurableTenantAndMemberQuotas()
    {
        await using var api = await Api.Start(tenantLimit: 1, memberLimit: 1);
        var responses = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => api.Create()));
        var created = Assert.Single(responses, r => r.Status == 201);
        Assert.Equal(5, responses.Count(r => r.Status == 429 && r.RetryAfter == "60"));
        var tenant = created.Id("tenant_id");
        var members = await Task.WhenAll(Enumerable.Range(0, 6).Select(i => api.Enroll(tenant, "user-" + i)));
        Assert.Single(members, r => r.Status == 201);
        Assert.Equal(5, members.Count(r => r.Status == 429));
        Assert.Equal(1L, await api.Admin("SELECT count(*) FROM amdn_identity.tenants WHERE provisioner_actor=@actor"));
        Assert.Equal(1L, await api.Admin("SELECT count(*) FROM amdn_identity.memberships WHERE tenant_id=@tenant", tenant));
        Assert.Equal(2L, await api.Admin("SELECT count(*) FROM amdn_identity.provisioning_audit WHERE actor_id=@actor"));
    }

    [Theory]
    [InlineData("{\"display_name\":\"x\",\"display_name\":\"y\"}")]
    [InlineData("{\"display_name\":\"x\",\"tenant_id\":\"forged\"}")]
    [InlineData("{\"display_name\":5}")]
    [InlineData("{\"display_name\":\" \"}")]
    [InlineData("{}")]
    [InlineData("[]")]
    public async Task StrictCommandsRejectMalformedOrUnknownFieldsWithoutEffects(string body)
    {
        await using var api = await Api.Start();
        var response = await api.Send(api.Operator, "POST", "/v1/tenants", api.OperatorToken(), body, Guid.NewGuid().ToString("N"));
        Assert.Equal(400, response.Status);
        Assert.Equal("application/problem+json", response.ContentType);
        Assert.Equal(0L, await api.Admin("SELECT count(*) FROM amdn_identity.tenants WHERE provisioner_actor=@actor"));
    }

    [Fact]
    public async Task BodyBoundsKeysEncodingAndIssuerRestrictionsAreEnforced()
    {
        await using var api = await Api.Start();
        var tenant = (await api.Create()).Id("tenant_id");
        var valid = "{\"display_name\":\"Synthetic\"}";
        Assert.Equal(400, (await api.Send(api.Operator, "POST", "/v1/tenants", api.OperatorToken(), valid)).Status);
        Assert.Equal(400, (await api.Send(api.Operator, "POST", "/v1/tenants", api.OperatorToken(), valid, "short")).Status);
        Assert.Equal(413, (await api.Send(api.Operator, "POST", "/v1/tenants", api.OperatorToken(), new string('x', 17000), Guid.NewGuid().ToString("N"))).Status);
        Assert.Equal(415, (await api.Send(api.Operator, "POST", "/v1/tenants", api.OperatorToken(), valid, Guid.NewGuid().ToString("N"), compressed: true)).Status);
        var foreign = JsonSerializer.Serialize(new { issuer = "https://foreign.invalid", subject = "alice" });
        Assert.Equal(400, (await api.Send(api.Operator, "POST", $"/v1/tenants/{tenant}/memberships", api.OperatorToken(), foreign, Guid.NewGuid().ToString("N"))).Status);
        Assert.Equal(400, (await api.Send(api.Owner, "GET", $"/v1/postman?tenant_id={tenant}&tenant_id={tenant}", api.Token("alice"))).Status);
        Assert.Equal(400, (await api.Send(api.Owner, "GET", $"/v1/postman?tenant_id={tenant}&postman_id={Guid.NewGuid()}", api.Token("alice"))).Status);
    }

    [Fact]
    public async Task FailedAuditInsertRollsBackEffectQuotaAndReplayThenRetrySucceeds()
    {
        await using var api = await Api.Start(tenantLimit: 1);
        await api.Admin("""
            CREATE FUNCTION amdn_identity.test_reject_audit() RETURNS trigger LANGUAGE plpgsql AS $body$
            BEGIN RAISE EXCEPTION 'Synthetic audit failure'; END $body$;
            CREATE TRIGGER test_reject_audit BEFORE INSERT ON amdn_identity.provisioning_audit
              FOR EACH ROW EXECUTE FUNCTION amdn_identity.test_reject_audit();
            """);
        var key = Guid.NewGuid().ToString("N");
        try
        {
            var failed = await api.Create(key);
            Assert.Equal(503, failed.Status);
            Assert.Equal("5", failed.RetryAfter);
            Assert.DoesNotContain("Synthetic audit failure", failed.Json.ToString());
            Assert.Equal(0L, await api.Admin("SELECT count(*) FROM amdn_identity.tenants WHERE provisioner_actor=@actor"));
            Assert.Equal(0L, await api.Admin("SELECT count(*) FROM amdn_identity.provisioning_commands WHERE actor_id=@actor"));
            Assert.Equal(0, await api.Admin("SELECT allocated_tenants FROM amdn_identity.platform_grants WHERE actor_id=@actor"));
        }
        finally
        {
            await api.Admin("DROP TRIGGER test_reject_audit ON amdn_identity.provisioning_audit; DROP FUNCTION amdn_identity.test_reject_audit()");
        }
        Assert.Equal(201, (await api.Create(key)).Status);
        Assert.Equal(201, (await api.Create(key)).Status);
        Assert.Equal(1L, await api.Admin("SELECT count(*) FROM amdn_identity.provisioning_audit WHERE actor_id=@actor"));
    }

    [Fact]
    public async Task ApiRolesCannotMintPlatformAuthorityOrRewriteAuditAndWrongCredentialFailsClosed()
    {
        await using var api = await Api.Start();
        foreach (var role in new[] { "runtime", "provisioner" })
        {
            await using var connection = new NpgsqlConnection(api.State.IdentityConnection(role));
            await connection.OpenAsync();
            foreach (var sql in new[] { "UPDATE amdn_identity.platform_grants SET status='active'", "DELETE FROM amdn_identity.provisioning_audit", "TRUNCATE amdn_identity.provisioning_commands" })
            {
                await using var command = new NpgsqlCommand(sql, connection);
                Assert.Equal("42501", (await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync())).SqlState);
            }
        }
        var settings = api.OwnerSettings();
        settings["IdentityApi:ConnectionString"] = api.State.IdentityConnection("provisioner");
        await using var wrong = api.Oidc.Application<Program>(settings);
        using var client = api.Oidc.Client(wrong);
        var response = await api.Send(client, "GET", "/v1/postman?tenant_id=" + Guid.NewGuid(), api.Token("alice"));
        Assert.Equal(503, response.Status);
        Assert.DoesNotContain(api.State.IdentityProvisionerPassword, response.Json.ToString());
    }

    [Fact]
    public async Task ActorRateLimitReturnsProblemAndDoesNotDisableLiveness()
    {
        await using var api = await Api.Start(ownerActorLimit: 1);
        var tenant = (await api.Create()).Id("tenant_id");
        await api.Enroll(tenant, "alice");
        Assert.Equal(200, (await api.Read("alice", tenant)).Status);
        var limited = await api.Read("alice", tenant);
        Assert.Equal(429, limited.Status);
        Assert.Equal("60", limited.RetryAfter);
        Assert.Equal("application/problem+json", limited.ContentType);
        Assert.Equal(200, (await api.Send(api.Owner, "GET", "/health/live", api.Token("alice"))).Status);
    }

    [Fact]
    public async Task TenantBudgetUsesVerifiedMembershipAndApisRequireHttpsAndExplicitOptIn()
    {
        await using var api = await Api.Start();
        var tenant = (await api.Create()).Id("tenant_id");
        await api.Enroll(tenant, "alice");
        await api.Enroll(tenant, "ann");
        var settings = api.OwnerSettings();
        settings["IdentityApi:TenantRequestsPerMinute"] = "1";
        await using var limited = api.Oidc.Application<Program>(settings);
        using var client = api.Oidc.Client(limited);
        Assert.Equal(404, (await api.Send(client, "GET", "/v1/postman?tenant_id=" + tenant, api.Token("foreign"))).Status);
        Assert.Equal(200, (await api.Send(client, "GET", "/v1/postman?tenant_id=" + tenant, api.Token("alice"))).Status);
        Assert.Equal(429, (await api.Send(client, "GET", "/v1/postman?tenant_id=" + tenant, api.Token("ann"))).Status);
        await using var insecure = api.Oidc.Application<Program>(api.OwnerSettings(), https: false);
        using var http = insecure.CreateClient();
        Assert.Equal(400, (await api.Send(http, "GET", "/v1/postman?tenant_id=" + tenant, api.Token("alice"))).Status);
        await using var disabledOwner = api.Oidc.Application<Program>();
        await using var disabledProvisioner = api.Oidc.Application<ProvisioningProgram>();
        using var owner = api.Oidc.Client(disabledOwner);
        using var provisioner = api.Oidc.Client(disabledProvisioner);
        Assert.Equal(404, (await api.Send(owner, "GET", "/v1/postman?tenant_id=" + tenant, api.Token("alice"))).Status);
        Assert.Equal(404, (await api.Send(provisioner, "POST", "/v1/tenants", api.OperatorToken(), "{}", Guid.NewGuid().ToString("N"))).Status);
    }

    [Fact]
    public async Task GrantRevocationCommittedBeforeBlockedReadDeniesTheRead()
    {
        await using var api = await Api.Start();
        var tenant = (await api.Create()).Id("tenant_id");
        await api.Enroll(tenant, "alice");
        await using var connection = new NpgsqlConnection(api.State.IdentityConnection("provisioner"));
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        await using var revoke = new NpgsqlCommand("UPDATE amdn_identity.owner_grants SET status='revoked' WHERE tenant_id=@tenant", connection, transaction);
        revoke.Parameters.AddWithValue("tenant", tenant);
        await revoke.ExecuteNonQueryAsync();
        var read = api.Read("alice", tenant);
        await Task.Delay(100);
        Assert.False(read.IsCompleted);
        await transaction.CommitAsync();
        Assert.Equal(404, (await read.WaitAsync(TimeSpan.FromSeconds(10))).Status);
    }

    private sealed record Response(int Status, JsonElement Json, string? ETag, string? RetryAfter, string? ContentType)
    {
        public Guid Id(string name) => Json.GetProperty(name).GetGuid();
    }

    private sealed class Api : IAsyncDisposable
    {
        public RunState State { get; } = RunState.Load();
        public OidcFixture Oidc { get; } = new();
        public string Subject { get; } = "operator-" + Guid.NewGuid().ToString("N");
        private Guid Actor { get; set; }
        private WebApplicationFactory<ProvisioningProgram> _operator = null!;
        private WebApplicationFactory<Program> _owner = null!;
        public HttpClient Operator { get; private set; } = null!;
        public HttpClient Owner { get; private set; } = null!;
        private int OwnerLimit { get; set; }

        public static async Task<Api> Start(int tenantLimit = 8, int memberLimit = 8, int ownerActorLimit = 1000)
        {
            var api = new Api { OwnerLimit = ownerActorLimit };
            await api.Oidc.InitializeAsync();
            api.Actor = (Guid)(await api.Admin("""
                INSERT INTO amdn_identity.platform_grants(issuer,subject,expires_at,tenant_limit)
                  VALUES(@issuer,@subject,clock_timestamp()+interval '1 hour',@limit) RETURNING actor_id
                """, limit: tenantLimit))!;
            api._operator = api.Oidc.Application<ProvisioningProgram>(new Dictionary<string, string?>
            {
                ["ProvisioningApi:Enabled"] = "true",
                ["ProvisioningApi:ConnectionString"] = api.State.IdentityConnection("provisioner"),
                ["ProvisioningApi:RequestsPerMinute"] = "1000",
                ["ProvisioningApi:ActorRequestsPerMinute"] = "1000",
                ["ProvisioningApi:TenantMemberLimit"] = memberLimit.ToString(),
                ["ProvisioningApi:OwnerIssuer"] = api.Oidc.Issuer
            });
            api._owner = api.Oidc.Application<Program>(api.OwnerSettings());
            api.Operator = api.Oidc.Client(api._operator);
            api.Owner = api.Oidc.Client(api._owner);
            return api;
        }

        public Dictionary<string, string?> OwnerSettings() => new()
        {
            ["IdentityApi:Enabled"] = "true",
            ["IdentityApi:ConnectionString"] = State.IdentityConnection("runtime"),
            ["IdentityApi:TenantRequestsPerMinute"] = "1000",
            ["IdentityApi:RequestsPerMinute"] = "1000",
            ["IdentityApi:ActorRequestsPerMinute"] = OwnerLimit.ToString()
        };
        public string Token(string subject, string scope = "postman.read") => Oidc.Token(claims =>
        {
            claims["sub"] = subject;
            if (scope.Length == 0) claims.Remove("scope"); else claims["scope"] = scope;
        });
        public string OperatorToken() => Token(Subject, "tenant.provision membership.provision");
        public Task<Response> Create(string? key = null) => Send(Operator, "POST", "/v1/tenants", OperatorToken(), "{\"display_name\":\"Synthetic\"}", key ?? Guid.NewGuid().ToString("N"));
        public Task<Response> Enroll(Guid tenant, string subject, string? key = null) => Send(Operator, "POST", $"/v1/tenants/{tenant}/memberships", OperatorToken(),
            JsonSerializer.Serialize(new { issuer = Oidc.Issuer, subject }), key ?? Guid.NewGuid().ToString("N"));
        public Task<Response> Read(string subject, Guid tenant, string scope = "postman.read") => Send(Owner, "GET", "/v1/postman?tenant_id=" + tenant, Token(subject, scope));

        public async Task<Response> Send(HttpClient client, string method, string path, string? token, string? body = null, string? key = null, bool compressed = false, Guid? tenantHeader = null)
        {
            using var request = new HttpRequestMessage(new HttpMethod(method), path);
            if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            if (key is not null) request.Headers.Add("Idempotency-Key", key);
            if (tenantHeader is not null) request.Headers.Add("X-Tenant-ID", tenantHeader.ToString());
            if (body is not null) request.Content = new StringContent(body, Encoding.UTF8, "application/json");
            if (compressed) request.Content!.Headers.ContentEncoding.Add("gzip");
            using var response = await client.SendAsync(request);
            var text = await response.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(text.Length == 0 ? "null" : text);
            return new((int)response.StatusCode, document.RootElement.Clone(), response.Headers.ETag?.ToString(), response.Headers.RetryAfter?.ToString(), response.Content.Headers.ContentType?.MediaType);
        }

        public async Task<object?> Admin(string sql, Guid? tenant = null, int limit = 0)
        {
            await using var connection = new NpgsqlConnection(State.IdentityConnection("migrator"));
            await connection.OpenAsync();
            await using var transaction = await connection.BeginTransactionAsync();
            await using var role = new NpgsqlCommand("SET LOCAL ROLE amdn_identity_owner", connection, transaction);
            await role.ExecuteNonQueryAsync();
            await using var command = new NpgsqlCommand(sql, connection, transaction);
            command.Parameters.AddWithValue("actor", Actor);
            command.Parameters.AddWithValue("issuer", Oidc.Issuer);
            command.Parameters.AddWithValue("subject", Subject);
            command.Parameters.AddWithValue("limit", limit);
            command.Parameters.AddWithValue("tenant", tenant ?? Guid.Empty);
            var result = await command.ExecuteScalarAsync();
            await transaction.CommitAsync();
            return result;
        }

        public async ValueTask DisposeAsync()
        {
            Owner?.Dispose(); Operator?.Dispose();
            if (_owner is not null) await _owner.DisposeAsync();
            if (_operator is not null) await _operator.DisposeAsync();
            await Oidc.DisposeAsync();
        }
    }
}
