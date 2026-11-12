using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using AMDN.Identity.Authentication;
using AMDN.Identity.Membership;
using AMDN.Infrastructure.Identity;
using AMDN.Integration.Tests;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Xunit;

namespace AMDN.Harness.Tests;

public sealed class IdentityPersistenceTests
{
    private const string Issuer = "https://synthetic-identity.invalid";
    private readonly RunState _state = RunState.Load();
    private NpgsqlDataSource Runtime() => IdentityDatabase.RuntimePool(_state.IdentityConnection("runtime"), 1);
    private NpgsqlDataSource Provisioning() => IdentityDatabase.ProvisioningPool(_state.IdentityConnection("provisioner"));
    private static ClaimsPrincipal Caller(string subject, string issuer = Issuer) => new(new ClaimsIdentity(
        [new("iss", issuer), new("sub", subject)], IdentityAuthentication.Scheme));

    [Fact]
    public async Task ConcurrentRegistrationHasOneStablePrimaryPostmanAndTenantLocalIdentity()
    {
        await using var db = Provisioning();
        var provisioner = new IdentityProvisioner(db);
        var tenant = await provisioner.CreateTenantAsync();
        var subject = Guid.NewGuid().ToString();
        var registrations = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => provisioner.EnsureMemberAsync(tenant, Issuer, subject)));
        Assert.Single(registrations.Distinct());
        var other = await provisioner.EnsureMemberAsync(await provisioner.CreateTenantAsync(), Issuer, subject);
        Assert.NotEqual(registrations[0].UserId, other.UserId);
        Assert.NotEqual(registrations[0].PostmanId, other.PostmanId);
        await using var runtime = Runtime();
        var store = new PersonalPostmanStore(runtime);
        Assert.Null(await store.ReadAsync(Caller(subject))); // Ambiguous; selection is required.
        Assert.Equal(registrations[0], await store.ReadAsync(Caller(subject), tenant));
        Assert.Equal(other, await store.ReadAsync(Caller(subject), other.TenantId));
        Assert.Null(await store.ReadAsync(Caller(subject), Guid.NewGuid()));
        Assert.Null(await store.ReadAsync(Caller(subject, Issuer + "/different"), tenant));
        Assert.Null(await store.ReadAsync(new ClaimsPrincipal(), tenant));
    }

    [Fact]
    public async Task DatabaseConstraintsProtectPrimaryOwnershipAndImmutableBindings()
    {
        await using var db = Provisioning();
        var provisioner = new IdentityProvisioner(db);
        var first = await provisioner.EnsureMemberAsync(await provisioner.CreateTenantAsync(), Issuer, Guid.NewGuid().ToString());
        var second = await provisioner.EnsureMemberAsync(await provisioner.CreateTenantAsync(), Issuer, Guid.NewGuid().ToString());
        await Denied(db, "INSERT INTO amdn_identity.postmen (tenant_id,owner_user_id) VALUES (@tenant,@user)", "23505", first);
        await Denied(db, "INSERT INTO amdn_identity.postmen (tenant_id,owner_user_id) VALUES (@tenant,@user)", "23503", first with { UserId = second.UserId });
        await Denied(db, "UPDATE amdn_identity.users SET user_id=gen_random_uuid() WHERE tenant_id=@tenant", "42501", first);
        await Denied(db, "UPDATE amdn_identity.memberships SET subject='rebound' WHERE tenant_id=@tenant", "42501", first);
        // The migration owner also encounters immutable identity triggers.
        await using var owner = NpgsqlDataSource.Create(_state.IdentityConnection("migrator"));
        await using var connection = await owner.OpenConnectionAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        await Sql(connection, "SET LOCAL ROLE amdn_identity_owner");
        var exception = await Assert.ThrowsAsync<PostgresException>(() => Sql(connection,
            "UPDATE amdn_identity.postmen SET postman_id=gen_random_uuid() WHERE tenant_id=@tenant", ("tenant", first.TenantId)));
        Assert.Equal("23514", exception.SqlState);
    }

    [Fact]
    public async Task WrongRolesFailBeforeRuntimeUseAndRuntimeHasNoWritePrivileges()
    {
        foreach (var role in new[] { "provisioner", "migrator" })
        {
            await using var wrong = IdentityDatabase.RuntimePool(_state.IdentityConnection(role));
            await Assert.ThrowsAsync<InvalidOperationException>(async () => { await using var connection = await wrong.OpenConnectionAsync(); });
        }
        await using var runtime = Runtime();
        await using var connection2 = await runtime.OpenConnectionAsync();
        Assert.Equal(4L, await Sql(connection2, """
            SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='amdn_identity' AND c.relname IN ('tenants','users','memberships','postmen')
              AND c.relrowsecurity AND c.relforcerowsecurity
            """));
        foreach (var sql in new[] { "INSERT INTO amdn_identity.tenants DEFAULT VALUES", "TRUNCATE amdn_identity.postmen",
            "UPDATE amdn_identity.memberships SET status='revoked'", "DELETE FROM amdn_identity.postmen",
            "SET ROLE amdn_identity_owner", "SET ROLE amdn_identity_provisioner", "CREATE TABLE amdn_identity.untrusted(id int)",
            "SELECT * FROM amdn_identity.schema_migrations" })
        {
            var exception = await Assert.ThrowsAsync<PostgresException>(() => Sql(connection2, sql));
            Assert.Equal("42501", exception.SqlState);
        }
    }

    [Fact]
    public async Task PoolReusesConnectionWithoutContextAfterSuccessDenialRollbackErrorAndCancellation()
    {
        await using var provisioning = Provisioning();
        var provisioner = new IdentityProvisioner(provisioning);
        var tenant = await provisioner.CreateTenantAsync();
        var alice = Guid.NewGuid().ToString();
        var bob = Guid.NewGuid().ToString();
        var a = await provisioner.EnsureMemberAsync(tenant, Issuer, alice);
        var b = await provisioner.EnsureMemberAsync(tenant, Issuer, bob);
        await using var runtime = Runtime();
        var store = new PersonalPostmanStore(runtime);
        var pid = await Clean(runtime);
        foreach (var name in new[] { alice, bob, alice, bob })
        {
            Assert.Equal(name == alice ? a : b, await store.ReadAsync(Caller(name)));
            Assert.Null(await store.ReadAsync(Caller("unknown-" + name)));
            Assert.Equal(pid, await Clean(runtime));
        }
        var concurrent = await Task.WhenAll(Enumerable.Range(0, 8).Select(i => store.ReadAsync(Caller(i % 2 == 0 ? alice : bob))));
        for (var i = 0; i < concurrent.Length; i++) Assert.Equal(i % 2 == 0 ? a : b, concurrent[i]);
        // Actual pool/configuration, synthetic failure injection inside scoped transactions.
        foreach (var mode in new[] { "rollback", "error", "cancel" })
        {
            await using (var connection = await runtime.OpenConnectionAsync())
            await using (var transaction = await connection.BeginTransactionAsync())
            {
                await Context(connection, a, alice);
                Assert.Equal(1L, await Sql(connection, "SELECT count(*) FROM amdn_identity.postmen"));
                Assert.Equal(0L, await Sql(connection, "SELECT count(*) FROM amdn_identity.postmen WHERE owner_user_id=@user", ("user", b.UserId)));
                if (mode == "error") await Assert.ThrowsAsync<PostgresException>(() => Sql(connection, "SELECT 1/0"));
                if (mode == "cancel")
                {
                    using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(150));
                    await using var command = new NpgsqlCommand("SELECT pg_sleep(10)", connection, transaction);
                    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => command.ExecuteScalarAsync(cancellation.Token));
                }
            }
            Assert.Equal(pid, await Clean(runtime));
            Assert.Equal(b, await store.ReadAsync(Caller(bob)));
        }
        await using (var connection = await runtime.OpenConnectionAsync())
        await using (var transaction = await connection.BeginTransactionAsync())
        {
            // Partial and mismatched contexts fail closed, even with valid local IDs.
            await Sql(connection, "SELECT set_config('amdn.tenant_id',@tenant,true)", ("tenant", tenant.ToString()));
            Assert.Equal(0L, await Sql(connection, "SELECT count(*) FROM amdn_identity.postmen"));
            await Context(connection, a, bob);
            Assert.Equal(0L, await Sql(connection, "SELECT count(*) FROM amdn_identity.postmen"));
        }
        Assert.Equal(pid, await Clean(runtime));
    }

    [Theory]
    [InlineData("tenants")]
    [InlineData("users")]
    [InlineData("memberships")]
    [InlineData("postmen")]
    public async Task CurrentLifecycleStateDeniesReadsAndReenrollment(string table)
    {
        await using var provisioning = Provisioning();
        var provisioner = new IdentityProvisioner(provisioning);
        var subject = Guid.NewGuid().ToString();
        var person = await provisioner.EnsureMemberAsync(await provisioner.CreateTenantAsync(), Issuer, subject);
        await using var runtime = Runtime();
        var store = new PersonalPostmanStore(runtime);
        Assert.Equal(person, await store.ReadAsync(Caller(subject)));
        await using var connection = await provisioning.OpenConnectionAsync();
        // Table comes only from the fixed theory list, never untrusted input.
        await Sql(connection, $"UPDATE amdn_identity.{table} SET status='suspended' WHERE tenant_id=@tenant", ("tenant", person.TenantId));
        Assert.Null(await store.ReadAsync(Caller(subject)));
        await Assert.ThrowsAsync<InvalidOperationException>(() => provisioner.EnsureMemberAsync(person.TenantId, Issuer, subject));
        await Sql(connection, $"UPDATE amdn_identity.{table} SET status='active' WHERE tenant_id=@tenant", ("tenant", person.TenantId));
        var resumed = await store.ReadAsync(Caller(subject));
        Assert.NotNull(resumed);
        Assert.Equal(person.PostmanId, resumed.PostmanId);
        Assert.Equal(table == "users" ? 3 : 1, resumed.IdentityVersion);
        Assert.Equal(table == "memberships" ? 3 : 1, resumed.MembershipVersion);
        Assert.Equal(table == "postmen" ? 3 : 1, resumed.PolicyVersion);
        await Sql(connection, $"UPDATE amdn_identity.{table} SET status='revoked' WHERE tenant_id=@tenant", ("tenant", person.TenantId));
        Assert.Null(await store.ReadAsync(Caller(subject)));
        var exception = await Assert.ThrowsAsync<PostgresException>(() => Sql(connection,
            $"UPDATE amdn_identity.{table} SET status='active' WHERE tenant_id=@tenant", ("tenant", person.TenantId)));
        Assert.Equal("23514", exception.SqlState);
    }

    [Fact]
    public async Task MigrationsAreRepeatableAndCommittedIdentitySurvivesDatabaseRestart()
    {
        await IdentityMigrations.ApplyAsync(_state.IdentityConnection("migrator"));
        await IdentityMigrations.ApplyAsync(_state.IdentityConnection("migrator"));
        PersonalPostman expected;
        var subject = Guid.NewGuid().ToString();
        await using (var provisioning = Provisioning())
        {
            var provisioner = new IdentityProvisioner(provisioning);
            expected = await provisioner.EnsureMemberAsync(await provisioner.CreateTenantAsync(), Issuer, subject);
        }
        var restarted = await _state.CrashAndRestart(_state.PostgresContainer);
        // The restarted database may still be in recovery. Bound retry, then fail.
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                await using var runtime = IdentityDatabase.RuntimePool(restarted.IdentityConnection("runtime"), 1);
                Assert.Equal(expected, await new PersonalPostmanStore(runtime).ReadAsync(Caller(subject)));
                break;
            }
            catch (NpgsqlException) when (attempt < 30) { await Task.Delay(200); }
        }
    }

    [Fact]
    public async Task HttpValidatedSubjectResolvesMembershipAndIgnoresProviderAuthorityClaims()
    {
        await using var provisioning = Provisioning();
        var provisioner = new IdentityProvisioner(provisioning);
        var oidc = new OidcFixture();
        await oidc.InitializeAsync();
        try
        {
            var person = await provisioner.EnsureMemberAsync(await provisioner.CreateTenantAsync(), oidc.Issuer, "synthetic-alice");
            var foreign = await provisioner.EnsureMemberAsync(await provisioner.CreateTenantAsync(), oidc.Issuer, "synthetic-bob");
            await using var runtime = Runtime();
            await using var gateway = oidc.Gateway(configure: services =>
            {
                services.AddSingleton<IPersonalPostmanStore>(new PersonalPostmanStore(runtime));
                services.AddSingleton<IStartupFilter, MembershipProbe>();
            });
            using var client = gateway.CreateClient();
            async Task<HttpResponseMessage> Request(string? token, Guid? tenant = null)
            {
                using var request = new HttpRequestMessage(HttpMethod.Get, "/__membership" + (tenant is null ? "" : "?tenant=" + tenant));
                if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                return await client.SendAsync(request);
            }
            using var valid = await Request(oidc.Token(claims =>
            {
                claims["tenant_id"] = foreign.TenantId.ToString(); claims["role"] = "admin"; claims["user_id"] = foreign.UserId.ToString();
            }));
            Assert.Equal(HttpStatusCode.OK, valid.StatusCode);
            Assert.Equal(person, await valid.Content.ReadFromJsonAsync<PersonalPostman>());
            using var wrongTenant = await Request(oidc.Token(), foreign.TenantId);
            Assert.Equal(HttpStatusCode.Forbidden, wrongTenant.StatusCode);
            using var unknown = await Request(oidc.Token(claims => claims["sub"] = "unregistered"));
            Assert.Equal(HttpStatusCode.Forbidden, unknown.StatusCode);
            using var rogue = await Request(oidc.Token(rogue: true));
            Assert.Equal(HttpStatusCode.Unauthorized, rogue.StatusCode);
            using var anonymous = await Request(null);
            Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
            await using var connection = await provisioning.OpenConnectionAsync();
            await Sql(connection, "UPDATE amdn_identity.memberships SET status='revoked' WHERE tenant_id=@tenant", ("tenant", person.TenantId));
            using var revoked = await Request(oidc.Token());
            Assert.Equal(HttpStatusCode.Forbidden, revoked.StatusCode);
        }
        finally { await oidc.DisposeAsync(); }
    }

    private sealed class MembershipProbe : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Map("/__membership", probe =>
            {
                probe.UseRouting(); probe.UseAuthentication(); probe.UseAuthorization();
                probe.UseEndpoints(endpoints => endpoints.MapGet("/", async (HttpContext context, IPersonalPostmanStore store, Guid? tenant) =>
                {
                    var person = await store.ReadAsync(context.User, tenant, context.RequestAborted);
                    return person is null ? Results.StatusCode(403) : Results.Json(person);
                }).RequireAuthorization(IdentityAuthentication.TokenValidatedPolicy));
            });
            next(app);
        };
    }

    private static async Task<object?> Sql(NpgsqlConnection connection, string sql, params (string Name, object Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value);
        return await command.ExecuteScalarAsync();
    }

    private static async Task Context(NpgsqlConnection connection, PersonalPostman person, string subject) =>
        await Sql(connection, """
            SELECT set_config('amdn.tenant_id',@tenant,true),set_config('amdn.user_id',@user,true),
                   set_config('amdn.issuer',@issuer,true),set_config('amdn.subject',@subject,true)
            """, ("tenant", person.TenantId.ToString()), ("user", person.UserId.ToString()), ("issuer", Issuer), ("subject", subject));

    private static async Task<int> Clean(NpgsqlDataSource runtime)
    {
        await using var connection = await runtime.OpenConnectionAsync();
        Assert.Equal(0L, await Sql(connection, "SELECT count(*) FROM amdn_identity.postmen"));
        foreach (var setting in new[] { "amdn.tenant_id", "amdn.user_id", "amdn.issuer", "amdn.subject" })
            Assert.Equal(DBNull.Value, await Sql(connection, "SELECT nullif(current_setting(@setting,true),'')", ("setting", setting)));
        return (int)(await Sql(connection, "SELECT pg_backend_pid()"))!;
    }

    private static async Task Denied(NpgsqlDataSource db, string sql, string state, PersonalPostman person)
    {
        await using var connection = await db.OpenConnectionAsync();
        var exception = await Assert.ThrowsAsync<PostgresException>(() => Sql(connection, sql, ("tenant", person.TenantId), ("user", person.UserId)));
        Assert.Equal(state, exception.SqlState);
    }
}
