using System.Security.Cryptography;
using System.Text.Json;
using AMDN.Enrollment;
using AMDN.Identity.Membership;
using AMDN.Infrastructure.Identity;
using Npgsql;
using NpgsqlTypes;
using Xunit;

namespace AMDN.Harness.Tests;

// Trusted administrator SQL and actual application-role denials. These are not
// public administration/enrollment endpoints or independent security approval.
public sealed class EnrollmentAdministrationTests
{
    private readonly RunState _state = RunState.Load();
    private const string Issuer = "https://admin-issuer.invalid";
    private const string Acr = "urn:amdn:test:strong";
    private sealed record Member(PersonalPostman Person, string Subject);

    [Fact]
    public async Task ConfigurationHasExplicitVersionsAuditedReplayAndCommandBinding()
    {
        await using var owner = await Owner();
        var id = Guid.NewGuid(); var command = Guid.NewGuid();
        var created = await Configure(owner, id, command: command);
        Outcome("ok", created); Assert.Equal(1, created.GetProperty("version").GetInt64());
        Assert.False(created.GetProperty("enabled").GetBoolean());
        Assert.Equal(created.GetRawText(), (await Configure(owner, id, command: command)).GetRawText());
        Outcome("conflict", await Configure(owner, Guid.NewGuid(), command: command));
        Outcome("conflict", await Configure(owner, id, enabled: true, command: command));
        Outcome("conflict", await Configure(owner, id)); // Create is not an upsert.
        var changed = await Configure(owner, id, expected: 1, enabled: true);
        Outcome("ok", changed); Assert.Equal(2, changed.GetProperty("version").GetInt64());
        Outcome("conflict", await Configure(owner, id, expected: 1));
        Assert.Equal(2L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_administration_audit WHERE configuration_id=@id", ("id", id)));
        Assert.Equal("harness_identity_migrator", await Sql(owner, "SELECT operator_name::text FROM amdn_identity.device_administration_audit WHERE command_id=@id", ("id", command)));
        // Replay is the historical command result, never a fresh enable operation.
        Assert.Equal(created.GetRawText(), (await Configure(owner, id, command: command)).GetRawText());
        Assert.Equal(true, await Sql(owner, "SELECT enabled FROM amdn_identity.device_configurations WHERE configuration_id=@id", ("id", id)));
    }

    [Fact]
    public async Task DeploymentOriginBindingCannotBeRetargetedInPlace()
    {
        await using var owner = await Owner(); var id = Guid.NewGuid();
        Outcome("ok", await Configure(owner, id));
        Outcome("conflict", await Configure(owner, id, expected: 1, origin: "https://other.admin.invalid"));
        Assert.Equal("https://admin.invalid", await Sql(owner, "SELECT origin FROM amdn_identity.device_configurations WHERE configuration_id=@id", ("id", id)));
        Outcome("ok", await Configure(owner, Guid.NewGuid(), origin: "https://other.admin.invalid:8443"));
    }

    [Fact]
    public async Task ConcurrentCreatesAndStaleUpdatesHaveOneDurableEffect()
    {
        var id = Guid.NewGuid(); var command = Guid.NewGuid();
        await using var first = await Owner(); await using var second = await Owner();
        var same = await Task.WhenAll(Configure(first, id, command: command), Configure(second, id, command: command));
        Assert.Equal(same[0].GetRawText(), same[1].GetRawText());
        var updates = await Task.WhenAll(Configure(first, id, expected: 1, maximumAge: 500), Configure(second, id, expected: 1, maximumAge: 501));
        Assert.Single(updates, value => value.GetProperty("outcome").GetString() == "ok");
        Assert.Single(updates, value => value.GetProperty("outcome").GetString() == "conflict");
        Assert.Equal(2L, await Sql(first, "SELECT version FROM amdn_identity.device_configurations WHERE configuration_id=@id", ("id", id)));
        Assert.Equal(2L, await Sql(first, "SELECT count(*) FROM amdn_identity.device_administration_audit WHERE configuration_id=@id", ("id", id)));
    }

    [Fact]
    public async Task GrantIssueAndRevocationControlActualEnrollmentAndNeverReviveGrants()
    {
        var member = await Person(); var config = Guid.NewGuid(); var issue = Guid.NewGuid();
        var expires = DateTime.UtcNow.AddHours(1);
        await using var owner = await Owner();
        Outcome("ok", await Configure(owner, config, enabled: true));
        await using var pool = EnrollmentDatabase.Pool(_state.IdentityConnection("enrollment"), 1);
        Outcome("forbidden", await Begin(pool, member, config));
        var granted = await Grant(owner, member, expiry: expires, command: issue);
        Outcome("ok", granted);
        var key = Guid.NewGuid().ToString("N");
        Outcome("ok", await Begin(pool, member, config, key));
        await Sql(owner, "SET TIME ZONE 'Pacific/Honolulu'");
        Assert.Equal(granted.GetRawText(), (await Grant(owner, member, expiry: expires, command: issue)).GetRawText());
        await Sql(owner, "SET TIME ZONE 'UTC'");
        var revoke = Guid.NewGuid();
        var revoked = await Grant(owner, member, "grant.revoke", expected: 1, command: revoke);
        Outcome("ok", revoked); Assert.Equal(2, revoked.GetProperty("version").GetInt64());
        Outcome("forbidden", await Begin(pool, member, config, key));
        Assert.Equal(revoked.GetRawText(), (await Grant(owner, member, "grant.revoke", expected: 1, command: revoke)).GetRawText());
        Assert.Equal(granted.GetRawText(), (await Grant(owner, member, expiry: expires, command: issue)).GetRawText());
        Outcome("conflict", await Grant(owner, member, expiry: expires));
        Outcome("conflict", await Grant(owner, member, "grant.revoke", expected: 2));
        Outcome("conflict", await Configure(owner, config, command: issue)); // Keys bind operations too.
        Assert.Equal("revoked", await Sql(owner, "SELECT status FROM amdn_identity.device_management_grants WHERE tenant_id=@tenant", ("tenant", member.Person.TenantId)));
        Assert.Equal(2L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_administration_audit WHERE tenant_id=@tenant", ("tenant", member.Person.TenantId)));
    }

    [Fact]
    public async Task ConfigurationChangeInvalidatesAnAlreadyBegunCeremony()
    {
        var member = await Person(); var config = Guid.NewGuid();
        await using var owner = await Owner();
        Outcome("ok", await Configure(owner, config, enabled: true));
        Outcome("ok", await Grant(owner, member, expiry: DateTime.UtcNow.AddHours(1)));
        await using var pool = EnrollmentDatabase.Pool(_state.IdentityConnection("enrollment"), 1);
        var key = Guid.NewGuid().ToString("N");
        Outcome("ok", await Begin(pool, member, config, key));
        Outcome("ok", await Configure(owner, config, expected: 1, enabled: true, maximumAge: 599));
        Outcome("conflict", await Begin(pool, member, config, key));
        Outcome("ok", await Configure(owner, config, expected: 2, enabled: false));
        Outcome("forbidden", await Begin(pool, member, config));
    }

    [Theory]
    [InlineData("runtime")]
    [InlineData("provisioner")]
    [InlineData("enrollment")]
    [InlineData("executor")]
    public async Task ApplicationRolesCannotAdministerOrAccessAudit(string role)
    {
        await using var connection = role == "executor" ? await Owner() : new NpgsqlConnection(_state.IdentityConnection(role));
        if (role == "executor") await Sql(connection, "SET ROLE amdn_identity_ceremony_executor");
        else await connection.OpenAsync();
        foreach (var sql in new[]
        {
            "SELECT amdn_identity.administer_device_configuration(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)",
            "SELECT amdn_identity.administer_device_grant(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)",
            "SELECT amdn_identity.device_admin_replay(NULL,NULL)",
            "SELECT * FROM amdn_identity.device_administration_audit",
            "INSERT INTO amdn_identity.device_administration_audit DEFAULT VALUES",
            "DELETE FROM amdn_identity.device_administration_audit",
            "TRUNCATE amdn_identity.device_administration_audit"
        }) Assert.Equal("42501", (await Assert.ThrowsAsync<PostgresException>(() => Sql(connection, sql))).SqlState);
    }

    [Theory]
    [InlineData("rp")]
    [InlineData("suffix")]
    [InlineData("http")]
    [InlineData("path")]
    [InlineData("userinfo")]
    [InlineData("uppercase")]
    [InlineData("port")]
    [InlineData("default-port")]
    [InlineData("age")]
    [InlineData("acrs")]
    [InlineData("reference")]
    [InlineData("id")]
    public async Task InvalidConfigurationCannotChangeStateOrReserveReplay(string invalid)
    {
        await using var owner = await Owner(); var id = invalid == "id" ? Guid.Empty : Guid.NewGuid(); var command = Guid.NewGuid();
        var origin = invalid switch
        {
            "suffix" => "https://admin.invalid.evil.invalid",
            "http" => "http://admin.invalid",
            "path" => "https://admin.invalid/",
            "userinfo" => "https://user@admin.invalid",
            "uppercase" => "https://ADMIN.invalid",
            "port" => "https://admin.invalid:65536",
            "default-port" => "https://admin.invalid:443",
            _ => "https://admin.invalid"
        };
        Outcome("invalid_request", await Configure(owner, id, rp: invalid == "rp" ? "evil.invalid" : "admin.invalid", origin: origin,
            maximumAge: invalid == "age" ? 901 : 600, acrs: invalid == "acrs" ? [Acr, Acr] : [Acr],
            reference: invalid == "reference" ? "contains space" : "synthetic-change", command: command));
        Assert.Equal(0L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_configurations WHERE configuration_id=@id", ("id", id)));
        Assert.Equal(0L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_administration_audit WHERE command_id=@id", ("id", command)));
    }

    [Theory]
    [InlineData("tenants")]
    [InlineData("users")]
    [InlineData("memberships")]
    [InlineData("postmen")]
    public async Task InactiveIdentityCannotReceiveNewAuthorityButCanBeRevoked(string table)
    {
        var member = await Person(); await using var owner = await Owner();
        Outcome("ok", await Grant(owner, member, expiry: DateTime.UtcNow.AddHours(1)));
        await Sql(owner, $"UPDATE amdn_identity.{table} SET status='suspended' WHERE tenant_id=@tenant", ("tenant", member.Person.TenantId));
        Outcome("not_found", await Grant(owner, member, expiry: DateTime.UtcNow.AddHours(1)));
        Outcome("ok", await Grant(owner, member, "grant.revoke", expected: 1));
    }

    [Fact]
    public async Task ForeignTargetStaleVersionAndInvalidExpiryCannotMintAuthority()
    {
        var alice = await Person(); var bob = await Person(); await using var owner = await Owner();
        Outcome("not_found", await Grant(owner, alice with { Person = alice.Person with { PostmanId = bob.Person.PostmanId } }, expiry: DateTime.UtcNow.AddHours(1)));
        Outcome("invalid_request", await Grant(owner, alice, expiry: DateTime.UtcNow.AddMinutes(-1)));
        Outcome("invalid_request", await Grant(owner, alice, expiry: DateTime.MaxValue));
        Outcome("ok", await Grant(owner, alice, expiry: DateTime.UtcNow.AddHours(1)));
        Outcome("conflict", await Grant(owner, alice, "grant.revoke", expected: 2));
        Assert.Equal("active", await Sql(owner, "SELECT status FROM amdn_identity.device_management_grants WHERE tenant_id=@tenant", ("tenant", alice.Person.TenantId)));
        Assert.Equal(0L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_management_grants WHERE tenant_id=@tenant", ("tenant", bob.Person.TenantId)));
    }

    [Fact]
    public async Task AuditFailureRollsBackEffectAndAllowsTheSameCommandToRetry()
    {
        await using var owner = await Owner(); var id = Guid.NewGuid(); var command = Guid.NewGuid();
        await Sql(owner, """
            CREATE FUNCTION amdn_identity.fail_device_admin_test() RETURNS trigger LANGUAGE plpgsql
              SET search_path=pg_catalog,pg_temp AS $body$
              BEGIN RAISE EXCEPTION 'Synthetic audit failure'; END $body$;
            REVOKE ALL ON FUNCTION amdn_identity.fail_device_admin_test() FROM PUBLIC;
            """);
        await Sql(owner, $"""
            CREATE TRIGGER fail_device_admin_test BEFORE INSERT ON amdn_identity.device_administration_audit
              FOR EACH ROW WHEN (NEW.command_id='{command:D}') EXECUTE FUNCTION amdn_identity.fail_device_admin_test()
            """);
        try
        {
            await Assert.ThrowsAsync<PostgresException>(() => Configure(owner, id, command: command));
            Assert.Equal(0L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_configurations WHERE configuration_id=@id", ("id", id)));
            Assert.Equal(0L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_administration_audit WHERE command_id=@id", ("id", command)));
        }
        finally
        {
            await Sql(owner, "DROP TRIGGER fail_device_admin_test ON amdn_identity.device_administration_audit; DROP FUNCTION amdn_identity.fail_device_admin_test()");
        }
        Outcome("ok", await Configure(owner, id, command: command));
        foreach (var sql in new[]
        {
            "UPDATE amdn_identity.device_administration_audit SET change_reference='rewrite' WHERE command_id=@id",
            "DELETE FROM amdn_identity.device_administration_audit WHERE command_id=@id",
            "TRUNCATE amdn_identity.device_administration_audit"
        }) Assert.Equal("23514", (await Assert.ThrowsAsync<PostgresException>(() => Sql(owner, sql, ("id", command)))).SqlState);
    }

    [Fact]
    public async Task GrantExpiryIsRecheckedAfterWaitingForTheIdentityLock()
    {
        var member = await Person(); await using var blocker = await Owner(); await using var issuer = await Owner();
        // Observe as the actual login, not SET ROLE owner: PostgreSQL restricts
        // another backend's activity details based on its login identity.
        await using var observer = new NpgsqlConnection(_state.IdentityConnection("migrator"));
        await observer.OpenAsync();
        await using var transaction = await blocker.BeginTransactionAsync();
        await Sql(blocker, "SELECT user_id FROM amdn_identity.users WHERE tenant_id=@tenant FOR UPDATE", ("tenant", member.Person.TenantId));
        var pid = (int)(await Sql(issuer, "SELECT pg_backend_pid()"))!;
        var expires = (DateTime)(await Sql(observer, "SELECT clock_timestamp()+interval '3 seconds'"))!;
        var pending = Task.Run(() => Grant(issuer, member, expiry: expires));
        var committed = false;
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            while (!Equals("Lock", await Sql(observer, "SELECT wait_event_type FROM pg_stat_activity WHERE pid=@pid", ("pid", pid))))
                await Task.Delay(20, deadline.Token);
            Assert.Equal(true, await Sql(observer, "SELECT @expiry::timestamptz>clock_timestamp()", ("expiry", expires)));
            await Sql(observer, "SELECT pg_sleep(greatest(extract(epoch FROM @expiry::timestamptz-clock_timestamp())+0.05,0))", ("expiry", expires));
            await transaction.CommitAsync();
            committed = true;
            Outcome("invalid_request", await pending.WaitAsync(TimeSpan.FromSeconds(8)));
        }
        finally
        {
            if (!committed) await transaction.RollbackAsync();
            // Release the blocker before disposing an issuer with an in-flight command.
            await pending.WaitAsync(TimeSpan.FromSeconds(8));
        }
        Assert.Equal(0L, await Sql(blocker, "SELECT count(*) FROM amdn_identity.device_management_grants WHERE tenant_id=@tenant", ("tenant", member.Person.TenantId)));
    }

    private static Task<JsonElement> Configure(NpgsqlConnection connection, Guid id, long expected = 0, bool enabled = false,
        int maximumAge = 600, string rp = "admin.invalid", string origin = "https://admin.invalid", string[]? acrs = null,
        string reference = "synthetic-change", Guid? command = null) => Json(connection, """
            SELECT amdn_identity.administer_device_configuration(@command,@id,@expected,@rp,@origin,@acrs,@age,@enabled,@reference)
            """, ("command", command ?? Guid.NewGuid()), ("id", id), ("expected", expected), ("rp", rp), ("origin", origin),
            ("acrs", acrs ?? [Acr]), ("age", maximumAge), ("enabled", enabled), ("reference", reference));

    private static Task<JsonElement> Grant(NpgsqlConnection connection, Member member, string action = "grant.issue", long expected = 0,
        DateTime? expiry = null, Guid? command = null) => Json(connection, """
            SELECT amdn_identity.administer_device_grant(@command,@tenant,@user,@postman,@action,@expected,@expiry,@reference)
            """, ("command", command ?? Guid.NewGuid()), ("tenant", member.Person.TenantId), ("user", member.Person.UserId),
            ("postman", member.Person.PostmanId), ("action", action), ("expected", expected), ("expiry", expiry), ("reference", "synthetic-change"));

    private static async Task<JsonElement> Begin(NpgsqlDataSource database, Member member, Guid configuration, string? key = null)
    {
        await using var connection = await database.OpenConnectionAsync();
        return await Json(connection, """
            SELECT amdn_enrollment.begin(ROW(@tenant,@issuer,@subject,'synthetic-client','https://admin.invalid',@config,
              'device.manage',@acr,clock_timestamp()-interval '2 seconds',clock_timestamp()+interval '10 minutes')::amdn_identity.ceremony_actor,
              'enrollment',1,NULL,@key,@body,@challenge,@handle)
            """, ("tenant", member.Person.TenantId), ("issuer", Issuer), ("subject", member.Subject), ("config", configuration), ("acr", Acr),
            ("key", key ?? Guid.NewGuid().ToString("N")), ("body", "{}"u8.ToArray()),
            ("challenge", RandomNumberGenerator.GetBytes(32)), ("handle", RandomNumberGenerator.GetBytes(32)));
    }

    private async Task<Member> Person()
    {
        await using var pool = IdentityDatabase.ProvisioningPool(_state.IdentityConnection("provisioner"));
        var service = new IdentityProvisioner(pool); var subject = Guid.NewGuid().ToString("N");
        return new(await service.EnsureMemberAsync(await service.CreateTenantAsync(), Issuer, subject), subject);
    }

    private async Task<NpgsqlConnection> Owner()
    {
        var connection = new NpgsqlConnection(_state.IdentityConnection("migrator")); await connection.OpenAsync();
        await Sql(connection, "SET ROLE amdn_identity_owner"); return connection;
    }

    private static async Task<JsonElement> Json(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] values)
    {
        using var document = JsonDocument.Parse((string)(await Sql(connection, sql, values))!);
        return document.RootElement.Clone();
    }

    private static async Task<object?> Sql(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] values)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        foreach (var (name, value) in values)
        {
            if (value is null) command.Parameters.Add(new NpgsqlParameter(name, NpgsqlDbType.TimestampTz) { Value = DBNull.Value });
            else command.Parameters.AddWithValue(name, value);
        }
        return await command.ExecuteScalarAsync();
    }
    private static void Outcome(string expected, JsonElement value) => Assert.Equal(expected, value.GetProperty("outcome").GetString());
}
