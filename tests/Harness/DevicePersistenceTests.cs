using System.Security.Claims;
using System.Security.Cryptography;
using AMDN.Identity.Authentication;
using AMDN.Identity.Membership;
using AMDN.Infrastructure.Identity;
using Npgsql;
using Xunit;

namespace AMDN.Harness.Tests;

// Migration-owner writes are synthetic storage setup, NOT enrollment authorization.
public sealed class DevicePersistenceTests
{
    private const string Issuer = "https://device-storage.invalid";
    private const string Rp = "device-storage.invalid";
    private readonly RunState _state = RunState.Load();
    private NpgsqlDataSource Runtime() => IdentityDatabase.RuntimePool(_state.IdentityConnection("runtime"), 1);
    private static ClaimsPrincipal Caller(string subject) => new(new ClaimsIdentity(
        [new("iss", Issuer), new("sub", subject)], IdentityAuthentication.Scheme));

    [Fact]
    public async Task MetadataReadUsesCurrentMembershipAndReusedPoolWithoutExposingCredentials()
    {
        var (alice, aSubject) = await Person();
        var (ann, annSubject) = await Person(alice.TenantId);
        var (bob, bSubject) = await Person();
        var a = await Seed(alice); var n = await Seed(ann); var b = await Seed(bob);
        await using var runtime = Runtime();
        var store = new DeviceMetadataStore(runtime);
        foreach (var (person, subject, device) in new[] { (alice, aSubject, a), (ann, annSubject, n), (bob, bSubject, b), (alice, aSubject, a) })
        {
            var read = await store.ReadAsync(Caller(subject), person.TenantId, device);
            Assert.NotNull(read);
            Assert.Equal(person.UserId, read.UserId);
            Assert.Equal("pending", read.Status);
            Assert.Null(read.ActivatedAt);
            Assert.Null(await store.ReadAsync(Caller(subject), person.TenantId, Guid.NewGuid()));
            await using var connection = await runtime.OpenConnectionAsync();
            Assert.Equal(0L, await Sql(connection, "SELECT count(device_id) FROM amdn_identity.devices"));
            foreach (var setting in new[] { "amdn.tenant_id", "amdn.user_id", "amdn.issuer", "amdn.subject" })
                Assert.Equal(DBNull.Value, await Sql(connection, "SELECT nullif(current_setting(@setting,true),'')", ("setting", setting)));
        }
        Assert.Null(await store.ReadAsync(Caller(aSubject), alice.TenantId, n));
        Assert.Null(await store.ReadAsync(Caller(aSubject), bob.TenantId, b));
        Assert.Null(await store.ReadAsync(new ClaimsPrincipal(), alice.TenantId, a));
        Assert.Null(await store.ReadAsync(new ClaimsPrincipal(new ClaimsIdentity([new("iss", Issuer), new("sub", aSubject)], "untrusted")), alice.TenantId, a));
        var duplicate = Caller(aSubject); ((ClaimsIdentity)duplicate.Identity!).AddClaim(new("sub", aSubject));
        Assert.Null(await store.ReadAsync(duplicate, alice.TenantId, a));
        await using var raw = await runtime.OpenConnectionAsync();
        await using var transaction = await raw.BeginTransactionAsync();
        await Context(raw, alice, aSubject);
        Assert.Equal(1L, await Sql(raw, "SELECT count(device_id) FROM amdn_identity.devices"));
        await Denied(raw, "SELECT credential_id,public_key_cose FROM amdn_identity.devices", "42501");
    }

    [Theory]
    [InlineData("tenants")]
    [InlineData("users")]
    [InlineData("memberships")]
    [InlineData("postmen")]
    public async Task InactiveOwnerComponentsHideAllDeviceStates(string table)
    {
        var (person, subject) = await Person(); var device = await Seed(person);
        await using var runtime = Runtime();
        var store = new DeviceMetadataStore(runtime);
        Assert.NotNull(await store.ReadAsync(Caller(subject), person.TenantId, device));
        await using var owner = await Owner();
        await Sql(owner, $"UPDATE amdn_identity.{table} SET status='suspended' WHERE tenant_id=@tenant", ("tenant", person.TenantId));
        Assert.Null(await store.ReadAsync(Caller(subject), person.TenantId, device));
        await using var raw = await runtime.OpenConnectionAsync();
        await using var transaction = await raw.BeginTransactionAsync();
        await Context(raw, person, subject);
        Assert.Equal(0L, await Sql(raw, "SELECT count(device_id) FROM amdn_identity.devices"));
    }

    [Fact]
    public async Task MissingPartialMismatchedContextsAndCancelledTransactionsDoNotLeakRows()
    {
        var (person, subject) = await Person(); await Seed(person);
        await using var runtime = Runtime();
        int pid;
        await using (var connection = await runtime.OpenConnectionAsync())
        await using (var transaction = await connection.BeginTransactionAsync())
        {
            pid = (int)(await Sql(connection, "SELECT pg_backend_pid()"))!;
            await Sql(connection, "SELECT set_config('amdn.tenant_id',@tenant,true)", ("tenant", person.TenantId.ToString()));
            Assert.Equal(0L, await Sql(connection, "SELECT count(device_id) FROM amdn_identity.devices"));
            await Context(connection, person, "wrong-subject");
            Assert.Equal(0L, await Sql(connection, "SELECT count(device_id) FROM amdn_identity.devices"));
            await Context(connection, person, subject);
            Assert.Equal(1L, await Sql(connection, "SELECT count(device_id) FROM amdn_identity.devices"));
            using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
            await using var command = new NpgsqlCommand("SELECT pg_sleep(10)", connection, transaction);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => command.ExecuteScalarAsync(cancel.Token));
        }
        await using var reused = await runtime.OpenConnectionAsync();
        Assert.Equal(pid, await Sql(reused, "SELECT pg_backend_pid()"));
        Assert.Equal(0L, await Sql(reused, "SELECT count(device_id) FROM amdn_identity.devices"));
    }

    [Fact]
    public async Task ApplicationRolesHaveNoMutationOrHandleAccessAndRlsIsForced()
    {
        foreach (var role in new[] { "runtime", "provisioner" })
        {
            await using var connection = new NpgsqlConnection(_state.IdentityConnection(role));
            await connection.OpenAsync();
            foreach (var sql in new[] { "INSERT INTO amdn_identity.devices DEFAULT VALUES", "UPDATE amdn_identity.devices SET status='revoked'",
                "DELETE FROM amdn_identity.devices", "TRUNCATE amdn_identity.devices", "SELECT * FROM amdn_identity.device_subjects",
                "INSERT INTO amdn_identity.device_subjects DEFAULT VALUES", "UPDATE amdn_identity.device_subjects SET user_handle='\\x00'",
                "DELETE FROM amdn_identity.device_subjects", "TRUNCATE amdn_identity.device_subjects" })
                await Denied(connection, sql, "42501");
        }
        await using var owner = await Owner();
        Assert.Equal(2L, await Sql(owner, """
            SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='amdn_identity' AND c.relname IN ('devices','device_subjects')
              AND c.relrowsecurity AND c.relforcerowsecurity
            """));
        Assert.Equal(false, await Sql(owner, "SELECT has_function_privilege('harness_identity_runtime','amdn_identity.preserve_device()','EXECUTE')"));
    }

    [Fact]
    public async Task OwnershipHandlesAndCredentialBindingsAreImmutableAndRetained()
    {
        var (person, _) = await Person(); var (other, _) = await Person();
        var credential = RandomNumberGenerator.GetBytes(32); var key = PublicKey();
        var device = await Seed(person, credential, key);
        await using var owner = await Owner();
        foreach (var assignment in new[] { "tenant_id=gen_random_uuid()", "user_id=gen_random_uuid()", "device_id=gen_random_uuid()",
            "rp_id='changed.invalid'", "configuration_version=2", "public_key_cose=NULL", "credential_id=NULL", "backup_eligible=true" })
            await Denied(owner, $"UPDATE amdn_identity.devices SET {assignment} WHERE device_id=@id", "23514", ("id", device));
        await Denied(owner, "UPDATE amdn_identity.device_subjects SET user_handle=@handle WHERE tenant_id=@tenant", "23514",
            ("handle", RandomNumberGenerator.GetBytes(32)), ("tenant", person.TenantId));
        await Denied(owner, "DELETE FROM amdn_identity.devices WHERE device_id=@id", "23514", ("id", device));
        await Denied(owner, "DELETE FROM amdn_identity.device_subjects WHERE tenant_id=@tenant", "23514", ("tenant", person.TenantId));
        await Denied(owner, "INSERT INTO amdn_identity.devices(tenant_id,user_id,rp_id,configuration_version) VALUES(@tenant,@user,@rp,1)", "23503",
            ("tenant", other.TenantId), ("user", person.UserId), ("rp", Rp));
        await Sql(owner, "UPDATE amdn_identity.devices SET status='abandoned' WHERE device_id=@id", ("id", device));
        await Denied(owner, "UPDATE amdn_identity.devices SET status='pending' WHERE device_id=@id", "23514", ("id", device));
        await AssertSqlState("23505", () => Seed(other, credential, PublicKey()));
        await AssertSqlState("23505", () => Seed(other, RandomNumberGenerator.GetBytes(32), key));
    }

    [Fact]
    public async Task PartialCredentialsBadShapesAndCountersAreRejected()
    {
        var (person, _) = await Person(); var device = await Seed(person);
        await using var owner = await Owner();
        var empty = (Guid)(await Sql(owner, "INSERT INTO amdn_identity.devices(tenant_id,user_id,rp_id,configuration_version) VALUES(@tenant,@user,@rp,1) RETURNING device_id",
            ("tenant", person.TenantId), ("user", person.UserId), ("rp", Rp)))!;
        foreach (var assignment in new[] { "credential_id='\\x01'", "sign_count=1", "backup_state=true" })
            await Denied(owner, $"UPDATE amdn_identity.devices SET {assignment} WHERE device_id=@id", "23514", ("id", empty));
        foreach (var assignment in new[] { "sign_count=-1", "sign_count=4294967296", "backup_state=true", "public_key_cose='\\x00'" })
            await Denied(owner, $"UPDATE amdn_identity.devices SET {assignment} WHERE device_id=@id", "23514", ("id", device));
        await Sql(owner, "UPDATE amdn_identity.devices SET sign_count=10 WHERE device_id=@id", ("id", device));
        await Denied(owner, "UPDATE amdn_identity.devices SET sign_count=9 WHERE device_id=@id", "23514", ("id", device));
        await Denied(owner, "UPDATE amdn_identity.devices SET sign_count=0 WHERE device_id=@id", "23514", ("id", device));
        // Storage permits equal counters for non-proof updates; replay/non-increase proof checks remain pending.
        await Sql(owner, "UPDATE amdn_identity.devices SET sign_count=10 WHERE device_id=@id", ("id", device));
        await AssertSqlState("23514", () => Seed(person, new byte[1024], PublicKey()));
        var wrongAlgorithm = PublicKey(); wrongAlgorithm[4] = 0x27;
        await AssertSqlState("23514", () => Seed(person, RandomNumberGenerator.GetBytes(32), wrongAlgorithm));
    }

    [Fact]
    public async Task PendingReservationCanAttachOnlyOneCompleteCredentialAndNeedsItToActivate()
    {
        var (person, _) = await Person();
        await Seed(person); // Creates the stable per-owner RP handle.
        await using var owner = await Owner();
        var device = (Guid)(await Sql(owner, "INSERT INTO amdn_identity.devices(tenant_id,user_id,rp_id,configuration_version) VALUES(@tenant,@user,@rp,1) RETURNING device_id",
            ("tenant", person.TenantId), ("user", person.UserId), ("rp", Rp)))!;
        await Denied(owner, "UPDATE amdn_identity.devices SET status='credential_active' WHERE device_id=@id", "23514", ("id", device));
        await Sql(owner, """
            UPDATE amdn_identity.devices SET credential_id=@credential,public_key_cose=@key,backup_eligible=true,backup_state=true,sign_count=0
            WHERE device_id=@id
            """, ("credential", RandomNumberGenerator.GetBytes(32)), ("key", PublicKey()), ("id", device));
        await Sql(owner, "UPDATE amdn_identity.devices SET status='credential_active' WHERE device_id=@id", ("id", device));
        await Denied(owner, "UPDATE amdn_identity.devices SET credential_id=@credential WHERE device_id=@id", "23514",
            ("credential", RandomNumberGenerator.GetBytes(32)), ("id", device));
        await Sql(owner, "UPDATE amdn_identity.devices SET backup_state=false WHERE device_id=@id", ("id", device));
        Assert.Equal(4L, await Sql(owner, "SELECT record_version FROM amdn_identity.devices WHERE device_id=@id", ("id", device)));
    }

    [Fact]
    public async Task ConcurrentActivationHasOneWinnerAndReplacementRollbackPreservesOldDevice()
    {
        var (person, subject) = await Person();
        var a = await Seed(person); var b = await Seed(person);
        async Task<bool> Activate(Guid id)
        {
            await using var owner = await Owner();
            try { await Sql(owner, "UPDATE amdn_identity.devices SET status='credential_active' WHERE device_id=@id", ("id", id)); return true; }
            catch (PostgresException e) when (e.SqlState == "23505") { return false; }
        }
        var results = await Task.WhenAll(Activate(a), Activate(b));
        Assert.Single(results, success => success);
        var active = results[0] ? a : b; var candidate = results[0] ? b : a;
        await using var runtime = Runtime();
        var store = new DeviceMetadataStore(runtime);
        var original = await store.ReadAsync(Caller(subject), person.TenantId, active);
        Assert.Equal("credential_active", original!.Status);
        await using (var owner = await Owner())
        await using (var transaction = await owner.BeginTransactionAsync())
        {
            await Sql(owner, "UPDATE amdn_identity.devices SET status='revoked' WHERE device_id=@id", ("id", active));
            await Sql(owner, "UPDATE amdn_identity.devices SET status='credential_active' WHERE device_id=@id", ("id", candidate));
            await transaction.RollbackAsync();
        }
        Assert.Equal(original, await store.ReadAsync(Caller(subject), person.TenantId, active));
        await using (var owner = await Owner())
        await using (var transaction = await owner.BeginTransactionAsync())
        {
            await Sql(owner, "UPDATE amdn_identity.devices SET status='revoked' WHERE device_id=@id", ("id", active));
            await Sql(owner, "UPDATE amdn_identity.devices SET status='credential_active' WHERE device_id=@id", ("id", candidate));
            await transaction.CommitAsync();
        }
        var revoked = await store.ReadAsync(Caller(subject), person.TenantId, active);
        Assert.Equal("revoked", revoked!.Status); Assert.NotNull(revoked.RevokedAt);
        Assert.Equal("credential_active", (await store.ReadAsync(Caller(subject), person.TenantId, candidate))!.Status);
        await using var final = await Owner();
        await Denied(final, "UPDATE amdn_identity.devices SET status='credential_active' WHERE device_id=@id", "23514", ("id", active));
    }

    [Fact]
    public async Task MigrationReplayAndDatabaseRestartRetainDeviceMetadata()
    {
        await IdentityMigrations.ApplyAsync(_state.IdentityConnection("migrator"));
        await IdentityMigrations.ApplyAsync(_state.IdentityConnection("migrator"));
        var (person, subject) = await Person(); var device = await Seed(person);
        await using (var owner = await Owner())
        {
            Assert.Equal(7L, await Sql(owner, "SELECT count(*) FROM amdn_identity.schema_migrations"));
            await Sql(owner, "UPDATE amdn_identity.devices SET status='credential_active' WHERE device_id=@id", ("id", device));
        }
        var restarted = await _state.CrashAndRestart(_state.PostgresContainer);
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                await using var runtime = IdentityDatabase.RuntimePool(restarted.IdentityConnection("runtime"), 1);
                var result = await new DeviceMetadataStore(runtime).ReadAsync(Caller(subject), person.TenantId, device);
                Assert.NotNull(result); Assert.Equal("credential_active", result.Status); Assert.NotNull(result.ActivatedAt);
                break;
            }
            catch (NpgsqlException) when (attempt < 30) { await Task.Delay(200); }
        }
    }

    private async Task<(PersonalPostman Person, string Subject)> Person(Guid? tenant = null)
    {
        await using var db = IdentityDatabase.ProvisioningPool(_state.IdentityConnection("provisioner"));
        var provisioner = new IdentityProvisioner(db); var subject = Guid.NewGuid().ToString();
        return (await provisioner.EnsureMemberAsync(tenant ?? await provisioner.CreateTenantAsync(), Issuer, subject), subject);
    }

    private async Task<NpgsqlConnection> Owner()
    {
        var connection = new NpgsqlConnection(_state.IdentityConnection("migrator"));
        await connection.OpenAsync();
        await Sql(connection, "SET ROLE amdn_identity_owner");
        return connection;
    }

    private async Task<Guid> Seed(PersonalPostman person, byte[]? credential = null, byte[]? key = null)
    {
        await using var owner = await Owner();
        await using var transaction = await owner.BeginTransactionAsync();
        await Sql(owner, """
            INSERT INTO amdn_identity.device_subjects(tenant_id,user_id,rp_id,user_handle) VALUES(@tenant,@user,@rp,@handle)
            ON CONFLICT(tenant_id,user_id,rp_id) DO NOTHING
            """, ("tenant", person.TenantId), ("user", person.UserId), ("rp", Rp), ("handle", RandomNumberGenerator.GetBytes(32)));
        var id = (Guid)(await Sql(owner, """
            INSERT INTO amdn_identity.devices(tenant_id,user_id,rp_id,configuration_version,credential_id,public_key_cose,backup_eligible,backup_state,sign_count)
            VALUES(@tenant,@user,@rp,1,@credential,@key,false,false,0) RETURNING device_id
            """, ("tenant", person.TenantId), ("user", person.UserId), ("rp", Rp),
            ("credential", credential ?? RandomNumberGenerator.GetBytes(32)), ("key", key ?? PublicKey())))!;
        await transaction.CommitAsync(); return id;
    }

    private static byte[] PublicKey()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var point = key.ExportParameters(false).Q;
        return [.. Convert.FromHexString("a5010203262001215820"), .. point.X!, 0x22, 0x58, 0x20, .. point.Y!];
    }

    private static async Task<object?> Sql(NpgsqlConnection connection, string sql, params (string Name, object Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value);
        return await command.ExecuteScalarAsync();
    }

    private static async Task Denied(NpgsqlConnection connection, string sql, string state, params (string Name, object Value)[] parameters) =>
        await AssertSqlState(state, () => Sql(connection, sql, parameters));

    private static async Task AssertSqlState(string state, Func<Task> action)
    {
        var error = await Assert.ThrowsAsync<PostgresException>(action);
        Assert.Equal(state, error.SqlState);
    }

    private static Task<object?> Context(NpgsqlConnection connection, PersonalPostman person, string subject) => Sql(connection, """
        SELECT set_config('amdn.tenant_id',@tenant,true),set_config('amdn.user_id',@user,true),
               set_config('amdn.issuer',@issuer,true),set_config('amdn.subject',@subject,true)
        """, ("tenant", person.TenantId.ToString()), ("user", person.UserId.ToString()), ("issuer", Issuer), ("subject", subject));
}
