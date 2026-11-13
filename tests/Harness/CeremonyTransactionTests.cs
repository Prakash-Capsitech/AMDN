using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AMDN.Identity.Membership;
using AMDN.Infrastructure.Identity;
using Npgsql;
using NpgsqlTypes;
using Xunit;

namespace AMDN.Harness.Tests;

// Exercises real SQL transactions with synthetic actor/proof projections.
// No OIDC signature, WebAuthn proof, browser or public enrollment endpoint is tested here.
public sealed partial class CeremonyTransactionTests
{
    private RunState _state = RunState.Load();
    private const string ActorSql = "ROW(@tenant,@issuer,@subject,@client,@origin,@config,@scope,@acr,@auth_time,@token_exp)::amdn_identity.ceremony_actor";
    private sealed record Actor(PersonalPostman Person, string Subject, Guid Configuration)
    {
        public string Client { get; init; } = "synthetic-client";
        public string Origin { get; init; } = "https://ceremony.invalid";
        public string Scope { get; init; } = "device.manage";
        public string Acr { get; init; } = "urn:amdn:test:strong";
        public DateTime AuthTime { get; init; } = DateTime.UtcNow.AddSeconds(-2);
        public DateTime TokenExpiry { get; init; } = DateTime.UtcNow.AddMinutes(10);
    }
    private sealed record Key(byte[] Credential, byte[] Public)
    {
        public static Key New()
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var point = key.ExportParameters(false).Q;
            return new(RandomNumberGenerator.GetBytes(32), [.. Convert.FromHexString("a5010203262001215820"), .. point.X!, 0x22, 0x58, 0x20, .. point.Y!]);
        }
    }

    [Fact]
    public async Task InitialRevocationAndHistoricalReplayChangeIdentityExactlyOnce()
    {
        var actor = await Setup(); var key = Key.New(); var beginKey = Idempotency();
        var begin = await Begin(actor, key: beginKey); var id = Id(begin, "ceremony_id");
        Assert.Equal(begin.GetRawText(), (await Begin(actor, key: beginKey)).GetRawText());
        AssertOutcome("conflict", await Begin(actor, key: beginKey, body: "{\"changed\":true}"));
        var registrationKey = Idempotency();
        var registration = await Reserve(actor, id, "registration", registrationKey);
        AssertOutcome("reserved", registration);
        var candidate = await Finish(actor, registration, key, next: true);
        Assert.Equal("candidate", candidate.GetProperty("state").GetString());
        Assert.Equal(candidate.GetRawText(), (await Reserve(actor, id, "registration", registrationKey)).GetRawText());
        AssertOutcome("conflict", await Begin(actor, key: beginKey));
        var proofKey = Idempotency(); var proof = await Reserve(actor, id, "candidate", proofKey);
        var completed = await Finish(actor, proof, key);
        Assert.Equal(2, completed.GetProperty("committed_identity_version").GetInt64());
        Assert.False(completed.GetProperty("messaging_ready").GetBoolean());
        var device = Id(completed, "device_id");
        var revoke = await Begin(actor, "revocation", 2, device);
        var revokeProof = await Reserve(actor, Id(revoke, "ceremony_id"), "revocation");
        var revoked = await Finish(actor, revokeProof, key);
        Assert.Equal(3, revoked.GetProperty("committed_identity_version").GetInt64());
        var replay = await Reserve(actor, id, "candidate", proofKey);
        AssertOutcome("ok", replay);
        Assert.Equal(2, replay.GetProperty("committed_identity_version").GetInt64());
        Assert.Equal(3, replay.GetProperty("current_lifecycle").GetProperty("identity_version").GetInt64());
        Assert.Equal("revoked", replay.GetProperty("current_lifecycle").GetProperty("status").GetString());
        AssertOutcome("conflict", await Reserve(actor, id, "candidate"));
        AssertOutcome("conflict", await Reserve(actor, id, "registration", registrationKey));
        AssertOutcome("conflict", await Begin(actor, expected: 1));
        AssertOutcome("conflict", await Begin(actor, expected: 0));
        await using var owner = await Owner();
        Assert.Equal(3L, await Sql(owner, "SELECT identity_version FROM amdn_identity.users WHERE tenant_id=@tenant AND user_id=@user",
            ("tenant", actor.Person.TenantId), ("user", actor.Person.UserId)));
        Assert.Equal(3L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_challenges h JOIN amdn_identity.device_ceremonies c USING(ceremony_id) WHERE c.tenant_id=@tenant AND h.consumed_at IS NOT NULL", ("tenant", actor.Person.TenantId)));
        await Sql(owner, "UPDATE amdn_identity.device_management_grants SET status='revoked' WHERE tenant_id=@tenant", ("tenant", actor.Person.TenantId));
        AssertOutcome("forbidden", await Reserve(actor, id, "candidate", proofKey));
        var deletion = await Assert.ThrowsAsync<PostgresException>(() => Sql(owner,
            "DELETE FROM amdn_identity.device_management_grants WHERE tenant_id=@tenant", ("tenant", actor.Person.TenantId)));
        Assert.Equal("23514", deletion.SqlState); // Prevent delete/recreate from recycling an old grant version.
    }

    [Fact]
    public async Task ReplacementRequiresCandidateThenOldCredentialAndRetainsAttribution()
    {
        var actor = await Setup(); var oldKey = Key.New(); var active = await Enroll(actor, oldKey);
        var oldDevice = Id(active, "device_id"); var newKey = Key.New();
        var begin = await Begin(actor, expected: 2, target: oldDevice); var id = Id(begin, "ceremony_id");
        AssertOutcome("conflict", await Reserve(actor, id, "current"));
        await Finish(actor, await Reserve(actor, id, "registration"), newKey, next: true);
        AssertOutcome("conflict", await Reserve(actor, id, "current"));
        var candidate = await Finish(actor, await Reserve(actor, id, "candidate"), newKey, next: true);
        Assert.Equal("current", candidate.GetProperty("state").GetString());
        var wrongProof = await Reserve(actor, id, "current");
        AssertOutcome("invalid_proof", await Finish(actor, wrongProof, newKey));
        var current = await Reserve(actor, id, "current");
        Assert.Equal(Convert.ToHexString(oldKey.Credential).ToLowerInvariant(), current.GetProperty("credential_id_hex").GetString());
        var result = await Finish(actor, current, oldKey);
        Assert.Equal(3, result.GetProperty("committed_identity_version").GetInt64());
        await using var owner = await Owner();
        Assert.Equal("revoked", await Sql(owner, "SELECT status FROM amdn_identity.devices WHERE device_id=@id", ("id", oldDevice)));
        Assert.Equal("credential_active", await Sql(owner, "SELECT status FROM amdn_identity.devices WHERE device_id=@id", ("id", Id(result, "device_id"))));
        Assert.Equal(1L, await Sql(owner, "SELECT count(*) FROM amdn_identity.devices WHERE tenant_id=@tenant AND status='credential_active'", ("tenant", actor.Person.TenantId)));
    }

    [Fact]
    public async Task ConcurrentBeginsShareReplayButAllowOnlyOneUnfinishedCeremony()
    {
        var actor = await Setup(); var key = Idempotency();
        var same = await Task.WhenAll(Begin(actor, key: key), Begin(actor, key: key));
        Assert.Equal(Id(same[0], "ceremony_id"), Id(same[1], "ceremony_id"));
        AssertOutcome("conflict", await Begin(actor));
        var another = await Setup();
        var different = await Task.WhenAll(Begin(another), Begin(another));
        Assert.Single(different, result => result.GetProperty("outcome").GetString() == "ok");
        Assert.Single(different, result => result.GetProperty("outcome").GetString() == "conflict");
    }

    [Fact]
    public async Task AttemptReservationsAreBoundedDurableAndFailedReplaysStayFailed()
    {
        var actor = await Setup(); var id = Id(await Begin(actor), "ceremony_id");
        var keys = Enumerable.Range(0, 6).Select(_ => Idempotency()).ToArray();
        var results = await Task.WhenAll(keys.Select(key => Reserve(actor, id, "registration", key)));
        Assert.Equal(5, results.Count(value => value.GetProperty("outcome").GetString() == "reserved"));
        Assert.Single(results, value => value.GetProperty("outcome").GetString() == "unavailable");
        var firstIndex = Array.FindIndex(results, result => result.GetProperty("outcome").GetString() == "reserved");
        AssertOutcome("unavailable", await Reserve(actor, id, "registration", keys[firstIndex]));
        AssertOutcome("conflict", await Reserve(actor, id, "registration", keys[firstIndex], "different bytes"));
        foreach (var reserved in results.Where(result => result.GetProperty("outcome").GetString() == "reserved"))
            AssertOutcome("invalid_proof", await Fail(actor, reserved));
        AssertOutcome("invalid_proof", await Reserve(actor, id, "registration", keys[firstIndex]));
        AssertOutcome("conflict", await Reserve(actor, id, "registration"));
        await using var owner = await Owner();
        Assert.Equal("abandoned", await Sql(owner, "SELECT state FROM amdn_identity.device_ceremonies WHERE ceremony_id=@id", ("id", id)));
        Assert.Equal(5L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_commands WHERE ceremony_id=@id AND attempt_number IS NOT NULL", ("id", id)));
    }

    [Fact]
    public async Task FinishRequiresACommittedReservationAndMatchingDigest()
    {
        var actor = await Setup(); var id = Id(await Begin(actor), "ceremony_id"); var key = Key.New();
        await using (var owner = await Owner())
        await using (var transaction = await owner.BeginTransactionAsync())
        {
            var reserved = await Reserve(actor, id, "registration", connection: owner);
            AssertOutcome("conflict", await Finish(actor, reserved, key, next: true, connection: owner));
            Assert.Equal(actor.Person.TenantId.ToString(), await Sql(owner, "SELECT current_setting('amdn.tenant_id')"));
            Assert.Equal(actor.Person.UserId.ToString(), await Sql(owner, "SELECT current_setting('amdn.user_id')"));
            await transaction.RollbackAsync();
            Assert.Equal(DBNull.Value, await Sql(owner, "SELECT nullif(current_setting('amdn.tenant_id',true),'')"));
        }
        var attempt = await Reserve(actor, id, "registration");
        var bad = await Call(actor, "ceremony_finish", "@attempt,@digest,@credential,@publickey,false,false,0,@next", null,
            ("attempt", Id(attempt, "attempt_id")), ("digest", new byte[32]), ("credential", key.Credential), ("publickey", key.Public), ("next", RandomNumberGenerator.GetBytes(32)));
        AssertOutcome("conflict", bad);
        AssertOutcome("ok", await Finish(actor, attempt, key, next: true));
    }

    [Theory]
    [InlineData("config")]
    [InlineData("grant")]
    [InlineData("membership")]
    [InlineData("device")]
    public async Task StateChangesBetweenReservationAndCommitAbandonTheCeremony(string change)
    {
        var actor = await Setup(); var begin = await Begin(actor); var id = Id(begin, "ceremony_id");
        var key = Key.New(); await Finish(actor, await Reserve(actor, id, "registration"), key, next: true);
        var proof = await Reserve(actor, id, "candidate");
        await using var owner = await Owner();
        var sql = change switch
        {
            "config" => "UPDATE amdn_identity.device_configurations SET maximum_age_seconds=899 WHERE configuration_id=@config",
            "grant" => "UPDATE amdn_identity.device_management_grants SET expires_at=expires_at+interval '1 minute' WHERE tenant_id=@tenant",
            "membership" => "UPDATE amdn_identity.memberships SET status='suspended' WHERE tenant_id=@tenant; UPDATE amdn_identity.memberships SET status='active' WHERE tenant_id=@tenant",
            _ => "UPDATE amdn_identity.devices SET sign_count=1 WHERE device_id=@device"
        };
        await Sql(owner, sql, ("config", actor.Configuration), ("tenant", actor.Person.TenantId), ("device", Id(begin, "device_id")));
        AssertOutcome("conflict", await Finish(actor, proof, key));
        Assert.Equal("abandoned", await Sql(owner, "SELECT state FROM amdn_identity.device_ceremonies WHERE ceremony_id=@id", ("id", id)));
        Assert.Equal(1L, await Sql(owner, "SELECT identity_version FROM amdn_identity.users WHERE tenant_id=@tenant", ("tenant", actor.Person.TenantId)));
    }

    [Fact]
    public async Task ForeignOwnerClientOriginScopeAndStepUpCannotUseAReservation()
    {
        var actor = await Setup(); var id = Id(await Begin(actor), "ceremony_id");
        var other = await Setup(actor.Person.TenantId, actor.Configuration);
        AssertOutcome("not_found", await Reserve(other, id, "registration"));
        AssertOutcome("conflict", await Reserve(actor with { Client = "another-client" }, id, "registration"));
        AssertOutcome("forbidden", await Reserve(actor with { Origin = "https://foreign.invalid" }, id, "registration"));
        AssertOutcome("forbidden", await Reserve(actor with { Scope = "postman.read" }, id, "registration"));
        AssertOutcome("forbidden", await Reserve(actor with { Acr = "weak" }, id, "registration"));
        AssertOutcome("forbidden", await Reserve(actor with { AuthTime = DateTime.UtcNow.AddHours(-1) }, id, "registration"));
        AssertOutcome("forbidden", await Reserve(actor with { AuthTime = DateTime.UtcNow.AddMinutes(1) }, id, "registration"));
        AssertOutcome("forbidden", await Reserve(actor with { TokenExpiry = DateTime.UtcNow.AddSeconds(-1) }, id, "registration"));
        var foreign = await Setup(); AssertOutcome("not_found", await Reserve(foreign, id, "registration"));
    }

    [Fact]
    public async Task ExpiredChallengeCannotRefreshOrActivateAndNewBeginRetainsOldAttribution()
    {
        var actor = await Setup(); var key = Key.New(); var begin = await Begin(actor); var id = Id(begin, "ceremony_id");
        var proof = await Reserve(actor, id, "registration");
        await using var owner = await Owner();
        await Sql(owner, "UPDATE amdn_identity.device_challenges SET issued_at=statement_timestamp()-interval '3 minutes',expires_at=statement_timestamp()-interval '1 minute' WHERE ceremony_id=@id", ("id", id));
        AssertOutcome("conflict", await Finish(actor, proof, key, next: true));
        Assert.Equal("expired", await Sql(owner, "SELECT state FROM amdn_identity.device_ceremonies WHERE ceremony_id=@id", ("id", id)));
        var again = await Begin(actor); AssertOutcome("ok", again);
        Assert.NotEqual(Id(begin, "device_id"), Id(again, "device_id"));
        Assert.Equal("abandoned", await Sql(owner, "SELECT status FROM amdn_identity.devices WHERE device_id=@id", ("id", Id(begin, "device_id"))));
    }

    [Fact]
    public async Task AuditFailureRollsBackActivationVersionReplayAndChallengeTogether()
    {
        var actor = await Setup(); var key = Key.New(); var begin = await Begin(actor); var id = Id(begin, "ceremony_id");
        await Finish(actor, await Reserve(actor, id, "registration"), key, next: true);
        var proof = await Reserve(actor, id, "candidate");
        await using var owner = await Owner();
        await Sql(owner, """
            CREATE FUNCTION amdn_identity.test_ceremony_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $f$
            BEGIN IF NEW.action='candidate' THEN RAISE EXCEPTION 'Synthetic audit failure' USING ERRCODE='23514'; END IF; RETURN NEW; END $f$;
            CREATE TRIGGER test_ceremony_audit_failure BEFORE INSERT ON amdn_identity.device_ceremony_audit
              FOR EACH ROW EXECUTE FUNCTION amdn_identity.test_ceremony_audit_failure();
            """);
        try
        {
            var exception = await Assert.ThrowsAsync<PostgresException>(() => Finish(actor, proof, key));
            Assert.Equal("23514", exception.SqlState);
            Assert.Equal(1L, await Sql(owner, "SELECT identity_version FROM amdn_identity.users WHERE tenant_id=@tenant", ("tenant", actor.Person.TenantId)));
            Assert.Equal("pending", await Sql(owner, "SELECT status FROM amdn_identity.devices WHERE device_id=@id", ("id", Id(begin, "device_id"))));
            Assert.Equal("reserved", await Sql(owner, "SELECT state FROM amdn_identity.device_commands WHERE command_id=@id", ("id", Id(proof, "attempt_id"))));
            Assert.Equal(1L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_challenges WHERE ceremony_id=@id AND stage='candidate' AND consumed_at IS NULL", ("id", id)));
        }
        finally { await Sql(owner, "DROP TRIGGER test_ceremony_audit_failure ON amdn_identity.device_ceremony_audit; DROP FUNCTION amdn_identity.test_ceremony_audit_failure()"); }
        AssertOutcome("ok", await Finish(actor, proof, key));
    }

    [Theory]
    [InlineData("token")]
    [InlineData("challenge")]
    [InlineData("command")]
    public async Task DeadlineIsRecheckedAfterWaitingForRowLock(string deadline)
    {
        var actor = await Setup(); var key = Key.New(); var begin = await Begin(actor); var id = Id(begin, "ceremony_id");
        await Finish(actor, await Reserve(actor, id, "registration"), key, next: true);
        var proof = await Reserve(actor, id, "candidate");
        await using var holder = await Owner(); await using var transaction = await holder.BeginTransactionAsync();
        var pid = (int)(await Sql(holder, "SELECT pg_backend_pid()"))!;
        var authorityDeadline = deadline != "challenge";
        if (deadline == "command")
            await Sql(holder, "SELECT command_id FROM amdn_identity.device_commands WHERE command_id=@id FOR UPDATE", ("id", Id(proof, "attempt_id")));
        else
            await Sql(holder, "SELECT device_id FROM amdn_identity.devices WHERE device_id=@id FOR UPDATE", ("id", Id(begin, "device_id")));
        if (deadline == "challenge")
            await Sql(holder, "UPDATE amdn_identity.device_challenges SET issued_at=statement_timestamp()-interval '3 minutes',expires_at=statement_timestamp()-interval '1 minute' WHERE ceremony_id=@id AND stage='candidate'", ("id", id));
        var attemptedActor = authorityDeadline ? actor with { TokenExpiry = DateTime.UtcNow.AddMilliseconds(400) } : actor;
        var finishing = Finish(attemptedActor, proof, key);
        await WaitBlocked(pid);
        if (authorityDeadline) await Task.Delay(450);
        await transaction.CommitAsync();
        AssertOutcome(authorityDeadline ? "forbidden" : "conflict", await finishing);
        Assert.Equal(1L, await Sql(holder, "SELECT identity_version FROM amdn_identity.users WHERE tenant_id=@tenant", ("tenant", actor.Person.TenantId)));
    }

    [Theory]
    [InlineData("credential", "challenge")]
    [InlineData("credential", "authority")]
    [InlineData("public_key", "challenge")]
    [InlineData("public_key", "authority")]
    [InlineData("next_challenge", "challenge")]
    [InlineData("next_challenge", "authority")]
    public async Task ExpiryDuringUniqueWriteRollsBackSuccessAndRetainsCommittedReservation(string collision, string deadline)
    {
        var holderActor = await Setup(); var actor = await Setup();
        var holderBegin = await Begin(holderActor); var begin = await Begin(actor); var id = Id(begin, "ceremony_id");
        var holderProof = await Reserve(holderActor, Id(holderBegin, "ceremony_id"), "registration");
        var proof = await Reserve(actor, id, "registration");
        var holderKey = Key.New(); var key = Key.New();
        key = collision switch
        {
            "credential" => key with { Credential = holderKey.Credential },
            "public_key" => key with { Public = holderKey.Public },
            _ => key
        };
        var holderNext = RandomNumberGenerator.GetBytes(32);
        var next = collision == "next_challenge" ? holderNext : RandomNumberGenerator.GetBytes(32);
        await using var observer = await Owner();
        await using var holder = await Owner(); await using var transaction = await holder.BeginTransactionAsync();
        AssertOutcome("ok", await Call(holderActor, "ceremony_finish", "@attempt,@digest,@credential,@publickey,false,false,0,@next", holder,
            ("attempt", Id(holderProof, "attempt_id")), ("digest", Digest(holderProof)), ("credential", holderKey.Credential),
            ("publickey", holderKey.Public), ("next", holderNext)));
        var pid = (int)(await Sql(holder, "SELECT pg_backend_pid()"))!;
        var expiresAt = (DateTime)(await Sql(observer, "SELECT clock_timestamp()+interval '2 seconds'"))!;
        if (deadline == "challenge")
            await Sql(observer, "UPDATE amdn_identity.device_challenges SET expires_at=@expires WHERE ceremony_id=@id AND stage='registration'",
                ("expires", expiresAt), ("id", id));
        var attemptedActor = deadline == "authority" ? actor with { TokenExpiry = expiresAt } : actor;
        var finishing = Call(attemptedActor, "ceremony_finish", "@attempt,@digest,@credential,@publickey,false,false,0,@next", null,
            ("attempt", Id(proof, "attempt_id")), ("digest", Digest(proof)), ("credential", key.Credential),
            ("publickey", key.Public), ("next", next));
        await WaitBlocked(pid);
        await Sql(observer, "SELECT pg_sleep(greatest(0,extract(epoch FROM (@expires-clock_timestamp()))))", ("expires", expiresAt));
        await transaction.RollbackAsync();
        AssertOutcome(deadline == "authority" ? "forbidden" : "conflict", await finishing);
        Assert.Equal(1L, await Sql(observer, "SELECT identity_version FROM amdn_identity.users WHERE tenant_id=@tenant", ("tenant", actor.Person.TenantId)));
        Assert.Equal(deadline == "authority" ? "registration" : "expired",
            await Sql(observer, "SELECT state FROM amdn_identity.device_ceremonies WHERE ceremony_id=@id", ("id", id)));
        Assert.Equal(deadline == "authority" ? "pending" : "abandoned",
            await Sql(observer, "SELECT status FROM amdn_identity.devices WHERE device_id=@id", ("id", Id(begin, "device_id"))));
        Assert.Equal(true, await Sql(observer, """
            SELECT credential_id IS NULL AND public_key_cose IS NULL AND backup_eligible IS NULL
              AND backup_state IS NULL AND sign_count IS NULL AND activated_at IS NULL AND revoked_at IS NULL
              AND record_version=@version
            FROM amdn_identity.devices WHERE device_id=@id
            """, ("id", Id(begin, "device_id")), ("version", deadline == "authority" ? 1L : 2L)));
        Assert.Equal(true, await Sql(observer, """
            SELECT state='reserved' AND result IS NULL AND request_digest=@digest AND attempt_number=1
              AND reservation_tx<>pg_current_xact_id() AND verified_device_version=1
            FROM amdn_identity.device_commands WHERE command_id=@id
            """, ("id", Id(proof, "attempt_id")), ("digest", Digest(proof))));
        Assert.Equal(1L, await Sql(observer, "SELECT count(*) FROM amdn_identity.device_challenges WHERE ceremony_id=@id", ("id", id)));
        Assert.Equal(1L, await Sql(observer, "SELECT count(*) FROM amdn_identity.device_challenges WHERE ceremony_id=@id AND stage='registration' AND consumed_at IS NULL", ("id", id)));
        Assert.Equal(0L, await Sql(observer, "SELECT count(*) FROM amdn_identity.device_ceremony_audit WHERE ceremony_id=@id AND action NOT IN ('begun','reserved','expired')", ("id", id)));
        if (deadline == "authority")
            AssertOutcome("ok", await Finish(actor, proof, key, next: true));
    }

    [Fact]
    public async Task NonzeroCounterReplayAndBackupEligibilityChangesFailBeforeEffects()
    {
        var actor = await Setup(); var key = Key.New(); var id = Id(await Begin(actor), "ceremony_id");
        await Finish(actor, await Reserve(actor, id, "registration"), key, next: true, counter: 10);
        AssertOutcome("invalid_proof", await Finish(actor, await Reserve(actor, id, "candidate"), key, counter: 10));
        AssertOutcome("invalid_proof", await Finish(actor, await Reserve(actor, id, "candidate"), key, counter: 0));
        var be = await Reserve(actor, id, "candidate");
        AssertOutcome("invalid_proof", await Call(actor, "ceremony_finish", "@attempt,@digest,@credential,@publickey,true,false,11,NULL", null,
            ("attempt", Id(be, "attempt_id")), ("digest", Digest(be)), ("credential", key.Credential), ("publickey", key.Public)));
        AssertOutcome("ok", await Finish(actor, await Reserve(actor, id, "candidate"), key, counter: 11));
    }

    [Fact]
    public async Task ReservedAttemptSurvivesDatabaseRestartAndIsNotReissued()
    {
        var actor = await Setup(); var id = Id(await Begin(actor), "ceremony_id"); var key = Idempotency();
        var attempt = await Reserve(actor, id, "registration", key);
        _state = await _state.CrashAndRestart(_state.PostgresContainer);
        for (var retry = 0; ; retry++)
        {
            try { AssertOutcome("unavailable", await Reserve(actor, id, "registration", key)); break; }
            catch (NpgsqlException) when (retry < 30) { await Task.Delay(200); }
        }
        AssertOutcome("ok", await Finish(actor, attempt, Key.New(), next: true));
    }

    [Fact]
    public async Task NoApiRoleCanReadOrExecuteTheCeremonyBoundaryAndRlsIsForced()
    {
        foreach (var role in new[] { "runtime", "provisioner" })
        {
            await using var connection = new NpgsqlConnection(_state.IdentityConnection(role)); await connection.OpenAsync();
            foreach (var table in new[] { "device_configurations", "device_management_grants", "device_ceremonies", "device_challenges", "device_commands", "device_ceremony_audit" })
            {
                foreach (var sql in new[] { $"SELECT * FROM amdn_identity.{table}", $"INSERT INTO amdn_identity.{table} DEFAULT VALUES", $"DELETE FROM amdn_identity.{table}" })
                {
                    var error = await Assert.ThrowsAsync<PostgresException>(() => Sql(connection, sql)); Assert.Equal("42501", error.SqlState);
                }
            }
            Assert.Equal(false, await Sql(connection, "SELECT has_function_privilege(current_user,'amdn_identity.ceremony_snapshot(uuid)','EXECUTE')"));
            var denied = await Assert.ThrowsAsync<PostgresException>(() => Sql(connection, "SELECT amdn_identity.ceremony_snapshot(gen_random_uuid())"));
            Assert.Equal("42501", denied.SqlState);
        }
        await using var owner = await Owner();
        Assert.Equal(6L, await Sql(owner, """
            SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='amdn_identity'
            AND c.relname IN ('device_configurations','device_management_grants','device_ceremonies','device_challenges','device_commands','device_ceremony_audit')
            AND c.relrowsecurity AND c.relforcerowsecurity
            """));
        Assert.Equal(0L, await Sql(owner, "SELECT count(*) FROM pg_proc WHERE pronamespace='amdn_identity'::regnamespace AND proname LIKE 'ceremony_%' AND prosecdef"));
    }

    private async Task<Actor> Setup(Guid? tenant = null, Guid? config = null)
    {
        await using var provisioning = IdentityDatabase.ProvisioningPool(_state.IdentityConnection("provisioner"));
        var provisioner = new IdentityProvisioner(provisioning); var subject = Guid.NewGuid().ToString();
        var person = await provisioner.EnsureMemberAsync(tenant ?? await provisioner.CreateTenantAsync(), "https://ceremony-issuer.invalid", subject);
        await using var owner = await Owner();
        var configuration = config ?? (Guid)(await Sql(owner, """
            INSERT INTO amdn_identity.device_configurations(rp_id,origin,allowed_acrs,maximum_age_seconds,enabled)
            VALUES('ceremony.invalid','https://ceremony.invalid',ARRAY['urn:amdn:test:strong'],900,true) RETURNING configuration_id
            """))!;
        await Sql(owner, "INSERT INTO amdn_identity.device_management_grants(tenant_id,user_id,postman_id,expires_at) VALUES(@tenant,@user,@postman,clock_timestamp()+interval '1 hour')",
            ("tenant", person.TenantId), ("user", person.UserId), ("postman", person.PostmanId));
        return new(person, subject, configuration);
    }
    private async Task<JsonElement> Enroll(Actor actor, Key key)
    {
        var id = Id(await Begin(actor), "ceremony_id");
        await Finish(actor, await Reserve(actor, id, "registration"), key, next: true);
        return await Finish(actor, await Reserve(actor, id, "candidate"), key);
    }
    private Task<JsonElement> Begin(Actor actor, string operation = "enrollment", long expected = 1, Guid? target = null, string? key = null, string body = "{\"synthetic\":true}") =>
        Call(actor, "ceremony_begin", "@operation,@expected,@target,@key,@body,@challenge,@handle", null,
            ("operation", operation), ("expected", expected), ("target", target), ("key", key ?? Idempotency()), ("body", Encoding.UTF8.GetBytes(body)),
            ("challenge", RandomNumberGenerator.GetBytes(32)), ("handle", RandomNumberGenerator.GetBytes(32)));
    private Task<JsonElement> Reserve(Actor actor, Guid ceremony, string stage, string? key = null, string body = "{\"synthetic\":true}", NpgsqlConnection? connection = null) =>
        Call(actor, "ceremony_reserve", "@id,@stage,@key,@body", connection,
            ("id", ceremony), ("stage", stage), ("key", key ?? Idempotency()), ("body", Encoding.UTF8.GetBytes(body)));
    private Task<JsonElement> Finish(Actor actor, JsonElement reservation, Key key, bool next = false, long counter = 0, NpgsqlConnection? connection = null) =>
        Call(actor, "ceremony_finish", "@attempt,@digest,@credential,@publickey,false,false,@counter,@next", connection,
            ("attempt", Id(reservation, "attempt_id")), ("digest", Digest(reservation)), ("credential", key.Credential), ("publickey", key.Public),
            ("counter", counter), ("next", next ? RandomNumberGenerator.GetBytes(32) : null));
    private Task<JsonElement> Fail(Actor actor, JsonElement reservation) => Call(actor, "ceremony_fail", "@attempt,@digest", null,
        ("attempt", Id(reservation, "attempt_id")), ("digest", Digest(reservation)));
    private async Task<JsonElement> Call(Actor actor, string function, string arguments, NpgsqlConnection? supplied, params (string Name, object? Value)[] values)
    {
        var connection = supplied ?? await Owner();
        try
        {
            var parameters = new List<(string, object?)>
            {
                ("tenant", actor.Person.TenantId), ("issuer", "https://ceremony-issuer.invalid"), ("subject", actor.Subject), ("client", actor.Client),
                ("origin", actor.Origin), ("config", actor.Configuration), ("scope", actor.Scope), ("acr", actor.Acr), ("auth_time", actor.AuthTime), ("token_exp", actor.TokenExpiry)
            };
            parameters.AddRange(values);
            var result = (string)(await Sql(connection, $"SELECT amdn_identity.{function}({ActorSql},{arguments})", parameters.ToArray()))!;
            using var json = JsonDocument.Parse(result); return json.RootElement.Clone();
        }
        finally { if (supplied is null) await connection.DisposeAsync(); }
    }
    private async Task<NpgsqlConnection> Owner()
    {
        var connection = new NpgsqlConnection(_state.IdentityConnection("migrator")); await connection.OpenAsync();
        await Sql(connection, "SET ROLE amdn_identity_owner"); return connection;
    }
    private async Task WaitBlocked(int pid)
    {
        await using var observer = await Owner();
        for (var retry = 0; retry < 100; retry++)
        {
            if (await Sql(observer, "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE @pid=ANY(pg_blocking_pids(pid)))", ("pid", pid)) is true) return;
            await Task.Delay(20);
        }
        Assert.Fail("Expected a transaction waiting on the synthetic device lock.");
    }
    private static async Task<object?> Sql(NpgsqlConnection connection, string sql, params (string Name, object? Value)[] values)
    {
        await using var command = new NpgsqlCommand(sql, connection);
        foreach (var (name, value) in values)
        {
            if (value is null) command.Parameters.Add(new NpgsqlParameter(name, name == "target" ? NpgsqlDbType.Uuid : NpgsqlDbType.Bytea) { Value = DBNull.Value });
            else command.Parameters.AddWithValue(name, value);
        }
        return await command.ExecuteScalarAsync();
    }
    private static void AssertOutcome(string expected, JsonElement value) => Assert.Equal(expected, value.GetProperty("outcome").GetString());
    private static Guid Id(JsonElement value, string name) => value.GetProperty(name).GetGuid();
    private static byte[] Digest(JsonElement value) => Convert.FromHexString(value.GetProperty("request_digest_hex").GetString()!);
    private static string Idempotency() => Guid.NewGuid().ToString("N");
}
