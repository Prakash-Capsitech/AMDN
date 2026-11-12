using NATS.Client.JetStream;
using NATS.Net;
using Npgsql;
using Xunit;

namespace AMDN.Harness.Tests;

public sealed class HarnessTests
{
    private RunState _state = RunState.Load();

    [Fact]
    public async Task ApplicationRoleCannotBypassForcedRlsOrAssumeOwner()
    {
        await using var database = _state.Database();
        await using var connection = await database.OpenConnectionAsync();
        await using var role = new NpgsqlCommand("SELECT rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb FROM pg_roles WHERE rolname=current_user", connection);
        Assert.Equal(false, await role.ExecuteScalarAsync());
        await using var tables = new NpgsqlCommand("""
            SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname='fixture' AND c.relrowsecurity AND c.relforcerowsecurity
              AND pg_get_userbyid(c.relowner) <> current_user
            """, connection);
        Assert.Equal(5L, await tables.ExecuteScalarAsync());
        await using var metadata = new NpgsqlCommand("SELECT run_id FROM fixture.run_metadata", connection);
        Assert.Equal(_state.RunId, await metadata.ExecuteScalarAsync());
        foreach (var sql in new[] { "SET ROLE harness_owner", "TRUNCATE fixture.inbox" })
        {
            await using var denied = new NpgsqlCommand(sql, connection);
            var error = await Assert.ThrowsAsync<PostgresException>(() => denied.ExecuteNonQueryAsync());
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
        }
    }

    [Fact]
    public async Task TwoTenantsAndFourUsersSeeOnlyTheirOwnRowsAndCannotForgeWrites()
    {
        await using var database = _state.Database();
        var jobs = Principal.All.Select(principal => Job.New() with { Sender = principal }).ToArray();
        foreach (var job in jobs) await Model.Accept(database, job);
        foreach (var principal in Principal.All)
        {
            await using var scope = await Scope.Open(database, principal);
            foreach (var job in jobs)
            {
                Assert.Equal(job.Sender == principal ? 1L : 0L,
                    await scope.Sql("SELECT count(*) FROM fixture.envelopes WHERE envelope_id=@id", ("id", job.Envelope)));
            }
            Assert.Equal(1L, await scope.Sql("SELECT count(*) FROM fixture.users"));
            Assert.Equal(principal.User, await scope.Sql("SELECT user_id FROM fixture.users"));
            foreach (var other in Principal.All.Where(value => value != principal))
            {
                Assert.Equal(0L, await scope.Sql("SELECT count(*) FROM fixture.users WHERE tenant_id=@tenant AND user_id=@user",
                    ("tenant", other.Tenant), ("user", other.User)));
            }
        }
        foreach (var forged in new[] { Principal.Ann, Principal.Bob })
        {
            await using var scope = await Scope.Open(database, Principal.Alice);
            var error = await Assert.ThrowsAsync<PostgresException>(() => Model.Insert(scope, Job.New() with { Sender = forged }));
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
        }
        // Neither tenant-only nor absent context can read identity rows.
        await using var connection = await database.OpenConnectionAsync();
        await using var query = new NpgsqlCommand("SELECT count(*) FROM fixture.users", connection);
        Assert.Equal(0L, await query.ExecuteScalarAsync());
        await using var missingContextWrite = new NpgsqlCommand("""
            INSERT INTO fixture.inbox (tenant_id,user_id,envelope_id,ciphertext)
            VALUES (@tenant,@user,@id,@bytes)
            """, connection);
        missingContextWrite.Parameters.AddWithValue("tenant", Principal.Alice.Tenant);
        missingContextWrite.Parameters.AddWithValue("user", Principal.Alice.User);
        missingContextWrite.Parameters.AddWithValue("id", Guid.NewGuid());
        missingContextWrite.Parameters.AddWithValue("bytes", Model.SealedFixture);
        var denied = await Assert.ThrowsAsync<PostgresException>(() => missingContextWrite.ExecuteNonQueryAsync());
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, denied.SqlState);
        await using var transaction = await connection.BeginTransactionAsync();
        await using var partial = new NpgsqlCommand("SELECT set_config('amdn.tenant_id', @tenant, true)", connection, transaction);
        partial.Parameters.AddWithValue("tenant", Principal.Alice.Tenant.ToString());
        await partial.ExecuteNonQueryAsync();
        Assert.Equal(0L, await query.ExecuteScalarAsync());
    }

    [Theory]
    [InlineData("commit")]
    [InlineData("rollback")]
    [InlineData("error")]
    public async Task TransactionContextDoesNotLeakAcrossPhysicalPoolReuse(string end)
    {
        await using var database = _state.Database();
        int firstPid;
        await using (var scope = await Scope.Open(database, Principal.Alice))
        {
            firstPid = scope.Connection.ProcessID;
            Assert.Equal(Principal.Alice.User, await scope.Sql("SELECT user_id FROM fixture.users"));
            if (end == "commit")
            {
                await scope.Commit();
                await using var afterCommit = new NpgsqlCommand("SELECT count(*) FROM fixture.users", scope.Connection);
                Assert.Equal(0L, await afterCommit.ExecuteScalarAsync());
            }
            else if (end == "error")
            {
                var error = await Assert.ThrowsAsync<PostgresException>(() => scope.Sql("SELECT 1/0"));
                Assert.Equal(PostgresErrorCodes.DivisionByZero, error.SqlState);
            }
        }
        await using (var connection = await database.OpenConnectionAsync())
        {
            Assert.Equal(firstPid, connection.ProcessID);
            await using var noContext = new NpgsqlCommand("SELECT count(*) FROM fixture.users", connection);
            Assert.Equal(0L, await noContext.ExecuteScalarAsync());
        }
        await Task.WhenAll(Principal.All.Select(async principal =>
        {
            await using var scope = await Scope.Open(database, principal);
            Assert.Equal(firstPid, scope.Connection.ProcessID);
            Assert.Equal(principal.User, await scope.Sql("SELECT user_id FROM fixture.users"));
            await scope.Commit();
        }));
    }

    [Theory]
    [InlineData("before-commit", 0L)]
    [InlineData("after-commit", 1L)]
    public async Task KilledWriterLeavesEnvelopeAndOutboxAtomic(string checkpoint, long expected)
    {
        var job = Job.New();
        await CrashProbe.KillAt(checkpoint, job);
        await using var database = _state.Database();
        Assert.Equal(expected, await Model.Count(database, job.Sender, "envelopes", job.Envelope));
        Assert.Equal(expected, await Model.Count(database, job.Sender, "outbox", job.Event));
    }

    [Fact]
    public async Task CrashAfterPubAckReplaysOutboxWithoutDuplicatingInboxEffect()
    {
        await using var database = _state.Database();
        await using var broker = _state.Broker();
        var js = broker.CreateJetStreamContext();
        var stream = await Model.Stream(js);
        var job = Job.New();
        await CrashProbe.KillAt("after-publish", job, stream);
        await using (var scope = await Scope.Open(database, job.Sender))
        {
            Assert.Equal(false, await scope.Sql("SELECT published FROM fixture.outbox WHERE event_id=@event", ("event", job.Event)));
            // No broker deduplication header: both publishes must reach the consumer.
            (await js.PublishAsync(stream, job)).EnsureSuccess();
            await scope.Sql("UPDATE fixture.outbox SET published=true WHERE event_id=@event", ("event", job.Event));
            await scope.Commit();
        }
        var consumer = await Model.Consumer(js, stream);
        var sequences = new HashSet<ulong>();
        for (var i = 0; i < 2; i++)
        {
            var message = await Model.Next(consumer);
            Assert.Equal(job, message.Data);
            sequences.Add(message.Metadata!.Value.Sequence.Stream);
            Assert.True(await Model.Deliver(database, Principal.Alice, message.Data!));
            await message.AckAsync();
        }
        Assert.Equal(2, sequences.Count);
        Assert.Equal(1L, await Model.Count(database, job.Recipient, "inbox", job.Envelope));
        Assert.Equal(1L, await Model.Count(database, job.Recipient, "processed_events", job.Event));
    }

    [Fact]
    public async Task CrashAfterInboxCommitRedeliversAndBrokerAckDoesNotAcknowledgeDevice()
    {
        await using var database = _state.Database();
        var job = Job.New();
        await Model.Accept(database, job);
        await using var broker = _state.Broker();
        var js = broker.CreateJetStreamContext();
        var stream = await Model.Stream(js);
        (await js.PublishAsync(stream, job)).EnsureSuccess();
        await CrashProbe.KillAt("after-delivery", job, stream);
        var consumer = await Model.Consumer(js, stream);
        var replay = await Model.Next(consumer);
        Assert.Equal(job, replay.Data);
        Assert.True(replay.Metadata!.Value.NumDelivered >= 2);
        Assert.True(await Model.Deliver(database, Principal.Alice, replay.Data!));
        await replay.AckAsync();
        Assert.Equal(1L, await Model.Count(database, job.Recipient, "inbox", job.Envelope));
        Assert.Equal(1L, await Model.Count(database, job.Recipient, "processed_events", job.Event));
        await using var scope = await Scope.Open(database, job.Recipient);
        Assert.Equal(false, await scope.Sql("SELECT device_acked FROM fixture.inbox WHERE envelope_id=@id", ("id", job.Envelope)));
    }

    [Fact]
    public async Task ForgedJobClaimsCannotSelectAnotherSenderRecipientOrEnvelope()
    {
        await using var database = _state.Database();
        var job = Job.New();
        await Model.Accept(database, job);
        foreach (var forged in new[]
        {
            job with { Sender = Principal.Ann }, job with { Sender = Principal.Bob },
            job with { Recipient = Principal.Bea }, job with { Envelope = Guid.NewGuid() },
            job with { Event = Guid.NewGuid() }
        })
            Assert.False(await Model.Deliver(database, Principal.Alice, forged));
        Assert.Equal(0L, await Model.Count(database, job.Recipient, "inbox", job.Envelope));
        Assert.Equal(0L, await Model.Count(database, Principal.Bea, "inbox", job.Envelope));
        Assert.True(await Model.Deliver(database, Principal.Alice, job));
    }

    [Fact]
    public async Task OfflineRecipientRecoversAfterPostgresAndJetStreamProcessRestarts()
    {
        var job = Job.New();
        string stream;
        await using (var database = _state.Database()) await Model.Accept(database, job);
        await using (var broker = _state.Broker())
        {
            var js = broker.CreateJetStreamContext();
            stream = await Model.Stream(js);
            (await js.PublishAsync(stream, job)).EnsureSuccess();
        }
        _state = await _state.CrashAndRestart(_state.PostgresContainer);
        _state = await _state.CrashAndRestart(_state.NatsContainer);
        // Poll readiness with a bounded deadline; assertions below are never retried away.
        await WaitForDatabase();
        await using var recovered = _state.Database();
        Assert.Equal(1L, await Model.Count(recovered, job.Sender, "envelopes", job.Envelope));
        Assert.Equal(1L, await Model.Count(recovered, job.Sender, "outbox", job.Event));
        await using var online = _state.Broker();
        var consumer = await Model.Consumer(online.CreateJetStreamContext(), stream);
        var message = await Model.Next(consumer);
        Assert.Equal(job, message.Data);
        Assert.True(await Model.Deliver(recovered, Principal.Alice, message.Data!));
        await message.AckAsync();
        await using var recipient = await Scope.Open(recovered, job.Recipient);
        Assert.Equal(Model.SealedFixture, await recipient.Sql("SELECT ciphertext FROM fixture.inbox WHERE envelope_id=@id", ("id", job.Envelope)));
        Assert.Equal(false, await recipient.Sql("SELECT device_acked FROM fixture.inbox WHERE envelope_id=@id", ("id", job.Envelope)));
    }

    private async Task WaitForDatabase()
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (true)
        {
            try
            {
                await using var database = _state.Database();
                await using var connection = await database.OpenConnectionAsync();
                return;
            }
            catch (NpgsqlException) when (DateTime.UtcNow < deadline) { await Task.Delay(200); }
        }
    }
}
