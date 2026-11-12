using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using NATS.Client.Core;
using NATS.Client.JetStream;
using NATS.Client.JetStream.Models;
using NATS.Net;
using Npgsql;
using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace AMDN.Harness.Tests;

// All identities and payloads in this assembly are synthetic. No production auth adapter exists yet.
internal sealed record Principal(Guid Tenant, Guid User)
{
    public static readonly Principal Alice = new(Guid.Parse("10000000-0000-0000-0000-000000000001"), Guid.Parse("00000000-0000-0000-0000-000000000001"));
    public static readonly Principal Ann = Alice with { User = Guid.Parse("00000000-0000-0000-0000-000000000002") };
    public static readonly Principal Bob = new(Guid.Parse("20000000-0000-0000-0000-000000000001"), Guid.Parse("00000000-0000-0000-0000-000000000003"));
    public static readonly Principal Bea = Bob with { User = Guid.Parse("00000000-0000-0000-0000-000000000004") };
    public static readonly Principal[] All = [Alice, Ann, Bob, Bea];
}

internal sealed record Job(Guid Event, Guid Envelope, Principal Sender, Principal Recipient)
{
    public static Job New() => new(Guid.NewGuid(), Guid.NewGuid(), Principal.Alice, Principal.Bob);
}

internal sealed record RunState(string RunId, int PostgresPort, int NatsPort, string AppPassword,
    string NatsToken, string PostgresContainer, string NatsContainer)
{
    public static RunState Load()
    {
        var path = Environment.GetEnvironmentVariable("AMDN_HARNESS_STATE")
            ?? throw new InvalidOperationException("Use make harness-test; missing runner state is a failure, never a skip.");
        var state = JsonSerializer.Deserialize<RunState>(File.ReadAllText(path))!;
        if (!Regex.IsMatch(state.RunId, "^[a-f0-9]{32}$") || state.PostgresPort is < 1 or > 65535 || state.NatsPort is < 1 or > 65535)
            throw new InvalidOperationException("Invalid disposable run state.");
        return state;
    }

    public NpgsqlDataSource Database() => NpgsqlDataSource.Create(new NpgsqlConnectionStringBuilder
    {
        Host = "127.0.0.1",
        Port = PostgresPort,
        Database = "amdn_harness",
        Username = "harness_app",
        Password = AppPassword,
        Pooling = true,
        MaxPoolSize = 1, // Forces physical connection reuse, including concurrent callers.
        NoResetOnClose = false,
        Timeout = 5,
        CommandTimeout = 5,
        IncludeErrorDetail = false,
        ApplicationName = "amdn-f05-fixture"
    }.ConnectionString);

    public NatsClient Broker() => new(new NatsOpts
    {
        Url = $"nats://127.0.0.1:{NatsPort}",
        AuthOpts = new NatsAuthOpts { Token = NatsToken },
        ConnectTimeout = TimeSpan.FromSeconds(5),
        RequestTimeout = TimeSpan.FromSeconds(5)
    });

    public async Task<RunState> CrashAndRestart(string container)
    {
        if (container != PostgresContainer && container != NatsContainer)
            throw new InvalidOperationException("Not a resource owned by this run.");
        if (!Regex.IsMatch(container, "^[a-f0-9]{64}$"))
            throw new InvalidOperationException("Invalid container identity.");
        var label = await Docker("inspect", "--format", "{{index .Config.Labels \"amdn.harness.run\"}}", container);
        Assert.Equal(RunId, label.Trim());
        await Docker("kill", "--signal", "KILL", container);
        await Docker("start", container);
        // Docker may reassign an ephemeral host port on start. Discover only the
        // exact owned container, then share the refreshed state with later probes.
        var isDatabase = container == PostgresContainer;
        var address = (await Docker("port", container, isDatabase ? "5432/tcp" : "4222/tcp")).Trim();
        if (!address.StartsWith("127.0.0.1:", StringComparison.Ordinal) ||
            !int.TryParse(address[10..], out var port) || port is < 1 or > 65535)
            throw new InvalidOperationException("Restarted service must remain loopback-only.");
        var updated = isDatabase ? this with { PostgresPort = port } : this with { NatsPort = port };
        await File.WriteAllTextAsync(Environment.GetEnvironmentVariable("AMDN_HARNESS_STATE")!, JsonSerializer.Serialize(updated));
        return updated;
    }

    private static async Task<string> Docker(params string[] args)
    {
        var start = new ProcessStartInfo("docker") { RedirectStandardOutput = true, RedirectStandardError = true };
        start.ArgumentList.Add("--context");
        start.ArgumentList.Add("default");
        foreach (var argument in args) start.ArgumentList.Add(argument);
        using var process = Process.Start(start)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20)); }
        finally { if (!process.HasExited) process.Kill(entireProcessTree: true); }
        await stderr;
        Assert.Equal(0, process.ExitCode);
        return await stdout;
    }
}

internal sealed class Scope : IAsyncDisposable
{
    public NpgsqlConnection Connection { get; }
    private NpgsqlTransaction Transaction { get; }
    private Scope(NpgsqlConnection connection, NpgsqlTransaction transaction) => (Connection, Transaction) = (connection, transaction);

    public static async Task<Scope> Open(NpgsqlDataSource database, Principal principal)
    {
        var connection = await database.OpenConnectionAsync();
        try
        {
            var transaction = await connection.BeginTransactionAsync();
            var scope = new Scope(connection, transaction);
            await scope.Sql("SELECT set_config('amdn.tenant_id', @tenant, true), set_config('amdn.user_id', @user, true)",
                ("tenant", principal.Tenant.ToString()), ("user", principal.User.ToString()));
            return scope;
        }
        catch { await connection.DisposeAsync(); throw; }
    }

    public async Task<object?> Sql(string sql, params (string Name, object Value)[] parameters)
    {
        await using var command = new NpgsqlCommand(sql, Connection, Transaction);
        foreach (var (name, value) in parameters) command.Parameters.AddWithValue(name, value);
        return await command.ExecuteScalarAsync();
    }

    public Task Commit() => Transaction.CommitAsync();
    public async ValueTask DisposeAsync()
    {
        await Transaction.DisposeAsync();
        await Connection.DisposeAsync();
    }
}

internal static class Model
{
    public static readonly byte[] SealedFixture = [0x41, 0x4d, 0x44, 0x4e, 0, 255, 17];

    public static async Task Insert(Scope scope, Job job)
    {
        await scope.Sql("""
            INSERT INTO fixture.envelopes VALUES (@tenant,@user,@envelope,@recipientTenant,@recipientUser,@ciphertext);
            INSERT INTO fixture.outbox (tenant_id,user_id,event_id,envelope_id) VALUES (@tenant,@user,@event,@envelope);
            """, ("tenant", job.Sender.Tenant), ("user", job.Sender.User), ("event", job.Event), ("envelope", job.Envelope),
            ("recipientTenant", job.Recipient.Tenant), ("recipientUser", job.Recipient.User), ("ciphertext", SealedFixture));
    }

    public static async Task Accept(NpgsqlDataSource database, Job job)
    {
        await using var scope = await Scope.Open(database, job.Sender);
        await Insert(scope, job);
        await scope.Commit();
    }

    // Trusted principal is a fixture input, never taken from the untrusted job.
    // Production narrow routing privileges and authenticated broker provenance remain future work.
    public static async Task<bool> Deliver(NpgsqlDataSource database, Principal trustedSender, Job job)
    {
        if (trustedSender != job.Sender) return false;
        byte[] ciphertext;
        await using (var sender = await Scope.Open(database, trustedSender))
        {
            var stored = await sender.Sql("""
                SELECT e.ciphertext FROM fixture.outbox o JOIN fixture.envelopes e
                  USING (tenant_id,user_id,envelope_id)
                WHERE o.event_id=@event AND e.envelope_id=@envelope
                  AND e.recipient_tenant=@tenant AND e.recipient_user=@user
                """, ("event", job.Event), ("envelope", job.Envelope),
                ("tenant", job.Recipient.Tenant), ("user", job.Recipient.User));
            if (stored is not byte[] bytes) return false;
            ciphertext = bytes;
        }
        await using var recipient = await Scope.Open(database, job.Recipient);
        await recipient.Sql("""
            INSERT INTO fixture.processed_events VALUES (@tenant,@user,@event) ON CONFLICT DO NOTHING;
            INSERT INTO fixture.inbox (tenant_id,user_id,envelope_id,ciphertext)
              VALUES (@tenant,@user,@envelope,@ciphertext) ON CONFLICT DO NOTHING;
            """, ("tenant", job.Recipient.Tenant), ("user", job.Recipient.User), ("event", job.Event),
            ("envelope", job.Envelope), ("ciphertext", ciphertext));
        await recipient.Commit();
        return true;
    }

    public static async Task<long> Count(NpgsqlDataSource database, Principal principal, string table, Guid id)
    {
        var key = table switch
        {
            "envelopes" or "inbox" => "envelope_id",
            "outbox" or "processed_events" => "event_id",
            _ => throw new ArgumentException("Unknown fixture table", nameof(table))
        };
        await using var scope = await Scope.Open(database, principal);
        return (long)(await scope.Sql($"SELECT count(*) FROM fixture.{table} WHERE {key}=@id", ("id", id)))!;
    }

    public static async Task<INatsJSConsumer> Consumer(INatsJSContext js, string stream) =>
        await js.CreateOrUpdateConsumerAsync(stream, new ConsumerConfig("worker")
        {
            AckPolicy = ConsumerConfigAckPolicy.Explicit,
            AckWait = TimeSpan.FromSeconds(1),
            MaxDeliver = 10
        });

    public static async Task<INatsJSMsg<Job>> Next(INatsJSConsumer consumer)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        return await consumer.NextAsync<Job>(opts: new NatsJSNextOpts { Expires = TimeSpan.FromSeconds(10) },
            cancellationToken: deadline.Token) ?? throw new InvalidOperationException("Expected a durable message; timed out.");
    }

    public static async Task<string> Stream(INatsJSContext js)
    {
        var name = "F05_" + Guid.NewGuid().ToString("N");
        await js.CreateStreamAsync(new StreamConfig(name, [name])
        {
            Storage = StreamConfigStorage.File,
            MaxBytes = 1024 * 1024,
            NumReplicas = 1
        });
        return name;
    }
}
