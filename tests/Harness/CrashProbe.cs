using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using NATS.Net;
using NATS.Client.JetStream;
using Xunit;

namespace AMDN.Harness.Tests;

internal static class CrashProbe
{
    // Invoked only by this test assembly. A killed child cannot run disposal/finally handlers.
    public static async Task<int> Main(string[] args)
    {
        if (args is ["identity-migrate"])
        {
            try
            {
                await AMDN.Infrastructure.Identity.IdentityMigrations.ApplyAsync(RunState.Load().IdentityConnection("migrator"));
                return 0;
            }
            catch (Exception exception)
            {
                // Message/detail may contain sensitive values. Type and SQLSTATE are safe diagnostics.
                Console.Error.WriteLine("Identity migration failed: " + exception.GetType().Name +
                    (exception is Npgsql.PostgresException postgres ? " " + postgres.SqlState : ""));
                return 1;
            }
        }
        if (args.Length != 4 || args[0] != "crash-probe") return 2;
        try
        {
            var state = RunState.Load();
            var job = JsonSerializer.Deserialize<Job>(args[2])!;
            await using var database = state.Database();
            if (args[1] is "before-commit" or "after-commit")
            {
                await using var scope = await Scope.Open(database, job.Sender);
                await Model.Insert(scope, job);
                if (args[1] == "after-commit") await scope.Commit();
                await Ready();
            }
            else if (args[1] == "after-publish")
            {
                await Model.Accept(database, job);
                await using var broker = state.Broker();
                var js = broker.CreateJetStreamContext();
                (await js.PublishAsync(args[3], job)).EnsureSuccess();
                await Ready(); // PubAck received, outbox still unpublished.
            }
            else if (args[1] == "after-delivery")
            {
                await using var broker = state.Broker();
                var consumer = await Model.Consumer(broker.CreateJetStreamContext(), args[3]);
                var message = await Model.Next(consumer);
                if (message.Data != job || !await Model.Deliver(database, Principal.Alice, message.Data)) return 1;
                await Ready(); // Database committed; broker ACK deliberately absent.
            }
            else return 2;
            return 0;
        }
        catch (Exception) { Console.Error.WriteLine("Crash probe failed before the requested checkpoint."); return 1; }
    }

    private static async Task Ready()
    {
        Console.WriteLine("READY");
        await Console.Out.FlushAsync();
        await Task.Delay(Timeout.InfiniteTimeSpan);
    }

    public static async Task KillAt(string checkpoint, Job job, string stream = "unused")
    {
        var start = new ProcessStartInfo("dotnet") { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var value in new[] { Assembly.GetExecutingAssembly().Location, "crash-probe", checkpoint, JsonSerializer.Serialize(job), stream })
            start.ArgumentList.Add(value);
        using var child = Process.Start(start)!;
        var errors = child.StandardError.ReadToEndAsync();
        try
        {
            Assert.Equal("READY", await child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(30)));
            Assert.False(child.HasExited);
        }
        finally
        {
            if (!child.HasExited) child.Kill(entireProcessTree: true);
            await child.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            await errors;
        }
        Assert.NotEqual(0, child.ExitCode);
    }
}
