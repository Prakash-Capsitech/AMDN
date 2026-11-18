using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using AMDN.Identity.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using Npgsql;

namespace AMDN.Enrollment;

public sealed class EnrollmentApiSettings
{
    public bool Enabled { get; set; }
    public string ConnectionString { get; set; } = "";
    public Guid ConfigurationId { get; set; }
    public string Origin { get; set; } = "";
    public int MaximumPoolSize { get; set; }
    public int RequestsPerMinute { get; set; }
    public int ActorRequestsPerMinute { get; set; }
    public int TenantRequestsPerMinute { get; set; }
    public int MaximumConcurrentProofs { get; set; }
}

public static class EnrollmentHttp
{
    private const string Policy = "AmdnEnrollmentCommand";
    internal const string Profile = "amdn-webauthn-enrollment/1";
    private sealed class Endpoint;

    public static void Configure(WebApplicationBuilder builder)
    {
        builder.Services.AddOptions<EnrollmentApiSettings>()
            .Bind(builder.Configuration.GetSection("EnrollmentApi"), options => options.ErrorOnUnknownConfiguration = true)
            .Validate(settings => Valid(settings, builder.Configuration), "Enrollment requires enabled OIDC/step-up, an explicit DNS HTTPS binding, separate database settings and bounded budgets.")
            .ValidateOnStart();
        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<EnrollmentHttpRuntime>();
        builder.Services.AddAuthorization(options => options.AddPolicy(Policy, policy =>
            policy.AddAuthenticationSchemes(IdentityAuthentication.Scheme).RequireAuthenticatedUser()));
    }

    private static bool Valid(EnrollmentApiSettings settings, IConfiguration configuration)
    {
        if (!settings.Enabled) return settings.ConnectionString.Length == 0 && settings.ConfigurationId == Guid.Empty
            && settings.Origin.Length == 0 && settings.MaximumPoolSize == 0 && settings.RequestsPerMinute == 0
            && settings.ActorRequestsPerMinute == 0 && settings.TenantRequestsPerMinute == 0 && settings.MaximumConcurrentProofs == 0;
        if (!configuration.GetValue<bool>("Authentication:Oidc:Enabled") || !configuration.GetValue<bool>("Authentication:DeviceStepUp:Enabled")
            || string.IsNullOrWhiteSpace(settings.ConnectionString) || settings.ConfigurationId == Guid.Empty
            || settings.MaximumPoolSize is < 1 or > 20 || settings.RequestsPerMinute is < 1 or > 10000
            || settings.ActorRequestsPerMinute < 1 || settings.ActorRequestsPerMinute > settings.RequestsPerMinute
            || settings.TenantRequestsPerMinute < 1 || settings.TenantRequestsPerMinute > settings.RequestsPerMinute
            || settings.MaximumConcurrentProofs is < 1 or > 32) return false;
        try
        {
            _ = new NpgsqlConnectionStringBuilder(settings.ConnectionString);
            _ = new EnrollmentConfiguration(settings.ConfigurationId, settings.Origin);
            var uri = new Uri(settings.Origin);
            if (uri.HostNameType != UriHostNameType.Dns || uri.Host.Length > 253) return false;
            var labels = uri.Host.Split('.');
            if (labels.Any(label => label.Length is < 1 or > 63 || !char.IsAsciiLetterOrDigit(label[0]) || !char.IsAsciiLetterOrDigit(label[^1])
                || label.Any(c => !(char.IsAsciiLetterLower(c) || char.IsAsciiDigit(c) || c == '-')))) return false;
            var last = labels[^1];
            return !last.All(char.IsAsciiDigit) && !(last.StartsWith("0x", StringComparison.Ordinal) && last.AsSpan(2).ToArray().All(char.IsAsciiHexDigit));
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException) { return false; }
    }

    // Charge the global budget before token validation. The explicit AMDN
    // authentication call supplies immutable evidence for the actor budget;
    // normal authentication/authorization then run with the cached result.
    public static async Task Transport(HttpContext context, RequestDelegate next)
    {
        if (context.GetEndpoint()?.Metadata.GetMetadata<Endpoint>() is null) { await next(context); return; }
        IdentityProblem.RequestId(context);
        context.Response.Headers.CacheControl = "no-store";
        var aborted = context.RequestAborted;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(aborted);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        context.RequestAborted = deadline.Token;
        try
        {
            var runtime = context.RequestServices.GetRequiredService<EnrollmentHttpRuntime>();
            using var global = runtime.Global.AttemptAcquire();
            if (!global.IsAcquired) { await IdentityProblem.Create(context, 429).ExecuteAsync(context); return; }
            if (!context.Request.IsHttps) { await IdentityProblem.Create(context, 400).ExecuteAsync(context); return; }
            var token = await ValidatedAccessToken.FromRequestAsync(context);
            using var actor = token is null ? null : runtime.Actors.AttemptAcquire(JsonSerializer.Serialize(new[] { token.Issuer, token.Subject }));
            if (actor is { IsAcquired: false }) { await IdentityProblem.Create(context, 429).ExecuteAsync(context); return; }
            await next(context);
        }
        catch (OperationCanceledException) when (aborted.IsCancellationRequested) { }
        catch (Exception)
        {
            // Verifier/parser/storage exceptions must not log raw proof or token
            // material or expose internal SQL results to a caller.
            context.RequestAborted = aborted;
            if (!context.Response.HasStarted) await IdentityProblem.Create(context, 503).ExecuteAsync(context);
        }
        finally { context.RequestAborted = aborted; }
    }

    public static void MapEnrollmentEndpoints(this WebApplication app)
    {
        if (!app.Services.GetRequiredService<IOptions<EnrollmentApiSettings>>().Value.Enabled) return;
        Map("/v1/device-enrollments", "enrollment", begin: true);
        Map("/v1/device-enrollments/{id}/registration", "registration");
        Map("/v1/device-enrollments/{id}/candidate-proof", "candidate");
        Map("/v1/device-enrollments/{id}/current-proof", "current");
        Map("/v1/devices/{id}/revocations", "revocation", begin: true);
        Map("/v1/device-revocations/{id}/proof", "revocation");
        void Map(string pattern, string stage, bool begin = false) => app.MapPost(pattern,
            (HttpContext context, EnrollmentHttpRuntime runtime) => Handle(context, runtime, stage, begin))
            .WithMetadata(new Endpoint()).RequireAuthorization(Policy).DisableRateLimiting();
    }

    private static async Task<IResult> Handle(HttpContext context, EnrollmentHttpRuntime runtime, string stage, bool begin)
    {
        var selection = context.Request.Query["tenant_id"];
        if (context.Request.Query.Count != 1 || selection.Count != 1 || !CanonicalId(selection[0], out var tenant)) return IdentityProblem.Create(context, 400);
        var origins = context.Request.Headers.Origin;
        if (origins.Count != 1 || origins[0] != runtime.Settings.Origin) return IdentityProblem.Create(context, 403);
        var keys = context.Request.Headers["Idempotency-Key"];
        var key = keys.Count == 1 ? keys[0] : null;
        if (key is null || key.Length is < 16 or > 128 || key.Any(c => c < 0x21 || c > 0x7e)) return IdentityProblem.Create(context, 400);
        Guid? path = null;
        if (context.Request.RouteValues.TryGetValue("id", out var route))
        {
            if (!CanonicalId(route as string, out var id)) return IdentityProblem.Create(context, 400);
            path = id;
        }
        if (tenant == Guid.Empty) return IdentityProblem.Create(context, 404);
        var principal = await runtime.Mapper.FromRequestAsync(context, tenant);
        if (principal is null) return IdentityProblem.Create(context, 403);
        var authority = await runtime.Commands.AuthorizeAsync(principal, context.RequestAborted);
        if (authority.GetProperty("outcome").GetString() != "ok") return Problem(context, authority);
        // Only a current authorized membership can charge a tenant's budget.
        using var tenantLease = runtime.Tenants.AttemptAcquire(tenant);
        if (!tenantLease.IsAcquired) return IdentityProblem.Create(context, 429);
        var body = await Body(context.Request, context.RequestAborted);
        if (body.Error != 0) return IdentityProblem.Create(context, body.Error);
        long expected = 0; Guid? target = null;
        try
        {
            if (begin)
            {
                using var json = ProofRequest.StrictJson(body.Bytes);
                var root = json.RootElement;
                ProofRequest.Fields(root, stage == "enrollment" ? ["profile", "expected_identity_version", "replace_device_id"] : ["profile", "expected_identity_version"]);
                ProofRequest.Require(root.GetProperty("profile").GetString() == Profile);
                ProofRequest.Require(root.GetProperty("expected_identity_version").TryGetInt64(out expected) && expected is >= 0 and <= 9007199254740990);
                if (stage == "revocation") target = path;
                else if (root.GetProperty("replace_device_id").ValueKind != JsonValueKind.Null)
                {
                    ProofRequest.Require(CanonicalId(root.GetProperty("replace_device_id").GetString(), out var replaced));
                    target = replaced;
                }
            }
            else _ = ProofRequest.Parse(body.Bytes, stage == "registration");
        }
        catch (ProofTooLargeException) { return IdentityProblem.Create(context, 413); }
        catch (Exception exception) when (exception is InvalidProofEncodingException or JsonException or DecoderFallbackException or InvalidOperationException or KeyNotFoundException)
        { return IdentityProblem.Create(context, 400); }
        JsonElement answer;
        if (begin) answer = await runtime.Commands.BeginAsync(principal, stage, expected, target, key, body.Bytes, context.RequestAborted);
        else
        {
            using var verification = runtime.Proofs.AttemptAcquire();
            if (!verification.IsAcquired) return IdentityProblem.Create(context, 429);
            answer = await runtime.Commands.CompleteAsync(principal, path!.Value, stage, key, body.Bytes, context.RequestAborted);
        }
        return answer.GetProperty("outcome").GetString() == "ok" ? Results.Json(EnrollmentWire.Project(answer)) : Problem(context, answer);
    }

    private static IResult Problem(HttpContext context, JsonElement result) => IdentityProblem.Create(context,
        result.GetProperty("outcome").GetString() switch
        {
            "invalid_request" or "invalid_proof" => 400,
            "forbidden" => 403,
            "not_found" => 404,
            "conflict" => 409,
            "unavailable" => 503,
            _ => 503
        });

    internal static bool CanonicalId(string? value, out Guid id) => Guid.TryParseExact(value, "D", out id) && value == id.ToString("D");

    private static async Task<(byte[] Bytes, int Error)> Body(HttpRequest request, CancellationToken cancellationToken)
    {
        if (request.Headers.ContentEncoding.Count != 0 || !request.HasJsonContentType()
            || !MediaTypeHeaderValue.TryParse(request.ContentType, out var media)) return ([], 415);
        var charsets = media.Parameters.Where(p => p.Name.Equals("charset", StringComparison.OrdinalIgnoreCase)).ToArray();
        if (charsets.Length > 1 || (charsets.Length == 1 && !HeaderUtilities.RemoveQuotes(charsets[0].Value).Equals("utf-8", StringComparison.OrdinalIgnoreCase))) return ([], 415);
        if (request.ContentLength > 65536) return ([], 413);
        using var stream = new MemoryStream(); var chunk = new byte[4096];
        while (true)
        {
            var read = await request.Body.ReadAsync(chunk, cancellationToken);
            if (read == 0) break;
            if (stream.Length + read > 65536) return ([], 413);
            await stream.WriteAsync(chunk.AsMemory(0, read), cancellationToken);
        }
        return (stream.ToArray(), 0);
    }
}

internal sealed class EnrollmentHttpRuntime : IDisposable, IAsyncDisposable
{
    internal EnrollmentApiSettings Settings { get; }
    internal EnrollmentPrincipalMapper Mapper { get; }
    internal EnrollmentCommands Commands { get; }
    internal FixedWindowRateLimiter Global { get; }
    internal PartitionedRateLimiter<string> Actors { get; }
    internal PartitionedRateLimiter<Guid> Tenants { get; }
    internal ConcurrencyLimiter Proofs { get; }
    private readonly NpgsqlDataSource _database;
    private int _disposed;

    public EnrollmentHttpRuntime(IOptions<EnrollmentApiSettings> configured, IOptions<DeviceStepUpSettings> stepUp, TimeProvider clock)
    {
        Settings = configured.Value;
        if (!Settings.Enabled) throw new InvalidOperationException("Enrollment API is disabled.");
        _database = EnrollmentDatabase.Pool(Settings.ConnectionString, Settings.MaximumPoolSize);
        Commands = new EnrollmentCommands(_database);
        Mapper = new(new EnrollmentConfiguration(Settings.ConfigurationId, Settings.Origin), stepUp, clock);
        Global = new(Window(Settings.RequestsPerMinute));
        Actors = PartitionedRateLimiter.Create<string, string>(actor => RateLimitPartition.GetFixedWindowLimiter(actor, _ => Window(Settings.ActorRequestsPerMinute)));
        Tenants = PartitionedRateLimiter.Create<Guid, Guid>(tenant => RateLimitPartition.GetFixedWindowLimiter(tenant, _ => Window(Settings.TenantRequestsPerMinute)));
        Proofs = new(new ConcurrencyLimiterOptions { PermitLimit = Settings.MaximumConcurrentProofs, QueueLimit = 0 });
    }
    private static FixedWindowRateLimiterOptions Window(int count) => new() { PermitLimit = count, Window = TimeSpan.FromMinutes(1), QueueLimit = 0, AutoReplenishment = true };
    private void DisposeBudgets() { Global.Dispose(); Actors.Dispose(); Tenants.Dispose(); Proofs.Dispose(); }
    public void Dispose() { if (Interlocked.Exchange(ref _disposed, 1) == 0) { _database.Dispose(); DisposeBudgets(); } }
    public async ValueTask DisposeAsync() { if (Interlocked.Exchange(ref _disposed, 1) == 0) { await _database.DisposeAsync(); DisposeBudgets(); } }
}
