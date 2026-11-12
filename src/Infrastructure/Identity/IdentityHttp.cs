using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using AMDN.Identity.Authentication;
using AMDN.Identity.Membership;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Npgsql;

namespace AMDN.Infrastructure.Identity;

public sealed class IdentityApiSettings
{
    public bool Enabled { get; set; }
    public string ConnectionString { get; set; } = "";
    public int RequestsPerMinute { get; set; }
    public int ActorRequestsPerMinute { get; set; }
    public int TenantRequestsPerMinute { get; set; }
    public int TenantMemberLimit { get; set; }
    public string OwnerIssuer { get; set; } = "";
}

public static class IdentityHttp
{
    public static void Configure(WebApplicationBuilder builder, string section, bool provisioning)
    {
        builder.Services.AddOptions<IdentityApiSettings>(section)
            .Bind(builder.Configuration.GetSection(section), options => options.ErrorOnUnknownConfiguration = true)
            .Validate(settings => Valid(settings, provisioning, builder.Configuration), "Identity API settings require enabled OIDC, a role-specific connection, explicit bounded budgets, and an HTTPS owner issuer for provisioning.")
            .ValidateOnStart();
        builder.Services.AddSingleton(provider =>
        {
            var settings = provider.GetRequiredService<IOptionsMonitor<IdentityApiSettings>>().Get(section);
            if (!settings.Enabled) throw new InvalidOperationException("Identity API is disabled.");
            return provisioning ? IdentityDatabase.ProvisioningPool(settings.ConnectionString) : IdentityDatabase.RuntimePool(settings.ConnectionString);
        });
        builder.Services.AddAuthorization(options =>
        {
            foreach (var scope in provisioning ? new[] { "tenant.provision", "membership.provision" } : new[] { "postman.read" })
                options.AddPolicy(scope, policy => policy.AddAuthenticationSchemes(IdentityAuthentication.Scheme)
                    .RequireAuthenticatedUser().RequireAssertion(context => IdentityScopes.Has(context.User, scope)));
        });
        builder.Services.AddRateLimiter(_ => { });
        builder.Services.AddOptions<RateLimiterOptions>().Configure<IOptionsMonitor<IdentityApiSettings>>((options, configured) =>
        {
            var settings = configured.Get(section);
            if (!settings.Enabled) return;
            options.AddFixedWindowLimiter("identity-global", limiter =>
            {
                limiter.PermitLimit = settings.RequestsPerMinute;
                limiter.Window = TimeSpan.FromMinutes(1);
                limiter.QueueLimit = 0;
            });
            // Actor partitions supplement the endpoint-wide limiter. Partitions
            // are derived only from the validated principal, never request tenant headers.
            options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
            {
                var subject = VerifiedExternalSubject.FromPrincipal(context.User);
                var key = subject is null ? "anonymous" : JsonSerializer.Serialize(new[] { subject.Issuer, subject.Subject });
                return RateLimitPartition.GetFixedWindowLimiter(key, _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = settings.ActorRequestsPerMinute,
                    Window = TimeSpan.FromMinutes(1),
                    QueueLimit = 0
                });
            });
            options.OnRejected = async (context, cancellationToken) =>
            {
                context.HttpContext.Response.Headers.RetryAfter = "60";
                await Problem(context.HttpContext, 429).ExecuteAsync(context.HttpContext);
            };
        });
        if (provisioning) builder.Services.AddSingleton<PlatformProvisioner>();
        else
        {
            builder.Services.AddSingleton<PersonalPostmanStore>();
            builder.Services.AddSingleton(provider =>
            {
                var settings = provider.GetRequiredService<IOptionsMonitor<IdentityApiSettings>>().Get(section);
                return PartitionedRateLimiter.Create<Guid, Guid>(tenant => RateLimitPartition.GetFixedWindowLimiter(tenant, _ =>
                    new FixedWindowRateLimiterOptions { PermitLimit = settings.TenantRequestsPerMinute, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
            });
        }
    }

    private static bool Valid(IdentityApiSettings settings, bool provisioning, IConfiguration configuration)
    {
        if (!settings.Enabled) return settings.ConnectionString.Length == 0 && settings.RequestsPerMinute == 0
            && settings.ActorRequestsPerMinute == 0 && settings.TenantMemberLimit == 0 && settings.OwnerIssuer.Length == 0 && settings.TenantRequestsPerMinute == 0;
        if (!configuration.GetValue<bool>("Authentication:Oidc:Enabled") || string.IsNullOrWhiteSpace(settings.ConnectionString)
            || settings.RequestsPerMinute is < 1 or > 10000 || settings.ActorRequestsPerMinute is < 1 or > 10000
            || settings.ActorRequestsPerMinute > settings.RequestsPerMinute) return false;
        if (!provisioning) return settings.TenantMemberLimit == 0 && settings.OwnerIssuer.Length == 0
            && settings.TenantRequestsPerMinute >= 1 && settings.TenantRequestsPerMinute <= settings.RequestsPerMinute;
        return settings.TenantMemberLimit is >= 1 and <= 10000 && settings.TenantRequestsPerMinute == 0
            && Uri.TryCreate(settings.OwnerIssuer, UriKind.Absolute, out var issuer) && issuer.Scheme == "https"
            && issuer.UserInfo.Length == 0 && issuer.Query.Length == 0 && issuer.Fragment.Length == 0
            && settings.OwnerIssuer.Length <= 2048 && settings.OwnerIssuer == settings.OwnerIssuer.Trim() && !settings.OwnerIssuer.Any(char.IsControl);
    }

    public static async ValueTask<object?> RequireHttps(EndpointFilterInvocationContext context, EndpointFilterDelegate next) =>
        context.HttpContext.Request.IsHttps ? await next(context) : Problem(context.HttpContext, 400);

    public static IResult Problem(HttpContext context, int status)
    {
        var code = status switch
        {
            400 => "invalid_request",
            403 => "forbidden",
            404 => "not_found",
            409 => "conflict",
            413 => "request_too_large",
            415 => "unsupported_media_type",
            429 => "quota_exceeded",
            _ => "unavailable"
        };
        if (status is 429 or 503) context.Response.Headers.RetryAfter = status == 429 ? "60" : "5";
        return Results.Problem(statusCode: status, title: code,
            extensions: new Dictionary<string, object?> { ["code"] = code, ["request_id"] = context.TraceIdentifier });
    }

    public static async Task Errors(HttpContext context, RequestDelegate next)
    {
        context.Response.Headers.CacheControl = "no-store";
        try { await next(context); }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { }
        catch (Exception exception) when (exception is NpgsqlException or TimeoutException or InvalidOperationException)
        {
            // Never expose SQL, connection strings or internal exception text to HTTP callers.
            if (!context.Response.HasStarted) await Problem(context, 503).ExecuteAsync(context);
        }
    }

    public static bool CanonicalId(string? value, out Guid id) => Guid.TryParseExact(value, "D", out id) && value == id.ToString("D");

    public static async Task<(byte[] Bytes, Dictionary<string, string> Fields, int Error)> Body(HttpRequest request, string[] fields, CancellationToken ct)
    {
        if (request.Headers.ContentEncoding.Count != 0 || !request.HasJsonContentType()
            || (request.ContentType?.Contains("charset=", StringComparison.OrdinalIgnoreCase) == true
                && !request.ContentType.EndsWith("charset=utf-8", StringComparison.OrdinalIgnoreCase))) return ([], [], 415);
        if (request.ContentLength > 16384) return ([], [], 413);
        using var buffer = new MemoryStream();
        var chunk = new byte[4096];
        while (true)
        {
            var count = await request.Body.ReadAsync(chunk, ct);
            if (count == 0) break;
            if (buffer.Length + count > 16384) return ([], [], 413);
            await buffer.WriteAsync(chunk.AsMemory(0, count), ct);
        }
        var bytes = buffer.ToArray();
        try
        {
            _ = new UTF8Encoding(false, true).GetString(bytes);
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 });
            if (document.RootElement.ValueKind != JsonValueKind.Object) return ([], [], 400);
            var values = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (!fields.Contains(property.Name, StringComparer.Ordinal) || property.Value.ValueKind != JsonValueKind.String
                    || !values.TryAdd(property.Name, property.Value.GetString()!)) return ([], [], 400);
            }
            if (values.Count != fields.Length || values.Values.Any(value => string.IsNullOrWhiteSpace(value) || value.Any(char.IsControl))) return ([], [], 400);
            return (bytes, values, 0);
        }
        catch (Exception exception) when (exception is JsonException or DecoderFallbackException) { return ([], [], 400); }
    }

    public static string? IdempotencyKey(HttpRequest request)
    {
        var keys = request.Headers["Idempotency-Key"];
        var key = keys.Count == 1 ? keys[0] : null;
        return key is not null && key.Length is >= 16 and <= 128 && key.All(c => c is >= (char)0x21 and <= (char)0x7e) ? key : null;
    }
}
