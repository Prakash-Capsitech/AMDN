using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;

namespace AMDN.Identity.Authentication;

public static class IdentityAuthentication
{
    public const string Scheme = "AmdnOidc";
    // Authentication only. Never use this policy to authorize tenant data or commands.
    public const string TokenValidatedPolicy = "AmdnTokenValidated";
    private static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(30);

    public static IServiceCollection AddAmdnIdentityAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<OidcSettings>()
            .Bind(configuration.GetSection(OidcSettings.Section), options => options.ErrorOnUnknownConfiguration = true)
            .Validate(settings => settings.IsValid(), "OIDC requires Enabled, an HTTPS issuer without userinfo/query/fragment, and an explicit audience; omit all settings to disable.")
            .ValidateOnStart();
        services.AddOptions<DeviceStepUpSettings>()
            .Bind(configuration.GetSection(DeviceStepUpSettings.Section), options => options.ErrorOnUnknownConfiguration = true)
            .Validate<IOptions<OidcSettings>>((settings, oidc) => settings.IsValid(settings.Enabled && oidc.Value.Enabled),
                "Device step-up requires enabled OIDC, explicit unique ACR values and a maximum age of 1–900 seconds; omit all settings to disable.")
            .ValidateOnStart();
        services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        services.AddSingleton<DeviceStepUp>();
        services.AddAuthentication(Scheme).AddJwtBearer(Scheme, _ => { });
        services.AddOptions<JwtBearerOptions>(Scheme).Configure<IOptions<OidcSettings>>(ConfigureBearer);
        services.AddAuthorization(options =>
        {
            var deny = new AuthorizationPolicyBuilder(Scheme)
                .RequireAuthenticatedUser().RequireAssertion(_ => false).Build();
            // Until verified membership and operation grants exist, an accidental
            // endpoint or bare RequireAuthorization() cannot expose tenant data.
            options.DefaultPolicy = deny;
            options.FallbackPolicy = deny;
            options.AddPolicy(TokenValidatedPolicy, new AuthorizationPolicyBuilder(Scheme)
                .RequireAuthenticatedUser().Build());
            options.AddPolicy(DeviceStepUp.Policy, new AuthorizationPolicyBuilder(Scheme)
                .RequireAuthenticatedUser().RequireAssertion(context =>
                    context.Resource is HttpContext http
                    && http.RequestServices.GetRequiredService<DeviceStepUp>().SatisfiedBy(context.User)).Build());
        });
        return services;
    }

    private static void ConfigureBearer(JwtBearerOptions options, IOptions<OidcSettings> configured)
    {
        var settings = configured.Value;
        options.MapInboundClaims = false;
        options.SaveToken = false;
        options.IncludeErrorDetails = false;
        options.RequireHttpsMetadata = true;
        options.BackchannelTimeout = TimeSpan.FromSeconds(5);
        options.BackchannelHttpHandler = new HttpClientHandler { AllowAutoRedirect = false };
        if (settings.Enabled)
        {
            options.Authority = settings.Issuer;
            options.MetadataAddress = settings.Issuer.TrimEnd('/') + "/.well-known/openid-configuration";
        }
        options.TokenValidationParameters = new TokenValidationParameters
        {
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            // Do not silently accept an additional issuer advertised by metadata.
            IssuerValidator = (issuer, _, _) => settings.Enabled && string.Equals(issuer, settings.Issuer, StringComparison.Ordinal)
                ? issuer : throw new SecurityTokenInvalidIssuerException("Unexpected issuer."),
            ValidIssuer = settings.Issuer,
            ValidateAudience = true,
            RequireAudience = true,
            ValidAudience = settings.Audience,
            IgnoreTrailingSlashWhenValidatingAudience = false,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ClockSkew = ClockSkew,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            ValidTypes = ["at+jwt", "application/at+jwt"],
            LogTokenId = false,
            IncludeTokenOnFailedValidation = false
        };
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                if (!settings.Enabled) context.NoResult();
                else if (context.Request.Headers.Authorization.ToString().Length > 16 * 1024)
                    context.Fail("Bearer header exceeds the supported bound.");
                return Task.CompletedTask;
            },
            OnTokenValidated = async context =>
            {
                var metadata = await options.ConfigurationManager!.GetConfigurationAsync(context.HttpContext.RequestAborted);
                if (!string.Equals(metadata.Issuer, settings.Issuer, StringComparison.Ordinal))
                {
                    context.Fail("Discovery issuer does not match configured issuer.");
                    return;
                }
                if (context.SecurityToken is not JsonWebToken token || !ValidClaimTypes(token))
                {
                    context.Fail("Access token claim types do not satisfy the supported profile.");
                    return;
                }
                var principal = context.Principal!;
                var issuer = Single(principal, "iss");
                var subject = Single(principal, "sub");
                var client = Single(principal, "client_id");
                var tokenId = Single(principal, "jti");
                var issuedAt = Single(principal, "iat");
                var scopes = principal.FindAll("scope").ToArray();
                if (issuer is null || subject is null || client is null || tokenId is null
                    || !long.TryParse(issuedAt, NumberStyles.None, CultureInfo.InvariantCulture, out var timestamp)
                    || timestamp > DateTimeOffset.UtcNow.Add(ClockSkew).ToUnixTimeSeconds()
                    || timestamp >= new DateTimeOffset(context.SecurityToken.ValidTo).ToUnixTimeSeconds()
                    || scopes.Length > 1 || (scopes.Length == 1 && !ValidScope(scopes[0].Value)))
                {
                    context.Fail("Access token claims do not satisfy the supported profile.");
                    return;
                }
                // Never promote provider tenant/user/device/email/role claims into
                // local authority. F1.2 must resolve (issuer, subject) to membership.
                var claims = new List<Claim> { new("iss", issuer), new("sub", subject), new("client_id", client) };
                if (scopes.Length == 1) claims.Add(new Claim("scope", scopes[0].Value));
                foreach (var name in new[] { "acr", "auth_time" })
                    if (Single(principal, name) is { } value) claims.Add(new Claim(name, value));
                context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme));
            },
            OnChallenge = async context =>
            {
                context.HandleResponse();
                context.Response.Headers.WWWAuthenticate = "Bearer";
                await IdentityProblem.Create(context.HttpContext, StatusCodes.Status401Unauthorized).ExecuteAsync(context.HttpContext);
            },
            OnForbidden = context => IdentityProblem.Create(context.HttpContext, StatusCodes.Status403Forbidden).ExecuteAsync(context.HttpContext)
        };
    }

    private static bool ValidClaimTypes(JsonWebToken token)
    {
        // Claim projection alone loses JSON type distinctions (e.g. numeric strings
        // and single-element arrays). Check the signed payload's profile types too.
        using var document = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(token.EncodedPayload));
        var payload = document.RootElement;
        var names = payload.EnumerateObject().Select(property => property.Name).ToArray();
        if (names.Distinct(StringComparer.Ordinal).Count() != names.Length) return false;
        if (!payload.TryGetProperty("aud", out var audience)
            || (audience.ValueKind != JsonValueKind.String
                && (audience.ValueKind != JsonValueKind.Array || audience.GetArrayLength() == 0
                    || audience.EnumerateArray().Any(value => value.ValueKind != JsonValueKind.String)))) return false;
        foreach (var name in new[] { "iss", "sub", "client_id", "jti" })
            if (!payload.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String) return false;
        foreach (var name in new[] { "iat", "exp" })
            if (!payload.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out _)) return false;
        if (payload.TryGetProperty("nbf", out var notBefore)
            && (notBefore.ValueKind != JsonValueKind.Number || !notBefore.TryGetInt64(out _))) return false;
        if (payload.TryGetProperty("acr", out var acr)
            && (acr.ValueKind != JsonValueKind.String || !DeviceStepUpSettings.ValidAcr(acr.GetString()!))) return false;
        if (payload.TryGetProperty("auth_time", out var authTime)
            && (authTime.ValueKind != JsonValueKind.Number || !authTime.TryGetInt64(out var authenticatedAt)
                || authenticatedAt < 0 || authenticatedAt > payload.GetProperty("iat").GetInt64())) return false;
        return !payload.TryGetProperty("scope", out var scope) || scope.ValueKind == JsonValueKind.String;
    }

    private static string? Single(ClaimsPrincipal principal, string name)
    {
        var values = principal.FindAll(name).ToArray();
        return values.Length == 1 && !string.IsNullOrWhiteSpace(values[0].Value) ? values[0].Value : null;
    }

    private static bool ValidScope(string scope) => scope.Length > 0 && scope.Split(' ').All(value =>
        value.Length > 0 && value.All(character => character == 0x21 || character is >= (char)0x23 and <= (char)0x5b
            || character is >= (char)0x5d and <= (char)0x7e));
}
