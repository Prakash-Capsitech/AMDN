using AMDN.Identity.Authentication;
using AMDN.Infrastructure.Identity;

namespace AMDN.Provisioning;

public partial class ProvisioningProgram
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        builder.Services.AddAmdnIdentityAuthentication(builder.Configuration);
        IdentityHttp.Configure(builder, "ProvisioningApi", provisioning: true);
        var app = builder.Build();
        var settings = app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<IdentityApiSettings>>().Get("ProvisioningApi");
        app.Use(IdentityHttp.Errors);
        app.UseAuthentication();
        app.UseAuthorization();
        if (settings.Enabled)
        {
            app.UseRateLimiter();
            app.MapPost("/v1/tenants", async (HttpContext context, PlatformProvisioner provisioner) =>
            {
                if (context.Request.Query.Count != 0) return IdentityProblem.Create(context, 400);
                var key = IdentityHttp.IdempotencyKey(context.Request);
                if (key is null) return IdentityProblem.Create(context, 400);
                var body = await IdentityHttp.Body(context.Request, ["display_name"], context.RequestAborted);
                if (body.Error != 0) return IdentityProblem.Create(context, body.Error);
                if (body.Fields["display_name"].Length > 100) return IdentityProblem.Create(context, 400);
                var result = await provisioner.CreateTenantAsync(context.User, key, body.Bytes, body.Fields["display_name"], settings.TenantMemberLimit, context.RequestAborted);
                return result.Status == 201 ? Results.Json(new { tenant_id = result.TenantId, status = "active" }, statusCode: 201)
                    : IdentityProblem.Create(context, result.Status);
            }).AddEndpointFilter(IdentityHttp.RequireHttps).RequireAuthorization("tenant.provision").RequireRateLimiting("identity-global");
            app.MapPost("/v1/tenants/{tenantId}/memberships", async (HttpContext context, string tenantId, PlatformProvisioner provisioner) =>
            {
                if (context.Request.Query.Count != 0 || !IdentityHttp.CanonicalId(tenantId, out var tenant)) return IdentityProblem.Create(context, 400);
                var key = IdentityHttp.IdempotencyKey(context.Request);
                if (key is null) return IdentityProblem.Create(context, 400);
                var body = await IdentityHttp.Body(context.Request, ["issuer", "subject"], context.RequestAborted);
                if (body.Error != 0) return IdentityProblem.Create(context, body.Error);
                // Enrollment binds an exact configured issuer, never an email or a provider role.
                var ownerIssuer = settings.OwnerIssuer;
                if (string.IsNullOrEmpty(ownerIssuer) || body.Fields["issuer"] != ownerIssuer || body.Fields["subject"].Length > 255)
                    return IdentityProblem.Create(context, 400);
                var result = await provisioner.EnrollAsync(context.User, key, body.Bytes, tenant, body.Fields["issuer"], body.Fields["subject"], context.RequestAborted);
                return result.Status == 201 ? Results.Json(new { tenant_id = result.TenantId, user_id = result.UserId, postman_id = result.PostmanId }, statusCode: 201)
                    : IdentityProblem.Create(context, result.Status);
            }).AddEndpointFilter(IdentityHttp.RequireHttps).RequireAuthorization("membership.provision").RequireRateLimiting("identity-global");
        }
        app.MapGet("/health/live", () => Results.Ok(new { status = "alive" })).AllowAnonymous().DisableRateLimiting();
        app.MapFallback("/{**path}", () => Results.NotFound()).AllowAnonymous().DisableRateLimiting();
        app.Run();
    }
}
