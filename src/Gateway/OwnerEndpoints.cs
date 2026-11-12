using AMDN.Infrastructure.Identity;
using System.Threading.RateLimiting;

namespace AMDN.Gateway;

internal static class OwnerEndpoints
{
    public static void MapOwnerEndpoints(this WebApplication app)
    {
        app.MapGet("/v1/postman", async (HttpContext context, PersonalPostmanStore store, PartitionedRateLimiter<Guid> tenantBudget) =>
        {
            // Selection is explicit even for a single membership, and is reverified
            // against the authenticated subject on every operation. No sticky session.
            var values = context.Request.Query["tenant_id"];
            if (context.Request.Query.Count != 1 || values.Count != 1 || !IdentityHttp.CanonicalId(values[0], out var tenant))
                return IdentityHttp.Problem(context, 400);
            var result = await store.ReadOwnerAsync(context.User, tenant, context.RequestAborted);
            if (result is null) return IdentityHttp.Problem(context, 404);
            using var lease = tenantBudget.AttemptAcquire(result.TenantId);
            if (!lease.IsAcquired) return IdentityHttp.Problem(context, 429);
            context.Response.Headers.ETag = $"\"{result.PolicyVersion}\"";
            return Results.Json(new
            {
                postman_id = result.PostmanId,
                policy_version = result.PolicyVersion,
                policy = new { receive_enabled = result.ReceiveEnabled, dispatch_enabled = result.DispatchEnabled, retry_enabled = result.RetryEnabled }
            });
        }).AddEndpointFilter(IdentityHttp.RequireHttps).RequireAuthorization("postman.read").RequireRateLimiting("identity-global");
    }
}
