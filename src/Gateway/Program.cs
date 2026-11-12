using AMDN.Identity.Authentication;
using AMDN.Infrastructure.Identity;
using AMDN.Gateway;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAmdnIdentityAuthentication(builder.Configuration);
IdentityHttp.Configure(builder, "IdentityApi", provisioning: false);
var app = builder.Build();
app.Use(IdentityHttp.Errors);
app.UseAuthentication();
app.UseAuthorization();
if (app.Services.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<IdentityApiSettings>>().Get("IdentityApi").Enabled)
{
    app.UseRateLimiter();
    app.MapOwnerEndpoints();
}

// Process liveness only. This does not certify dependencies or delivery readiness.
app.MapGet("/health/live", () => Results.Ok(new { status = "alive" })).AllowAnonymous().DisableRateLimiting();
// Only unmatched routes are public 404s. Future mapped routes inherit deny-by-default.
app.MapFallback("/{**path}", () => Results.NotFound()).AllowAnonymous().DisableRateLimiting();

app.Run();

public partial class Program;
