using AMDN.Identity.Authentication;
using AMDN.Infrastructure.Identity;
using AMDN.Gateway;
using AMDN.Enrollment;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAmdnIdentityAuthentication(builder.Configuration);
IdentityHttp.Configure(builder, "IdentityApi", provisioning: false);
EnrollmentHttp.Configure(builder);
var app = builder.Build();
app.UseRouting();
app.Use(IdentityHttp.Errors);
app.Use(EnrollmentHttp.Transport);
app.UseAuthentication();
app.UseAuthorization();
app.MapEnrollmentEndpoints();
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
