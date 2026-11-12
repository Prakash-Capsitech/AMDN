using AMDN.Identity.Authentication;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAmdnIdentityAuthentication(builder.Configuration);
var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

// Process liveness only. This does not certify dependencies or delivery readiness.
app.MapGet("/health/live", () => Results.Ok(new { status = "alive" })).AllowAnonymous();
// Only unmatched routes are public 404s. Future mapped routes inherit deny-by-default.
app.MapFallback("/{**path}", () => Results.NotFound()).AllowAnonymous();

app.Run();

public partial class Program;
