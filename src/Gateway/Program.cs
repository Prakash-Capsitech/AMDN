var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Process liveness only. This does not certify dependencies or delivery readiness.
app.MapGet("/health/live", () => Results.Ok(new { status = "alive" }));

app.Run();

public partial class Program;
