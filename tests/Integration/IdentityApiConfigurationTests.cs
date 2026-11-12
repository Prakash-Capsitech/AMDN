using AMDN.Identity.Authentication;
using AMDN.Infrastructure.Identity;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace AMDN.Integration.Tests;

public sealed class IdentityApiConfigurationTests
{
    [Theory]
    [InlineData("IdentityApi:ConnectionString", "")]
    [InlineData("IdentityApi:RequestsPerMinute", "0")]
    [InlineData("IdentityApi:ActorRequestsPerMinute", "11")]
    [InlineData("IdentityApi:TenantRequestsPerMinute", "0")]
    [InlineData("IdentityApi:TenantMemberLimit", "1")]
    [InlineData("IdentityApi:Enabled", "false")]
    [InlineData("Authentication:Oidc:Enabled", "false")]
    public async Task MissingOrInconsistentConfigurationFailsOwnedHostStartup(string name, string value)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        builder.Logging.ClearProviders();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Authentication:Oidc:Enabled"] = "true",
            ["Authentication:Oidc:Issuer"] = "https://synthetic.invalid",
            ["Authentication:Oidc:Audience"] = "synthetic",
            ["IdentityApi:Enabled"] = "true",
            ["IdentityApi:ConnectionString"] = "Host=127.0.0.1;Database=not-opened;Username=synthetic",
            ["IdentityApi:RequestsPerMinute"] = "10",
            ["IdentityApi:ActorRequestsPerMinute"] = "10",
            ["IdentityApi:TenantRequestsPerMinute"] = "10"
        });
        builder.Configuration[name] = value;
        if (name == "Authentication:Oidc:Enabled")
        {
            builder.Configuration["Authentication:Oidc:Issuer"] = "";
            builder.Configuration["Authentication:Oidc:Audience"] = "";
        }
        builder.Services.AddAmdnIdentityAuthentication(builder.Configuration);
        IdentityHttp.Configure(builder, "IdentityApi", provisioning: false);
        await using var app = builder.Build();
        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => app.StartAsync());
        Assert.Equal(typeof(IdentityApiSettings), error.OptionsType);
    }
}
