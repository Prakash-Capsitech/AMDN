using AMDN.Enrollment;
using AMDN.Identity.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

namespace AMDN.Integration.Tests;

public sealed class EnrollmentApiConfigurationTests
{
    [Theory]
    [InlineData("EnrollmentApi:ConnectionString", "")]
    [InlineData("EnrollmentApi:ConfigurationId", "00000000-0000-0000-0000-000000000000")]
    [InlineData("EnrollmentApi:Origin", "https://ceremony.invalid/")]
    [InlineData("EnrollmentApi:Origin", "https://ceremony.invalid:443")]
    [InlineData("EnrollmentApi:Origin", "https://0xffffffff")]
    [InlineData("EnrollmentApi:Origin", "https://example.0xff")]
    [InlineData("EnrollmentApi:Origin", "http://ceremony.invalid")]
    [InlineData("EnrollmentApi:MaximumPoolSize", "0")]
    [InlineData("EnrollmentApi:MaximumPoolSize", "21")]
    [InlineData("EnrollmentApi:RequestsPerMinute", "0")]
    [InlineData("EnrollmentApi:ActorRequestsPerMinute", "11")]
    [InlineData("EnrollmentApi:TenantRequestsPerMinute", "0")]
    [InlineData("EnrollmentApi:MaximumConcurrentProofs", "33")]
    [InlineData("EnrollmentApi:Enabled", "false")]
    [InlineData("Authentication:DeviceStepUp:Enabled", "false")]
    public async Task IncompleteOrInconsistentEnrollmentBindingFailsStartup(string name, string value)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        builder.Logging.ClearProviders();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Authentication:Oidc:Enabled"] = "true",
            ["Authentication:Oidc:Issuer"] = "https://synthetic.invalid",
            ["Authentication:Oidc:Audience"] = "synthetic",
            ["Authentication:DeviceStepUp:Enabled"] = "true",
            ["Authentication:DeviceStepUp:AllowedAcrValues:0"] = "urn:amdn:test:strong",
            ["Authentication:DeviceStepUp:MaximumAgeSeconds"] = "120",
            ["EnrollmentApi:Enabled"] = "true",
            ["EnrollmentApi:ConnectionString"] = "Host=127.0.0.1;Database=not-opened;Username=synthetic",
            ["EnrollmentApi:ConfigurationId"] = Guid.NewGuid().ToString(),
            ["EnrollmentApi:Origin"] = "https://ceremony.invalid",
            ["EnrollmentApi:MaximumPoolSize"] = "1",
            ["EnrollmentApi:RequestsPerMinute"] = "10",
            ["EnrollmentApi:ActorRequestsPerMinute"] = "10",
            ["EnrollmentApi:TenantRequestsPerMinute"] = "10",
            ["EnrollmentApi:MaximumConcurrentProofs"] = "1"
        });
        builder.Configuration[name] = value;
        builder.Services.AddAmdnIdentityAuthentication(builder.Configuration);
        EnrollmentHttp.Configure(builder);
        await using var app = builder.Build();
        var error = await Record.ExceptionAsync(() => app.StartAsync());
        Assert.NotNull(error);
        var errors = error is AggregateException aggregate ? aggregate.Flatten().InnerExceptions : [error];
        Assert.Contains(errors, failure => failure is OptionsValidationException options && options.OptionsType == typeof(EnrollmentApiSettings));
    }
}
