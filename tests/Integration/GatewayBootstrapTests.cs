using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace AMDN.Integration.Tests;

public sealed class GatewayBootstrapTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public GatewayBootstrapTests(WebApplicationFactory<Program> application)
    {
        _client = application.CreateClient();
    }

    [Fact]
    public async Task LivenessReportsOnlyThatTheProcessIsAlive()
    {
        using var response = await _client.GetAsync("/health/live");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<Dictionary<string, string>>();
        Assert.Equal("alive", Assert.Single(Assert.IsType<Dictionary<string, string>>(body)).Value);
    }

    [Fact]
    public async Task ScaffoldDoesNotAcceptMessagesBeforeAuthorizationExists()
    {
        using var response = await _client.PostAsJsonAsync("/v1/messages", new { ciphertext = "placeholder" });
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
