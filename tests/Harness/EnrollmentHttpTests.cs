using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AMDN.Enrollment;
using AMDN.Infrastructure.Identity;
using AMDN.Integration.Tests;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Xunit;

namespace AMDN.Harness.Tests;

public sealed class EnrollmentHttpTests(OidcFixture issuer) : IClassFixture<OidcFixture>
{
    private const string Profile = "amdn-webauthn-enrollment/1";
    private const string Acr = "urn:amdn:test:strong";
    private readonly RunState _state = RunState.Load();
    private sealed record Member(Guid Tenant, Guid User, Guid Postman, Guid Config, string Subject);

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task ClientDataMetadataCompletesLifecycleWithExactReplay(bool chromiumMetadata, bool edgeMetadata)
    {
        var member = await Setup();
        await using var app = App(member); using var client = issuer.Client(app);
        using var first = new SyntheticWebAuthn(); using var second = new SyntheticWebAuthn();
        var beginBody = Begin(1); var beginKey = Key();
        var begin = await Ok(client, member, "/v1/device-enrollments", beginBody, key: beginKey);
        Shape(begin, "EnrollmentRegistrationOptions");
        var creation = begin.GetProperty("public_key");
        Assert.Equal("ceremony.invalid", creation.GetProperty("rp").GetProperty("id").GetString());
        Assert.Equal(32, Decode(creation.GetProperty("user").GetProperty("id").GetString()!).Length);
        Assert.Equal("device_" + begin.GetProperty("device_id").GetGuid().ToString("N"), creation.GetProperty("user").GetProperty("name").GetString());
        Assert.Empty(creation.GetProperty("excludeCredentials").EnumerateArray());
        Assert.Equal(begin.GetRawText(), (await Ok(client, member, "/v1/device-enrollments", beginBody, key: beginKey)).GetRawText());
        await Error(client, member, "/v1/device-enrollments", Begin(2), 409, key: beginKey);
        var id = begin.GetProperty("ceremony_id").GetGuid();
        var candidate = await Prove(begin, "registration", first);
        Shape(candidate, "EnrollmentCandidateOptions"); Allowed(candidate, first.Id);
        var proof = first.Response(Challenge(candidate), false, chromiumMetadata: chromiumMetadata, edgeMetadata: edgeMetadata); var proofKey = Key();
        var completed = await Ok(client, member, $"/v1/device-enrollments/{id}/candidate-proof", proof, key: proofKey);
        Shape(completed, "EnrollmentCompleted"); Assert.Equal(2, completed.GetProperty("committed_identity_version").GetInt64());
        Assert.False(completed.GetProperty("messaging_ready").GetBoolean());
        var originalDevice = completed.GetProperty("device_id").GetGuid();

        var replacement = await Ok(client, member, "/v1/device-enrollments", Begin(2, originalDevice));
        Assert.Equal(SyntheticWebAuthn.Encode(first.Id), replacement.GetProperty("public_key").GetProperty("excludeCredentials")[0].GetProperty("id").GetString());
        var replacementCandidate = await Prove(replacement, "registration", second);
        Allowed(replacementCandidate, second.Id);
        var current = await Prove(replacementCandidate, "candidate", second);
        Shape(current, "EnrollmentCurrentOptions"); Allowed(current, first.Id);
        var replaced = await Prove(current, "current", first);
        Assert.Equal(3, replaced.GetProperty("committed_identity_version").GetInt64());

        var history = await Ok(client, member, $"/v1/device-enrollments/{id}/candidate-proof", proof, key: proofKey);
        Assert.Equal(2, history.GetProperty("committed_identity_version").GetInt64());
        Assert.Equal(completed.GetProperty("completed_at").GetString(), history.GetProperty("completed_at").GetString());
        Assert.Equal("revoked", history.GetProperty("current_lifecycle").GetProperty("status").GetString());
        Assert.Equal(3, history.GetProperty("current_lifecycle").GetProperty("identity_version").GetInt64());

        var device = replaced.GetProperty("device_id").GetGuid();
        var revoke = await Ok(client, member, $"/v1/devices/{device}/revocations", JsonSerializer.SerializeToUtf8Bytes(new { profile = Profile, expected_identity_version = 3 }));
        Shape(revoke, "RevocationOptions"); Allowed(revoke, second.Id);
        var revoked = await Prove(revoke, "revocation", second);
        Shape(revoked, "RevocationCompleted");
        Assert.Equal(4, revoked.GetProperty("committed_identity_version").GetInt64());
        Assert.Equal("revoked", revoked.GetProperty("current_lifecycle").GetProperty("status").GetString());
        await using var owner = await Owner();
        Assert.Equal(0L, await Sql(owner, "SELECT count(*) FROM amdn_identity.devices WHERE tenant_id=@tenant AND status='credential_active'", ("tenant", member.Tenant)));

        async Task<JsonElement> Prove(JsonElement options, string stage, SyntheticWebAuthn credential)
        {
            var ceremony = options.GetProperty("ceremony_id").GetGuid();
            var path = stage == "revocation" ? $"/v1/device-revocations/{ceremony}/proof"
                : $"/v1/device-enrollments/{ceremony}/" + (stage == "registration" ? stage : stage + "-proof");
            var body = credential.Response(Challenge(options), stage == "registration", chromiumMetadata: chromiumMetadata, edgeMetadata: edgeMetadata);
            if (chromiumMetadata && stage != "registration")
            {
                // Removing signed metadata without resigning must fail verification.
                var tampered = JsonNode.Parse(body)!;
                var data = JsonNode.Parse(Decode(tampered["response"]!["clientDataJSON"]!.GetValue<string>()))!.AsObject();
                data.Remove("other_keys_can_be_added_here");
                tampered["response"]!["clientDataJSON"] = SyntheticWebAuthn.Encode(JsonSerializer.SerializeToUtf8Bytes(data));
                await Error(client, member, path, JsonSerializer.SerializeToUtf8Bytes(tampered), 400);
            }
            var key = Key();
            var result = await Ok(client, member, path, body, key: key);
            var replay = await Ok(client, member, path, body, key: key);
            var expected = JsonNode.Parse(result.GetRawText())!;
            var actual = JsonNode.Parse(replay.GetRawText())!;
            // Historical replies refresh the lifecycle observation time by contract.
            expected["current_lifecycle"]?.AsObject().Remove("observed_at");
            actual["current_lifecycle"]?.AsObject().Remove("observed_at");
            Assert.True(JsonNode.DeepEquals(expected, actual));
            await Error(client, member, path, [.. body, 32], 409, key: key);
            await using var connection = await Owner();
            Assert.Equal(1L, await Sql(connection, "SELECT count(*) FROM amdn_identity.device_commands WHERE ceremony_id=@id AND stage=@stage AND state='succeeded'", ("id", ceremony), ("stage", stage)));
            return result;
        }
    }

    [Theory]
    [InlineData("missing-token", 401)]
    [InlineData("bad-signature", 401)]
    [InlineData("scope", 403)]
    [InlineData("old-step-up", 403)]
    [InlineData("origin", 403)]
    [InlineData("missing-origin", 403)]
    [InlineData("key", 400)]
    [InlineData("query", 400)]
    [InlineData("foreign", 404)]
    [InlineData("compression", 415)]
    [InlineData("charset", 415)]
    [InlineData("duplicate-charset", 415)]
    [InlineData("duplicate", 400)]
    [InlineData("unknown", 400)]
    [InlineData("unsafe-version", 400)]
    [InlineData("oversize", 413)]
    public async Task TransportFailuresAreGenericAndDoNotCreateCeremonies(string scenario, int status)
    {
        var member = await Setup(); await using var app = App(member); using var client = issuer.Client(app);
        var body = scenario switch
        {
            "duplicate" => Encoding.UTF8.GetBytes("{\"profile\":\"amdn-webauthn-enrollment/1\",\"expected_identity_version\":1,\"replace_device_id\":null,\"profi\\u006ce\":\"other\"}"),
            "unknown" => Encoding.UTF8.GetBytes("{\"profile\":\"amdn-webauthn-enrollment/1\",\"expected_identity_version\":1,\"replace_device_id\":null,\"owner\":\"injected\"}"),
            "unsafe-version" => Begin(9007199254740991),
            "oversize" => new byte[65537],
            _ => Begin(1)
        };
        await Error(client, member, "/v1/device-enrollments", body, status, scenario);
        await using var owner = await Owner();
        Assert.Equal(0L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_ceremonies WHERE tenant_id=@tenant", ("tenant", member.Tenant)));
    }

    [Fact]
    public async Task SignedForeignActorsClientRebindingAndRevokedGrantCannotContinueAProof()
    {
        var member = await Setup(); var foreign = await Setup();
        await using var app = App(member); using var client = issuer.Client(app); using var credential = new SyntheticWebAuthn();
        var begin = await Ok(client, member, "/v1/device-enrollments", Begin(1)); var id = begin.GetProperty("ceremony_id").GetGuid();
        var body = credential.Response(Challenge(begin), true);
        var path = $"/v1/device-enrollments/{id}/registration";
        await Error(client, foreign, path, body, 404);
        await Error(client, member, path, body, 409, "different-client");
        await using var owner = await Owner();
        await Sql(owner, "UPDATE amdn_identity.device_management_grants SET status='revoked' WHERE tenant_id=@tenant", ("tenant", member.Tenant));
        await Error(client, member, path, body, 403);
        Assert.Equal(0L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_commands WHERE ceremony_id=@id AND stage='registration'", ("id", id)));
    }

    [Fact]
    public async Task ProofLimitsAndBusyVerifierRejectBeforeDurableReservation()
    {
        var member = await Setup(); await using var app = App(member); using var client = issuer.Client(app); using var credential = new SyntheticWebAuthn();
        var begin = await Ok(client, member, "/v1/device-enrollments", Begin(1)); var id = begin.GetProperty("ceremony_id").GetGuid();
        var path = $"/v1/device-enrollments/{id}/registration";
        var valid = credential.Response(Challenge(begin), true);
        var large = JsonNode.Parse(valid)!; large["response"]!["attestationObject"] = new string('A', 22000);
        await Error(client, member, path, JsonSerializer.SerializeToUtf8Bytes(large), 413);
        await Error(client, member, path, "{}"u8.ToArray(), 400);
        using (var occupied = app.Services.GetRequiredService<EnrollmentHttpRuntime>().Proofs.AttemptAcquire())
        {
            Assert.True(occupied.IsAcquired);
            await Error(client, member, path, valid, 429);
        }
        await using var owner = await Owner();
        Assert.Equal(0L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_commands WHERE ceremony_id=@id AND stage='registration'", ("id", id)));
        Shape(await Ok(client, member, path, valid, "quoted-charset"), "EnrollmentCandidateOptions");
    }

    [Fact]
    public async Task MalformedClientDataPreservesAttemptsAcrossAllProofStages()
    {
        var member = await Setup();
        await using var app = App(member, globalBudget: 500, actorBudget: 500, tenantBudget: 500);
        using var client = issuer.Client(app); using var first = new SyntheticWebAuthn(); using var second = new SyntheticWebAuthn();
        var begin = await Ok(client, member, "/v1/device-enrollments", Begin(1));
        var candidate = await Prove(begin, "registration", first);
        var active = await Prove(candidate, "candidate", first);
        var replacement = await Ok(client, member, "/v1/device-enrollments", Begin(2, active.GetProperty("device_id").GetGuid()));
        var replacementId = replacement.GetProperty("ceremony_id").GetGuid();
        var replacementCandidate = await Ok(client, member, $"/v1/device-enrollments/{replacementId}/registration", second.Response(Challenge(replacement), true));
        var current = await Ok(client, member, $"/v1/device-enrollments/{replacementId}/candidate-proof", second.Response(Challenge(replacementCandidate), false));
        var replaced = await Prove(current, "current", first);
        var revoke = await Ok(client, member, $"/v1/devices/{replaced.GetProperty("device_id").GetGuid()}/revocations",
            JsonSerializer.SerializeToUtf8Bytes(new { profile = Profile, expected_identity_version = 3 }));
        var revoked = await Prove(revoke, "revocation", second);
        Assert.Equal(4, revoked.GetProperty("committed_identity_version").GetInt64());

        async Task<JsonElement> Prove(JsonElement options, string stage, SyntheticWebAuthn credential)
        {
            var id = options.GetProperty("ceremony_id").GetGuid();
            var path = stage == "revocation" ? $"/v1/device-revocations/{id}/proof"
                : $"/v1/device-enrollments/{id}/" + (stage == "registration" ? stage : stage + "-proof");
            var valid = credential.Response(Challenge(options), stage == "registration");
            var envelope = JsonNode.Parse(valid)!;
            var clientBytes = Decode(envelope["response"]!["clientDataJSON"]!.GetValue<string>());
            for (var submission = 0; submission < 6; submission++)
                await Reject("{}"u8.ToArray(), 400);
            await Reject("[]"u8.ToArray(), 400);
            await Reject("null"u8.ToArray(), 400);
            var data = JsonNode.Parse(clientBytes)!.AsObject();
            foreach (var field in new[] { "type", "challenge", "origin" })
            {
                var missing = data.DeepClone().AsObject(); missing.Remove(field);
                await Reject(JsonSerializer.SerializeToUtf8Bytes(missing), 400);
            }
            foreach (var field in new[] { "type", "challenge", "origin", "crossOrigin" })
            {
                foreach (var value in new[] { "null", "1", "{}", "[]", field == "crossOrigin" ? "\"false\"" : "false" })
                {
                    var malformed = data.DeepClone(); malformed[field] = JsonNode.Parse(value);
                    await Reject(JsonSerializer.SerializeToUtf8Bytes(malformed), 400);
                }
            }
            var unknown = data.DeepClone(); unknown["topOrigin"] = "https://ceremony.invalid";
            await Reject(JsonSerializer.SerializeToUtf8Bytes(unknown), 400);
            unknown = data.DeepClone(); unknown["unrecognized_metadata"] = "ignored?";
            await Reject(JsonSerializer.SerializeToUtf8Bytes(unknown), 400);
            foreach (var value in new[] { "null", "1", "true", "{}", "[]", "\"unknown value\"", "\"" + new string('x', 1024) + "\"" })
            {
                var malformed = data.DeepClone(); malformed["other_keys_can_be_added_here"] = JsonNode.Parse(value);
                await Reject(JsonSerializer.SerializeToUtf8Bytes(malformed), 400);
            }
            var text = Encoding.UTF8.GetString(clientBytes);
            foreach (var name in new[] { "other_keys_can_be_added_here", "other_keys_can_be_added_her\\u0065" })
                await Reject(Encoding.UTF8.GetBytes("{\"other_keys_can_be_added_here\":\"do not compare clientDataJSON against a template. See https://goo.gl/yabPex\",\"" + name + "\":\"duplicate\"," + text[1..]), 400);
            await Reject(Encoding.UTF8.GetBytes("{\"type\":\"webauthn.create\"," + text[1..]), 400);
            await Reject(Encoding.UTF8.GetBytes("{\"t\\u0079pe\":\"webauthn.create\"," + text[1..]), 400);
            foreach (var challenge in new[] { "", "!", "AA=", new string('A', 42) + "B", SyntheticWebAuthn.Encode(new byte[31]) })
            {
                var malformed = data.DeepClone(); malformed["challenge"] = challenge;
                await Reject(JsonSerializer.SerializeToUtf8Bytes(malformed), 400);
            }
            var oversized = data.DeepClone(); oversized["challenge"] = SyntheticWebAuthn.Encode(new byte[33]);
            await Reject(JsonSerializer.SerializeToUtf8Bytes(oversized), 413);
            await using var owner = await Owner();
            Assert.Equal(0L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_commands WHERE ceremony_id=@id AND stage=@stage", ("id", id), ("stage", stage)));
            Assert.Equal(stage, await Sql(owner, "SELECT state FROM amdn_identity.device_ceremonies WHERE ceremony_id=@id", ("id", id)));
            var invalidProof = credential.Response(Challenge(options), stage == "registration", scenario: stage == "registration" ? "wrong-challenge" : "wrong-signature");
            var failureKey = Key();
            for (var retry = 0; retry < 2; retry++) await Error(client, member, path, invalidProof, 400, key: failureKey);
            Assert.Equal(1L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_commands WHERE ceremony_id=@id AND stage=@stage AND state='failed' AND attempt_number=1", ("id", id), ("stage", stage)));
            return await Ok(client, member, path, valid);

            async Task Reject(byte[] malformed, int status)
            {
                envelope["response"]!["clientDataJSON"] = SyntheticWebAuthn.Encode(malformed);
                await Error(client, member, path, JsonSerializer.SerializeToUtf8Bytes(envelope), status);
            }
        }
    }

    [Fact]
    public async Task GlobalBudgetCountsAnonymousFailuresWithoutThrottlingLiveness()
    {
        var member = await Setup(); await using var app = App(member, 1); using var client = issuer.Client(app);
        await Error(client, member, "/v1/device-enrollments", Begin(1), 401, "missing-token");
        await Error(client, member, "/v1/device-enrollments", Begin(1), 429);
        using var health = await client.GetAsync("/health/live"); Assert.Equal(HttpStatusCode.OK, health.StatusCode);
    }

    [Fact]
    public async Task UnverifiedTenantSelectionCannotDrainAnotherMembersQuota()
    {
        var member = await Setup(); var foreign = await Setup();
        await using var app = App(member, tenantBudget: 1); using var client = issuer.Client(app);
        await Error(client, foreign, "/v1/device-enrollments", Begin(1), 404, tenant: member.Tenant);
        var begin = await Ok(client, member, "/v1/device-enrollments", Begin(1));
        await Error(client, member, "/v1/device-enrollments", Begin(1), 429);
        Assert.Equal("awaiting_registration", begin.GetProperty("state").GetString());
    }

    [Fact]
    public async Task ActorBudgetSurvivesClientIdChanges()
    {
        var member = await Setup(); await using var app = App(member, actorBudget: 1); using var client = issuer.Client(app);
        await Error(client, member, "/v1/device-enrollments", Begin(1), 403, "scope");
        await Error(client, member, "/v1/device-enrollments", Begin(1), 429, "different-client");
    }

    [Fact]
    public async Task EnrollmentRemainsAbsentByDefault()
    {
        await using var app = issuer.Application<Program>(); using var client = issuer.Client(app);
        using var response = await client.PostAsync("/v1/device-enrollments", new StringContent("{}"));
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task EnrollmentAndOwnerReadUseSeparatePoolsAndBudgetsInTheSameHost()
    {
        var member = await Setup(); await using var app = App(member, globalBudget: 1, ownerApi: true); using var client = issuer.Client(app);
        Shape(await Ok(client, member, "/v1/device-enrollments", Begin(1)), "EnrollmentRegistrationOptions");
        await Error(client, member, "/v1/device-enrollments", Begin(1), 429);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/v1/postman?tenant_id=" + member.Tenant);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", issuer.Token(payload => { payload["sub"] = member.Subject; payload["scope"] = "postman.read"; }));
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync());
        Assert.Equal(member.Postman, json.RootElement.GetProperty("postman_id").GetGuid());
    }

    private WebApplicationFactory<Program> App(Member member, int globalBudget = 100, int actorBudget = 100, int tenantBudget = 100, bool ownerApi = false)
    {
        var settings = new Dictionary<string, string?>
        {
            ["Authentication:DeviceStepUp:Enabled"] = "true",
            ["Authentication:DeviceStepUp:AllowedAcrValues:0"] = Acr,
            ["Authentication:DeviceStepUp:MaximumAgeSeconds"] = "120",
            ["EnrollmentApi:Enabled"] = "true",
            ["EnrollmentApi:ConnectionString"] = _state.IdentityConnection("enrollment"),
            ["EnrollmentApi:ConfigurationId"] = member.Config.ToString(),
            ["EnrollmentApi:Origin"] = "https://ceremony.invalid",
            ["EnrollmentApi:MaximumPoolSize"] = "2",
            ["EnrollmentApi:RequestsPerMinute"] = globalBudget.ToString(),
            ["EnrollmentApi:ActorRequestsPerMinute"] = Math.Min(globalBudget, actorBudget).ToString(),
            ["EnrollmentApi:TenantRequestsPerMinute"] = Math.Min(globalBudget, tenantBudget).ToString(),
            ["EnrollmentApi:MaximumConcurrentProofs"] = "1"
        };
        if (ownerApi)
        {
            settings["IdentityApi:Enabled"] = "true";
            settings["IdentityApi:ConnectionString"] = _state.IdentityConnection("runtime");
            settings["IdentityApi:RequestsPerMinute"] = "1";
            settings["IdentityApi:ActorRequestsPerMinute"] = "1";
            settings["IdentityApi:TenantRequestsPerMinute"] = "1";
        }
        return issuer.Application<Program>(settings);
    }

    private async Task<Member> Setup()
    {
        await using var pool = IdentityDatabase.ProvisioningPool(_state.IdentityConnection("provisioner"));
        var provisioner = new IdentityProvisioner(pool); var subject = Key();
        var member = await provisioner.EnsureMemberAsync(await provisioner.CreateTenantAsync(), issuer.Issuer, subject);
        await using var owner = await Owner(); var config = Guid.NewGuid();
        var configured = await Sql(owner, "SELECT amdn_identity.administer_device_configuration(@command,@config,0,'ceremony.invalid','https://ceremony.invalid',ARRAY['urn:amdn:test:strong'],900,true,'http-fixture')",
            ("command", Guid.NewGuid()), ("config", config));
        Assert.Equal("ok", JsonSerializer.Deserialize<JsonElement>((string)configured!).GetProperty("outcome").GetString());
        var granted = await Sql(owner, "SELECT amdn_identity.administer_device_grant(@command,@tenant,@user,@postman,'grant.issue',0,clock_timestamp()+interval '1 hour','http-fixture')",
            ("command", Guid.NewGuid()), ("tenant", member.TenantId), ("user", member.UserId), ("postman", member.PostmanId));
        Assert.Equal("ok", JsonSerializer.Deserialize<JsonElement>((string)granted!).GetProperty("outcome").GetString());
        return new(member.TenantId, member.UserId, member.PostmanId, config, subject);
    }
    private async Task<NpgsqlConnection> Owner()
    {
        var connection = new NpgsqlConnection(_state.IdentityConnection("migrator")); await connection.OpenAsync();
        await Sql(connection, "SET ROLE amdn_identity_owner"); return connection;
    }
    private static async Task<object?> Sql(NpgsqlConnection connection, string text, params (string, object)[] values)
    {
        await using var command = new NpgsqlCommand(text, connection);
        foreach (var (name, value) in values) command.Parameters.AddWithValue(name, value);
        return await command.ExecuteScalarAsync();
    }
    private async Task<HttpResponseMessage> Request(HttpClient client, Member member, string path, byte[] bytes, string scenario = "valid", string? key = null, Guid? tenant = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path + "?tenant_id=" + (scenario == "foreign" ? Guid.NewGuid() : tenant ?? member.Tenant) + (scenario == "query" ? "&tenant_id=" + member.Tenant : ""));
        if (scenario != "missing-origin") request.Headers.Add("Origin", scenario == "origin" ? "https://ceremony.invalid:443" : "https://ceremony.invalid");
        request.Headers.Add("Idempotency-Key", scenario == "key" ? "short" : key ?? Key());
        if (scenario != "missing-token") request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", issuer.Token(payload =>
        {
            payload["sub"] = member.Subject; payload["scope"] = scenario == "scope" ? "device.manage.extra" : "device.manage";
            payload["acr"] = Acr; payload["auth_time"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - (scenario == "old-step-up" ? 121 : 1);
            if (scenario == "different-client") payload["client_id"] = "different-client";
        }, rogue: scenario == "bad-signature"));
        request.Content = new ByteArrayContent(bytes);
        request.Content.Headers.TryAddWithoutValidation("Content-Type", scenario switch
        {
            "charset" => "application/json; charset=latin1",
            "duplicate-charset" => "application/json; charset=utf-8; charset=utf-8",
            "quoted-charset" => "application/json; charset=\"utf-8\"",
            _ => "application/json"
        });
        if (scenario == "compression") request.Content.Headers.ContentEncoding.Add("gzip");
        return await client.SendAsync(request);
    }
    private async Task<JsonElement> Ok(HttpClient client, Member member, string path, byte[] body, string scenario = "valid", string? key = null)
    {
        using var response = await Request(client, member, path, body, scenario, key);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        using var json = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync()); return json.RootElement.Clone();
    }
    private async Task Error(HttpClient client, Member member, string path, byte[] body, int status, string scenario = "valid", string? key = null, Guid? tenant = null)
    {
        using var response = await Request(client, member, path, body, scenario, key, tenant);
        Assert.Equal((HttpStatusCode)status, response.StatusCode); Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        using var json = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync()); HttpProblemContract.AssertResponse(response, json.RootElement);
    }
    private static byte[] Begin(long version, Guid? replace = null) => JsonSerializer.SerializeToUtf8Bytes(new { profile = Profile, expected_identity_version = version, replace_device_id = replace });
    private static string Key() => Guid.NewGuid().ToString("N");
    private static byte[] Decode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
    private static byte[] Challenge(JsonElement value) => Decode(value.GetProperty("public_key").GetProperty("challenge").GetString()!);
    private static void Allowed(JsonElement options, byte[] credential)
    {
        var descriptor = Assert.Single(options.GetProperty("public_key").GetProperty("allowCredentials").EnumerateArray());
        Assert.Equal(SyntheticWebAuthn.Encode(credential), descriptor.GetProperty("id").GetString());
        Assert.Equal("required", options.GetProperty("public_key").GetProperty("userVerification").GetString());
    }
    private static void Shape(JsonElement value, string schema)
    {
        var schemas = JsonSerializer.Deserialize<JsonElement>(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "openapi.json"))).GetProperty("components").GetProperty("schemas");
        Closed(value, schemas.GetProperty(schema));
        Assert.Equal(Profile, value.GetProperty("profile").GetString());
        foreach (var name in new[] { "completed_at", "expires_at", "challenge_expires_at" })
            if (value.TryGetProperty(name, out var time)) Assert.EndsWith("Z", time.GetString());
        if (value.TryGetProperty("public_key", out var options))
            Closed(options, schemas.GetProperty(schema == "EnrollmentRegistrationOptions" ? "WebAuthnCreationOptions" : "WebAuthnRequestOptions"));
        if (value.TryGetProperty("current_lifecycle", out var lifecycle)) Assert.EndsWith("Z", lifecycle.GetProperty("observed_at").GetString());
        static void Closed(JsonElement result, JsonElement contract)
        {
            foreach (var required in contract.GetProperty("required").EnumerateArray()) Assert.True(result.TryGetProperty(required.GetString()!, out _));
            var fields = contract.GetProperty("properties");
            Assert.All(result.EnumerateObject(), field => Assert.True(fields.TryGetProperty(field.Name, out _)));
            foreach (var field in fields.EnumerateObject())
                if (field.Value.TryGetProperty("const", out var expected) && result.TryGetProperty(field.Name, out var actual)) Assert.Equal(expected.GetRawText(), actual.GetRawText());
        }
    }
}
