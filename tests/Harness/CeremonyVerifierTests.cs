using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AMDN.Enrollment;
using Npgsql;
using Xunit;

namespace AMDN.Harness.Tests;

public sealed partial class CeremonyTransactionTests
{
    [Fact]
    public async Task SignedProofsDriveInitialReplacementRevocationAndHistoricalReplay()
    {
        var actor = await Setup(); using var oldKey = new SyntheticWebAuthn(); using var newKey = new SyntheticWebAuthn();
        var begin = await Begin(actor); var id = Id(begin, "ceremony_id"); var handle = await Handle(actor);
        var candidate = await Verify(actor, id, "registration", oldKey.Response(Challenge(begin), true));
        Assert.Equal("candidate", candidate.GetProperty("state").GetString());
        var candidateBody = oldKey.Response(Challenge(candidate), false, handle, counter: 1);
        var replayKey = Idempotency(); var active = await Verify(actor, id, "candidate", candidateBody, replayKey);
        Assert.Equal(2, active.GetProperty("committed_identity_version").GetInt64());
        Assert.False(active.GetProperty("messaging_ready").GetBoolean());
        AssertOutcome("conflict", await Verify(actor, id, "candidate", [.. candidateBody, 32], replayKey));
        var oldDevice = Id(active, "device_id");
        begin = await Begin(actor, expected: 2, target: oldDevice); var replacementId = Id(begin, "ceremony_id");
        candidate = await Verify(actor, replacementId, "registration", newKey.Response(Challenge(begin), true));
        var current = await Verify(actor, replacementId, "candidate", newKey.Response(Challenge(candidate), false));
        Assert.Equal("current", current.GetProperty("state").GetString());
        AssertOutcome("invalid_proof", await Verify(actor, replacementId, "current", newKey.Response(Challenge(current), false)));
        var replaced = await Verify(actor, replacementId, "current", oldKey.Response(Challenge(current), false, counter: 2));
        Assert.Equal(3, replaced.GetProperty("committed_identity_version").GetInt64());
        var newDevice = Id(replaced, "device_id");
        var revoke = await Begin(actor, "revocation", 3, newDevice);
        var revoked = await Verify(actor, Id(revoke, "ceremony_id"), "revocation", newKey.Response(Challenge(revoke), false));
        Assert.Equal(4, revoked.GetProperty("committed_identity_version").GetInt64());
        var replay = await Verify(actor, id, "candidate", candidateBody, replayKey);
        Assert.Equal(2, replay.GetProperty("committed_identity_version").GetInt64());
        Assert.Equal("revoked", replay.GetProperty("current_lifecycle").GetProperty("status").GetString());
        Assert.Equal(4, replay.GetProperty("current_lifecycle").GetProperty("identity_version").GetInt64());
        await using var owner = await Owner();
        Assert.Equal(0L, await Sql(owner, "SELECT count(*) FROM amdn_identity.devices WHERE tenant_id=@id AND status='credential_active'", ("id", actor.Person.TenantId)));
    }

    [Theory]
    [InlineData(true, "wrong-origin")]
    [InlineData(true, "normalized-origin")]
    [InlineData(true, "wrong-rp")]
    [InlineData(true, "wrong-challenge")]
    [InlineData(true, "wrong-type")]
    [InlineData(true, "cross-origin")]
    [InlineData(true, "no-up")]
    [InlineData(true, "no-uv")]
    [InlineData(true, "invalid-backup")]
    [InlineData(true, "extensions")]
    [InlineData(true, "wrong-algorithm")]
    [InlineData(true, "wrong-curve")]
    [InlineData(true, "invalid-point")]
    [InlineData(true, "attested-id")]
    [InlineData(true, "packed")]
    [InlineData(true, "trailing-cbor")]
    [InlineData(true, "bad-cbor")]
    [InlineData(true, "label-overflow-positive")]
    [InlineData(true, "label-overflow-negative")]
    [InlineData(true, "kty-overflow-positive")]
    [InlineData(true, "kty-overflow-negative")]
    [InlineData(true, "algorithm-overflow-positive")]
    [InlineData(true, "algorithm-overflow-negative")]
    [InlineData(true, "curve-overflow-positive")]
    [InlineData(true, "curve-overflow-negative")]
    [InlineData(false, "wrong-origin")]
    [InlineData(false, "normalized-origin")]
    [InlineData(false, "wrong-rp")]
    [InlineData(false, "wrong-challenge")]
    [InlineData(false, "wrong-type")]
    [InlineData(false, "cross-origin")]
    [InlineData(false, "no-up")]
    [InlineData(false, "no-uv")]
    [InlineData(false, "invalid-backup")]
    [InlineData(false, "extensions")]
    [InlineData(false, "assertion-at")]
    [InlineData(false, "wrong-signature")]
    [InlineData(false, "tampered")]
    [InlineData(false, "wrong-id")]
    [InlineData(false, "wrong-handle")]
    [InlineData(false, "backup-eligible")]
    public async Task VerifierDeniesInvalidProofAndCachesFailureWithoutLifecycleEffects(bool registration, string scenario)
    {
        var actor = await Setup(); using var key = new SyntheticWebAuthn(); var begin = await Begin(actor); var id = Id(begin, "ceremony_id");
        var options = registration ? begin : await Verify(actor, id, "registration", key.Response(Challenge(begin), true));
        var body = key.Response(Challenge(options), registration, await Handle(actor), scenario);
        var stage = registration ? "registration" : "candidate"; var replayKey = Idempotency();
        for (var call = 0; call < 2; call++)
        {
            var result = await Verify(actor, id, stage, body, replayKey);
            AssertOutcome("invalid_proof", result);
            Assert.Single(result.EnumerateObject());
            await using var owner = await Owner();
            Assert.Equal(1L, await Sql(owner, "SELECT identity_version FROM amdn_identity.users WHERE tenant_id=@id", ("id", actor.Person.TenantId)));
            Assert.Equal(1L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_commands WHERE ceremony_id=@id AND stage=@stage", ("id", id), ("stage", stage)));
            Assert.Equal(1L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_commands WHERE ceremony_id=@id AND stage=@stage AND state='failed' AND result='{\"outcome\":\"invalid_proof\"}'::jsonb", ("id", id), ("stage", stage)));
            Assert.Equal(stage, await Sql(owner, "SELECT state FROM amdn_identity.device_ceremonies WHERE ceremony_id=@id", ("id", id)));
            Assert.Equal(1L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_challenges WHERE ceremony_id=@id AND stage=@stage AND consumed_at IS NULL", ("id", id), ("stage", stage)));
            if (registration)
                Assert.Equal(1L, await Sql(owner, "SELECT count(*) FROM amdn_identity.devices WHERE device_id=@id AND credential_id IS NULL AND public_key_cose IS NULL", ("id", Id(begin, "device_id"))));
        }
    }

    [Theory]
    [InlineData("duplicate")]
    [InlineData("escaped-duplicate")]
    [InlineData("unknown")]
    [InlineData("extension-output")]
    [InlineData("padded")]
    [InlineData("noncanonical")]
    [InlineData("id-mismatch")]
    [InlineData("oversize-body")]
    [InlineData("oversize-id")]
    [InlineData("oversize-client")]
    [InlineData("oversize-attestation")]
    [InlineData("client-duplicate")]
    [InlineData("invalid-utf8")]
    [InlineData("deep-json")]
    public async Task MalformedProjectionNeverOpensDatabaseOrReservesAttempt(string scenario)
    {
        using var fixture = new SyntheticWebAuthn();
        var bytes = fixture.Response(new byte[32], true); var json = JsonNode.Parse(bytes)!;
        switch (scenario)
        {
            case "unknown": json["owner"] = "untrusted"; break;
            case "extension-output": json["clientExtensionResults"]!["appid"] = true; break;
            case "padded": json["id"] = json["id"]!.GetValue<string>() + "="; break;
            case "noncanonical": json["id"] = "AB"; break;
            case "id-mismatch": json["rawId"] = "AA"; break;
            case "oversize-id": json["id"] = SyntheticWebAuthn.Encode(new byte[1024]); break;
            case "oversize-client": json["response"]!["clientDataJSON"] = SyntheticWebAuthn.Encode(new byte[8193]); break;
            case "oversize-attestation": json["response"]!["attestationObject"] = SyntheticWebAuthn.Encode(new byte[16385]); break;
            case "client-duplicate": json["response"]!["clientDataJSON"] = SyntheticWebAuthn.Encode(Encoding.UTF8.GetBytes("{\"type\":\"a\",\"type\":\"b\"}")); break;
        }
        bytes = JsonSerializer.SerializeToUtf8Bytes(json);
        bytes = scenario switch
        {
            "duplicate" => Encoding.UTF8.GetBytes("{\"type\":\"public-key\"," + Encoding.UTF8.GetString(bytes)[1..]),
            "escaped-duplicate" => Encoding.UTF8.GetBytes("{\"t\\u0079pe\":\"public-key\"," + Encoding.UTF8.GetString(bytes)[1..]),
            "oversize-body" => new byte[65537],
            "invalid-utf8" => [0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d],
            "deep-json" => Encoding.UTF8.GetBytes(new string('[', 20) + "0" + new string(']', 20)),
            _ => bytes
        };
        var bridge = new CeremonyVerifier(_ => throw new InvalidOperationException("Malformed projection reached database"));
        var actor = new CeremonyActor(Guid.NewGuid(), "issuer", "subject", "client", "https://ceremony.invalid", Guid.NewGuid(), "device.manage", "acr", DateTime.UtcNow, DateTime.UtcNow.AddMinutes(5));
        AssertOutcome("invalid_request", await bridge.CompleteAsync(actor, Guid.NewGuid(), "registration", Idempotency(), bytes));
    }

    [Theory]
    [InlineData("registration")]
    [InlineData("candidate")]
    [InlineData("current")]
    [InlineData("revocation")]
    public async Task UnknownClientDataFieldsNeverOpenDatabaseOrReserveAttempt(string stage)
    {
        using var fixture = new SyntheticWebAuthn();
        var body = fixture.Response(new byte[32], stage == "registration", scenario: "top-origin");
        var bridge = new CeremonyVerifier(_ => throw new InvalidOperationException("Malformed client data reached database"));
        var actor = new CeremonyActor(Guid.NewGuid(), "issuer", "subject", "client", "https://ceremony.invalid", Guid.NewGuid(), "device.manage", "acr", DateTime.UtcNow, DateTime.UtcNow.AddMinutes(5));
        AssertOutcome("invalid_request", await bridge.CompleteAsync(actor, Guid.NewGuid(), stage, Idempotency(), body));
    }

    [Fact]
    public async Task ChangedAuthorityBetweenVerificationAndCommitDeniesAndNoLocksSpanVerification()
    {
        var actor = await Setup(); using var key = new SyntheticWebAuthn(); var begin = await Begin(actor); var id = Id(begin, "ceremony_id");
        var calls = 0;
        var bridge = new CeremonyVerifier(async _ =>
        {
            var connection = await Owner();
            if (++calls == 2)
            {
                await using var tx = await connection.BeginTransactionAsync();
                // Would fail NOWAIT if reservation transaction still owned the user lock.
                await Sql(connection, "SELECT user_id FROM amdn_identity.users WHERE tenant_id=@id FOR UPDATE NOWAIT", ("id", actor.Person.TenantId));
                Assert.Equal(1L, await Sql(connection, "SELECT count(*) FROM amdn_identity.device_commands WHERE ceremony_id=@id AND state='reserved'", ("id", id)));
                await Sql(connection, "UPDATE amdn_identity.device_management_grants SET expires_at=expires_at+interval '1 minute' WHERE tenant_id=@id", ("id", actor.Person.TenantId));
                await tx.CommitAsync();
            }
            return connection;
        });
        AssertOutcome("conflict", await bridge.CompleteAsync(Projection(actor), id, "registration", Idempotency(), key.Response(Challenge(begin), true)));
        await using var owner = await Owner();
        Assert.Equal("abandoned", await Sql(owner, "SELECT state FROM amdn_identity.device_ceremonies WHERE ceremony_id=@id", ("id", id)));
        Assert.Equal(DBNull.Value, await Sql(owner, "SELECT credential_id FROM amdn_identity.devices WHERE device_id=@id", ("id", Id(begin, "device_id"))));
    }

    [Fact]
    public async Task InterruptedVerificationKeepsReservationAndNeverRerunsItOnRetry()
    {
        var actor = await Setup(); using var key = new SyntheticWebAuthn(); var begin = await Begin(actor); var id = Id(begin, "ceremony_id");
        var body = key.Response(Challenge(begin), true); var replay = Idempotency(); var calls = 0;
        var bridge = new CeremonyVerifier(async _ => { if (++calls == 2) throw new OperationCanceledException(); return await Owner(); });
        await Assert.ThrowsAsync<OperationCanceledException>(() => bridge.CompleteAsync(Projection(actor), id, "registration", replay, body));
        AssertOutcome("unavailable", await Verify(actor, id, "registration", body, replay));
        await using var owner = await Owner();
        Assert.Equal(1L, await Sql(owner, "SELECT count(*) FROM amdn_identity.device_commands WHERE ceremony_id=@id AND state='reserved'", ("id", id)));
        Assert.Equal(DBNull.Value, await Sql(owner, "SELECT credential_id FROM amdn_identity.devices WHERE device_id=@id", ("id", Id(begin, "device_id"))));
    }

    [Fact]
    public async Task SignedRequestRejectsForeignOwnerAndReusedPublicKey()
    {
        var actor = await Setup(); var foreign = await Setup(); using var key = new SyntheticWebAuthn();
        var begin = await Begin(actor); var id = Id(begin, "ceremony_id"); var body = key.Response(Challenge(begin), true);
        AssertOutcome("not_found", await Verify(foreign, id, "registration", body));
        AssertOutcome("ok", await Verify(actor, id, "registration", body));
        key.RotateId(); // Distinct credential ID, same normalized public key.
        var other = await Begin(foreign);
        AssertOutcome("conflict", await Verify(foreign, Id(other, "ceremony_id"), "registration", key.Response(Challenge(other), true)));
    }

    [Fact]
    public async Task SignedNonzeroCounterMustIncreaseAndBackupEligibleCredentialWorks()
    {
        var actor = await Setup(); using var key = new SyntheticWebAuthn(); var begin = await Begin(actor); var id = Id(begin, "ceremony_id");
        var candidate = await Verify(actor, id, "registration", key.Response(Challenge(begin), true, scenario: "backup-eligible", counter: 10));
        AssertOutcome("invalid_proof", await Verify(actor, id, "candidate", key.Response(Challenge(candidate), false, scenario: "backup-eligible", counter: 10)));
        AssertOutcome("invalid_proof", await Verify(actor, id, "candidate", key.Response(Challenge(candidate), false, scenario: "backup-eligible", counter: 0)));
        var body = key.Response(Challenge(candidate), false, scenario: "backup-eligible", counter: 11); var replay = Idempotency();
        var results = await Task.WhenAll(Verify(actor, id, "candidate", body, replay), Verify(actor, id, "candidate", body, replay));
        Assert.Contains(results, result => result.GetProperty("outcome").GetString() == "ok");
        Assert.All(results, result => Assert.Contains(result.GetProperty("outcome").GetString(), new[] { "ok", "unavailable" }));
        AssertOutcome("ok", await Verify(actor, id, "candidate", body, replay));
        AssertOutcome("conflict", await Verify(actor, id, "candidate", body));
        await using var owner = await Owner();
        Assert.Equal(2L, await Sql(owner, "SELECT identity_version FROM amdn_identity.users WHERE tenant_id=@id", ("id", actor.Person.TenantId)));
        Assert.Equal(11L, await Sql(owner, "SELECT sign_count FROM amdn_identity.devices WHERE device_id=@id", ("id", Id(begin, "device_id"))));
    }

    [Theory]
    [InlineData("signature", 1025)]
    [InlineData("authenticatorData", 4097)]
    [InlineData("userHandle", 33)]
    [InlineData("userHandle", 31)]
    public async Task OversizedAssertionFieldsAreRejectedBeforeReservation(string field, int bytes)
    {
        using var fixture = new SyntheticWebAuthn(); var json = JsonNode.Parse(fixture.Response(new byte[32], false))!;
        json["response"]![field] = SyntheticWebAuthn.Encode(new byte[bytes]);
        var bridge = new CeremonyVerifier(_ => throw new InvalidOperationException("Malformed assertion reached database"));
        var actor = new CeremonyActor(Guid.NewGuid(), "issuer", "subject", "client", "https://ceremony.invalid", Guid.NewGuid(), "device.manage", "acr", DateTime.UtcNow, DateTime.UtcNow.AddMinutes(5));
        AssertOutcome("invalid_request", await bridge.CompleteAsync(actor, Guid.NewGuid(), "candidate", Idempotency(), JsonSerializer.SerializeToUtf8Bytes(json)));
    }

    [Fact]
    public async Task AmbientTransactionCannotUndoReservation()
    {
        using var ambient = new System.Transactions.TransactionScope(System.Transactions.TransactionScopeAsyncFlowOption.Enabled);
        var bridge = new CeremonyVerifier(_ => throw new Exception("Ambient transaction reached database"));
        var actor = new CeremonyActor(Guid.NewGuid(), "issuer", "subject", "client", "https://ceremony.invalid", Guid.NewGuid(), "device.manage", "acr", DateTime.UtcNow, DateTime.UtcNow.AddMinutes(5));
        await Assert.ThrowsAsync<InvalidOperationException>(() => bridge.CompleteAsync(actor, Guid.NewGuid(), "candidate", Idempotency(), new byte[1]));
    }

    private Task<JsonElement> Verify(Actor actor, Guid id, string stage, byte[] body, string? key = null) =>
        new CeremonyVerifier(_ => Owner()).CompleteAsync(Projection(actor), id, stage, key ?? Idempotency(), body);
    private static CeremonyActor Projection(Actor actor) => new(actor.Person.TenantId, "https://ceremony-issuer.invalid", actor.Subject,
        actor.Client, actor.Origin, actor.Configuration, actor.Scope, actor.Acr, actor.AuthTime, actor.TokenExpiry);
    private async Task<byte[]> Handle(Actor actor)
    {
        await using var owner = await Owner();
        return (byte[])(await Sql(owner, "SELECT user_handle FROM amdn_identity.device_subjects WHERE tenant_id=@tenant AND user_id=@user",
            ("tenant", actor.Person.TenantId), ("user", actor.Person.UserId)))!;
    }
    private static byte[] Challenge(JsonElement value) => Convert.FromHexString(value.GetProperty("challenge_hex").GetString()!);
}
