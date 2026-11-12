using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Fido2NetLib;
using Fido2NetLib.Objects;

// Disposable standards fixtures, not an authenticator, enrollment service or
// application verifier. No private material or raw responses leave this process.
var passed = 0;
foreach (var scenario in new[] { "valid", "backup-eligible", "wrong-origin", "wrong-rp", "wrong-challenge",
    "cross-origin", "no-uv", "no-up", "duplicate-id", "wrong-type", "wrong-algorithm", "invalid-backup-flags" })
{
    using var fixture = new Ceremony();
    var accepted = scenario is "valid" or "backup-eligible";
    await Check("registration/" + scenario, accepted, () => fixture.Register(scenario));
}
foreach (var scenario in new[] { "valid", "zero-counter", "backup-eligible", "wrong-signature", "tampered",
    "wrong-origin", "wrong-rp", "wrong-challenge", "cross-origin", "no-uv", "no-up", "wrong-id",
    "wrong-handle", "wrong-type", "counter-regression", "counter-reset", "invalid-backup-flags" })
{
    using var fixture = new Ceremony();
    var registered = await fixture.Register(scenario == "backup-eligible" ? scenario : "valid");
    var accepted = scenario is "valid" or "zero-counter" or "backup-eligible";
    await Check("assertion/" + scenario, accepted, () => fixture.Assert(registered, scenario));
}

// Explicitly demonstrate boundaries the future application must enforce.
using (var fixture = new Ceremony())
{
    var registered = await fixture.Register("valid");
    var options = fixture.AssertionOptions();
    var response = fixture.Assertion(options, "zero-counter");
    await fixture.Verify(registered, options, response, 0);
    await fixture.Verify(registered, options, response, 0);
    Pass("boundary/raw-verifier-does-not-consume-challenges");
    // This API has no stored BE input; application storage must compare it.
    await fixture.Assert(registered, "backup-eligible");
    Pass("boundary/raw-verifier-does-not-check-stored-backup-eligibility");
}
Console.WriteLine($"PASS: {passed} verifier scenarios; synthetic authenticator only; enrollment and production approval pending.");

async Task Check<T>(string name, bool accepted, Func<Task<T>> action)
{
    try
    {
        await action();
        if (!accepted) throw new InvalidOperationException("Unexpected acceptance: " + name);
    }
    catch (Fido2VerificationException) when (!accepted) { }
    Pass(name);
}
void Pass(string name) { passed++; Console.WriteLine("PASS: " + name); }

sealed class Ceremony : IDisposable
{
    private const string Rp = "enrollment.example.invalid";
    private const string Origin = "https://enrollment.example.invalid";
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly byte[] _id = RandomNumberGenerator.GetBytes(32);
    private readonly byte[] _handle = RandomNumberGenerator.GetBytes(32);
    private readonly Fido2 _verifier = new(new Fido2Configuration
    {
        RPID = Rp,
        RPName = "AMDN synthetic enrollment",
        Origins = new HashSet<string> { Origin },
        ChallengeSize = 32,
        Timeout = 120000,
        AllowCrossOriginRequests = false,
        BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Allowed,
        BackedUpCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Allowed
    });

    public Task<RegisteredPublicKeyCredential> Register(string scenario)
    {
        var options = _verifier.RequestNewCredential(new RequestNewCredentialParams
        {
            User = new Fido2User { Id = _handle, Name = "synthetic", DisplayName = "Synthetic user" },
            AuthenticatorSelection = new AuthenticatorSelection
            { UserVerification = UserVerificationRequirement.Required, ResidentKey = ResidentKeyRequirement.Discouraged },
            AttestationPreference = AttestationConveyancePreference.None,
            PubKeyCredParams = [new PubKeyCredParam(COSE.Algorithm.ES256)]
        });
        if (options.Challenge.Length != 32) throw new InvalidOperationException("Unexpected challenge length.");
        var clientData = ClientData(options.Challenge, "webauthn.create", scenario);
        var data = AuthenticatorData(scenario, 0, true);
        var writer = new CborWriter();
        writer.WriteStartMap(3);
        writer.WriteTextString("fmt"); writer.WriteTextString("none");
        writer.WriteTextString("attStmt"); writer.WriteStartMap(0); writer.WriteEndMap();
        writer.WriteTextString("authData"); writer.WriteByteString(data); writer.WriteEndMap();
        var response = new AuthenticatorAttestationRawResponse
        {
            Id = Encode(_id),
            RawId = _id,
            Type = PublicKeyCredentialType.PublicKey,
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs(),
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            { AttestationObject = writer.Encode(), ClientDataJson = clientData, Transports = [] }
        };
        return _verifier.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = response,
            OriginalOptions = options,
            IsCredentialIdUniqueToUserCallback = (_, _) => Task.FromResult(scenario != "duplicate-id")
        });
    }

    public AssertionOptions AssertionOptions() => _verifier.GetAssertionOptions(new GetAssertionOptionsParams
    {
        AllowedCredentials = [new PublicKeyCredentialDescriptor(_id)],
        UserVerification = UserVerificationRequirement.Required
    });

    public async Task<VerifyAssertionResult> Assert(RegisteredPublicKeyCredential registered, string scenario)
    {
        var options = AssertionOptions();
        return await Verify(registered, options, Assertion(options, scenario),
            scenario is "counter-regression" or "counter-reset" ? 1u : 0u);
    }

    public Task<VerifyAssertionResult> Verify(RegisteredPublicKeyCredential registered, AssertionOptions options,
        AuthenticatorAssertionRawResponse response, uint storedCounter) => _verifier.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = response,
            OriginalOptions = options,
            StoredPublicKey = registered.PublicKey,
            StoredSignatureCounter = storedCounter,
            IsUserHandleOwnerOfCredentialIdCallback = (args, _) => Task.FromResult(
                args.CredentialId.AsSpan().SequenceEqual(_id) && args.UserHandle.AsSpan().SequenceEqual(_handle))
        });

    public AuthenticatorAssertionRawResponse Assertion(AssertionOptions options, string scenario)
    {
        var clientData = ClientData(options.Challenge, "webauthn.get", scenario);
        var count = scenario is "zero-counter" or "counter-reset" ? 0u : 1u;
        var data = AuthenticatorData(scenario, count, false);
        byte[] signed = [.. data, .. SHA256.HashData(clientData)];
        using var rogue = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signature = (scenario == "wrong-signature" ? rogue : _key).SignData(signed, HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
        if (scenario == "tampered") data[36] ^= 1;
        var id = scenario == "wrong-id" ? RandomNumberGenerator.GetBytes(32) : _id;
        return new AuthenticatorAssertionRawResponse
        {
            Id = Encode(id),
            RawId = id,
            Type = PublicKeyCredentialType.PublicKey,
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs(),
            Response = new AuthenticatorAssertionRawResponse.AssertionResponse
            {
                AuthenticatorData = data,
                ClientDataJson = clientData,
                Signature = signature,
                UserHandle = scenario == "wrong-handle" ? RandomNumberGenerator.GetBytes(32) : _handle
            }
        };
    }

    private byte[] AuthenticatorData(string scenario, uint counter, bool registration)
    {
        var rpHash = SHA256.HashData(Encoding.UTF8.GetBytes(scenario == "wrong-rp" ? "other.example.invalid" : Rp));
        byte flags = 0x05; // UP and UV
        if (scenario == "no-up") flags &= 0xfe;
        if (scenario == "no-uv") flags &= 0xfb;
        if (scenario == "backup-eligible") flags |= 0x18; // BE and BS
        if (scenario == "invalid-backup-flags") flags |= 0x10; // BS without BE
        if (registration) flags |= 0x40; // AT
        var count = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(count, counter);
        if (!registration) return [.. rpHash, flags, .. count];
        var size = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(size, (ushort)_id.Length);
        var publicKey = _key.ExportParameters(false);
        var cose = new CborWriter(); cose.WriteStartMap(5);
        cose.WriteInt32(1); cose.WriteInt32(2); // EC2
        cose.WriteInt32(3); cose.WriteInt32(scenario == "wrong-algorithm" ? -35 : -7);
        cose.WriteInt32(-1); cose.WriteInt32(1); // P-256
        cose.WriteInt32(-2); cose.WriteByteString(publicKey.Q.X!);
        cose.WriteInt32(-3); cose.WriteByteString(publicKey.Q.Y!); cose.WriteEndMap();
        return [.. rpHash, flags, .. count, .. new byte[16], .. size, .. _id, .. cose.Encode()];
    }

    private static byte[] ClientData(byte[] challenge, string type, string scenario) => JsonSerializer.SerializeToUtf8Bytes(new
    {
        type = scenario == "wrong-type" ? "webauthn.other" : type,
        challenge = Encode(scenario == "wrong-challenge" ? RandomNumberGenerator.GetBytes(32) : challenge),
        origin = scenario == "wrong-origin" ? "https://other.example.invalid" : Origin,
        crossOrigin = scenario == "cross-origin"
    });
    private static string Encode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    public void Dispose() => _key.Dispose();
}
