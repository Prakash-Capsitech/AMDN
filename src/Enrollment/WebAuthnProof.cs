using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text.Json;
using Fido2NetLib;
using Fido2NetLib.Objects;
using static AMDN.Enrollment.ProofRequest;

namespace AMDN.Enrollment;

internal sealed record VerifiedProof(byte[] Credential, byte[] PublicKey, bool BackupEligible, bool BackedUp, uint Counter);

internal static class WebAuthnProof
{
    internal static async Task<VerifiedProof?> VerifyAsync(ProofRequest proof, JsonElement snapshot, CancellationToken cancellationToken)
    {
        // All context comes from the committed SQL reservation, never request options.
        var challenge = Hex(snapshot, "challenge_hex");
        var handle = Hex(snapshot, "user_handle_hex");
        var rp = snapshot.GetProperty("rp_id").GetString()!;
        var origin = snapshot.GetProperty("origin").GetString()!;
        var registration = snapshot.GetProperty("stage").GetString() == "registration";
        try
        {
            Require(challenge.Length == 32 && handle.Length == 32);
            // Configuration must be canonical HTTPS and within its configured RP.
            Require(Uri.TryCreate(origin, UriKind.Absolute, out var uri) && uri.Scheme == "https"
                && uri.GetLeftPart(UriPartial.Authority) == origin && uri.UserInfo.Length == 0
                && Uri.CheckHostName(rp) == UriHostNameType.Dns && rp == rp.ToLowerInvariant()
                && (uri.Host == rp || uri.Host.EndsWith("." + rp, StringComparison.Ordinal)));
            using (var client = StrictJson(proof.ClientData))
            {
                var data = client.RootElement;
                Fields(data, ["type", "challenge", "origin"], ["crossOrigin"]);
                Require(data.GetProperty("type").GetString() == (registration ? "webauthn.create" : "webauthn.get")
                    && data.GetProperty("origin").GetString() == origin
                    && Decode(data.GetProperty("challenge"), 32).AsSpan().SequenceEqual(challenge));
                if (data.TryGetProperty("crossOrigin", out var cross)) Require(cross.ValueKind == JsonValueKind.False);
            }
            var verifier = new Fido2(new Fido2Configuration
            {
                RPID = rp,
                RPName = "AMDN",
                Origins = new HashSet<string> { origin },
                ChallengeSize = 32,
                Timeout = 120000,
                AllowCrossOriginRequests = false,
                BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Allowed,
                BackedUpCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Allowed
            }); // No metadata service, attestation URLs or network callbacks.
            if (registration)
            {
                var authData = AttestationData(proof.AuthenticatorOrAttestation);
                Require(authData.Length >= 55 && (authData[32] & 0xc0) == 0x40); // AT required, ED forbidden.
                var length = BinaryPrimitives.ReadUInt16BigEndian(authData.AsSpan(53, 2));
                Require(length is > 0 and <= 1023 && authData.Length > 55 + length
                    && authData.AsSpan(55, length).SequenceEqual(proof.Credential));
                // Bounded profile/normalization checks; Fido2 performs standard verification.
                var key = NormalizeKey(authData.AsMemory(55 + length));
                var options = verifier.RequestNewCredential(new RequestNewCredentialParams
                {
                    User = new Fido2User { Id = handle, Name = "AMDN device", DisplayName = "AMDN device" },
                    AuthenticatorSelection = new AuthenticatorSelection { UserVerification = UserVerificationRequirement.Required, ResidentKey = ResidentKeyRequirement.Discouraged },
                    AttestationPreference = AttestationConveyancePreference.None,
                    PubKeyCredParams = [new PubKeyCredParam(COSE.Algorithm.ES256)]
                });
                options.Challenge = challenge;
                var result = await verifier.MakeNewCredentialAsync(new MakeNewCredentialParams
                {
                    OriginalOptions = options,
                    AttestationResponse = new AuthenticatorAttestationRawResponse
                    {
                        Id = Encode(proof.Credential),
                        RawId = proof.Credential,
                        Type = PublicKeyCredentialType.PublicKey,
                        ClientExtensionResults = new AuthenticationExtensionsClientOutputs(),
                        Response = new AuthenticatorAttestationRawResponse.AttestationResponse
                        { ClientDataJson = proof.ClientData, AttestationObject = proof.AuthenticatorOrAttestation, Transports = [] }
                    },
                    // Database uniqueness at the final commit is authoritative and race-safe.
                    // This callback makes no early uniqueness/ownership assertion to the client.
                    IsCredentialIdUniqueToUserCallback = (_, _) => Task.FromResult(true)
                }, cancellationToken);
                Require(result.AttestationFormat == "none" && result.Id.AsSpan().SequenceEqual(proof.Credential)
                    && NormalizeKey(result.PublicKey).AsSpan().SequenceEqual(key));
                return new(result.Id, key, result.IsBackupEligible, result.IsBackedUp, result.SignCount);
            }
            var storedId = Hex(snapshot, "credential_id_hex");
            var storedKey = Hex(snapshot, "public_key_hex");
            Require(storedId.AsSpan().SequenceEqual(proof.Credential)
                && (proof.UserHandle is null || proof.UserHandle.AsSpan().SequenceEqual(handle)));
            Require(proof.AuthenticatorOrAttestation.Length == 37 && (proof.AuthenticatorOrAttestation[32] & 0xc0) == 0);
            _ = NormalizeKey(storedKey);
            var assertionOptions = verifier.GetAssertionOptions(new GetAssertionOptionsParams
            {
                AllowedCredentials = [new PublicKeyCredentialDescriptor(storedId)],
                UserVerification = UserVerificationRequirement.Required
            });
            assertionOptions.Challenge = challenge;
            var assertion = new AuthenticatorAssertionRawResponse
            {
                Id = Encode(proof.Credential),
                RawId = proof.Credential,
                Type = PublicKeyCredentialType.PublicKey,
                ClientExtensionResults = new AuthenticationExtensionsClientOutputs(),
                Response = new AuthenticatorAssertionRawResponse.AssertionResponse
                {
                    ClientDataJson = proof.ClientData,
                    AuthenticatorData = proof.AuthenticatorOrAttestation,
                    Signature = proof.Signature!,
                    UserHandle = proof.UserHandle
                }
            };
            var verified = await verifier.MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = assertion,
                OriginalOptions = assertionOptions,
                StoredPublicKey = storedKey,
                StoredSignatureCounter = snapshot.GetProperty("sign_count").GetUInt32(),
                IsUserHandleOwnerOfCredentialIdCallback = (args, _) => Task.FromResult(
                    args.CredentialId.AsSpan().SequenceEqual(storedId) && args.UserHandle.AsSpan().SequenceEqual(handle))
            }, cancellationToken);
            var parsed = AuthenticatorAssertionResponse.Parse(assertion).AuthenticatorData;
            Require(parsed.IsBackupEligible == snapshot.GetProperty("backup_eligible").GetBoolean());
            return new(storedId, storedKey, parsed.IsBackupEligible, parsed.IsBackedUp, verified.SignCount);
        }
        catch (Exception exception) when (exception is InvalidProofEncodingException or Fido2VerificationException
            or CborContentException or OverflowException or CryptographicException or JsonException or FormatException or ArgumentException or InvalidOperationException)
        {
            // Only this pure proof boundary is translated. Database/commit failures propagate.
            // Do not log raw exceptions: third-party messages can contain supplied proof data.
            return null;
        }
    }

    private static byte[] AttestationData(byte[] bytes)
    {
        var reader = new CborReader(bytes, CborConformanceMode.Strict);
        Require(reader.ReadStartMap() == 3);
        var keys = new HashSet<string>(StringComparer.Ordinal);
        byte[]? data = null;
        for (var index = 0; index < 3; index++)
        {
            var key = reader.ReadTextString(); Require(keys.Add(key));
            switch (key)
            {
                case "fmt": Require(reader.ReadTextString() == "none"); break;
                case "attStmt": Require(reader.ReadStartMap() == 0); reader.ReadEndMap(); break;
                case "authData": data = reader.ReadByteString(); Require(data.Length <= 4096); break;
                default: throw new InvalidProofEncodingException();
            }
        }
        reader.ReadEndMap(); Require(reader.BytesRemaining == 0 && data is not null);
        return data!;
    }

    // Only the selected public EC2/ES256/P-256 profile; canonical storage prevents
    // alternate CBOR encodings from evading retained-key uniqueness. No private d.
    private static byte[] NormalizeKey(ReadOnlyMemory<byte> bytes)
    {
        var reader = new CborReader(bytes, CborConformanceMode.Strict);
        Require(reader.ReadStartMap() == 5);
        var keys = new HashSet<int>(); byte[]? x = null; byte[]? y = null;
        for (var index = 0; index < 5; index++)
        {
            var key = reader.ReadInt32(); Require(keys.Add(key));
            switch (key)
            {
                case 1: Require(reader.ReadInt32() == 2); break;
                case 3: Require(reader.ReadInt32() == -7); break;
                case -1: Require(reader.ReadInt32() == 1); break;
                case -2: x = reader.ReadByteString(); Require(x.Length == 32); break;
                case -3: y = reader.ReadByteString(); Require(y.Length == 32); break;
                default: throw new InvalidProofEncodingException();
            }
        }
        reader.ReadEndMap(); Require(reader.BytesRemaining == 0 && x is not null && y is not null);
        // Platform crypto validates the public point; no custom curve/signature arithmetic.
        using var point = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } });
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(5);
        writer.WriteInt32(1); writer.WriteInt32(2); writer.WriteInt32(3); writer.WriteInt32(-7);
        writer.WriteInt32(-1); writer.WriteInt32(1); writer.WriteInt32(-2); writer.WriteByteString(x!);
        writer.WriteInt32(-3); writer.WriteByteString(y!); writer.WriteEndMap();
        return writer.Encode();
    }
    private static byte[] Hex(JsonElement element, string name) => Convert.FromHexString(element.GetProperty(name).GetString()!);
}
