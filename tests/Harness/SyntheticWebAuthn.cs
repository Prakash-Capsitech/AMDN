using System.Buffers.Binary;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AMDN.Harness.Tests;

// Standards fixture only. Private keys stay in memory; no authenticator or browser claims.
internal sealed class SyntheticWebAuthn : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    internal byte[] Id { get; private set; } = RandomNumberGenerator.GetBytes(32);
    internal void RotateId() => Id = RandomNumberGenerator.GetBytes(32);

    internal byte[] Response(byte[] challenge, bool registration, byte[]? handle = null, string scenario = "valid", uint counter = 0, bool chromiumMetadata = false, bool edgeMetadata = false)
    {
        var client = JsonSerializer.SerializeToUtf8Bytes(new
        {
            type = scenario == "wrong-type" ? "webauthn.other" : registration ? "webauthn.create" : "webauthn.get",
            challenge = Encode(scenario == "wrong-challenge" ? RandomNumberGenerator.GetBytes(32) : challenge),
            origin = scenario switch { "wrong-origin" => "https://foreign.invalid", "normalized-origin" => "https://ceremony.invalid:443", _ => "https://ceremony.invalid" },
            crossOrigin = scenario == "cross-origin"
        });
        if (scenario == "top-origin")
        {
            var json = JsonNode.Parse(client)!; json["topOrigin"] = "https://ceremony.invalid";
            client = JsonSerializer.SerializeToUtf8Bytes(json);
        }
        if (chromiumMetadata || edgeMetadata)
        {
            // Published Chromium client_data_json.cc value, independent of the verifier.
            var json = JsonNode.Parse(client)!;
            json["other_keys_can_be_added_here"] = edgeMetadata
                ? "do not compare clientDataJSON against a template. See https://permanently-removed.invalid/yabPex"
                : "do not compare clientDataJSON against a template. See https://goo.gl/yabPex";
            client = JsonSerializer.SerializeToUtf8Bytes(json);
        }
        byte flags = 0x05;
        if (scenario == "no-up") flags &= 0xfe;
        if (scenario == "no-uv") flags &= 0xfb;
        if (scenario == "backup-eligible") flags |= 0x18;
        if (scenario == "invalid-backup") flags |= 0x10;
        if (scenario == "extensions") flags |= 0x80;
        if (registration || scenario == "assertion-at") flags |= 0x40;
        var count = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(count, counter);
        byte[] auth = [.. SHA256.HashData(Encoding.UTF8.GetBytes(scenario == "wrong-rp" ? "foreign.invalid" : "ceremony.invalid")), flags, .. count];
        byte[] payload;
        if (registration)
        {
            var size = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(size, (ushort)Id.Length);
            var q = _key.ExportParameters(false).Q;
            var cose = new CborWriter(); cose.WriteStartMap(5);
            // Different ordering is legal and must normalize to the database format.
            cose.WriteInt32(-3); cose.WriteByteString(scenario == "invalid-point" ? new byte[32] : q.Y!);
            cose.WriteInt32(-2); cose.WriteByteString(scenario == "invalid-point" ? new byte[32] : q.X!);
            cose.WriteInt32(-1); cose.WriteInt64(scenario switch { "curve-overflow-positive" => 2147483648L, "curve-overflow-negative" => -2147483649L, "wrong-curve" => 2, _ => 1 });
            cose.WriteInt32(3); cose.WriteInt64(scenario switch { "algorithm-overflow-positive" => 2147483648L, "algorithm-overflow-negative" => -2147483649L, "wrong-algorithm" => -35, _ => -7 });
            cose.WriteInt64(scenario switch { "label-overflow-positive" => 2147483648L, "label-overflow-negative" => -2147483649L, _ => 1 });
            cose.WriteInt64(scenario switch { "kty-overflow-positive" => 2147483648L, "kty-overflow-negative" => -2147483649L, _ => 2 }); cose.WriteEndMap();
            auth = [.. auth, .. new byte[16], .. size, .. (scenario == "attested-id" ? RandomNumberGenerator.GetBytes(Id.Length) : Id), .. cose.Encode()];
            var attestation = new CborWriter(); attestation.WriteStartMap(3);
            attestation.WriteTextString("fmt"); attestation.WriteTextString(scenario == "packed" ? "packed" : "none");
            attestation.WriteTextString("attStmt"); attestation.WriteStartMap(0); attestation.WriteEndMap();
            attestation.WriteTextString("authData"); attestation.WriteByteString(auth); attestation.WriteEndMap();
            payload = attestation.Encode();
            if (scenario == "trailing-cbor") payload = [.. payload, 0];
            if (scenario == "bad-cbor") payload = [0xff, 0xff];
        }
        else payload = auth;
        using var rogue = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var signature = (scenario == "wrong-signature" ? rogue : _key).SignData([.. auth, .. SHA256.HashData(client)], HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        if (scenario == "tampered") payload[^1] ^= 1;
        var response = new JsonObject { ["clientDataJSON"] = Encode(client) };
        if (registration) response["attestationObject"] = Encode(payload);
        else
        {
            response["authenticatorData"] = Encode(payload); response["signature"] = Encode(signature);
            if (handle is not null) response["userHandle"] = Encode(scenario == "wrong-handle" ? RandomNumberGenerator.GetBytes(32) : handle);
        }
        var id = scenario == "wrong-id" ? RandomNumberGenerator.GetBytes(32) : Id;
        return JsonSerializer.SerializeToUtf8Bytes(new JsonObject
        {
            ["id"] = Encode(id),
            ["rawId"] = Encode(id),
            ["type"] = "public-key",
            ["clientExtensionResults"] = new JsonObject(),
            ["response"] = response
        });
    }
    internal static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    public void Dispose() => _key.Dispose();
}
