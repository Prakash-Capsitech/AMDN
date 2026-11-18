using System.Text;
using System.Text.Json;

namespace AMDN.Enrollment;

internal class InvalidProofEncodingException : Exception;
internal sealed class ProofTooLargeException : InvalidProofEncodingException;

internal sealed record ProofRequest(byte[] Credential, byte[] ClientData, byte[] AuthenticatorOrAttestation,
    byte[]? Signature, byte[]? UserHandle)
{
    internal static ProofRequest Parse(byte[] bytes, bool registration)
    {
        try
        {
            using var document = StrictJson(bytes);
            var root = document.RootElement;
            Fields(root, ["id", "rawId", "type", "clientExtensionResults", "response"]);
            var id = Decode(root.GetProperty("id"), 1023);
            Require(id.AsSpan().SequenceEqual(Decode(root.GetProperty("rawId"), 1023)));
            Require(root.GetProperty("type").GetString() == "public-key");
            Fields(root.GetProperty("clientExtensionResults"), []);
            var response = root.GetProperty("response");
            Fields(response, registration ? ["clientDataJSON", "attestationObject"] : ["clientDataJSON", "authenticatorData", "signature"],
                registration ? [] : ["userHandle"]);
            var client = Decode(response.GetProperty("clientDataJSON"), 8192);
            // Structural JSON failure is rejected before reserving a verification slot.
            using var clientJson = StrictJson(client);
            Require(clientJson.RootElement.ValueKind == JsonValueKind.Object);
            byte[]? handle = null;
            if (!registration && response.TryGetProperty("userHandle", out var supplied) && supplied.ValueKind != JsonValueKind.Null)
            {
                handle = Decode(supplied, 32); Require(handle.Length == 32);
            }
            return new(id, client, Decode(response.GetProperty(registration ? "attestationObject" : "authenticatorData"), registration ? 16384 : 4096),
                registration ? null : Decode(response.GetProperty("signature"), 1024), handle);
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or FormatException or KeyNotFoundException or DecoderFallbackException)
        { throw new InvalidProofEncodingException(); }
    }

    internal static JsonDocument StrictJson(byte[] bytes)
    {
        // JsonDocument otherwise permits replacement of invalid UTF-8 when reading strings.
        _ = new UTF8Encoding(false, true).GetCharCount(bytes);
        var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 16 });
        try { UniqueNames(document.RootElement); return document; }
        catch { document.Dispose(); throw; }
    }
    private static void UniqueNames(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject()) { Require(names.Add(property.Name)); UniqueNames(property.Value); }
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var element in value.EnumerateArray()) UniqueNames(element);
    }
    internal static void Fields(JsonElement value, string[] required, string[]? optional = null)
    {
        Require(value.ValueKind == JsonValueKind.Object);
        foreach (var name in required) Require(value.TryGetProperty(name, out _));
        foreach (var property in value.EnumerateObject())
            Require(required.Contains(property.Name, StringComparer.Ordinal) || (optional?.Contains(property.Name, StringComparer.Ordinal) ?? false));
    }
    internal static byte[] Decode(JsonElement element, int max)
    {
        Require(element.ValueKind == JsonValueKind.String);
        var text = element.GetString()!;
        if (text.Length > (max * 8 + 5) / 6) throw new ProofTooLargeException();
        Require(text.Length > 0 && text.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'));
        var bytes = Convert.FromBase64String(text.Replace('-', '+').Replace('_', '/') + new string('=', (4 - text.Length % 4) % 4));
        if (bytes.Length > max) throw new ProofTooLargeException();
        Require(bytes.Length > 0 && Encode(bytes) == text);
        return bytes;
    }
    internal static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    internal static void Require(bool condition) { if (!condition) throw new InvalidProofEncodingException(); }
}
