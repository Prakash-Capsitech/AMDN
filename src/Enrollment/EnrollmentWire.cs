using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AMDN.Enrollment;

// Explicit wire projection: never serialize an internal SQL/verifier snapshot.
internal static class EnrollmentWire
{
    internal static JsonObject Project(JsonElement value)
    {
        var state = value.GetProperty("state").GetString();
        var result = new JsonObject
        {
            ["ceremony_id"] = value.GetProperty("ceremony_id").GetGuid().ToString("D"),
            ["profile"] = EnrollmentHttp.Profile,
            ["device_id"] = value.GetProperty("device_id").GetGuid().ToString("D")
        };
        if (state == "completed")
        {
            var lifecycle = value.GetProperty("current_lifecycle");
            var status = lifecycle.GetProperty("status").GetString();
            if (status is not ("credential_active" or "revoked")) throw new InvalidOperationException("Invalid lifecycle snapshot.");
            result["state"] = "completed";
            result["completed_at"] = Utc(value, "completed_at");
            result["committed_identity_version"] = value.GetProperty("committed_identity_version").GetInt64();
            result["messaging_ready"] = false;
            result["current_lifecycle"] = new JsonObject
            {
                ["status"] = status,
                ["identity_version"] = lifecycle.GetProperty("identity_version").GetInt64(),
                ["observed_at"] = Utc(lifecycle, "observed_at")
            };
            return result;
        }
        result["state"] = state switch
        {
            "registration" => "awaiting_registration",
            "candidate" => "awaiting_candidate_proof",
            "current" => "awaiting_current_proof",
            "revocation" => "awaiting_revocation_proof",
            _ => throw new InvalidOperationException("Invalid ceremony state.")
        };
        result["expires_at"] = Utc(value, "expires_at");
        result["challenge_expires_at"] = Utc(value, "challenge_expires_at");
        var descriptors = new JsonArray();
        if (value.GetProperty("option_credential_id_hex").ValueKind != JsonValueKind.Null)
            descriptors.Add(new JsonObject { ["type"] = "public-key", ["id"] = Encoded(value, "option_credential_id_hex") });
        var options = new JsonObject { ["challenge"] = Encoded(value, "challenge_hex"), ["timeout"] = 120000 };
        if (state == "registration")
        {
            var label = "device_" + value.GetProperty("device_id").GetGuid().ToString("N");
            options["rp"] = new JsonObject { ["id"] = value.GetProperty("rp_id").GetString(), ["name"] = "AMDN" };
            options["user"] = new JsonObject { ["id"] = Encoded(value, "user_handle_hex"), ["name"] = label, ["displayName"] = label };
            options["pubKeyCredParams"] = new JsonArray(new JsonObject { ["type"] = "public-key", ["alg"] = -7 });
            options["excludeCredentials"] = descriptors;
            options["authenticatorSelection"] = new JsonObject { ["residentKey"] = "discouraged", ["userVerification"] = "required" };
            options["attestation"] = "none";
        }
        else
        {
            if (descriptors.Count != 1) throw new InvalidOperationException("Missing allowed credential.");
            options["rpId"] = value.GetProperty("rp_id").GetString();
            options["allowCredentials"] = descriptors;
            options["userVerification"] = "required";
        }
        result["public_key"] = options;
        return result;
    }
    private static string Encoded(JsonElement value, string name) => ProofRequest.Encode(Convert.FromHexString(value.GetProperty(name).GetString()!));
    private static string Utc(JsonElement value, string name) => value.GetProperty(name).GetDateTimeOffset().UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
}
