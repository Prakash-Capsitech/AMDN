using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;
using NpgsqlTypes;

namespace AMDN.Enrollment;

// Internal-service integration seam. The connection factory is trusted infrastructure,
// never caller input. No role switch, host registration or application grant is added.
public sealed class CeremonyVerifier(Func<CancellationToken, Task<NpgsqlConnection>> openConnection)
{
    private const string ActorSql = "ROW(@tenant,@issuer,@subject,@client,@origin,@config,@scope,@acr,@auth_time,@token_exp)::amdn_identity.ceremony_actor";

    public async Task<JsonElement> CompleteAsync(CeremonyActor actor, Guid ceremonyId, string stage,
        string idempotencyKey, ReadOnlyMemory<byte> request, CancellationToken cancellationToken = default)
    {
        // No ambient transaction may undo a reservation or retain locks during crypto.
        if (System.Transactions.Transaction.Current is not null)
            throw new InvalidOperationException("Ceremony verification requires independent transactions.");
        if (stage is not ("registration" or "candidate" or "current" or "revocation") || request.Length is < 1 or > 65536)
            return Outcome("invalid_request");
        var bytes = request.ToArray(); // Stable private copy for parsing, digest and reservation.
        ProofRequest proof;
        try { proof = ProofRequest.Parse(bytes, stage == "registration"); }
        catch (InvalidProofEncodingException) { return Outcome("invalid_request"); }

        JsonElement reservation;
        bool needsChallenge = false;
        await using (var connection = await openConnection(cancellationToken))
        await using (var transaction = await connection.BeginTransactionAsync(cancellationToken))
        {
            reservation = await Call(connection, actor, "ceremony_reserve", "@id,@stage,@key,@body", cancellationToken,
                ("id", ceremonyId), ("stage", stage), ("key", idempotencyKey), ("body", bytes));
            if (reservation.GetProperty("outcome").GetString() == "reserved")
            {
                await using var command = new NpgsqlCommand("SELECT operation FROM amdn_identity.device_ceremonies WHERE ceremony_id=@id", connection);
                command.Parameters.AddWithValue("id", ceremonyId);
                var operation = (string)(await command.ExecuteScalarAsync(cancellationToken))!;
                needsChallenge = stage == "registration" || (stage == "candidate" && operation == "replacement");
            }
            await transaction.CommitAsync(cancellationToken);
        }
        if (reservation.GetProperty("outcome").GetString() != "reserved") return reservation;
        var digest = SHA256.HashData(bytes);
        if (!CryptographicOperations.FixedTimeEquals(digest, Convert.FromHexString(reservation.GetProperty("request_digest_hex").GetString()!)))
            throw new InvalidOperationException("Reservation digest mismatch.");
        var attempt = reservation.GetProperty("attempt_id").GetGuid();
        // Neither connection nor database transaction is held during verification.
        var verified = await WebAuthnProof.VerifyAsync(proof, reservation, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested(); // Interrupted reservations remain durable.
        await using var finishConnection = await openConnection(cancellationToken);
        await using var finishTransaction = await finishConnection.BeginTransactionAsync(cancellationToken);
        JsonElement result;
        if (verified is null)
            result = await Call(finishConnection, actor, "ceremony_fail", "@attempt,@digest", cancellationToken,
                ("attempt", attempt), ("digest", digest));
        else
            result = await Call(finishConnection, actor, "ceremony_finish", "@attempt,@digest,@credential,@publickey,@be,@bs,@counter,@next", cancellationToken,
                ("attempt", attempt), ("digest", digest), ("credential", verified.Credential), ("publickey", verified.PublicKey),
                ("be", verified.BackupEligible), ("bs", verified.BackedUp), ("counter", (long)verified.Counter),
                ("next", needsChallenge ? RandomNumberGenerator.GetBytes(32) : null));
        await finishTransaction.CommitAsync(cancellationToken);
        return result;
    }

    private static async Task<JsonElement> Call(NpgsqlConnection connection, CeremonyActor actor, string function,
        string arguments, CancellationToken cancellationToken, params (string Name, object? Value)[] values)
    {
        await using var command = new NpgsqlCommand($"SELECT amdn_identity.{function}({ActorSql},{arguments})", connection);
        foreach (var (name, value) in new (string, object)[] {
            ("tenant", actor.TenantId), ("issuer", actor.Issuer), ("subject", actor.Subject), ("client", actor.ClientId),
            ("origin", actor.Origin), ("config", actor.ConfigurationId), ("scope", actor.Scope), ("acr", actor.Acr),
            ("auth_time", actor.AuthTime), ("token_exp", actor.TokenExpiry) }) command.Parameters.AddWithValue(name, value);
        foreach (var (name, value) in values)
        {
            if (value is null) command.Parameters.Add(new NpgsqlParameter(name, NpgsqlDbType.Bytea) { Value = DBNull.Value });
            else command.Parameters.AddWithValue(name, value);
        }
        using var json = JsonDocument.Parse((string)(await command.ExecuteScalarAsync(cancellationToken))!);
        return json.RootElement.Clone();
    }
    private static JsonElement Outcome(string outcome) => JsonSerializer.SerializeToElement(new { outcome });
}
