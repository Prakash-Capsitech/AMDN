using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;

namespace AMDN.Enrollment;

// No host registration or HTTP routes. Production callers must use the guarded
// EnrollmentDatabase pool and a principal minted by EnrollmentPrincipalMapper.
public sealed class EnrollmentCommands(NpgsqlDataSource database)
{
    public async Task<JsonElement> BeginAsync(EnrollmentPrincipal principal, string operation, long expectedVersion,
        Guid? target, string idempotencyKey, ReadOnlyMemory<byte> body, CancellationToken cancellationToken = default)
    {
        if (System.Transactions.Transaction.Current is not null) throw new InvalidOperationException("Independent transactions required.");
        if (body.Length is < 1 or > 65536) return JsonSerializer.SerializeToElement(new { outcome = "invalid_request" });
        var bytes = body.ToArray();
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        var answer = await CeremonyVerifier.Call(connection, principal.Actor, "begin", "@operation,@expected,@target,@key,@body,@challenge,@handle", cancellationToken,
            ("operation", operation), ("expected", expectedVersion), ("target", target), ("key", idempotencyKey), ("body", bytes),
            ("challenge", RandomNumberGenerator.GetBytes(32)), ("handle", RandomNumberGenerator.GetBytes(32)));
        await transaction.CommitAsync(cancellationToken);
        return answer;
    }

    public Task<JsonElement> CompleteAsync(EnrollmentPrincipal principal, Guid ceremonyId, string stage, string idempotencyKey,
        ReadOnlyMemory<byte> body, CancellationToken cancellationToken = default) =>
        new CeremonyVerifier(async ct => await database.OpenConnectionAsync(ct)).CompleteAsync(principal.Actor, ceremonyId, stage, idempotencyKey, body, cancellationToken);
}
