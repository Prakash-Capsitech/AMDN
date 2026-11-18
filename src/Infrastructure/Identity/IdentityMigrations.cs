using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace AMDN.Infrastructure.Identity;

// Explicit deployment operation. Never called automatically by a request or Gateway startup.
public static class IdentityMigrations
{
    public static async Task ApplyAsync(string migrationConnectionString, CancellationToken cancellationToken = default)
    {
        await using var connection = new NpgsqlConnection(migrationConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken);
        await using var setup = new NpgsqlCommand("""
            SET LOCAL ROLE amdn_identity_owner;
            SELECT pg_advisory_xact_lock(18641002);
            CREATE SCHEMA IF NOT EXISTS amdn_identity AUTHORIZATION amdn_identity_owner;
            CREATE TABLE IF NOT EXISTS amdn_identity.schema_migrations (version integer PRIMARY KEY, checksum text NOT NULL);
            """, connection, transaction);
        await setup.ExecuteNonQueryAsync(cancellationToken);
        for (var number = 1; number <= 6; number++)
        {
            using var reader = new StreamReader(typeof(IdentityMigrations).Assembly.GetManifestResourceStream($"Identity.{number:000}.sql")!);
            var sql = await reader.ReadToEndAsync(cancellationToken);
            var checksum = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sql)));
            await using var version = new NpgsqlCommand("SELECT checksum FROM amdn_identity.schema_migrations WHERE version=@version", connection, transaction);
            version.Parameters.AddWithValue("version", number);
            var previous = await version.ExecuteScalarAsync(cancellationToken);
            if (previous is not null && !string.Equals((string)previous, checksum, StringComparison.Ordinal))
                throw new InvalidOperationException("Identity migration checksum mismatch; applied migrations must not be edited.");
            if (previous is null)
            {
                await using var migration = new NpgsqlCommand(sql, connection, transaction);
                await migration.ExecuteNonQueryAsync(cancellationToken);
                await using var record = new NpgsqlCommand("INSERT INTO amdn_identity.schema_migrations VALUES (@version,@checksum)", connection, transaction);
                record.Parameters.AddWithValue("version", number);
                record.Parameters.AddWithValue("checksum", checksum);
                await record.ExecuteNonQueryAsync(cancellationToken);
            }
        }
        await transaction.CommitAsync(cancellationToken);
    }
}
