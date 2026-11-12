using Npgsql;

namespace AMDN.Infrastructure.Identity;

public static class IdentityDatabase
{
    public static NpgsqlDataSource RuntimePool(string connectionString, int maximumPoolSize = 20) =>
        Pool(connectionString, "amdn_identity_runtime", maximumPoolSize);

    // Separate credential and process boundary; never register this pool with the Gateway.
    public static NpgsqlDataSource ProvisioningPool(string connectionString, int maximumPoolSize = 4) =>
        Pool(connectionString, "amdn_identity_provisioner", maximumPoolSize);

    private static NpgsqlDataSource Pool(string connectionString, string role, int maximumPoolSize)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumPoolSize, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maximumPoolSize, 50);
        var settings = new NpgsqlConnectionStringBuilder(connectionString)
        {
            Pooling = true,
            MinPoolSize = 0,
            MaxPoolSize = maximumPoolSize,
            NoResetOnClose = false,
            Multiplexing = false,
            Enlist = false,
            Timeout = 5,
            CommandTimeout = 5,
            IncludeErrorDetail = false,
            LogParameters = false
        };
        // Startup options could alter role or session context before the guard runs.
        if (!string.IsNullOrEmpty(settings.Options)) throw new ArgumentException("Database startup options are not supported.", nameof(connectionString));
        var builder = new NpgsqlDataSourceBuilder(settings.ConnectionString);
        builder.UsePhysicalConnectionInitializer(
            _ => throw new NotSupportedException("Identity database connections must be opened asynchronously."),
            async connection =>
            {
                await using var check = new NpgsqlCommand("""
                    SELECT NOT (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolreplication)
                      AND pg_has_role(current_user,@role,'USAGE')
                      AND NOT pg_has_role(current_user,'amdn_identity_owner','MEMBER')
                      AND (@role='amdn_identity_provisioner' OR NOT pg_has_role(current_user,'amdn_identity_provisioner','MEMBER'))
                      AND NOT EXISTS (SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                        WHERE n.nspname='amdn_identity' AND pg_has_role(current_user,c.relowner,'MEMBER'))
                    FROM pg_roles WHERE rolname=current_user
                    """, connection);
                check.Parameters.AddWithValue("role", role);
                if (await check.ExecuteScalarAsync() is not true)
                    throw new InvalidOperationException("Identity database credential violates the configured role boundary.");
            });
        return builder.Build();
    }
}
