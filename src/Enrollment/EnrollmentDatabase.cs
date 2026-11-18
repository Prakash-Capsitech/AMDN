using Npgsql;

namespace AMDN.Enrollment;

public static class EnrollmentDatabase
{
    public static NpgsqlDataSource Pool(string connectionString, int maximumPoolSize = 4)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumPoolSize, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maximumPoolSize, 20);
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
        if (!string.IsNullOrEmpty(settings.Options)) throw new ArgumentException("Enrollment startup options are not supported.", nameof(connectionString));
        var builder = new NpgsqlDataSourceBuilder(settings.ConnectionString);
        builder.UsePhysicalConnectionInitializer(_ => throw new NotSupportedException("Open enrollment connections asynchronously."), async connection =>
        {
            await using var check = new NpgsqlCommand("""
                SELECT NOT (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolreplication)
                  AND pg_has_role(current_user,'amdn_identity_enrollment','USAGE')
                  AND NOT EXISTS(SELECT FROM pg_roles WHERE rolname IN ('amdn_identity_enrollment','amdn_identity_ceremony_executor')
                    AND (rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolreplication))
                  AND NOT pg_has_role('amdn_identity_ceremony_executor','amdn_identity_owner','MEMBER')
                  AND NOT pg_has_role('amdn_identity_ceremony_executor','amdn_identity_provisioner','MEMBER')
                  AND NOT EXISTS(SELECT FROM unnest(ARRAY['amdn_identity_owner','amdn_identity_runtime','amdn_identity_provisioner','amdn_identity_ceremony_executor']) r WHERE pg_has_role(current_user,r,'MEMBER'))
                  AND NOT EXISTS(SELECT FROM pg_roles r WHERE (r.rolsuper OR r.rolbypassrls OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication) AND pg_has_role(current_user,r.oid,'MEMBER'))
                  AND NOT EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                    WHERE n.nspname IN ('amdn_identity','amdn_enrollment') AND c.relkind IN ('r','p','v','m','f')
                      AND (pg_has_role(current_user,c.relowner,'MEMBER')
                        OR has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                        OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
                  AND NOT has_schema_privilege(current_user,'amdn_identity','CREATE')
                  AND NOT has_schema_privilege(current_user,'amdn_enrollment','CREATE')
                  AND has_schema_privilege(current_user,'amdn_identity','USAGE')
                  AND has_schema_privilege(current_user,'amdn_enrollment','USAGE')
                  AND NOT EXISTS(SELECT FROM pg_proc p WHERE p.pronamespace='amdn_identity'::regnamespace AND has_function_privilege(current_user,p.oid,'EXECUTE'))
                  AND (SELECT count(*)=4 AND bool_and(p.prosecdef AND p.proowner='amdn_identity_ceremony_executor'::regrole
                    AND has_function_privilege(current_user,p.oid,'EXECUTE')) FROM pg_proc p WHERE p.pronamespace='amdn_enrollment'::regnamespace)
                FROM pg_roles WHERE rolname=current_user
                """, connection);
            if (await check.ExecuteScalarAsync() is not true)
                throw new InvalidOperationException("Enrollment credential violates the execute-only role boundary.");
        });
        return builder.Build();
    }
}
