-- Administrator-only role bootstrap; rerun before new role-dependent migrations.
-- No login/password is installed here.
DO $roles$
DECLARE role_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY['amdn_identity_owner','amdn_identity_runtime','amdn_identity_provisioner',
      'amdn_identity_enrollment','amdn_identity_ceremony_executor'] LOOP
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname=role_name) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION', role_name);
    END IF;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname=role_name AND
        (rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolreplication)) THEN
      RAISE EXCEPTION 'Identity group roles must remain non-login and unprivileged';
    END IF;
  END LOOP;
  IF pg_has_role('amdn_identity_runtime','amdn_identity_owner','MEMBER')
    OR pg_has_role('amdn_identity_runtime','amdn_identity_provisioner','MEMBER')
    OR pg_has_role('amdn_identity_provisioner','amdn_identity_owner','MEMBER') THEN
    RAISE EXCEPTION 'Identity role boundaries overlap';
  END IF;
  IF EXISTS (
    SELECT FROM unnest(ARRAY['amdn_identity_runtime','amdn_identity_provisioner','amdn_identity_enrollment','amdn_identity_ceremony_executor']) a
    CROSS JOIN unnest(ARRAY['amdn_identity_owner','amdn_identity_runtime','amdn_identity_provisioner','amdn_identity_enrollment','amdn_identity_ceremony_executor']) b
    WHERE a<>b AND pg_has_role(a,b,'MEMBER')) THEN
    RAISE EXCEPTION 'Application and ceremony executor roles must not overlap';
  END IF;
END $roles$;
-- Only the administrator-controlled migration owner may transfer function ownership.
-- It does not inherit executor privileges; no application login gets this membership.
GRANT amdn_identity_ceremony_executor TO amdn_identity_owner WITH INHERIT FALSE, SET TRUE;
