-- Administrator-only, one-time role bootstrap. No login/password is installed here.
DO $roles$
DECLARE role_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY['amdn_identity_owner','amdn_identity_runtime','amdn_identity_provisioner'] LOOP
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
END $roles$;
