CREATE TABLE amdn_identity.tenants (
  tenant_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','revoked')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE amdn_identity.users (
  tenant_id uuid NOT NULL REFERENCES amdn_identity.tenants,
  user_id uuid NOT NULL DEFAULT gen_random_uuid(),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','revoked')),
  identity_version bigint NOT NULL DEFAULT 1 CHECK (identity_version > 0),
  PRIMARY KEY (tenant_id,user_id)
);
CREATE TABLE amdn_identity.memberships (
  tenant_id uuid NOT NULL, user_id uuid NOT NULL,
  issuer text COLLATE "C" NOT NULL CHECK (length(issuer) BETWEEN 1 AND 2048),
  subject text COLLATE "C" NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','revoked')),
  membership_version bigint NOT NULL DEFAULT 1 CHECK (membership_version > 0),
  PRIMARY KEY (tenant_id,issuer,subject), UNIQUE (tenant_id,user_id),
  FOREIGN KEY (tenant_id,user_id) REFERENCES amdn_identity.users
);
CREATE TABLE amdn_identity.postmen (
  tenant_id uuid NOT NULL, postman_id uuid NOT NULL DEFAULT gen_random_uuid(), owner_user_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','revoked')),
  policy_version bigint NOT NULL DEFAULT 1 CHECK (policy_version > 0),
  PRIMARY KEY (tenant_id,postman_id), UNIQUE (tenant_id,owner_user_id),
  FOREIGN KEY (tenant_id,owner_user_id) REFERENCES amdn_identity.users
);
CREATE INDEX memberships_external_identity ON amdn_identity.memberships(issuer,subject);

CREATE FUNCTION amdn_identity.preserve_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $body$
BEGIN
  IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id THEN RAISE EXCEPTION 'Identity is immutable' USING ERRCODE='23514'; END IF;
  IF TG_TABLE_NAME='users' THEN
    IF OLD.user_id IS DISTINCT FROM NEW.user_id THEN RAISE EXCEPTION 'Identity is immutable' USING ERRCODE='23514'; END IF;
    NEW.identity_version := OLD.identity_version + CASE WHEN OLD.status<>NEW.status THEN 1 ELSE 0 END;
  ELSIF TG_TABLE_NAME='memberships' THEN
    IF ROW(OLD.user_id,OLD.issuer,OLD.subject) IS DISTINCT FROM ROW(NEW.user_id,NEW.issuer,NEW.subject) THEN
      RAISE EXCEPTION 'Identity binding is immutable' USING ERRCODE='23514';
    END IF;
    NEW.membership_version := OLD.membership_version + CASE WHEN OLD.status<>NEW.status THEN 1 ELSE 0 END;
  ELSIF TG_TABLE_NAME='postmen' THEN
    IF ROW(OLD.postman_id,OLD.owner_user_id) IS DISTINCT FROM ROW(NEW.postman_id,NEW.owner_user_id) THEN
      RAISE EXCEPTION 'Identity binding is immutable' USING ERRCODE='23514';
    END IF;
    NEW.policy_version := OLD.policy_version + CASE WHEN OLD.status<>NEW.status THEN 1 ELSE 0 END;
  END IF;
  IF OLD.status='revoked' AND NEW.status<>'revoked' THEN RAISE EXCEPTION 'Revocation is terminal' USING ERRCODE='23514'; END IF;
  RETURN NEW;
END $body$;

-- Only the trusted migration owner can bypass scoped policies, by explicit policy,
-- not by SUPERUSER/BYPASSRLS. Definer functions below expose a fixed narrow query.
DO $tables$
DECLARE tab text;
BEGIN
  FOREACH tab IN ARRAY ARRAY['tenants','users','memberships','postmen'] LOOP
    EXECUTE format('ALTER TABLE amdn_identity.%I ENABLE ROW LEVEL SECURITY',tab);
    EXECUTE format('ALTER TABLE amdn_identity.%I FORCE ROW LEVEL SECURITY',tab);
    EXECUTE format('CREATE POLICY owner_access ON amdn_identity.%I TO amdn_identity_owner USING (true) WITH CHECK (true)',tab);
    EXECUTE format('CREATE POLICY provisioning_access ON amdn_identity.%I TO amdn_identity_provisioner USING (true) WITH CHECK (true)',tab);
    EXECUTE format('CREATE TRIGGER preserve_identity BEFORE UPDATE ON amdn_identity.%I FOR EACH ROW EXECUTE FUNCTION amdn_identity.preserve_identity()',tab);
  END LOOP;
END $tables$;

CREATE FUNCTION amdn_identity.active_context(p_tenant uuid,p_user uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $body$
  SELECT p_tenant=nullif(current_setting('amdn.tenant_id',true),'')::uuid
    AND p_user=nullif(current_setting('amdn.user_id',true),'')::uuid
    AND EXISTS (
      SELECT FROM amdn_identity.memberships m
      JOIN amdn_identity.users u USING (tenant_id,user_id)
      JOIN amdn_identity.tenants t USING (tenant_id)
      WHERE m.tenant_id=p_tenant AND m.user_id=p_user AND m.status='active' AND u.status='active' AND t.status='active'
        AND m.issuer=current_setting('amdn.issuer',true) AND m.subject=current_setting('amdn.subject',true));
$body$;
CREATE POLICY runtime_scope ON amdn_identity.tenants FOR SELECT TO amdn_identity_runtime
  USING (amdn_identity.active_context(tenant_id,nullif(current_setting('amdn.user_id',true),'')::uuid));
CREATE POLICY runtime_scope ON amdn_identity.users FOR SELECT TO amdn_identity_runtime
  USING (amdn_identity.active_context(tenant_id,user_id));
CREATE POLICY runtime_scope ON amdn_identity.memberships FOR SELECT TO amdn_identity_runtime
  USING (amdn_identity.active_context(tenant_id,user_id));
CREATE POLICY runtime_scope ON amdn_identity.postmen FOR SELECT TO amdn_identity_runtime
  USING (status='active' AND amdn_identity.active_context(tenant_id,owner_user_id));

-- A selection is only a filter: issuer/subject and all active states still bind it.
-- Return at most two so the application can fail closed on ambiguous membership.
-- Row locks serialize suspension/revocation with this transaction's read.
CREATE FUNCTION amdn_identity.resolve_membership(p_issuer text,p_subject text,p_selected uuid)
RETURNS TABLE(tenant_id uuid,user_id uuid,postman_id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $body$
  SELECT m.tenant_id,m.user_id,p.postman_id FROM amdn_identity.memberships m
  JOIN amdn_identity.users u USING (tenant_id,user_id)
  JOIN amdn_identity.tenants t USING (tenant_id)
  JOIN amdn_identity.postmen p ON p.tenant_id=m.tenant_id AND p.owner_user_id=m.user_id
  WHERE m.issuer=p_issuer AND m.subject=p_subject
    AND (p_selected IS NULL OR m.tenant_id=p_selected)
    AND m.status='active' AND u.status='active' AND t.status='active' AND p.status='active'
  ORDER BY m.tenant_id LIMIT 2 FOR SHARE OF t,u,m,p;
$body$;

REVOKE ALL ON ALL TABLES IN SCHEMA amdn_identity FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA amdn_identity FROM PUBLIC;
GRANT USAGE ON SCHEMA amdn_identity TO amdn_identity_runtime,amdn_identity_provisioner;
GRANT SELECT ON amdn_identity.tenants,amdn_identity.users,amdn_identity.memberships,amdn_identity.postmen TO amdn_identity_runtime;
GRANT SELECT,INSERT ON amdn_identity.tenants,amdn_identity.users,amdn_identity.memberships,amdn_identity.postmen TO amdn_identity_provisioner;
GRANT UPDATE(status) ON amdn_identity.tenants,amdn_identity.users,amdn_identity.memberships,amdn_identity.postmen TO amdn_identity_provisioner;
GRANT EXECUTE ON FUNCTION amdn_identity.active_context(uuid,uuid),amdn_identity.resolve_membership(text,text,uuid) TO amdn_identity_runtime;
