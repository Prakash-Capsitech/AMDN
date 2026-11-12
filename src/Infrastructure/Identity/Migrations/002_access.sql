-- Never edit applied migration 001. F1.3 introduces explicit grants and audit.
ALTER TABLE amdn_identity.tenants ADD COLUMN display_name text NOT NULL DEFAULT '' CHECK(length(display_name)<=100);
ALTER TABLE amdn_identity.tenants ADD COLUMN member_limit integer NOT NULL DEFAULT 1 CHECK(member_limit BETWEEN 1 AND 10000);
ALTER TABLE amdn_identity.postmen ADD COLUMN receive_enabled boolean NOT NULL DEFAULT true;
ALTER TABLE amdn_identity.postmen ADD COLUMN dispatch_enabled boolean NOT NULL DEFAULT true;
ALTER TABLE amdn_identity.postmen ADD COLUMN retry_enabled boolean NOT NULL DEFAULT true;

CREATE TABLE amdn_identity.owner_grants (
  tenant_id uuid NOT NULL, postman_id uuid NOT NULL,
  action text NOT NULL CHECK(action='postman.read'),
  status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
  expires_at timestamptz,
  version bigint NOT NULL DEFAULT 1 CHECK(version>0),
  PRIMARY KEY(tenant_id,postman_id,action),
  FOREIGN KEY(tenant_id,postman_id) REFERENCES amdn_identity.postmen
);
INSERT INTO amdn_identity.owner_grants(tenant_id,postman_id,action)
  SELECT tenant_id,postman_id,'postman.read' FROM amdn_identity.postmen WHERE status='active';

CREATE TABLE amdn_identity.platform_grants (
  actor_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  issuer text COLLATE "C" NOT NULL CHECK(length(issuer) BETWEEN 1 AND 2048),
  subject text COLLATE "C" NOT NULL CHECK(length(subject) BETWEEN 1 AND 255),
  status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
  expires_at timestamptz NOT NULL,
  tenant_limit integer NOT NULL CHECK(tenant_limit BETWEEN 1 AND 10000),
  allocated_tenants integer NOT NULL DEFAULT 0 CHECK(allocated_tenants>=0 AND allocated_tenants<=tenant_limit),
  version bigint NOT NULL DEFAULT 1 CHECK(version>0),
  UNIQUE(issuer,subject)
);
ALTER TABLE amdn_identity.tenants ADD COLUMN provisioner_actor uuid REFERENCES amdn_identity.platform_grants;
CREATE TABLE amdn_identity.provisioning_commands (
  actor_id uuid NOT NULL REFERENCES amdn_identity.platform_grants,
  operation text NOT NULL CHECK(operation IN ('tenant.provision','membership.provision')),
  idempotency_key text COLLATE "C" NOT NULL CHECK(length(idempotency_key) BETWEEN 16 AND 128),
  digest bytea NOT NULL CHECK(octet_length(digest)=32),
  tenant_id uuid NOT NULL REFERENCES amdn_identity.tenants,
  user_id uuid, postman_id uuid,
  PRIMARY KEY(actor_id,operation,idempotency_key),
  FOREIGN KEY(tenant_id,user_id) REFERENCES amdn_identity.users,
  FOREIGN KEY(tenant_id,postman_id) REFERENCES amdn_identity.postmen
);
CREATE TABLE amdn_identity.provisioning_audit (
  audit_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id uuid NOT NULL REFERENCES amdn_identity.platform_grants,
  tenant_id uuid NOT NULL REFERENCES amdn_identity.tenants,
  user_id uuid, postman_id uuid,
  action text NOT NULL CHECK(action IN ('tenant.provision','membership.provision')),
  grant_version bigint NOT NULL CHECK(grant_version>0),
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY(tenant_id,user_id) REFERENCES amdn_identity.users,
  FOREIGN KEY(tenant_id,postman_id) REFERENCES amdn_identity.postmen
);

DO $tables$
DECLARE tab text;
BEGIN
  FOREACH tab IN ARRAY ARRAY['owner_grants','platform_grants','provisioning_commands','provisioning_audit'] LOOP
    EXECUTE format('ALTER TABLE amdn_identity.%I ENABLE ROW LEVEL SECURITY',tab);
    EXECUTE format('ALTER TABLE amdn_identity.%I FORCE ROW LEVEL SECURITY',tab);
    EXECUTE format('CREATE POLICY owner_access ON amdn_identity.%I TO amdn_identity_owner USING(true) WITH CHECK(true)',tab);
    EXECUTE format('CREATE POLICY provisioning_access ON amdn_identity.%I TO amdn_identity_provisioner USING(true) WITH CHECK(true)',tab);
  END LOOP;
END $tables$;
CREATE POLICY runtime_scope ON amdn_identity.owner_grants FOR SELECT TO amdn_identity_runtime
 USING(EXISTS(SELECT FROM amdn_identity.postmen p WHERE p.tenant_id=owner_grants.tenant_id AND p.postman_id=owner_grants.postman_id));

CREATE FUNCTION amdn_identity.lock_owner_grant(p_tenant uuid,p_user uuid,p_postman uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $body$
BEGIN
  IF NOT coalesce(amdn_identity.active_context(p_tenant,p_user),false) THEN RETURN false; END IF;
  PERFORM FROM amdn_identity.owner_grants g JOIN amdn_identity.postmen p USING(tenant_id,postman_id)
    WHERE g.tenant_id=p_tenant AND g.postman_id=p_postman AND p.owner_user_id=p_user
      AND p.status='active' AND g.action='postman.read' AND g.status='active'
      AND (g.expires_at IS NULL OR g.expires_at>clock_timestamp()) FOR SHARE OF g;
  IF NOT FOUND THEN RETURN false; END IF;
  RETURN EXISTS(SELECT FROM amdn_identity.owner_grants WHERE tenant_id=p_tenant AND postman_id=p_postman
    AND action='postman.read' AND status='active' AND (expires_at IS NULL OR expires_at>clock_timestamp()));
END $body$;

CREATE FUNCTION amdn_identity.preserve_access() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $body$
BEGIN
  IF TG_TABLE_NAME='platform_grants' THEN
    IF ROW(NEW.actor_id,NEW.issuer,NEW.subject) IS DISTINCT FROM ROW(OLD.actor_id,OLD.issuer,OLD.subject) THEN
      RAISE EXCEPTION 'Platform binding is immutable' USING ERRCODE='23514';
    END IF;
    NEW.version := OLD.version + CASE WHEN ROW(OLD.status,OLD.expires_at,OLD.tenant_limit) IS DISTINCT FROM ROW(NEW.status,NEW.expires_at,NEW.tenant_limit) THEN 1 ELSE 0 END;
  ELSE
    IF ROW(NEW.tenant_id,NEW.postman_id,NEW.action) IS DISTINCT FROM ROW(OLD.tenant_id,OLD.postman_id,OLD.action) THEN
      RAISE EXCEPTION 'Owner grant is immutable' USING ERRCODE='23514';
    END IF;
    NEW.version := OLD.version + CASE WHEN ROW(OLD.status,OLD.expires_at) IS DISTINCT FROM ROW(NEW.status,NEW.expires_at) THEN 1 ELSE 0 END;
  END IF;
  IF OLD.status='revoked' AND NEW.status<>'revoked' THEN RAISE EXCEPTION 'Revocation is terminal' USING ERRCODE='23514'; END IF;
  RETURN NEW;
END $body$;
CREATE TRIGGER preserve_access BEFORE UPDATE ON amdn_identity.platform_grants FOR EACH ROW EXECUTE FUNCTION amdn_identity.preserve_access();
CREATE TRIGGER preserve_access BEFORE UPDATE ON amdn_identity.owner_grants FOR EACH ROW EXECUTE FUNCTION amdn_identity.preserve_access();
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA amdn_identity FROM PUBLIC;
REVOKE ALL ON amdn_identity.owner_grants,amdn_identity.platform_grants,amdn_identity.provisioning_commands,amdn_identity.provisioning_audit FROM PUBLIC;
GRANT SELECT ON amdn_identity.owner_grants TO amdn_identity_runtime;
GRANT EXECUTE ON FUNCTION amdn_identity.lock_owner_grant(uuid,uuid,uuid) TO amdn_identity_runtime;
GRANT SELECT,INSERT ON amdn_identity.owner_grants,amdn_identity.provisioning_commands,amdn_identity.provisioning_audit TO amdn_identity_provisioner;
GRANT UPDATE(status,expires_at) ON amdn_identity.owner_grants TO amdn_identity_provisioner;
GRANT SELECT,UPDATE(allocated_tenants) ON amdn_identity.platform_grants TO amdn_identity_provisioner;
-- No API credential can create platform grants, rewrite audit or delete replay keys.
