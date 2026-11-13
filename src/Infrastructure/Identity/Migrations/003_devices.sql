-- Storage foundation only. No application role gains device mutation authority.
-- Ceremony authorization, proof verification, identity-version changes and audit
-- must be committed by a later reviewed transaction boundary before API enablement.
CREATE TABLE amdn_identity.device_subjects (
  tenant_id uuid NOT NULL, user_id uuid NOT NULL,
  rp_id text COLLATE "C" NOT NULL CHECK(octet_length(rp_id) BETWEEN 1 AND 253 AND rp_id !~ '[^a-z0-9.-]' AND rp_id ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'),
  user_handle bytea NOT NULL CHECK(octet_length(user_handle)=32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(tenant_id,user_id,rp_id), UNIQUE(rp_id,user_handle),
  FOREIGN KEY(tenant_id,user_id) REFERENCES amdn_identity.users
);
CREATE TABLE amdn_identity.devices (
  tenant_id uuid NOT NULL, user_id uuid NOT NULL,
  device_id uuid NOT NULL DEFAULT gen_random_uuid(),
  rp_id text COLLATE "C" NOT NULL,
  profile text NOT NULL DEFAULT 'amdn-webauthn-enrollment/1' CHECK(profile='amdn-webauthn-enrollment/1'),
  configuration_version bigint NOT NULL CHECK(configuration_version BETWEEN 1 AND 9007199254740991),
  status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','credential_active','revoked','abandoned')),
  credential_id bytea CHECK(octet_length(credential_id) BETWEEN 1 AND 1023),
  -- Normalized public EC2/P-256/ES256 map: {1:2,3:-7,-1:1,-2:x,-3:y}.
  -- Shape only; the future verifier must validate the curve point and possession.
  public_key_cose bytea CHECK(octet_length(public_key_cose)=77
    AND substring(public_key_cose FROM 1 FOR 10)=decode('a5010203262001215820','hex')
    AND substring(public_key_cose FROM 43 FOR 3)=decode('225820','hex')),
  backup_eligible boolean, backup_state boolean,
  sign_count bigint CHECK(sign_count BETWEEN 0 AND 4294967295),
  record_version bigint NOT NULL DEFAULT 1 CHECK(record_version BETWEEN 1 AND 9007199254740991),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  activated_at timestamptz, revoked_at timestamptz,
  PRIMARY KEY(tenant_id,device_id), UNIQUE(device_id),
  FOREIGN KEY(tenant_id,user_id,rp_id) REFERENCES amdn_identity.device_subjects,
  UNIQUE(rp_id,credential_id), UNIQUE(rp_id,public_key_cose),
  CHECK(num_nonnulls(credential_id,public_key_cose,backup_eligible,backup_state,sign_count) IN (0,5)),
  CHECK(backup_state IS NOT TRUE OR backup_eligible IS TRUE),
  CHECK(status NOT IN ('credential_active','revoked') OR credential_id IS NOT NULL),
  CHECK((status IN ('pending','abandoned') AND activated_at IS NULL AND revoked_at IS NULL)
     OR (status='credential_active' AND activated_at IS NOT NULL AND revoked_at IS NULL)
     OR (status='revoked' AND activated_at IS NOT NULL AND revoked_at IS NOT NULL))
);
CREATE UNIQUE INDEX devices_one_active_owner ON amdn_identity.devices(tenant_id,user_id) WHERE status='credential_active';
CREATE INDEX devices_owner ON amdn_identity.devices(tenant_id,user_id,device_id);

CREATE FUNCTION amdn_identity.preserve_device_subject() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $body$
BEGIN
  RAISE EXCEPTION 'Device subject binding is retained and immutable' USING ERRCODE='23514';
END $body$;
CREATE TRIGGER preserve_device_subject BEFORE UPDATE OR DELETE ON amdn_identity.device_subjects
  FOR EACH ROW EXECUTE FUNCTION amdn_identity.preserve_device_subject();

CREATE FUNCTION amdn_identity.preserve_device() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $body$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'Device attribution must be retained' USING ERRCODE='23514';
  ELSIF TG_OP='INSERT' THEN
    IF NEW.status<>'pending' THEN RAISE EXCEPTION 'Devices start pending' USING ERRCODE='23514'; END IF;
    NEW.record_version := 1;
    NEW.created_at := clock_timestamp(); NEW.updated_at := NEW.created_at;
    NEW.activated_at := NULL; NEW.revoked_at := NULL;
    RETURN NEW;
  END IF;
  IF ROW(NEW.tenant_id,NEW.user_id,NEW.device_id,NEW.rp_id,NEW.profile,NEW.configuration_version,NEW.created_at)
      IS DISTINCT FROM ROW(OLD.tenant_id,OLD.user_id,OLD.device_id,OLD.rp_id,OLD.profile,OLD.configuration_version,OLD.created_at) THEN
    RAISE EXCEPTION 'Device binding is immutable' USING ERRCODE='23514';
  END IF;
  IF OLD.credential_id IS NOT NULL AND
      ROW(NEW.credential_id,NEW.public_key_cose,NEW.backup_eligible) IS DISTINCT FROM
      ROW(OLD.credential_id,OLD.public_key_cose,OLD.backup_eligible) THEN
    RAISE EXCEPTION 'Credential binding is immutable' USING ERRCODE='23514';
  END IF;
  IF NEW.sign_count < OLD.sign_count THEN RAISE EXCEPTION 'Counter cannot regress' USING ERRCODE='23514'; END IF;
  IF OLD.status IN ('revoked','abandoned') AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION 'Terminal device is immutable' USING ERRCODE='23514';
  END IF;
  IF NEW.status<>OLD.status AND NOT ((OLD.status='pending' AND NEW.status IN ('credential_active','abandoned'))
      OR (OLD.status='credential_active' AND NEW.status='revoked')) THEN
    RAISE EXCEPTION 'Invalid device transition' USING ERRCODE='23514';
  END IF;
  -- Callers cannot rewrite lifecycle timestamps or the optimistic record version.
  NEW.record_version := OLD.record_version;
  NEW.updated_at := OLD.updated_at;
  NEW.activated_at := OLD.activated_at; NEW.revoked_at := OLD.revoked_at;
  IF NEW IS DISTINCT FROM OLD THEN
    NEW.record_version := OLD.record_version+1;
    NEW.updated_at := clock_timestamp();
    IF OLD.status='pending' AND NEW.status='credential_active' THEN NEW.activated_at := NEW.updated_at; END IF;
    IF OLD.status='credential_active' AND NEW.status='revoked' THEN NEW.revoked_at := NEW.updated_at; END IF;
  END IF;
  RETURN NEW;
END $body$;
CREATE TRIGGER preserve_device BEFORE INSERT OR UPDATE OR DELETE ON amdn_identity.devices
  FOR EACH ROW EXECUTE FUNCTION amdn_identity.preserve_device();

ALTER TABLE amdn_identity.device_subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE amdn_identity.device_subjects FORCE ROW LEVEL SECURITY;
ALTER TABLE amdn_identity.devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE amdn_identity.devices FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_access ON amdn_identity.device_subjects TO amdn_identity_owner USING(true) WITH CHECK(true);
CREATE POLICY owner_access ON amdn_identity.devices TO amdn_identity_owner USING(true) WITH CHECK(true);
CREATE POLICY runtime_scope ON amdn_identity.devices FOR SELECT TO amdn_identity_runtime
  USING(amdn_identity.active_context(tenant_id,user_id) AND EXISTS(
    SELECT FROM amdn_identity.postmen p WHERE p.tenant_id=devices.tenant_id AND p.owner_user_id=devices.user_id AND p.status='active'));
REVOKE ALL ON amdn_identity.devices,amdn_identity.device_subjects FROM PUBLIC,amdn_identity_runtime,amdn_identity_provisioner;
REVOKE ALL ON FUNCTION amdn_identity.preserve_device(),amdn_identity.preserve_device_subject() FROM PUBLIC;
-- Metadata only. Credential material/handles need a later narrow verifier boundary.
GRANT SELECT(tenant_id,user_id,device_id,profile,status,record_version,created_at,updated_at,activated_at,revoked_at)
  ON amdn_identity.devices TO amdn_identity_runtime;
