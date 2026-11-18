-- Trusted operator commands, invoked explicitly under the migration-owner role.
-- Application roles gain no administration privileges or new HTTP routes.
CREATE TABLE amdn_identity.device_administration_audit (
  operator_name name NOT NULL,
  command_id uuid NOT NULL CHECK(command_id<>'00000000-0000-0000-0000-000000000000'),
  action text NOT NULL CHECK(action IN ('configuration.set','grant.issue','grant.revoke')),
  request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
  configuration_id uuid REFERENCES amdn_identity.device_configurations,
  tenant_id uuid, user_id uuid, postman_id uuid,
  previous_version bigint NOT NULL CHECK(previous_version BETWEEN 0 AND 9007199254740991),
  resulting_version bigint NOT NULL CHECK(resulting_version BETWEEN 1 AND 9007199254740991),
  change_reference text NOT NULL CHECK(octet_length(change_reference) BETWEEN 1 AND 128 AND change_reference !~ '[^!-~]'),
  result jsonb NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(operator_name,command_id),
  FOREIGN KEY(tenant_id,user_id,postman_id) REFERENCES amdn_identity.postmen(tenant_id,owner_user_id,postman_id),
  CHECK((action='configuration.set' AND configuration_id IS NOT NULL AND num_nonnulls(tenant_id,user_id,postman_id)=0)
    OR (action IN ('grant.issue','grant.revoke') AND configuration_id IS NULL AND num_nonnulls(tenant_id,user_id,postman_id)=3))
);
ALTER TABLE amdn_identity.device_administration_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE amdn_identity.device_administration_audit FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_access ON amdn_identity.device_administration_audit TO amdn_identity_owner USING(true) WITH CHECK(true);
REVOKE ALL ON amdn_identity.device_administration_audit FROM PUBLIC,amdn_identity_runtime,
  amdn_identity_provisioner,amdn_identity_enrollment,amdn_identity_ceremony_executor;
CREATE FUNCTION amdn_identity.preserve_device_administration_audit() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $body$
BEGIN
  RAISE EXCEPTION 'Administration audit and replay records are retained' USING ERRCODE='23514';
END $body$;
CREATE TRIGGER preserve_device_administration_audit BEFORE UPDATE OR DELETE ON amdn_identity.device_administration_audit
  FOR EACH ROW EXECUTE FUNCTION amdn_identity.preserve_device_administration_audit();
CREATE TRIGGER retain_device_administration_audit BEFORE TRUNCATE ON amdn_identity.device_administration_audit
  FOR EACH STATEMENT EXECUTE FUNCTION amdn_identity.preserve_device_administration_audit();

-- Internal helper. Serialize identical command keys across all three operations.
-- The digest covers canonical typed SQL arguments, not an HTTP request body.
CREATE FUNCTION amdn_identity.device_admin_replay(p_command uuid,p_request jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $body$
DECLARE previous amdn_identity.device_administration_audit;
BEGIN
  IF current_user<>'amdn_identity_owner' THEN RAISE EXCEPTION 'Administrator role required' USING ERRCODE='42501'; END IF;
  IF p_command IS NULL OR p_command='00000000-0000-0000-0000-000000000000' THEN
    RETURN jsonb_build_object('outcome','invalid_request');
  END IF;
  PERFORM pg_advisory_xact_lock(18641003,hashtext(session_user::text||':'||p_command::text));
  SELECT * INTO previous FROM amdn_identity.device_administration_audit
    WHERE operator_name=session_user AND command_id=p_command;
  IF FOUND THEN
    IF previous.request_digest<>sha256(convert_to(p_request::text,'UTF8')) THEN
      RETURN jsonb_build_object('outcome','conflict');
    END IF;
    RETURN previous.result;
  END IF;
  RETURN NULL;
END $body$;

CREATE FUNCTION amdn_identity.administer_device_configuration(p_command uuid,p_id uuid,p_expected bigint,
  p_rp text,p_origin text,p_acrs text[],p_maximum_age integer,p_enabled boolean,p_reference text) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $body$
DECLARE request jsonb; replay jsonb; answer jsonb; old amdn_identity.device_configurations;
  host_name text; port_text text; new_version bigint;
BEGIN
  request:=jsonb_build_object('action','configuration.set','id',p_id,'expected',p_expected,'rp',p_rp,
    'origin',p_origin,'acrs',p_acrs,'maximum_age',p_maximum_age,'enabled',p_enabled,'reference',p_reference);
  replay:=amdn_identity.device_admin_replay(p_command,request);
  IF replay IS NOT NULL THEN RETURN replay; END IF;
  IF p_id IS NULL OR p_id='00000000-0000-0000-0000-000000000000' OR p_expected IS NULL
    OR p_expected NOT BETWEEN 0 AND 9007199254740991 OR p_enabled IS NULL
    OR p_maximum_age IS NULL OR p_maximum_age NOT BETWEEN 1 AND 900
    OR p_reference IS NULL OR octet_length(p_reference) NOT BETWEEN 1 AND 128 OR p_reference ~ '[^!-~]'
    OR p_rp IS NULL OR octet_length(p_rp) NOT BETWEEN 1 AND 253 OR p_rp ~ '(^|\.)([0-9]+|0x[0-9a-f]*)$'
    OR p_rp !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
    OR p_origin IS NULL OR octet_length(p_origin) NOT BETWEEN 9 AND 512
    OR p_origin !~ '^https://[a-z0-9.-]+(:[1-9][0-9]{0,4})?$'
    OR NOT amdn_identity.ceremony_valid_acrs(p_acrs) THEN RETURN jsonb_build_object('outcome','invalid_request'); END IF;
  host_name:=split_part(substring(p_origin FROM 9),':',1);
  port_text:=split_part(substring(p_origin FROM 9),':',2);
  IF octet_length(host_name)>253 OR host_name ~ '(^|\.)([0-9]+|0x[0-9a-f]*)$'
    OR host_name !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
    OR (host_name<>p_rp AND right(host_name,length(p_rp)+1)<>'.'||p_rp)
    OR (port_text<>'' AND (port_text::integer>65535 OR port_text='443')) THEN
    RETURN jsonb_build_object('outcome','invalid_request');
  END IF;
  -- Serialize creates as well as updates, even when the row does not yet exist.
  PERFORM pg_advisory_xact_lock(18641004,hashtext(p_id::text));
  SELECT * INTO old FROM amdn_identity.device_configurations WHERE configuration_id=p_id FOR UPDATE;
  IF (NOT FOUND AND p_expected<>0) OR (FOUND AND old.version<>p_expected) THEN
    RETURN jsonb_build_object('outcome','conflict');
  END IF;
  IF old.configuration_id IS NULL THEN
    INSERT INTO amdn_identity.device_configurations(configuration_id,rp_id,origin,allowed_acrs,maximum_age_seconds,enabled)
      VALUES(p_id,p_rp,p_origin,p_acrs,p_maximum_age,p_enabled) RETURNING version INTO new_version;
  ELSE
    -- A deployment origin/RP binding is never silently retargeted in place.
    IF ROW(old.rp_id,old.origin) IS DISTINCT FROM ROW(p_rp,p_origin) THEN RETURN jsonb_build_object('outcome','conflict'); END IF;
    IF old.version=9007199254740991 AND ROW(old.rp_id,old.origin,old.allowed_acrs,old.maximum_age_seconds,old.enabled)
      IS DISTINCT FROM ROW(p_rp,p_origin,p_acrs,p_maximum_age,p_enabled) THEN RETURN jsonb_build_object('outcome','conflict'); END IF;
    UPDATE amdn_identity.device_configurations SET rp_id=p_rp,origin=p_origin,allowed_acrs=p_acrs,
      maximum_age_seconds=p_maximum_age,enabled=p_enabled WHERE configuration_id=p_id RETURNING version INTO new_version;
  END IF;
  answer:=jsonb_build_object('outcome','ok','configuration_id',p_id,'version',new_version,'enabled',p_enabled);
  INSERT INTO amdn_identity.device_administration_audit(operator_name,command_id,action,request_digest,configuration_id,
    previous_version,resulting_version,change_reference,result)
    VALUES(session_user,p_command,'configuration.set',sha256(convert_to(request::text,'UTF8')),p_id,
      coalesce(old.version,0),new_version,p_reference,answer);
  RETURN answer;
END $body$;

CREATE FUNCTION amdn_identity.administer_device_grant(p_command uuid,p_tenant uuid,p_user uuid,p_postman uuid,
  p_action text,p_expected bigint,p_expiry timestamptz,p_reference text) RETURNS jsonb
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $body$
DECLARE request jsonb; replay jsonb; answer jsonb; old amdn_identity.device_management_grants;
  new_version bigint; membership_count bigint;
BEGIN
  -- Epoch encoding makes replay independent of the administrator's timezone.
  request:=jsonb_build_object('action',p_action,'tenant',p_tenant,'user',p_user,'postman',p_postman,
    'expected',p_expected,'expiry_epoch',extract(epoch FROM p_expiry),'reference',p_reference);
  replay:=amdn_identity.device_admin_replay(p_command,request);
  IF replay IS NOT NULL THEN RETURN replay; END IF;
  IF p_tenant IS NULL OR p_user IS NULL OR p_postman IS NULL OR p_action IS NULL OR p_action NOT IN ('grant.issue','grant.revoke')
    OR p_expected IS NULL OR p_expected NOT BETWEEN 0 AND 9007199254740991
    OR p_reference IS NULL OR octet_length(p_reference) NOT BETWEEN 1 AND 128 OR p_reference ~ '[^!-~]'
    OR (p_action='grant.issue' AND (p_expiry IS NULL OR NOT isfinite(p_expiry) OR p_expected<>0))
    OR (p_action='grant.revoke' AND (p_expiry IS NOT NULL OR p_expected=0)) THEN
    RETURN jsonb_build_object('outcome','invalid_request');
  END IF;
  -- Match ceremony lock ordering. Recheck time after locks, never before a wait.
  PERFORM FROM amdn_identity.tenants WHERE tenant_id=p_tenant AND (p_action='grant.revoke' OR status='active') FOR SHARE;
  IF NOT FOUND THEN RETURN jsonb_build_object('outcome','not_found'); END IF;
  PERFORM FROM amdn_identity.users WHERE tenant_id=p_tenant AND user_id=p_user AND (p_action='grant.revoke' OR status='active') FOR UPDATE;
  IF NOT FOUND THEN RETURN jsonb_build_object('outcome','not_found'); END IF;
  PERFORM FROM amdn_identity.memberships WHERE tenant_id=p_tenant AND user_id=p_user AND (p_action='grant.revoke' OR status='active') ORDER BY issuer,subject FOR SHARE;
  GET DIAGNOSTICS membership_count=ROW_COUNT;
  IF membership_count=0 THEN RETURN jsonb_build_object('outcome','not_found'); END IF;
  PERFORM FROM amdn_identity.postmen WHERE tenant_id=p_tenant AND owner_user_id=p_user AND postman_id=p_postman AND (p_action='grant.revoke' OR status='active') FOR SHARE;
  IF NOT FOUND THEN RETURN jsonb_build_object('outcome','not_found'); END IF;
  SELECT * INTO old FROM amdn_identity.device_management_grants WHERE tenant_id=p_tenant AND user_id=p_user FOR UPDATE;
  IF p_action='grant.issue' THEN
    IF old.user_id IS NOT NULL THEN RETURN jsonb_build_object('outcome','conflict'); END IF;
    IF p_expiry<=clock_timestamp() THEN RETURN jsonb_build_object('outcome','invalid_request'); END IF;
    INSERT INTO amdn_identity.device_management_grants(tenant_id,user_id,postman_id,expires_at)
      VALUES(p_tenant,p_user,p_postman,p_expiry) RETURNING version INTO new_version;
  ELSE
    IF old.user_id IS NULL THEN RETURN jsonb_build_object('outcome','not_found'); END IF;
    IF old.postman_id<>p_postman OR old.version<>p_expected OR old.status<>'active' OR old.version=9007199254740991 THEN
      RETURN jsonb_build_object('outcome','conflict');
    END IF;
    UPDATE amdn_identity.device_management_grants SET status='revoked' WHERE tenant_id=p_tenant AND user_id=p_user RETURNING version INTO new_version;
  END IF;
  answer:=jsonb_build_object('outcome','ok','tenant_id',p_tenant,'user_id',p_user,'postman_id',p_postman,
    'version',new_version,'status',CASE WHEN p_action='grant.issue' THEN 'active' ELSE 'revoked' END);
  INSERT INTO amdn_identity.device_administration_audit(operator_name,command_id,action,request_digest,tenant_id,user_id,postman_id,
    previous_version,resulting_version,change_reference,result)
    VALUES(session_user,p_command,p_action,sha256(convert_to(request::text,'UTF8')),p_tenant,p_user,p_postman,
      coalesce(old.version,0),new_version,p_reference,answer);
  RETURN answer;
END $body$;

REVOKE ALL ON FUNCTION amdn_identity.preserve_device_administration_audit(),
  amdn_identity.device_admin_replay(uuid,jsonb),
  amdn_identity.administer_device_configuration(uuid,uuid,bigint,text,text,text[],integer,boolean,text),
  amdn_identity.administer_device_grant(uuid,uuid,uuid,uuid,text,bigint,timestamptz,text)
  FROM PUBLIC,amdn_identity_runtime,amdn_identity_provisioner,amdn_identity_enrollment,amdn_identity_ceremony_executor;
