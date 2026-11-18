-- Transport preflight: establish current membership/grant authority before a
-- process-local tenant request budget is charged. Mutations still reauthorize.
CREATE FUNCTION amdn_enrollment.authorize(p amdn_identity.ceremony_actor) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $body$
DECLARE a amdn_identity.ceremony_authority;
BEGIN
  IF NOT amdn_identity.enrollment_context(p) THEN RETURN jsonb_build_object('outcome','not_found'); END IF;
  a:=amdn_identity.ceremony_authorize(p);
  RETURN jsonb_build_object('outcome',a.outcome);
END $body$;
REVOKE ALL ON FUNCTION amdn_enrollment.authorize(amdn_identity.ceremony_actor) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION amdn_enrollment.authorize(amdn_identity.ceremony_actor) TO amdn_identity_enrollment;
GRANT CREATE ON SCHEMA amdn_enrollment TO amdn_identity_ceremony_executor;
ALTER FUNCTION amdn_enrollment.authorize(amdn_identity.ceremony_actor) OWNER TO amdn_identity_ceremony_executor;
REVOKE CREATE ON SCHEMA amdn_enrollment FROM amdn_identity_ceremony_executor;
SET LOCAL ROLE amdn_identity_ceremony_executor;
GRANT EXECUTE ON FUNCTION amdn_enrollment.authorize(amdn_identity.ceremony_actor) TO amdn_identity_owner;
SET LOCAL ROLE amdn_identity_owner;

-- Public option material is read under the same authority/lifecycle locks as
-- the stage effect or authorized replay. No new application SELECT is granted.
CREATE OR REPLACE FUNCTION amdn_identity.ceremony_snapshot(p_id uuid) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $body$
DECLARE c amdn_identity.device_ceremonies; h amdn_identity.device_challenges;
  d amdn_identity.devices; version_now bigint; handle bytea; credential bytea;
BEGIN
  SELECT * INTO STRICT c FROM amdn_identity.device_ceremonies WHERE ceremony_id=p_id;
  SELECT * INTO STRICT d FROM amdn_identity.devices WHERE tenant_id=c.tenant_id AND device_id=c.device_id;
  IF c.state='completed' THEN
    SELECT identity_version INTO version_now FROM amdn_identity.users WHERE tenant_id=c.tenant_id AND user_id=c.user_id;
    RETURN jsonb_build_object('outcome','ok','state','completed','ceremony_id',c.ceremony_id,'device_id',c.device_id,
      'completed_at',c.completed_at,'committed_identity_version',c.committed_identity_version,'messaging_ready',false,
      'current_lifecycle',jsonb_build_object('status',d.status,'identity_version',version_now,'observed_at',clock_timestamp()));
  END IF;
  SELECT * INTO STRICT h FROM amdn_identity.device_challenges WHERE ceremony_id=c.ceremony_id AND stage=c.state;
  SELECT user_handle INTO STRICT handle FROM amdn_identity.device_subjects
    WHERE tenant_id=c.tenant_id AND user_id=c.user_id AND rp_id=d.rp_id;
  IF c.state IN ('registration','current') THEN
    SELECT credential_id INTO credential FROM amdn_identity.devices WHERE tenant_id=c.tenant_id AND device_id=c.target_id;
  ELSE credential:=d.credential_id; END IF;
  RETURN jsonb_build_object('outcome','ok','state',c.state,'ceremony_id',c.ceremony_id,'device_id',c.device_id,
    'expires_at',c.expires_at,'challenge_expires_at',h.expires_at,'challenge_hex',encode(h.challenge,'hex'),
    'rp_id',d.rp_id,'user_handle_hex',encode(handle,'hex'),'option_credential_id_hex',encode(credential,'hex'));
END $body$;
