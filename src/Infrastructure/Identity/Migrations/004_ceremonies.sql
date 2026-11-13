-- Internal transaction primitives only. No API role receives EXECUTE or table access.
-- Actor fields and proof projections must come from a future trusted OIDC/verifier adapter.
CREATE TYPE amdn_identity.ceremony_actor AS (
  tenant_id uuid, issuer text, subject text, client_id text, origin text,
  configuration_id uuid, scope text, acr text, auth_time timestamptz, token_expires_at timestamptz
);
CREATE TYPE amdn_identity.ceremony_authority AS (
  outcome text, user_id uuid, postman_id uuid, identity_version bigint,
  membership_version bigint, policy_version bigint, grant_version bigint,
  configuration_version bigint, rp_id text, valid_until timestamptz
);
CREATE FUNCTION amdn_identity.ceremony_valid_acrs(values_to_check text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $body$
  SELECT coalesce(cardinality(values_to_check) BETWEEN 1 AND 16
    AND (SELECT count(DISTINCT value) FROM unnest(values_to_check) value)=cardinality(values_to_check)
    AND NOT EXISTS(SELECT FROM unnest(values_to_check) value WHERE value IS NULL OR octet_length(value) NOT BETWEEN 1 AND 256 OR value ~ '[^!-~]'),false);
$body$;
CREATE TABLE amdn_identity.device_configurations (
  configuration_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  rp_id text COLLATE "C" NOT NULL CHECK(octet_length(rp_id) BETWEEN 1 AND 253),
  origin text COLLATE "C" NOT NULL CHECK(octet_length(origin) BETWEEN 9 AND 512 AND origin ~ '^https://[^/?#@[:space:]]+$'),
  allowed_acrs text[] NOT NULL CHECK(amdn_identity.ceremony_valid_acrs(allowed_acrs)),
  maximum_age_seconds integer NOT NULL CHECK(maximum_age_seconds BETWEEN 1 AND 900),
  enabled boolean NOT NULL DEFAULT false,
  version bigint NOT NULL DEFAULT 1 CHECK(version BETWEEN 1 AND 9007199254740991)
);
ALTER TABLE amdn_identity.postmen ADD UNIQUE(tenant_id,owner_user_id,postman_id);
ALTER TABLE amdn_identity.devices ADD UNIQUE(tenant_id,user_id,device_id);
CREATE TABLE amdn_identity.device_management_grants (
  tenant_id uuid NOT NULL, user_id uuid NOT NULL, postman_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
  expires_at timestamptz NOT NULL CHECK(isfinite(expires_at)),
  version bigint NOT NULL DEFAULT 1 CHECK(version BETWEEN 1 AND 9007199254740991),
  PRIMARY KEY(tenant_id,user_id),
  FOREIGN KEY(tenant_id,user_id,postman_id) REFERENCES amdn_identity.postmen(tenant_id,owner_user_id,postman_id)
);
CREATE FUNCTION amdn_identity.ceremony_preserve_control() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $body$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Control attribution is retained' USING ERRCODE='23514'; END IF;
  IF TG_TABLE_NAME='device_configurations' THEN
    IF NEW.configuration_id<>OLD.configuration_id THEN RAISE EXCEPTION 'Immutable configuration identity' USING ERRCODE='23514'; END IF;
  ELSE
    IF ROW(NEW.tenant_id,NEW.user_id,NEW.postman_id) IS DISTINCT FROM ROW(OLD.tenant_id,OLD.user_id,OLD.postman_id)
      OR (OLD.status='revoked' AND NEW.status<>'revoked') THEN
      RAISE EXCEPTION 'Immutable grant identity or terminal grant' USING ERRCODE='23514';
    END IF;
  END IF;
  NEW.version := OLD.version;
  IF NEW IS DISTINCT FROM OLD THEN NEW.version := OLD.version+1; END IF;
  RETURN NEW;
END $body$;
CREATE TRIGGER preserve_control BEFORE UPDATE OR DELETE ON amdn_identity.device_configurations FOR EACH ROW EXECUTE FUNCTION amdn_identity.ceremony_preserve_control();
CREATE TRIGGER preserve_control BEFORE UPDATE OR DELETE ON amdn_identity.device_management_grants FOR EACH ROW EXECUTE FUNCTION amdn_identity.ceremony_preserve_control();

CREATE TABLE amdn_identity.device_ceremonies (
  ceremony_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, user_id uuid NOT NULL,
  postman_id uuid NOT NULL, issuer text COLLATE "C" NOT NULL, subject text COLLATE "C" NOT NULL,
  client_id text COLLATE "C" NOT NULL, origin text COLLATE "C" NOT NULL,
  configuration_id uuid NOT NULL REFERENCES amdn_identity.device_configurations,
  configuration_version bigint NOT NULL, grant_version bigint NOT NULL,
  identity_version bigint NOT NULL, membership_version bigint NOT NULL, policy_version bigint NOT NULL,
  operation text NOT NULL CHECK(operation IN ('initial','replacement','revocation')),
  device_id uuid NOT NULL, target_id uuid, device_version bigint NOT NULL, target_version bigint,
  state text NOT NULL CHECK(state IN ('registration','candidate','current','revocation','completed','expired','abandoned')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), expires_at timestamptz NOT NULL,
  completed_at timestamptz, committed_identity_version bigint,
  UNIQUE(tenant_id,user_id,ceremony_id),
  FOREIGN KEY(tenant_id,user_id,postman_id) REFERENCES amdn_identity.postmen(tenant_id,owner_user_id,postman_id),
  FOREIGN KEY(tenant_id,user_id,device_id) REFERENCES amdn_identity.devices(tenant_id,user_id,device_id),
  FOREIGN KEY(tenant_id,user_id,target_id) REFERENCES amdn_identity.devices(tenant_id,user_id,device_id),
  CHECK(expires_at>created_at AND expires_at<=created_at+interval '5 minutes'),
  CHECK((operation='initial' AND target_id IS NULL AND target_version IS NULL)
    OR (operation IN ('replacement','revocation') AND target_id IS NOT NULL AND target_version IS NOT NULL)),
  CHECK((state='completed' AND completed_at IS NOT NULL AND committed_identity_version IS NOT NULL AND committed_identity_version BETWEEN 1 AND 9007199254740991)
    OR (state<>'completed' AND completed_at IS NULL AND committed_identity_version IS NULL))
);
CREATE UNIQUE INDEX one_unfinished_device_ceremony ON amdn_identity.device_ceremonies(tenant_id,user_id)
  WHERE state IN ('registration','candidate','current','revocation');
CREATE TABLE amdn_identity.device_challenges (
  ceremony_id uuid NOT NULL REFERENCES amdn_identity.device_ceremonies,
  stage text NOT NULL CHECK(stage IN ('registration','candidate','current','revocation')),
  challenge bytea NOT NULL UNIQUE CHECK(octet_length(challenge)=32),
  issued_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, consumed_at timestamptz,
  PRIMARY KEY(ceremony_id,stage), CHECK(expires_at>issued_at AND expires_at<=issued_at+interval '2 minutes')
);
CREATE TABLE amdn_identity.device_commands (
  command_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL, user_id uuid NOT NULL,
  ceremony_id uuid NOT NULL, stage text NOT NULL CHECK(stage IN ('begin_enrollment','begin_revocation','registration','candidate','current','revocation')),
  scope_id uuid NOT NULL, idempotency_key text COLLATE "C" NOT NULL CHECK(octet_length(idempotency_key) BETWEEN 16 AND 128 AND idempotency_key !~ '[^!-~]'),
  request_digest bytea NOT NULL CHECK(octet_length(request_digest)=32),
  state text NOT NULL CHECK(state IN ('reserved','failed','succeeded')),
  attempt_number integer CHECK(attempt_number BETWEEN 1 AND 5), reservation_tx xid8,
  verified_device_version bigint, result jsonb,
  UNIQUE(tenant_id,user_id,stage,scope_id,idempotency_key), UNIQUE(ceremony_id,stage,attempt_number),
  FOREIGN KEY(tenant_id,user_id,ceremony_id) REFERENCES amdn_identity.device_ceremonies(tenant_id,user_id,ceremony_id),
  CHECK((stage IN ('begin_enrollment','begin_revocation') AND attempt_number IS NULL AND reservation_tx IS NULL AND state='succeeded')
    OR (stage IN ('registration','candidate','current','revocation') AND attempt_number IS NOT NULL AND reservation_tx IS NOT NULL AND verified_device_version IS NOT NULL))
);
CREATE TABLE amdn_identity.device_ceremony_audit (
  audit_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), ceremony_id uuid NOT NULL REFERENCES amdn_identity.device_ceremonies,
  command_id uuid REFERENCES amdn_identity.device_commands,
  action text NOT NULL CHECK(action IN ('begun','reserved','failed','registration','candidate','current','revocation','expired','abandoned')),
  identity_version bigint NOT NULL, occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
DO $tables$
DECLARE tab text;
BEGIN
  FOREACH tab IN ARRAY ARRAY['device_configurations','device_management_grants','device_ceremonies','device_challenges','device_commands','device_ceremony_audit'] LOOP
    EXECUTE format('ALTER TABLE amdn_identity.%I ENABLE ROW LEVEL SECURITY',tab);
    EXECUTE format('ALTER TABLE amdn_identity.%I FORCE ROW LEVEL SECURITY',tab);
    EXECUTE format('CREATE POLICY owner_access ON amdn_identity.%I TO amdn_identity_owner USING(true) WITH CHECK(true)',tab);
    EXECUTE format('REVOKE ALL ON amdn_identity.%I FROM PUBLIC,amdn_identity_runtime,amdn_identity_provisioner',tab);
  END LOOP;
END $tables$;

-- Fixed lock order: tenant, user, membership, postman, grant, configuration,
-- ceremony, devices in UUID order, challenges in stage order, then command. The user lock serializes commands for one owner.
CREATE FUNCTION amdn_identity.ceremony_authorize(p amdn_identity.ceremony_actor)
RETURNS amdn_identity.ceremony_authority
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $body$
DECLARE a amdn_identity.ceremony_authority; u amdn_identity.users; m amdn_identity.memberships;
  post amdn_identity.postmen; g amdn_identity.device_management_grants; cfg amdn_identity.device_configurations;
  now_at timestamptz;
BEGIN
  a.outcome := 'forbidden';
  IF p.tenant_id IS NULL OR p.configuration_id IS NULL OR p.issuer IS NULL OR p.subject IS NULL
    OR p.client_id IS NULL OR octet_length(p.client_id) NOT BETWEEN 1 AND 256 OR p.origin IS NULL
    OR p.acr IS NULL OR p.auth_time IS NULL OR p.token_expires_at IS NULL OR NOT isfinite(p.auth_time) OR NOT isfinite(p.token_expires_at)
    OR NOT coalesce('device.manage'=ANY(string_to_array(p.scope,' ')),false) THEN RETURN a; END IF;
  PERFORM FROM amdn_identity.tenants WHERE tenant_id=p.tenant_id AND status='active' FOR SHARE;
  IF NOT FOUND THEN RETURN a; END IF;
  SELECT * INTO m FROM amdn_identity.memberships WHERE tenant_id=p.tenant_id AND issuer=p.issuer AND subject=p.subject;
  IF NOT FOUND THEN RETURN a; END IF;
  SELECT * INTO u FROM amdn_identity.users WHERE tenant_id=p.tenant_id AND user_id=m.user_id AND status='active' FOR UPDATE;
  IF NOT FOUND THEN RETURN a; END IF;
  SELECT * INTO m FROM amdn_identity.memberships WHERE tenant_id=p.tenant_id AND user_id=u.user_id AND issuer=p.issuer AND subject=p.subject AND status='active' FOR SHARE;
  IF NOT FOUND THEN RETURN a; END IF;
  SELECT * INTO post FROM amdn_identity.postmen WHERE tenant_id=p.tenant_id AND owner_user_id=u.user_id AND status='active' FOR SHARE;
  IF NOT FOUND THEN RETURN a; END IF;
  SELECT * INTO g FROM amdn_identity.device_management_grants WHERE tenant_id=p.tenant_id AND user_id=u.user_id AND postman_id=post.postman_id AND status='active' FOR SHARE;
  IF NOT FOUND THEN RETURN a; END IF;
  SELECT * INTO cfg FROM amdn_identity.device_configurations WHERE configuration_id=p.configuration_id AND enabled AND origin=p.origin AND p.acr=ANY(allowed_acrs) FOR SHARE;
  IF NOT FOUND THEN RETURN a; END IF;
  now_at := clock_timestamp();
  a.valid_until := least(g.expires_at,p.token_expires_at,p.auth_time+make_interval(secs=>cfg.maximum_age_seconds));
  IF p.auth_time>now_at OR a.valid_until<=now_at THEN RETURN a; END IF;
  a.outcome := 'ok'; a.user_id := u.user_id; a.postman_id := post.postman_id;
  a.identity_version := u.identity_version; a.membership_version := m.membership_version;
  a.policy_version := post.policy_version; a.grant_version := g.version;
  a.configuration_version := cfg.version; a.rp_id := cfg.rp_id;
  PERFORM set_config('amdn.tenant_id',p.tenant_id::text,true),set_config('amdn.user_id',a.user_id::text,true),
    set_config('amdn.issuer',p.issuer,true),set_config('amdn.subject',p.subject,true);
  RETURN a;
END $body$;

CREATE FUNCTION amdn_identity.ceremony_lock(p amdn_identity.ceremony_actor,p_id uuid)
RETURNS amdn_identity.ceremony_authority
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $body$
DECLARE a amdn_identity.ceremony_authority; c amdn_identity.device_ceremonies;
BEGIN
  a := amdn_identity.ceremony_authorize(p);
  IF a.outcome<>'ok' THEN RETURN a; END IF;
  SELECT * INTO c FROM amdn_identity.device_ceremonies WHERE ceremony_id=p_id AND tenant_id=p.tenant_id AND user_id=a.user_id FOR UPDATE;
  IF NOT FOUND THEN a.outcome:='not_found'; RETURN a; END IF;
  IF ROW(c.issuer,c.subject,c.client_id,c.origin,c.configuration_id) IS DISTINCT FROM ROW(p.issuer,p.subject,p.client_id,p.origin,p.configuration_id) THEN
    a.outcome:='conflict'; RETURN a;
  END IF;
  PERFORM FROM amdn_identity.devices WHERE tenant_id=p.tenant_id AND user_id=a.user_id AND device_id IN (c.device_id,c.target_id) ORDER BY device_id FOR UPDATE;
  PERFORM FROM amdn_identity.device_challenges WHERE ceremony_id=p_id ORDER BY stage FOR UPDATE;
  IF a.valid_until<=clock_timestamp() THEN a.outcome:='forbidden'; END IF;
  RETURN a;
END $body$;

CREATE FUNCTION amdn_identity.ceremony_terminate(p_id uuid,p_state text) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $body$
DECLARE c amdn_identity.device_ceremonies;
BEGIN
  IF p_state NOT IN ('expired','abandoned') THEN RAISE EXCEPTION 'Invalid terminal state' USING ERRCODE='23514'; END IF;
  UPDATE amdn_identity.device_ceremonies SET state=p_state WHERE ceremony_id=p_id AND state IN ('registration','candidate','current','revocation') RETURNING * INTO c;
  IF NOT FOUND THEN RETURN; END IF;
  IF c.operation<>'revocation' THEN
    UPDATE amdn_identity.devices SET status='abandoned' WHERE tenant_id=c.tenant_id AND device_id=c.device_id AND status='pending';
  END IF;
  INSERT INTO amdn_identity.device_ceremony_audit(ceremony_id,action,identity_version) VALUES(c.ceremony_id,p_state,c.identity_version);
END $body$;

CREATE FUNCTION amdn_identity.ceremony_ready(c amdn_identity.device_ceremonies,a amdn_identity.ceremony_authority) RETURNS boolean
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $body$
DECLARE d amdn_identity.devices; target amdn_identity.devices; challenge amdn_identity.device_challenges;
BEGIN
  IF c.state NOT IN ('registration','candidate','current','revocation') THEN RETURN false; END IF;
  SELECT * INTO challenge FROM amdn_identity.device_challenges WHERE ceremony_id=c.ceremony_id AND stage=c.state;
  IF NOT FOUND OR challenge.consumed_at IS NOT NULL OR least(c.expires_at,challenge.expires_at)<=clock_timestamp() THEN
    PERFORM amdn_identity.ceremony_terminate(c.ceremony_id,'expired'); RETURN false;
  END IF;
  SELECT * INTO d FROM amdn_identity.devices WHERE tenant_id=c.tenant_id AND device_id=c.device_id;
  SELECT * INTO target FROM amdn_identity.devices WHERE tenant_id=c.tenant_id AND device_id=c.target_id;
  IF ROW(c.identity_version,c.membership_version,c.policy_version,c.grant_version,c.configuration_version)
      IS DISTINCT FROM ROW(a.identity_version,a.membership_version,a.policy_version,a.grant_version,a.configuration_version)
    OR d.record_version IS DISTINCT FROM c.device_version
    OR (c.operation<>'revocation' AND d.status<>'pending')
    OR (c.target_id IS NOT NULL AND (target.record_version IS DISTINCT FROM c.target_version OR target.status<>'credential_active'))
    OR (c.operation='initial' AND EXISTS(SELECT FROM amdn_identity.devices WHERE tenant_id=c.tenant_id AND user_id=c.user_id AND status='credential_active')) THEN
    PERFORM amdn_identity.ceremony_terminate(c.ceremony_id,'abandoned'); RETURN false;
  END IF;
  RETURN true;
END $body$;

CREATE FUNCTION amdn_identity.ceremony_snapshot(p_id uuid) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $body$
DECLARE c amdn_identity.device_ceremonies; h amdn_identity.device_challenges; d amdn_identity.devices; version_now bigint;
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
  RETURN jsonb_build_object('outcome','ok','state',c.state,'ceremony_id',c.ceremony_id,'device_id',c.device_id,
    'expires_at',c.expires_at,'challenge_expires_at',h.expires_at,'challenge_hex',encode(h.challenge,'hex'));
END $body$;

CREATE FUNCTION amdn_identity.ceremony_replay(cmd amdn_identity.device_commands,c amdn_identity.device_ceremonies,a amdn_identity.ceremony_authority) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $body$
BEGIN
  IF cmd.state='failed' THEN RETURN cmd.result; END IF;
  IF cmd.state='succeeded' AND cmd.result->>'state'='completed' THEN RETURN amdn_identity.ceremony_snapshot(c.ceremony_id); END IF;
  IF NOT amdn_identity.ceremony_ready(c,a) THEN RETURN jsonb_build_object('outcome','conflict'); END IF;
  IF cmd.state='reserved' THEN
    IF cmd.stage<>c.state THEN RETURN jsonb_build_object('outcome','conflict'); END IF;
    RETURN jsonb_build_object('outcome','unavailable');
  END IF;
  IF c.state IS DISTINCT FROM cmd.result->>'state' THEN RETURN jsonb_build_object('outcome','conflict'); END IF;
  RETURN cmd.result;
END $body$;

CREATE FUNCTION amdn_identity.ceremony_begin(p amdn_identity.ceremony_actor,p_operation text,p_expected bigint,p_target uuid,
  p_key text,p_body bytea,p_challenge bytea,p_handle bytea) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $body$
DECLARE a amdn_identity.ceremony_authority; c amdn_identity.device_ceremonies; old_c amdn_identity.device_ceremonies;
  cmd amdn_identity.device_commands; d amdn_identity.devices; device uuid; mode text; next_stage text; command_stage text;
  command_scope uuid:=coalesce(p_target,'00000000-0000-0000-0000-000000000000'); now_at timestamptz; answer jsonb;
BEGIN
  a:=amdn_identity.ceremony_authorize(p);
  IF a.outcome<>'ok' THEN RETURN jsonb_build_object('outcome',a.outcome); END IF;
  IF p_operation IS NULL OR p_operation NOT IN ('enrollment','revocation') OR p_expected IS NULL
    OR p_expected NOT BETWEEN 0 AND 9007199254740990 OR p_key IS NULL OR octet_length(p_key) NOT BETWEEN 16 AND 128 OR p_key ~ '[^!-~]'
    OR p_body IS NULL OR octet_length(p_body) NOT BETWEEN 1 AND 65536 THEN RETURN jsonb_build_object('outcome','invalid_request'); END IF;
  command_stage:=CASE WHEN p_operation='enrollment' THEN 'begin_enrollment' ELSE 'begin_revocation' END;
  SELECT * INTO cmd FROM amdn_identity.device_commands WHERE tenant_id=p.tenant_id AND user_id=a.user_id
    AND device_commands.stage=command_stage AND device_commands.scope_id=command_scope AND idempotency_key=p_key;
  IF FOUND THEN
    a:=amdn_identity.ceremony_lock(p,cmd.ceremony_id);
    IF a.outcome<>'ok' THEN RETURN jsonb_build_object('outcome',a.outcome); END IF;
    SELECT * INTO c FROM amdn_identity.device_ceremonies WHERE ceremony_id=cmd.ceremony_id;
    IF cmd.request_digest<>sha256(p_body) OR c.identity_version<>p_expected OR c.target_id IS DISTINCT FROM p_target THEN RETURN jsonb_build_object('outcome','conflict'); END IF;
    RETURN amdn_identity.ceremony_replay(cmd,c,a);
  END IF;
  IF p_challenge IS NULL OR octet_length(p_challenge)<>32 OR p_handle IS NULL OR octet_length(p_handle)<>32 THEN RETURN jsonb_build_object('outcome','invalid_request'); END IF;
  -- Expired reservations stop blocking a new begin; they never revive an old device.
  SELECT * INTO old_c FROM amdn_identity.device_ceremonies WHERE tenant_id=p.tenant_id AND user_id=a.user_id
    AND state IN ('registration','candidate','current','revocation') FOR UPDATE;
  IF FOUND THEN
    PERFORM FROM amdn_identity.devices WHERE tenant_id=p.tenant_id AND device_id IN (old_c.device_id,old_c.target_id) ORDER BY device_id FOR UPDATE;
    IF EXISTS(SELECT FROM amdn_identity.device_challenges WHERE ceremony_id=old_c.ceremony_id AND device_challenges.stage=old_c.state
      AND least(expires_at,old_c.expires_at)<=clock_timestamp()) THEN
      PERFORM amdn_identity.ceremony_terminate(old_c.ceremony_id,'expired');
    ELSE RETURN jsonb_build_object('outcome','conflict'); END IF;
  END IF;
  SELECT * INTO d FROM amdn_identity.devices WHERE tenant_id=p.tenant_id AND user_id=a.user_id AND status='credential_active' FOR UPDATE;
  IF a.valid_until<=clock_timestamp() THEN RETURN jsonb_build_object('outcome','forbidden'); END IF;
  IF a.identity_version<>p_expected OR (p_target IS NULL AND d.device_id IS NOT NULL)
    OR (p_target IS NOT NULL AND (d.device_id IS DISTINCT FROM p_target OR d.rp_id IS DISTINCT FROM a.rp_id))
    OR (p_operation='revocation' AND p_target IS NULL) THEN RETURN jsonb_build_object('outcome','conflict'); END IF;
  mode:=CASE WHEN p_operation='revocation' THEN 'revocation' WHEN p_target IS NULL THEN 'initial' ELSE 'replacement' END;
  next_stage:=CASE WHEN mode='revocation' THEN 'revocation' ELSE 'registration' END;
  IF EXISTS(SELECT FROM amdn_identity.device_challenges WHERE challenge=p_challenge) THEN RETURN jsonb_build_object('outcome','conflict'); END IF;
  IF mode='revocation' THEN device:=d.device_id;
  ELSE
    INSERT INTO amdn_identity.device_subjects(tenant_id,user_id,rp_id,user_handle) VALUES(p.tenant_id,a.user_id,a.rp_id,p_handle)
      ON CONFLICT(tenant_id,user_id,rp_id) DO NOTHING;
    INSERT INTO amdn_identity.devices(tenant_id,user_id,rp_id,configuration_version)
      VALUES(p.tenant_id,a.user_id,a.rp_id,a.configuration_version) RETURNING device_id INTO device;
  END IF;
  now_at:=clock_timestamp();
  INSERT INTO amdn_identity.device_ceremonies(tenant_id,user_id,postman_id,issuer,subject,client_id,origin,configuration_id,
    configuration_version,grant_version,identity_version,membership_version,policy_version,operation,device_id,target_id,device_version,target_version,state,created_at,expires_at)
    VALUES(p.tenant_id,a.user_id,a.postman_id,p.issuer,p.subject,p.client_id,p.origin,p.configuration_id,a.configuration_version,
      a.grant_version,a.identity_version,a.membership_version,a.policy_version,mode,device,p_target,
      CASE WHEN mode='revocation' THEN d.record_version ELSE 1 END, d.record_version,next_stage,now_at,now_at+interval '5 minutes') RETURNING * INTO c;
  INSERT INTO amdn_identity.device_challenges VALUES(c.ceremony_id,next_stage,p_challenge,now_at,now_at+interval '2 minutes',NULL);
  answer:=amdn_identity.ceremony_snapshot(c.ceremony_id);
  INSERT INTO amdn_identity.device_commands(tenant_id,user_id,ceremony_id,stage,scope_id,idempotency_key,request_digest,state,result)
    VALUES(p.tenant_id,a.user_id,c.ceremony_id,command_stage,command_scope,p_key,sha256(p_body),'succeeded',answer) RETURNING * INTO cmd;
  INSERT INTO amdn_identity.device_ceremony_audit(ceremony_id,command_id,action,identity_version) VALUES(c.ceremony_id,cmd.command_id,'begun',a.identity_version);
  RETURN answer;
END $body$;

CREATE FUNCTION amdn_identity.ceremony_reserve(p amdn_identity.ceremony_actor,p_id uuid,p_stage text,p_key text,p_body bytea) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $body$
DECLARE a amdn_identity.ceremony_authority; c amdn_identity.device_ceremonies; cmd amdn_identity.device_commands;
  d amdn_identity.devices; h amdn_identity.device_challenges; count_attempts integer; handle bytea;
BEGIN
  a:=amdn_identity.ceremony_lock(p,p_id);
  IF a.outcome<>'ok' THEN RETURN jsonb_build_object('outcome',a.outcome); END IF;
  IF p_stage IS NULL OR p_stage NOT IN ('registration','candidate','current','revocation') OR p_key IS NULL
    OR octet_length(p_key) NOT BETWEEN 16 AND 128 OR p_key ~ '[^!-~]' OR p_body IS NULL OR octet_length(p_body) NOT BETWEEN 1 AND 65536
    THEN RETURN jsonb_build_object('outcome','invalid_request'); END IF;
  SELECT * INTO c FROM amdn_identity.device_ceremonies WHERE ceremony_id=p_id;
  SELECT * INTO cmd FROM amdn_identity.device_commands WHERE tenant_id=p.tenant_id AND user_id=a.user_id AND stage=p_stage AND scope_id=p_id AND idempotency_key=p_key;
  IF FOUND THEN
    IF cmd.request_digest<>sha256(p_body) THEN RETURN jsonb_build_object('outcome','conflict'); END IF;
    RETURN amdn_identity.ceremony_replay(cmd,c,a);
  END IF;
  IF NOT amdn_identity.ceremony_ready(c,a) OR c.state<>p_stage THEN RETURN jsonb_build_object('outcome','conflict'); END IF;
  SELECT count(*) INTO count_attempts FROM amdn_identity.device_commands WHERE ceremony_id=p_id AND stage=p_stage;
  IF count_attempts>=5 THEN RETURN jsonb_build_object('outcome','unavailable'); END IF;
  SELECT * INTO d FROM amdn_identity.devices WHERE tenant_id=c.tenant_id AND device_id=CASE WHEN p_stage='current' THEN c.target_id ELSE c.device_id END;
  SELECT * INTO h FROM amdn_identity.device_challenges WHERE ceremony_id=p_id AND stage=p_stage;
  SELECT user_handle INTO handle FROM amdn_identity.device_subjects WHERE tenant_id=c.tenant_id AND user_id=c.user_id AND rp_id=d.rp_id;
  INSERT INTO amdn_identity.device_commands(tenant_id,user_id,ceremony_id,stage,scope_id,idempotency_key,request_digest,state,attempt_number,reservation_tx,verified_device_version)
    VALUES(c.tenant_id,c.user_id,p_id,p_stage,p_id,p_key,sha256(p_body),'reserved',count_attempts+1,pg_current_xact_id(),d.record_version) RETURNING * INTO cmd;
  INSERT INTO amdn_identity.device_ceremony_audit(ceremony_id,command_id,action,identity_version) VALUES(p_id,cmd.command_id,'reserved',a.identity_version);
  -- Internal verifier snapshot, not a public HTTP response. Commit before verification.
  RETURN jsonb_build_object('outcome','reserved','attempt_id',cmd.command_id,'request_digest_hex',encode(cmd.request_digest,'hex'),
    'stage',p_stage,'challenge_hex',encode(h.challenge,'hex'),'credential_id_hex',encode(d.credential_id,'hex'),
    'public_key_hex',encode(d.public_key_cose,'hex'),'user_handle_hex',encode(handle,'hex'),'rp_id',d.rp_id,
    'origin',c.origin,'device_version',d.record_version,'backup_eligible',d.backup_eligible,'sign_count',d.sign_count);
END $body$;

CREATE FUNCTION amdn_identity.ceremony_fail(p amdn_identity.ceremony_actor,p_attempt uuid,p_digest bytea,p_outcome text DEFAULT 'invalid_proof') RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $body$
DECLARE a amdn_identity.ceremony_authority; c amdn_identity.device_ceremonies; cmd amdn_identity.device_commands; answer jsonb;
BEGIN
  SELECT * INTO cmd FROM amdn_identity.device_commands WHERE command_id=p_attempt;
  IF NOT FOUND THEN RETURN jsonb_build_object('outcome','not_found'); END IF;
  a:=amdn_identity.ceremony_lock(p,cmd.ceremony_id);
  IF a.outcome<>'ok' THEN RETURN jsonb_build_object('outcome',a.outcome); END IF;
  SELECT * INTO cmd FROM amdn_identity.device_commands WHERE command_id=p_attempt FOR UPDATE;
  IF a.valid_until<=clock_timestamp() THEN RETURN jsonb_build_object('outcome','forbidden'); END IF;
  SELECT * INTO c FROM amdn_identity.device_ceremonies WHERE ceremony_id=cmd.ceremony_id;
  IF cmd.stage NOT IN ('registration','candidate','current','revocation') OR p_digest IS NULL OR p_digest<>cmd.request_digest OR p_outcome IS NULL OR p_outcome NOT IN ('invalid_proof','conflict') THEN RETURN jsonb_build_object('outcome','conflict'); END IF;
  IF cmd.state<>'reserved' THEN RETURN amdn_identity.ceremony_replay(cmd,c,a); END IF;
  IF cmd.reservation_tx=pg_current_xact_id() OR NOT amdn_identity.ceremony_ready(c,a) OR c.state<>cmd.stage THEN RETURN jsonb_build_object('outcome','conflict'); END IF;
  answer:=jsonb_build_object('outcome',p_outcome);
  UPDATE amdn_identity.device_commands SET state='failed',result=answer WHERE command_id=p_attempt;
  INSERT INTO amdn_identity.device_ceremony_audit(ceremony_id,command_id,action,identity_version) VALUES(c.ceremony_id,p_attempt,'failed',a.identity_version);
  IF (SELECT count(*) FROM amdn_identity.device_commands WHERE ceremony_id=c.ceremony_id AND stage=cmd.stage AND state='failed')=5 THEN
    PERFORM amdn_identity.ceremony_terminate(c.ceremony_id,'abandoned');
  END IF;
  RETURN answer;
END $body$;

-- Permit only the trusted owner to make one explicit identity increment.
ALTER TABLE amdn_identity.users ADD CHECK(identity_version<=9007199254740991);
CREATE OR REPLACE FUNCTION amdn_identity.preserve_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $body$
BEGIN
  IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id THEN RAISE EXCEPTION 'Identity is immutable' USING ERRCODE='23514'; END IF;
  IF TG_TABLE_NAME='users' THEN
    IF OLD.user_id IS DISTINCT FROM NEW.user_id THEN RAISE EXCEPTION 'Identity is immutable' USING ERRCODE='23514'; END IF;
    IF OLD.status<>NEW.status THEN NEW.identity_version := OLD.identity_version+1;
    ELSIF NEW.identity_version IS DISTINCT FROM OLD.identity_version THEN
      IF current_user<>'amdn_identity_owner' OR NEW.identity_version<>OLD.identity_version+1 THEN
        RAISE EXCEPTION 'Invalid identity version transition' USING ERRCODE='23514';
      END IF;
    END IF;
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


-- This records a trusted verifier's public projection. It does not verify a signature.
-- The future adapter must bind this projection to the reserved digest and snapshot.
CREATE FUNCTION amdn_identity.ceremony_finish(p amdn_identity.ceremony_actor,p_attempt uuid,p_digest bytea,
  p_credential bytea,p_public_key bytea,p_be boolean,p_bs boolean,p_counter bigint,p_next_challenge bytea DEFAULT NULL) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $body$
DECLARE a amdn_identity.ceremony_authority; c amdn_identity.device_ceremonies; cmd amdn_identity.device_commands;
  d amdn_identity.devices; next_stage text; now_at timestamptz; answer jsonb;
BEGIN
  SELECT * INTO cmd FROM amdn_identity.device_commands WHERE command_id=p_attempt;
  IF NOT FOUND THEN RETURN jsonb_build_object('outcome','not_found'); END IF;
  a:=amdn_identity.ceremony_lock(p,cmd.ceremony_id);
  IF a.outcome<>'ok' THEN RETURN jsonb_build_object('outcome',a.outcome); END IF;
  SELECT * INTO cmd FROM amdn_identity.device_commands WHERE command_id=p_attempt FOR UPDATE;
  IF a.valid_until<=clock_timestamp() THEN RETURN jsonb_build_object('outcome','forbidden'); END IF;
  SELECT * INTO c FROM amdn_identity.device_ceremonies WHERE ceremony_id=cmd.ceremony_id;
  IF cmd.stage NOT IN ('registration','candidate','current','revocation') OR p_digest IS NULL OR p_digest<>cmd.request_digest THEN RETURN jsonb_build_object('outcome','conflict'); END IF;
  IF cmd.state<>'reserved' THEN RETURN amdn_identity.ceremony_replay(cmd,c,a); END IF;
  IF cmd.reservation_tx=pg_current_xact_id() OR NOT amdn_identity.ceremony_ready(c,a) OR c.state<>cmd.stage THEN RETURN jsonb_build_object('outcome','conflict'); END IF;
  SELECT * INTO d FROM amdn_identity.devices WHERE tenant_id=c.tenant_id AND device_id=CASE WHEN cmd.stage='current' THEN c.target_id ELSE c.device_id END;
  IF d.record_version<>cmd.verified_device_version THEN
    PERFORM amdn_identity.ceremony_terminate(c.ceremony_id,'abandoned'); RETURN jsonb_build_object('outcome','conflict');
  END IF;
  next_stage:=CASE WHEN cmd.stage='registration' THEN 'candidate' WHEN cmd.stage='candidate' AND c.operation='replacement' THEN 'current' ELSE 'completed' END;
  IF (next_stage<>'completed' AND (p_next_challenge IS NULL OR octet_length(p_next_challenge)<>32))
    OR (next_stage='completed' AND p_next_challenge IS NOT NULL) THEN RETURN jsonb_build_object('outcome','invalid_request'); END IF;
  IF next_stage<>'completed' AND EXISTS(SELECT FROM amdn_identity.device_challenges WHERE challenge=p_next_challenge) THEN RETURN jsonb_build_object('outcome','conflict'); END IF;
  IF p_credential IS NULL OR p_public_key IS NULL OR p_be IS NULL OR p_bs IS NULL OR p_counter IS NULL
    OR p_counter NOT BETWEEN 0 AND 4294967295 OR (p_bs AND NOT p_be) THEN
    RETURN amdn_identity.ceremony_fail(p,p_attempt,p_digest,'invalid_proof');
  END IF;
  IF cmd.stage<>'registration' AND (p_credential IS DISTINCT FROM d.credential_id OR p_public_key IS DISTINCT FROM d.public_key_cose
    OR p_be IS DISTINCT FROM d.backup_eligible OR ((d.sign_count<>0 OR p_counter<>0) AND p_counter<=d.sign_count)) THEN
    RETURN amdn_identity.ceremony_fail(p,p_attempt,p_digest,'invalid_proof');
  END IF;
  -- Catch only projection constraint failures. Audit or later state-write failures
  -- propagate and roll back every successful-stage effect, leaving the reservation.
  BEGIN
    IF cmd.stage='registration' THEN
      UPDATE amdn_identity.devices SET credential_id=p_credential,public_key_cose=p_public_key,backup_eligible=p_be,backup_state=p_bs,sign_count=p_counter
        WHERE tenant_id=c.tenant_id AND device_id=d.device_id;
    ELSE
      UPDATE amdn_identity.devices SET backup_state=p_bs,sign_count=p_counter WHERE tenant_id=c.tenant_id AND device_id=d.device_id;
    END IF;
  EXCEPTION WHEN unique_violation THEN RETURN amdn_identity.ceremony_fail(p,p_attempt,p_digest,'conflict');
    WHEN check_violation OR not_null_violation THEN RETURN amdn_identity.ceremony_fail(p,p_attempt,p_digest,'invalid_proof');
  END;
  now_at:=clock_timestamp();
  UPDATE amdn_identity.device_challenges SET consumed_at=now_at WHERE ceremony_id=c.ceremony_id AND stage=cmd.stage;
  IF next_stage='completed' THEN
    IF c.target_id IS NOT NULL THEN
      UPDATE amdn_identity.devices SET status='revoked' WHERE tenant_id=c.tenant_id AND device_id=c.target_id;
    END IF;
    IF c.operation<>'revocation' THEN
      UPDATE amdn_identity.devices SET status='credential_active' WHERE tenant_id=c.tenant_id AND device_id=c.device_id;
    END IF;
    UPDATE amdn_identity.users SET identity_version=identity_version+1 WHERE tenant_id=c.tenant_id AND user_id=c.user_id;
    UPDATE amdn_identity.device_ceremonies SET state='completed',completed_at=now_at,committed_identity_version=a.identity_version+1 WHERE ceremony_id=c.ceremony_id;
  ELSE
    INSERT INTO amdn_identity.device_challenges(ceremony_id,stage,challenge,issued_at,expires_at)
      VALUES(c.ceremony_id,next_stage,p_next_challenge,now_at,least(now_at+interval '2 minutes',c.expires_at));
    UPDATE amdn_identity.device_ceremonies SET state=next_stage WHERE ceremony_id=c.ceremony_id;
  END IF;
  UPDATE amdn_identity.device_ceremonies SET
    device_version=(SELECT record_version FROM amdn_identity.devices WHERE tenant_id=c.tenant_id AND device_id=c.device_id),
    target_version=(SELECT record_version FROM amdn_identity.devices WHERE tenant_id=c.tenant_id AND device_id=c.target_id)
    WHERE ceremony_id=c.ceremony_id;
  answer:=amdn_identity.ceremony_snapshot(c.ceremony_id);
  UPDATE amdn_identity.device_commands SET state='succeeded',result=answer WHERE command_id=p_attempt;
  INSERT INTO amdn_identity.device_ceremony_audit(ceremony_id,command_id,action,identity_version)
    VALUES(c.ceremony_id,p_attempt,cmd.stage,a.identity_version+CASE WHEN next_stage='completed' THEN 1 ELSE 0 END);
  RETURN answer;
END $body$;

-- No new application privileges. These INVOKER functions remain migration-owner
-- only until a reviewed authenticated verifier and narrow execution role exist.
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA amdn_identity FROM PUBLIC;
REVOKE ALL ON TYPE amdn_identity.ceremony_actor,amdn_identity.ceremony_authority FROM PUBLIC;
