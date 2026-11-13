-- Execute-only application boundary. Applied migrations 001-004 remain unchanged.
CREATE SCHEMA amdn_enrollment AUTHORIZATION amdn_identity_owner;
REVOKE ALL ON SCHEMA amdn_enrollment FROM PUBLIC;
GRANT USAGE ON SCHEMA amdn_identity,amdn_enrollment TO amdn_identity_enrollment,amdn_identity_ceremony_executor;
GRANT USAGE ON TYPE amdn_identity.ceremony_actor TO amdn_identity_enrollment,amdn_identity_ceremony_executor;
GRANT USAGE ON TYPE amdn_identity.ceremony_authority TO amdn_identity_ceremony_executor;

-- Bootstrap only the selected external subject's context before scoped RLS runs.
-- The executor cannot call resolve_membership or arbitrarily scan the identity tables.
CREATE FUNCTION amdn_identity.enrollment_context(p amdn_identity.ceremony_actor) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $body$
DECLARE local_user uuid;
BEGIN
  PERFORM set_config('amdn.tenant_id','',true),set_config('amdn.user_id','',true),
    set_config('amdn.issuer','',true),set_config('amdn.subject','',true),set_config('amdn.configuration_id','',true);
  SELECT m.user_id INTO local_user FROM amdn_identity.memberships m
    JOIN amdn_identity.users u USING(tenant_id,user_id) JOIN amdn_identity.tenants t USING(tenant_id)
    WHERE m.tenant_id=p.tenant_id AND m.issuer=p.issuer AND m.subject=p.subject
      AND m.status='active' AND u.status='active' AND t.status='active';
  IF NOT FOUND THEN RETURN false; END IF;
  PERFORM set_config('amdn.tenant_id',p.tenant_id::text,true),set_config('amdn.user_id',local_user::text,true),
    set_config('amdn.issuer',p.issuer,true),set_config('amdn.subject',p.subject,true),
    set_config('amdn.configuration_id',coalesce(p.configuration_id::text,''),true);
  RETURN true;
END $body$;
REVOKE ALL ON FUNCTION amdn_identity.enrollment_context(amdn_identity.ceremony_actor) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION amdn_identity.enrollment_context(amdn_identity.ceremony_actor),
  amdn_identity.active_context(uuid,uuid) TO amdn_identity_ceremony_executor;

-- Executor is neither a table owner nor BYPASSRLS. Its policies never grant
-- cross-tenant or cross-user access, including to grants and historical devices.
CREATE POLICY ceremony_executor ON amdn_identity.tenants TO amdn_identity_ceremony_executor
  USING(amdn_identity.active_context(tenant_id,nullif(current_setting('amdn.user_id',true),'')::uuid));
CREATE POLICY ceremony_executor ON amdn_identity.postmen TO amdn_identity_ceremony_executor
  USING(amdn_identity.active_context(tenant_id,owner_user_id));
DO $policies$
DECLARE tab text;
BEGIN
  FOREACH tab IN ARRAY ARRAY['users','memberships','device_subjects','devices','device_management_grants','device_ceremonies','device_commands'] LOOP
    EXECUTE format('CREATE POLICY ceremony_executor ON amdn_identity.%I TO amdn_identity_ceremony_executor USING(amdn_identity.active_context(tenant_id,user_id)) WITH CHECK(amdn_identity.active_context(tenant_id,user_id))',tab);
  END LOOP;
  FOREACH tab IN ARRAY ARRAY['device_challenges','device_ceremony_audit'] LOOP
    EXECUTE format('CREATE POLICY ceremony_executor ON amdn_identity.%I TO amdn_identity_ceremony_executor USING(EXISTS(SELECT FROM amdn_identity.device_ceremonies c WHERE c.ceremony_id=%I.ceremony_id)) WITH CHECK(EXISTS(SELECT FROM amdn_identity.device_ceremonies c WHERE c.ceremony_id=%I.ceremony_id))',tab,tab,tab);
  END LOOP;
END $policies$;
CREATE POLICY ceremony_executor ON amdn_identity.device_configurations TO amdn_identity_ceremony_executor
  USING(configuration_id=nullif(current_setting('amdn.configuration_id',true),'')::uuid);

GRANT SELECT ON amdn_identity.tenants,amdn_identity.users,amdn_identity.memberships,amdn_identity.postmen,
  amdn_identity.device_subjects,amdn_identity.devices,amdn_identity.device_configurations,
  amdn_identity.device_management_grants,amdn_identity.device_ceremonies,amdn_identity.device_challenges,
  amdn_identity.device_commands,amdn_identity.device_ceremony_audit TO amdn_identity_ceremony_executor;
GRANT INSERT ON amdn_identity.device_subjects,amdn_identity.devices,amdn_identity.device_ceremonies,
  amdn_identity.device_challenges,amdn_identity.device_commands,amdn_identity.device_ceremony_audit TO amdn_identity_ceremony_executor;
-- PostgreSQL row-locking SELECT requires UPDATE on at least one column. These
-- identity columns are never updated by ceremony code; existing triggers retain them.
GRANT UPDATE(tenant_id) ON amdn_identity.tenants,amdn_identity.memberships,amdn_identity.postmen,amdn_identity.device_management_grants TO amdn_identity_ceremony_executor;
GRANT UPDATE(configuration_id) ON amdn_identity.device_configurations TO amdn_identity_ceremony_executor;
GRANT UPDATE(identity_version) ON amdn_identity.users TO amdn_identity_ceremony_executor;
GRANT UPDATE(credential_id,public_key_cose,backup_eligible,backup_state,sign_count,status) ON amdn_identity.devices TO amdn_identity_ceremony_executor;
GRANT UPDATE(consumed_at) ON amdn_identity.device_challenges TO amdn_identity_ceremony_executor;
GRANT UPDATE(state,completed_at,committed_identity_version,device_version,target_version) ON amdn_identity.device_ceremonies TO amdn_identity_ceremony_executor;
GRANT UPDATE(state,result) ON amdn_identity.device_commands TO amdn_identity_ceremony_executor;

-- Explicit helper allowlist, not a grant on all present/future schema functions.
GRANT EXECUTE ON FUNCTION
  amdn_identity.ceremony_authorize(amdn_identity.ceremony_actor),
  amdn_identity.ceremony_lock(amdn_identity.ceremony_actor,uuid),
  amdn_identity.ceremony_terminate(uuid,text),
  amdn_identity.ceremony_ready(amdn_identity.device_ceremonies,amdn_identity.ceremony_authority),
  amdn_identity.ceremony_snapshot(uuid),
  amdn_identity.ceremony_replay(amdn_identity.device_commands,amdn_identity.device_ceremonies,amdn_identity.ceremony_authority),
  amdn_identity.ceremony_begin(amdn_identity.ceremony_actor,text,bigint,uuid,text,bytea,bytea,bytea),
  amdn_identity.ceremony_reserve(amdn_identity.ceremony_actor,uuid,text,text,bytea),
  amdn_identity.ceremony_fail(amdn_identity.ceremony_actor,uuid,bytea,text),
  amdn_identity.ceremony_finish(amdn_identity.ceremony_actor,uuid,bytea,bytea,bytea,boolean,boolean,bigint,bytea)
  TO amdn_identity_ceremony_executor;

CREATE FUNCTION amdn_enrollment.begin(p amdn_identity.ceremony_actor,operation text,expected bigint,target uuid,
  key text,body bytea,challenge bytea,handle bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $body$
BEGIN
  IF NOT amdn_identity.enrollment_context(p) THEN RETURN jsonb_build_object('outcome','forbidden'); END IF;
  RETURN amdn_identity.ceremony_begin(p,operation,expected,target,key,body,challenge,handle);
END $body$;
CREATE FUNCTION amdn_enrollment.reserve(p amdn_identity.ceremony_actor,id uuid,stage text,key text,body bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $body$
DECLARE answer jsonb; operation text;
BEGIN
  IF NOT amdn_identity.enrollment_context(p) THEN RETURN jsonb_build_object('outcome','forbidden'); END IF;
  answer:=amdn_identity.ceremony_reserve(p,id,stage,key,body);
  IF answer->>'outcome'='reserved' THEN
    SELECT c.operation INTO STRICT operation FROM amdn_identity.device_ceremonies c WHERE ceremony_id=id;
    answer:=answer||jsonb_build_object('next_challenge_required',stage='registration' OR (stage='candidate' AND operation='replacement'));
  END IF;
  RETURN answer;
END $body$;
CREATE FUNCTION amdn_enrollment.finish(p amdn_identity.ceremony_actor,attempt uuid,digest bytea,
  credential bytea,public_key bytea,be boolean,bs boolean,counter bigint,next_challenge bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $body$
BEGIN
  IF NOT amdn_identity.enrollment_context(p) THEN RETURN jsonb_build_object('outcome','forbidden'); END IF;
  RETURN amdn_identity.ceremony_finish(p,attempt,digest,credential,public_key,be,bs,counter,next_challenge);
END $body$;
CREATE FUNCTION amdn_enrollment.fail(p amdn_identity.ceremony_actor,attempt uuid,digest bytea) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $body$
BEGIN
  IF NOT amdn_identity.enrollment_context(p) THEN RETURN jsonb_build_object('outcome','forbidden'); END IF;
  RETURN amdn_identity.ceremony_fail(p,attempt,digest);
END $body$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA amdn_enrollment FROM PUBLIC;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA amdn_enrollment TO amdn_identity_enrollment,amdn_identity_owner;
-- Ownership transfer is confined to this atomic deployment transaction.
GRANT CREATE ON SCHEMA amdn_enrollment TO amdn_identity_ceremony_executor;
ALTER FUNCTION amdn_enrollment.begin(amdn_identity.ceremony_actor,text,bigint,uuid,text,bytea,bytea,bytea) OWNER TO amdn_identity_ceremony_executor;
ALTER FUNCTION amdn_enrollment.reserve(amdn_identity.ceremony_actor,uuid,text,text,bytea) OWNER TO amdn_identity_ceremony_executor;
ALTER FUNCTION amdn_enrollment.finish(amdn_identity.ceremony_actor,uuid,bytea,bytea,bytea,boolean,boolean,bigint,bytea) OWNER TO amdn_identity_ceremony_executor;
ALTER FUNCTION amdn_enrollment.fail(amdn_identity.ceremony_actor,uuid,bytea) OWNER TO amdn_identity_ceremony_executor;
REVOKE CREATE ON SCHEMA amdn_enrollment FROM amdn_identity_ceremony_executor;
-- ALTER OWNER rewrites the old owner's ACL entry; retain explicit migration-test
-- access after transfer, without making applications members of the executor.
SET LOCAL ROLE amdn_identity_ceremony_executor;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA amdn_enrollment TO amdn_identity_owner;
SET LOCAL ROLE amdn_identity_owner;

-- Permit the scoped executor the same exactly-once identity increment.
CREATE OR REPLACE FUNCTION amdn_identity.preserve_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $body$
BEGIN
  IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id THEN RAISE EXCEPTION 'Identity is immutable' USING ERRCODE='23514'; END IF;
  IF TG_TABLE_NAME='users' THEN
    IF OLD.user_id IS DISTINCT FROM NEW.user_id THEN RAISE EXCEPTION 'Identity is immutable' USING ERRCODE='23514'; END IF;
    IF OLD.status<>NEW.status THEN NEW.identity_version := OLD.identity_version+1;
    ELSIF NEW.identity_version IS DISTINCT FROM OLD.identity_version THEN
      IF current_user NOT IN ('amdn_identity_owner','amdn_identity_ceremony_executor') OR NEW.identity_version<>OLD.identity_version+1 THEN
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
