-- Synthetic test model only. This is not an application migration.
CREATE ROLE harness_owner NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE harness_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
  NOINHERIT PASSWORD '__APP_PASSWORD__';
REVOKE ALL ON DATABASE amdn_harness FROM PUBLIC;
GRANT CONNECT ON DATABASE amdn_harness TO harness_app;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA fixture AUTHORIZATION harness_owner;
GRANT USAGE ON SCHEMA fixture TO harness_app;
SET ROLE harness_owner;
CREATE TABLE fixture.run_metadata (run_id text PRIMARY KEY);
INSERT INTO fixture.run_metadata VALUES ('__RUN_ID__');
CREATE TABLE fixture.users (
  tenant_id uuid NOT NULL, user_id uuid NOT NULL,
  PRIMARY KEY (tenant_id, user_id)
);
CREATE TABLE fixture.envelopes (
  tenant_id uuid NOT NULL, user_id uuid NOT NULL, envelope_id uuid NOT NULL,
  recipient_tenant uuid NOT NULL, recipient_user uuid NOT NULL,
  ciphertext bytea NOT NULL,
  PRIMARY KEY (tenant_id, user_id, envelope_id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES fixture.users,
  FOREIGN KEY (recipient_tenant, recipient_user) REFERENCES fixture.users
);
CREATE TABLE fixture.outbox (
  tenant_id uuid NOT NULL, user_id uuid NOT NULL, event_id uuid NOT NULL,
  envelope_id uuid NOT NULL, published boolean NOT NULL DEFAULT false,
  PRIMARY KEY (tenant_id, user_id, event_id),
  FOREIGN KEY (tenant_id, user_id, envelope_id) REFERENCES fixture.envelopes
);
CREATE TABLE fixture.inbox (
  tenant_id uuid NOT NULL, user_id uuid NOT NULL, envelope_id uuid NOT NULL,
  ciphertext bytea NOT NULL, device_acked boolean NOT NULL DEFAULT false,
  PRIMARY KEY (tenant_id, user_id, envelope_id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES fixture.users
);
CREATE TABLE fixture.processed_events (
  tenant_id uuid NOT NULL, user_id uuid NOT NULL, event_id uuid NOT NULL,
  PRIMARY KEY (tenant_id, user_id, event_id),
  FOREIGN KEY (tenant_id, user_id) REFERENCES fixture.users
);
DO $body$
DECLARE tab text;
BEGIN
  FOREACH tab IN ARRAY ARRAY['users','envelopes','outbox','inbox','processed_events'] LOOP
    EXECUTE format('ALTER TABLE fixture.%I ENABLE ROW LEVEL SECURITY', tab);
    EXECUTE format('ALTER TABLE fixture.%I FORCE ROW LEVEL SECURITY', tab);
    EXECUTE format($policy$CREATE POLICY scope ON fixture.%I TO harness_app
      USING (tenant_id = nullif(current_setting('amdn.tenant_id', true), '')::uuid
        AND user_id = nullif(current_setting('amdn.user_id', true), '')::uuid)
      WITH CHECK (tenant_id = nullif(current_setting('amdn.tenant_id', true), '')::uuid
        AND user_id = nullif(current_setting('amdn.user_id', true), '')::uuid)$policy$, tab);
  END LOOP;
END $body$;
GRANT SELECT ON fixture.users, fixture.run_metadata TO harness_app;
GRANT SELECT, INSERT, UPDATE ON fixture.envelopes, fixture.outbox,
  fixture.inbox, fixture.processed_events TO harness_app;
RESET ROLE;
-- Bootstrap only; runtime tests never receive the bootstrap login.
INSERT INTO fixture.users VALUES
 ('10000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001'),
 ('10000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002'),
 ('20000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000003'),
 ('20000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000004');
