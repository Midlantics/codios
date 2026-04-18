-- Codios schema — A2A Agent Security Layer
-- Shares the same Supabase instance as the a2a schema.
-- Run in Supabase SQL editor OR auto-applied by backend on startup.

CREATE SCHEMA IF NOT EXISTS codios;

-- ── Organizations ─────────────────────────────────────────────────────────────
-- org_id = Supabase user UUID (same as a2a workspace_id pattern)

CREATE TABLE IF NOT EXISTS codios.organizations (
  id          TEXT PRIMARY KEY,   -- Supabase user UUID
  name        TEXT NOT NULL DEFAULT 'My Organization',
  plan        TEXT NOT NULL DEFAULT 'free' CHECK (plan IN ('free','starter','pro','enterprise')),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Agents ────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS codios.agents (
  id           TEXT PRIMARY KEY DEFAULT 'agt_' || replace(gen_random_uuid()::text, '-', ''),
  org_id       TEXT NOT NULL REFERENCES codios.organizations(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  description  TEXT NOT NULL DEFAULT '',
  did          TEXT UNIQUE NOT NULL,      -- did:key:z6Mk... (Ed25519 DID)
  public_key   TEXT NOT NULL,             -- raw Ed25519 public key, base64
  capabilities TEXT[] NOT NULL DEFAULT '{}',
  agent_card   JSONB NOT NULL DEFAULT '{}',
  status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','revoked')),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS codios_agents_org    ON codios.agents(org_id);
CREATE INDEX IF NOT EXISTS codios_agents_did    ON codios.agents(did);
CREATE INDEX IF NOT EXISTS codios_agents_status ON codios.agents(org_id, status);

-- ── Contracts ─────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS codios.contracts (
  id                TEXT PRIMARY KEY DEFAULT 'ctr_' || replace(gen_random_uuid()::text, '-', ''),
  org_id            TEXT NOT NULL REFERENCES codios.organizations(id) ON DELETE CASCADE,
  issuer_agent_id   TEXT NOT NULL REFERENCES codios.agents(id),
  target_agent_id   TEXT NOT NULL REFERENCES codios.agents(id),
  allowed_actions   TEXT[] NOT NULL,
  forbidden_actions TEXT[] NOT NULL DEFAULT '{}',
  resource_limits   JSONB NOT NULL DEFAULT '{}',
  nonce             TEXT UNIQUE NOT NULL,
  signature         TEXT NOT NULL,
  payload           JSONB NOT NULL DEFAULT '{}',   -- full signed contract JSON
  status            TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked','expired')),
  issued_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at        TIMESTAMPTZ NOT NULL,
  revoked_at        TIMESTAMPTZ,
  revoke_reason     TEXT
);

CREATE INDEX IF NOT EXISTS codios_contracts_org     ON codios.contracts(org_id);
CREATE INDEX IF NOT EXISTS codios_contracts_issuer  ON codios.contracts(issuer_agent_id);
CREATE INDEX IF NOT EXISTS codios_contracts_target  ON codios.contracts(target_agent_id);
CREATE INDEX IF NOT EXISTS codios_contracts_status  ON codios.contracts(org_id, status);
CREATE INDEX IF NOT EXISTS codios_contracts_expires ON codios.contracts(expires_at);

-- ── Audit Logs ────────────────────────────────────────────────────────────────
-- Append-only: rules prevent UPDATE and DELETE

CREATE TABLE IF NOT EXISTS codios.audit_logs (
  id              BIGSERIAL PRIMARY KEY,
  org_id          TEXT NOT NULL REFERENCES codios.organizations(id),
  contract_id     TEXT REFERENCES codios.contracts(id) ON DELETE SET NULL,
  issuer_agent_id TEXT REFERENCES codios.agents(id) ON DELETE SET NULL,
  target_agent_id TEXT REFERENCES codios.agents(id) ON DELETE SET NULL,
  action          TEXT NOT NULL,
  outcome         TEXT NOT NULL CHECK (outcome IN ('allowed','denied','error')),
  deny_reason     TEXT,
  payload_hash    TEXT,
  ip_address      TEXT,
  duration_ms     INTEGER,
  metadata        JSONB NOT NULL DEFAULT '{}',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS codios_audit_org      ON codios.audit_logs(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS codios_audit_contract ON codios.audit_logs(contract_id);
CREATE INDEX IF NOT EXISTS codios_audit_outcome  ON codios.audit_logs(org_id, outcome, created_at DESC);

-- ── Nonces ────────────────────────────────────────────────────────────────────
-- Replay protection fallback (primary is Redis; this is the Postgres fallback)

CREATE TABLE IF NOT EXISTS codios.nonces (
  nonce       TEXT PRIMARY KEY,
  contract_id TEXT NOT NULL,
  consumed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS codios_nonces_expires ON codios.nonces(expires_at);

-- ── API Keys ──────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS codios.api_keys (
  id           TEXT PRIMARY KEY DEFAULT 'key_' || replace(gen_random_uuid()::text, '-', ''),
  org_id       TEXT NOT NULL REFERENCES codios.organizations(id) ON DELETE CASCADE,
  agent_id     TEXT REFERENCES codios.agents(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  key_hash     TEXT NOT NULL UNIQUE,
  last_used_at TIMESTAMPTZ,
  revoked      BOOLEAN NOT NULL DEFAULT FALSE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS codios_api_keys_org   ON codios.api_keys(org_id);
CREATE INDEX IF NOT EXISTS codios_api_keys_hash  ON codios.api_keys(key_hash) WHERE revoked = false;
CREATE INDEX IF NOT EXISTS codios_api_keys_agent ON codios.api_keys(agent_id);

-- ── Row Level Security ────────────────────────────────────────────────────────

ALTER TABLE codios.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE codios.agents        ENABLE ROW LEVEL SECURITY;
ALTER TABLE codios.contracts     ENABLE ROW LEVEL SECURITY;
ALTER TABLE codios.audit_logs    ENABLE ROW LEVEL SECURITY;
ALTER TABLE codios.nonces        ENABLE ROW LEVEL SECURITY;
ALTER TABLE codios.api_keys      ENABLE ROW LEVEL SECURITY;

CREATE POLICY "service_role_all" ON codios.organizations FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_all" ON codios.agents        FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_all" ON codios.contracts     FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_all" ON codios.audit_logs    FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_all" ON codios.nonces        FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_all" ON codios.api_keys      FOR ALL TO service_role USING (true) WITH CHECK (true);


----Make it readable from external, 


  GRANT USAGE ON SCHEMA codios TO anon, authenticated, service_role;
  GRANT ALL ON ALL TABLES IN SCHEMA codios TO anon, authenticated,
  service_role;                                                               
  GRANT ALL ON ALL SEQUENCES IN SCHEMA codios TO anon, authenticated,
  service_role;                                                               
  GRANT ALL ON ALL FUNCTIONS IN SCHEMA codios TO anon, authenticated,
  service_role;                                                               
  
  -- Make sure future objects in this schema also get these grants            
  ALTER DEFAULT PRIVILEGES IN SCHEMA codios                
    GRANT ALL ON TABLES TO anon, authenticated, service_role;                 
  ALTER DEFAULT PRIVILEGES IN SCHEMA codios
    GRANT ALL ON SEQUENCES TO anon, authenticated, service_role;              
  ALTER DEFAULT PRIVILEGES IN SCHEMA codios                                  
    GRANT ALL ON FUNCTIONS TO anon, authenticated, service_role;
    

---  Add CODIOS in Project>Settings>Integration>Data API, Exposed schemas and Extra search path
-- ── Subscriptions ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS codios.subscriptions (
  org_id                   TEXT PRIMARY KEY REFERENCES codios.organizations(id) ON DELETE CASCADE,
  plan                     TEXT NOT NULL DEFAULT 'free' CHECK (plan IN ('free','starter','pro','enterprise')),
  status                   TEXT NOT NULL DEFAULT 'active',
  stripe_customer_id       TEXT,
  stripe_subscription_id   TEXT,
  current_period_end       TIMESTAMPTZ,
  updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Custom Policies ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS codios.custom_policies (
  id          TEXT PRIMARY KEY DEFAULT 'pol_' || replace(gen_random_uuid()::text, '-', ''),
  org_id      TEXT NOT NULL REFERENCES codios.organizations(id) ON DELETE CASCADE,
  name        TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  rego_source TEXT NOT NULL,
  active      BOOLEAN NOT NULL DEFAULT FALSE,
  last_tested_at  TIMESTAMPTZ,
  last_test_result JSONB,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS codios_policies_org ON codios.custom_policies(org_id);

ALTER TABLE codios.custom_policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all" ON codios.custom_policies FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── Alert Rules ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS codios.alert_rules (
  id               TEXT PRIMARY KEY DEFAULT 'alr_' || replace(gen_random_uuid()::text, '-', ''),
  org_id           TEXT NOT NULL REFERENCES codios.organizations(id) ON DELETE CASCADE,
  name             TEXT NOT NULL,
  condition_type   TEXT NOT NULL DEFAULT 'denial_spike'
                   CHECK (condition_type IN ('denial_spike', 'rate_limit_exceeded')),
  threshold        INTEGER NOT NULL DEFAULT 10,
  window_minutes   INTEGER NOT NULL DEFAULT 5,
  cooldown_minutes INTEGER NOT NULL DEFAULT 15,
  notify_emails    TEXT[] NOT NULL DEFAULT '{}',
  enabled          BOOLEAN NOT NULL DEFAULT TRUE,
  last_fired_at    TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS codios_alert_rules_org ON codios.alert_rules(org_id);

ALTER TABLE codios.alert_rules ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all" ON codios.alert_rules FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── Audit immutability trigger ───────────────────────────────────────────────

CREATE OR REPLACE FUNCTION codios.audit_logs_immutable()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs is append-only — UPDATE and DELETE are not permitted';
END;
$$;

DROP TRIGGER IF EXISTS audit_logs_no_update ON codios.audit_logs;
CREATE TRIGGER audit_logs_no_update
  BEFORE UPDATE ON codios.audit_logs
  FOR EACH ROW EXECUTE FUNCTION codios.audit_logs_immutable();

DROP TRIGGER IF EXISTS audit_logs_no_delete ON codios.audit_logs;
CREATE TRIGGER audit_logs_no_delete
  BEFORE DELETE ON codios.audit_logs
  FOR EACH ROW EXECUTE FUNCTION codios.audit_logs_immutable();

-- ── Audit export manifest ─────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS codios.audit_exports (
  id           TEXT PRIMARY KEY DEFAULT 'exp_' || replace(gen_random_uuid()::text, '-', ''),
  org_id       TEXT NOT NULL REFERENCES codios.organizations(id) ON DELETE CASCADE,
  from_date    TIMESTAMPTZ NOT NULL,
  to_date      TIMESTAMPTZ NOT NULL,
  row_count    BIGINT NOT NULL DEFAULT 0,
  sha256_hash  TEXT NOT NULL,
  format       TEXT NOT NULL DEFAULT 'jsonl' CHECK (format IN ('jsonl', 'csv')),
  s3_key       TEXT,
  s3_url       TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS codios_audit_exports_org ON codios.audit_exports(org_id, created_at DESC);
ALTER TABLE codios.audit_exports ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all" ON codios.audit_exports FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── Denial spike check function ────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION codios.denial_spike_check(p_since TIMESTAMPTZ, p_threshold INTEGER)
RETURNS TABLE(org_id TEXT, denial_count BIGINT, agent_ids TEXT[])
LANGUAGE SQL AS $$
  SELECT
    org_id,
    COUNT(*)                          AS denial_count,
    ARRAY_AGG(DISTINCT issuer_agent_id) AS agent_ids
  FROM codios.audit_logs
  WHERE outcome = 'denied'
    AND created_at >= p_since
  GROUP BY org_id
  HAVING COUNT(*) >= p_threshold;
$$;

-- ── Org Members ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS codios.org_members (
  id                TEXT PRIMARY KEY DEFAULT 'mem_' || replace(gen_random_uuid()::text, '-', ''),
  org_id            TEXT NOT NULL REFERENCES codios.organizations(id) ON DELETE CASCADE,
  user_id           TEXT,
  email             TEXT NOT NULL,
  role              TEXT NOT NULL DEFAULT 'member'
                    CHECK (role IN ('owner','admin','member','viewer')),
  status            TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','active')),
  invite_token      TEXT UNIQUE,
  invite_expires_at TIMESTAMPTZ,
  invited_by        TEXT,
  joined_at         TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS codios_org_members_user_uniq
  ON codios.org_members(org_id, user_id) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS codios_org_members_email_uniq
  ON codios.org_members(org_id, email);
CREATE INDEX IF NOT EXISTS codios_org_members_user
  ON codios.org_members(user_id) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS codios_org_members_token
  ON codios.org_members(invite_token) WHERE invite_token IS NOT NULL;

ALTER TABLE codios.org_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all" ON codios.org_members FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ── SSO Configs ───────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS codios.sso_configs (
  id             TEXT PRIMARY KEY DEFAULT 'sso_' || replace(gen_random_uuid()::text, '-', ''),
  org_id         TEXT NOT NULL REFERENCES codios.organizations(id) ON DELETE CASCADE UNIQUE,
  provider_name  TEXT NOT NULL DEFAULT 'OIDC',
  issuer_url     TEXT NOT NULL,
  client_id      TEXT NOT NULL,
  client_secret  TEXT NOT NULL,
  enabled        BOOLEAN NOT NULL DEFAULT TRUE,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE codios.sso_configs ENABLE ROW LEVEL SECURITY;
CREATE POLICY IF NOT EXISTS "service_role_all" ON codios.sso_configs FOR ALL TO service_role USING (true) WITH CHECK (true);
