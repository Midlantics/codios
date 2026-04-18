-- Codios schema — VPC / self-hosted edition
-- Identical table structure to schema.sql.
-- No Supabase-specific roles, no RLS (application layer handles authorization).
-- Applied automatically on startup when VPC_MODE=true.

CREATE SCHEMA IF NOT EXISTS codios;

-- ── Organizations ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS codios.organizations (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL DEFAULT 'My Organization',
  plan        TEXT NOT NULL DEFAULT 'enterprise' CHECK (plan IN ('free','starter','pro','enterprise')),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Agents ────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS codios.agents (
  id           TEXT PRIMARY KEY DEFAULT 'agt_' || replace(gen_random_uuid()::text, '-', ''),
  org_id       TEXT NOT NULL REFERENCES codios.organizations(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  description  TEXT NOT NULL DEFAULT '',
  did          TEXT UNIQUE NOT NULL,
  public_key   TEXT NOT NULL,
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
  payload           JSONB NOT NULL DEFAULT '{}',
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

-- ── Subscriptions ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS codios.subscriptions (
  org_id      TEXT PRIMARY KEY REFERENCES codios.organizations(id) ON DELETE CASCADE,
  plan        TEXT NOT NULL DEFAULT 'enterprise' CHECK (plan IN ('free','starter','pro','enterprise')),
  status      TEXT NOT NULL DEFAULT 'active',
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Custom Policies ───────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS codios.custom_policies (
  id               TEXT PRIMARY KEY DEFAULT 'pol_' || replace(gen_random_uuid()::text, '-', ''),
  org_id           TEXT NOT NULL REFERENCES codios.organizations(id) ON DELETE CASCADE,
  name             TEXT NOT NULL,
  description      TEXT NOT NULL DEFAULT '',
  rego_source      TEXT NOT NULL,
  active           BOOLEAN NOT NULL DEFAULT FALSE,
  last_tested_at   TIMESTAMPTZ,
  last_test_result JSONB,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS codios_policies_org ON codios.custom_policies(org_id);

-- ── Alert Rules ───────────────────────────────────────────────────────────────

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

-- ── Audit immutability trigger ───────────────────────────────────────────────
-- Prevents UPDATE and DELETE on audit_logs at the DB level (ISO A.12.4).

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

-- ── Denial spike check ────────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION codios.denial_spike_check(p_since TIMESTAMPTZ, p_threshold INTEGER)
RETURNS TABLE(org_id TEXT, denial_count BIGINT, agent_ids TEXT[])
LANGUAGE SQL AS $$
  SELECT
    org_id,
    COUNT(*)                             AS denial_count,
    ARRAY_AGG(DISTINCT issuer_agent_id)  AS agent_ids
  FROM codios.audit_logs
  WHERE outcome = 'denied'
    AND created_at >= p_since
  GROUP BY org_id
  HAVING COUNT(*) >= p_threshold;
$$;

-- ── VPC bootstrap: default org + subscription ─────────────────────────────────
-- Creates a single org on first run. API keys are created via POST /keys.

INSERT INTO codios.organizations (id, name, plan)
VALUES ('vpc-default-org', 'My Organization', 'enterprise')
ON CONFLICT (id) DO NOTHING;

INSERT INTO codios.subscriptions (org_id, plan, status)
VALUES ('vpc-default-org', 'enterprise', 'active')
ON CONFLICT (org_id) DO NOTHING;
