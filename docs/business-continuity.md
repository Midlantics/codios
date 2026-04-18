# Business Continuity Plan (ISO 27001 A.17)

**Owner:** Midlantics Engineering  
**Review cycle:** Annual (next review: 2027-04)  
**Version:** 1.0 — 2026-04

---

## 1. Objectives

| Metric | SaaS target | VPC self-hosted |
|--------|-------------|-----------------|
| **RTO** (Recovery Time Objective) | < 1 hour | Set by customer |
| **RPO** (Recovery Point Objective) | < 5 minutes | Set by customer |
| **Uptime target** | 99.9% monthly | N/A |

---

## 2. System components and dependencies

| Component | Provider | Criticality |
|-----------|----------|-------------|
| API server | Railway (auto-restart, auto-deploy) | Critical |
| Database (PostgreSQL) | Supabase | Critical |
| Frontend | Vercel | High |
| Redis (rate-limit cache) | Railway | Medium — degrades gracefully without it |
| Email (invite + alerts) | Resend / SMTP fallback | Low — invite URL returned in API response |
| Object storage (audit export) | AWS S3 | Low — streaming download available |

---

## 3. Backup strategy

### Database (Supabase)
- **Point-in-time recovery (PITR):** enabled — 7-day window on Pro plan, 30-day on Team/Enterprise
- **Daily automated backups:** retained for 30 days
- **Manual snapshots:** taken before every major schema migration
- **How to restore:** Supabase dashboard → Project → Backups → select restore point

### Audit logs
- Append-only Postgres table with immutability trigger (no UPDATE/DELETE permitted at DB level)
- Daily automated JSONL export to S3 with SHA-256 integrity hash (if `S3_AUDIT_BUCKET` configured)
- S3 Object Lock (WORM) retention: 7 years when `S3_OBJECT_LOCK=true`

### Configuration / secrets
- Stored in Railway environment variables (encrypted at rest by Railway)
- Owner maintains an offline copy in a password manager (1Password / Bitwarden)
- Ed25519 signing keypair and BYOK key must be rotated and re-backed-up after any suspected compromise

---

## 4. Recovery procedures

### 4.1 API server failure (Railway crash / OOM)

Railway restarts automatically. If restart loop:

```bash
# 1. Check logs
railway logs --tail 200

# 2. Identify cause (schema migration, missing env var, import error)
# 3. Push fix to main → Railway auto-deploys

# Last-resort: roll back to previous deployment
# Railway dashboard → Deployments → select previous → Redeploy
```

**Expected RTO:** 5–15 minutes (auto-restart) / 30 minutes (manual rollback)

### 4.2 Database unavailability (Supabase incident)

```
1. Monitor: https://status.supabase.com
2. API returns 503 — no data loss, stateless request processing fails gracefully
3. On restore: verify schema integrity
   SELECT COUNT(*) FROM codios.audit_logs;
   SELECT COUNT(*) FROM codios.contracts WHERE status='active';
4. Re-run schema migration if needed:
   VPC_MODE=true python -c "import asyncio; from main import _apply_schema; asyncio.run(_apply_schema())"
```

**Expected RTO:** Follows Supabase SLA (99.9% uptime). Customer RPO: 5 min (PITR).

### 4.3 Redis unavailability

Redis is used for rate-limiting only. The API degrades gracefully — requests proceed without rate-limit enforcement. No data loss. Redis auto-restarts on Railway.

### 4.4 Vercel frontend outage

Static assets served from Vercel's global CDN. Fallback: users can interact with the API directly. Deploy from any branch via `vercel --prod` if Vercel dashboard is unavailable.

### 4.5 Full data loss (catastrophic)

```
1. Create new Supabase project
2. Restore from latest backup (Supabase dashboard)
3. Re-run schema.sql to apply any missing migrations
4. Update DATABASE_URL in Railway
5. Verify: GET /health returns {"status": "ok"}
6. If audit S3 bucket exists, data is preserved independently of DB
```

**Expected RTO:** 2–4 hours  
**Expected RPO:** Up to 24 hours (last daily backup) if PITR unavailable

---

## 5. Incident severity levels

| Level | Description | Response SLA | Examples |
|-------|-------------|-------------|---------|
| P0 — Critical | Full service outage | 30 min | DB down, auth broken |
| P1 — High | Partial outage or data integrity risk | 2 hours | Contract verification failing, audit write errors |
| P2 — Medium | Degraded performance | 4 hours | Redis down (rate limiting off), slow queries |
| P3 — Low | Minor issue | 1 business day | UI glitch, non-critical warning |

---

## 6. Communication

| Situation | Action |
|-----------|--------|
| P0/P1 outage | Post to status page (statuspage.io or similar) within 30 min |
| Planned maintenance | Notify customers 48 hours in advance via email |
| Data breach | Notify affected customers within 72 hours (GDPR Article 33) |
| Restored | Update status page; send post-mortem within 5 business days for P0 |

---

## 7. Testing schedule

| Test | Frequency | Owner |
|------|-----------|-------|
| Backup restore drill | Quarterly | Engineering |
| Failover simulation (kill Railway deployment) | Bi-annual | Engineering |
| Schema migration rollback test | Before every major release | Engineering |
| Business continuity plan review | Annual | Engineering + Legal |

---

## 8. VPC / self-hosted customers

For VPC deployments, customers are responsible for:
- Database backups (Postgres `pg_dump` or managed provider)
- Redis persistence configuration (`appendonly yes` in `redis.conf`)
- Infrastructure-level HA (multi-replica Kubernetes deployment via the provided Helm chart)
- Defining their own RTO/RPO per their internal SLAs

Codios provides:
- Helm chart with HPA, liveness/readiness probes, and rolling updates
- `GET /health` endpoint for load-balancer health checks
- Schema idempotent migrations (safe to re-run)
