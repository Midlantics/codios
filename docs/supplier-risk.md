# Supplier Risk Register (ISO 27001 A.15)

**Owner:** Midlantics Engineering  
**Review cycle:** Annual (next review: 2027-04)  
**Version:** 1.0 — 2026-04

---

## 1. Critical suppliers

### 1.1 Supabase — Database (PostgreSQL + Auth)

| Attribute | Detail |
|-----------|--------|
| **Role** | Primary database (PostgreSQL), JWT auth infrastructure |
| **Data processed** | All Codios persistent data: agents, contracts, audit logs, org members |
| **Uptime SLA** | 99.9% (Pro plan) |
| **Data residency** | US East (default); EU available on Team/Enterprise plan |
| **Encryption at rest** | AES-256 (Supabase-managed) |
| **Encryption in transit** | TLS 1.2+ enforced |
| **Backup** | Automated daily + PITR (point-in-time recovery) |
| **Security certifications** | SOC 2 Type II |
| **DPA available** | Yes — via Supabase dashboard |
| **Status page** | https://status.supabase.com |
| **Contingency** | Postgres-compatible; migrate to self-hosted Postgres or AWS RDS with `pg_dump` restore + schema re-run |

**Risk:** Medium. Supabase outages directly impact API availability. Mitigated by PITR backups and graceful 503 degradation.

---

### 1.2 Railway — API hosting

| Attribute | Detail |
|-----------|--------|
| **Role** | Hosts the FastAPI backend container |
| **Data processed** | Transient request data; secrets stored as encrypted env vars |
| **Uptime SLA** | 99.95% (Railway Pro) |
| **Data residency** | US (default); configurable regions available |
| **Encryption at rest** | AES-256 (Railway-managed env var encryption) |
| **Encryption in transit** | TLS 1.2+ |
| **Security certifications** | SOC 2 Type II |
| **Status page** | https://status.railway.app |
| **Contingency** | Container image portable to any Docker host (Fly.io, AWS ECS, GCP Cloud Run, Kubernetes via Helm chart) |

**Risk:** Low. Stateless containers restart automatically. Migration is straightforward — push the same Docker image to any provider.

---

### 1.3 Vercel — Frontend hosting

| Attribute | Detail |
|-----------|--------|
| **Role** | Hosts Next.js frontend (static + edge functions) |
| **Data processed** | No persistent customer data (auth tokens handled client-side) |
| **Uptime SLA** | 99.99% (Enterprise); 99.9% (Pro) |
| **Data residency** | Global CDN; no customer data stored on Vercel servers |
| **Security certifications** | SOC 2 Type II |
| **Status page** | https://www.vercel-status.com |
| **Contingency** | Next.js app deployable to Netlify, AWS Amplify, or self-hosted with `next start` |

**Risk:** Low. Frontend is stateless; no customer data at risk.

---

### 1.4 Resend — Transactional email

| Attribute | Detail |
|-----------|--------|
| **Role** | Sends invite emails and alert notifications |
| **Data processed** | Email addresses; invite URLs |
| **Uptime SLA** | 99.9% |
| **Data residency** | US |
| **Security certifications** | SOC 2 Type II |
| **Status page** | https://resend-status.com |
| **Contingency** | SMTP fallback built into codebase (`SMTP_HOST` env var). Set to any SMTP provider (SendGrid, AWS SES, Postfix). Invite URL is also returned in the API response — email is non-blocking. |

**Risk:** Low. Email failure is non-fatal; invite link is returned directly in the API response.

---

### 1.5 AWS S3 — Audit log archival (optional)

| Attribute | Detail |
|-----------|--------|
| **Role** | WORM-compliant long-term audit log storage |
| **Data processed** | Audit log entries (enforcement decisions, agent IDs, outcomes) |
| **Uptime SLA** | 99.99% object durability; 99.9% availability |
| **Data residency** | Customer-selected AWS region |
| **Encryption at rest** | AES-256 (SSE-S3) or SSE-KMS |
| **WORM** | S3 Object Lock in COMPLIANCE mode (7-year retention when enabled) |
| **Security certifications** | ISO 27001, SOC 2, PCI DSS |
| **Contingency** | Audit data also available via streaming API (`GET /audit/export`). S3 is additive archival only. |

**Risk:** Very low. S3 is optional; streaming export works without it.

---

### 1.6 GitHub — Source code and CI/CD

| Attribute | Detail |
|-----------|--------|
| **Role** | Source control, CI/CD (GitHub Actions), Dependabot |
| **Data processed** | Source code; no customer data |
| **Uptime SLA** | 99.9% |
| **Security certifications** | SOC 2 Type II, ISO 27001 |
| **Status page** | https://www.githubstatus.com |
| **Contingency** | Git repo mirrors to GitLab or self-hosted Gitea; Actions replaced with self-hosted runners |

**Risk:** Low. Source code is fully portable; no lock-in.

---

## 2. Risk summary matrix

| Supplier | Criticality | Inherent risk | Controls | Residual risk |
|----------|-------------|--------------|----------|---------------|
| Supabase | Critical | Medium | PITR backups, graceful degradation, portable schema | Low |
| Railway | High | Low | Stateless containers, portable Docker image | Very low |
| Vercel | High | Low | Stateless frontend, multiple deployment targets | Very low |
| Resend | Medium | Low | SMTP fallback, non-blocking email | Very low |
| AWS S3 | Low | Very low | Optional feature; streaming fallback | Very low |
| GitHub | Medium | Low | Git is portable; Actions replaceable | Very low |

---

## 3. Due diligence checklist

For each critical supplier, we verify annually:

- [ ] Current security certifications (SOC 2 / ISO 27001)
- [ ] DPA (Data Processing Agreement) in place
- [ ] Incident notification SLA (≤ 72 hours for data breaches)
- [ ] Subprocessor list reviewed
- [ ] Status page subscribed for incident alerts
- [ ] Exit/migration plan documented and tested

---

## 4. Exit criteria

We would replace a supplier if:

- Uptime SLA breached for 2+ consecutive months
- SOC 2 certification lapsed without replacement
- Data breach attributable to supplier negligence
- Supplier acquired by a sanctioned entity or subject to legal proceedings affecting service

---

## 5. VPC customers

VPC customers supply their own infrastructure. Codios has no visibility into or responsibility for:
- Customer's cloud provider (AWS, GCP, Azure, on-premise)
- Customer's database hosting and backup strategy
- Customer's network security controls

Recommended controls for VPC deployments are documented in [business-continuity.md](./business-continuity.md) §8.
