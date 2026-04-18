# Security Policy

## Reporting a vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Email us at **security@midlantics.com** with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any proof-of-concept (if applicable)

We will acknowledge within **48 hours** and aim to release a fix within **14 days** for critical issues.

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest (`main`) | ✅ |
| Older releases | ❌ — please upgrade |

## Scope

In scope:
- Authentication and authorization bypass
- Ed25519 signature verification flaws
- Nonce / replay protection bypass
- SQL injection or data leakage
- OIDC SSO vulnerabilities
- License verification bypass

Out of scope:
- Issues requiring physical access to the server
- Denial of service via resource exhaustion
- Vulnerabilities in third-party dependencies (report to them directly, then open a Dependabot PR here)

## Disclosure policy

We follow **coordinated disclosure**. Please give us time to patch before publishing details publicly. We'll credit researchers in the release notes unless you prefer to remain anonymous.

## Vulnerability management (ISO 27001 A.12.6)

We run the following automated controls on every pull request and weekly:

| Tool | What it checks |
|------|---------------|
| **Dependabot** | Outdated Python, npm, and GitHub Actions dependencies |
| **pip-audit** | Known CVEs in Python dependencies (`backend/`, `sdk-python/`) |
| **npm audit** | Known CVEs in JS dependencies (`sdk-js/`, `cli/`) |
| **CodeQL** | Static analysis — injection, unsafe deserialization, path traversal |
| **Gitleaks** | Secrets accidentally committed to the repo |
| **Snyk** (private repo) | Deep dependency graph CVE scanning |

## Security controls summary (ISO 27001)

| Control area | Status | Implementation |
|-------------|--------|---------------|
| Access control (A.9) | ✅ | Ed25519 contracts, API key auth, RBAC org roles (owner/admin/member/viewer) |
| Cryptography (A.10.1) | ✅ | Ed25519 signatures, AES-256-GCM BYOK at-rest encryption, key rotation |
| Audit trail (A.12.4) | ✅ | Append-only DB log, immutability trigger, S3/WORM daily export with SHA-256 |
| Vulnerability management (A.12.6) | ✅ | Dependabot + pip-audit + CodeQL + Gitleaks on every PR |
| Incident response (A.16) | ✅ | Denial-spike alert rules, webhook notifications, SMTP/Resend email alerts |
| Data residency | ✅ | VPC/self-hosted mode via Helm chart or Docker Compose |
