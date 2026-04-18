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
