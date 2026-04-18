<div align="center">
  <h1>Codios</h1>
  <p><strong>A2A AI Agent Security Layer — open source enforcement core</strong></p>
  <p>
    <a href="https://codios.midlantics.com">SaaS Dashboard</a> ·
    <a href="https://codios.midlantics.com/docs">Documentation</a> ·
    <a href="https://github.com/Midlantics/codios/issues">Issues</a>
  </p>
  <img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="Apache 2.0">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/node-18%2B-green" alt="Node 18+">
</div>

---

Codios adds **signed capability contracts** to AI agent communication. Every action
an agent takes is governed by a cryptographic contract that specifies exactly what it
is allowed to do, for how long, and how many times — verified offline in ~0ms.

## What's in this repo

| Package | Description |
|---|---|
| `backend/` | FastAPI enforcement gateway — agents, contracts, audit, policies |
| `sdk-js/` | TypeScript SDK (`@codios/sdk`) — Ed25519 identity + middleware |
| `cli/` | `codios` CLI — keygen, register, issue, verify |

The commercial SaaS ([codios.midlantics.com](https://codios.midlantics.com)) adds a
dashboard UI, Stripe billing, SSO, and managed hosting. Everything in this repo is
Apache 2.0 and runs fully self-hosted.

## Quick start (Docker)

```bash
git clone https://github.com/Midlantics/codios
cd codios
./backend/setup-vpc.sh
```

One command generates Ed25519 keys, starts Postgres + Redis + the API, and prints
your platform public key and first API key.

## How it works

```
Agent A  ──(X-Codios-Contract: <signed contract>)──▶  Agent B service
                                                           │
                                                    codiosGuard() middleware
                                                           │
                                                    1. Verify Ed25519 sig  (~0ms, offline)
                                                    2. Check expiry + scope (~0ms, offline)
                                                    3. Consume nonce       (~1ms, Redis)
                                                    4. Evaluate OPA policy (~0ms, Python)
                                                    5. Log to audit trail  (async, non-blocking)
```

## TypeScript SDK

```bash
npm install @codios/sdk
```

```ts
import { generateAgentKeyPair, issueContract, verifyContract, codiosGuard } from "@codios/sdk"

// Generate agent identity
const agent = await generateAgentKeyPair()
console.log(agent.did)  // did:key:z6Mk...

// Issue a signed contract (server-side, uses platform key)
const contract = await issueContract(
  { issuer_did: callerDid, subject_did: serviceDid, actions: ["transfer"], ttl_seconds: 3600 },
  platformPrivateKey,
)

// Protect an Express endpoint
app.post("/transfer", codiosGuard({ action: "transfer", publicKey, gatewayUrl }), handler)

// Verify offline (no network)
const result = await verifyContract(encoded, platformPublicKey, "transfer")
```

## Python SDK

```bash
pip install codios-sdk
```

```python
from codios import verify_contract
from codios.middleware.fastapi import require_contract

# FastAPI dependency — reads X-Codios-Contract header
@app.post("/transfer")
async def transfer(contract = Depends(require_contract("transfer", PUBLIC_KEY))):
    return {"authorized_by": contract["issuer_did"]}
```

## CLI

```bash
codios keygen --save .env
codios register --name my-agent --public-key <key>
codios issue --issuer <did> --subject <did> --actions transfer,quote
codios verify --contract <b64> --action transfer
```

## Self-hosted environment variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | ✅ | PostgreSQL connection string |
| `REDIS_URL` | ✅ | Redis connection string |
| `CODIOS_PRIVATE_KEY` | ✅ | Ed25519 platform private key (base64) |
| `CODIOS_PUBLIC_KEY` | ✅ | Ed25519 platform public key (base64) |
| `CODIOS_DID` | ✅ | Platform DID (`did:key:z6Mk...`) |
| `SUPABASE_JWT_SECRET` | ✅ | JWT secret for API session tokens |
| `GATEWAY_SECRET` | ✅ | Internal shared secret |
| `RESEND_API_KEY` | ☐ | Email alerts via Resend |
| `SMTP_HOST` | ☐ | Email alerts via SMTP (alternative to Resend) |
| `S3_AUDIT_BUCKET` | ☐ | S3 bucket for immutable audit exports |

Run `./backend/setup-vpc.sh` to generate all secrets automatically.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Your VPC                         │
│                                                     │
│  ┌──────────┐    ┌──────────┐    ┌───────────────┐  │
│  │ Agent A  │───▶│ Codios   │───▶│ Agent B       │  │
│  │ (caller) │    │ Gateway  │    │ (service)     │  │
│  └──────────┘    │ FastAPI  │    │ +codiosGuard  │  │
│                  └────┬─────┘    └───────────────┘  │
│                       │                             │
│               ┌───────┴────────┐                    │
│               │   PostgreSQL   │   Redis            │
│               │   audit_logs   │   nonces           │
│               └───────────────┘   call counters     │
└─────────────────────────────────────────────────────┘
```

## ISO 27001 alignment

| Control | Implementation |
|---|---|
| A.9 Access control | Ed25519 signed contracts + API keys |
| A.10 Cryptography | Ed25519 + RFC 8785 canonical JSON |
| A.12.4 Audit logging | Append-only log with DB-level immutability trigger |
| A.12.4 Evidence preservation | SHA-256 signed exports to S3 WORM |
| A.16 Incident response | Email alert rules with cooldown |
| A.14.2 OPA policies | Custom Rego policy evaluation |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues → security@midlantics.com.

## License

Apache 2.0 — see [LICENSE](LICENSE).

Built by [Midlantics](https://midlantics.com). Copyright Sensart Technologies LLC 2026.
