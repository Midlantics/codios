# Authentication

Codios uses two distinct authentication mechanisms depending on how you deploy it.
Understanding which one applies to you prevents the most common setup confusion.

---

## TL;DR

| You are… | You authenticate with… | `SUPABASE_JWT_SECRET` / `JWT_SECRET` needed? |
|---|---|---|
| VPC / self-hosted user (CLI, SDK, direct API) | `codios_sk_*` API key | **No** |
| SaaS user (codios.midlantics.com dashboard) | Supabase session JWT | Yes (managed for you) |

---

## Method 1 — API Keys (`codios_sk_*`)

**This is what VPC users use for everything.**

API keys look like:

```
codios_sk_Abc123XyzDefGhiJklMno456PqrStuVwxYz
```

They are passed in the `Authorization` header:

```http
Authorization: Bearer codios_sk_Abc123...
```

### Where they come from

**VPC (`docker-compose` / Helm):** `setup-vpc.sh` automatically creates your first key
on startup and prints it to the terminal:

```
╔══════════════════════════════════════════════════════╗
║  Codios VPC is running                              ║
║  API Key:    codios_sk_...                          ║
╚══════════════════════════════════════════════════════╝
```

After that, use that key to create more keys via `POST /keys`.

**CLI:**
```bash
codios register --name "my-agent" --api-key codios_sk_...
```

**SDK:**
```python
# Python — FastAPI middleware
from codios.middleware.fastapi import require_contract

app.include_router(
    router,
    dependencies=[require_contract("summarize")],
)
# CODIOS_API_KEY env var is used for outbound calls
```

```typescript
// TypeScript — Express middleware
import { codiosGuard } from "@codios/sdk/middleware/express";

app.use(codiosGuard({
  gatewayUrl: "https://your-codios-api/enforce",
  apiKey: process.env.CODIOS_API_KEY,
}));
```

### Permissions

API keys carry `admin` role — they can read and write all resources within their org.
For read-only monitoring integrations, create a separate key and document which
key is used for what.

---

## Method 2 — Supabase JWTs (SaaS dashboard only)

When you log in to **codios.midlantics.com**, the Codios dashboard receives a
session JWT from Supabase. The backend verifies it using `SUPABASE_JWT_SECRET`.

**You never handle this JWT directly.** The dashboard manages it in the browser.
It is only relevant if you are running the full SaaS stack yourself (frontend +
backend with Supabase as the auth provider).

### When `SUPABASE_JWT_SECRET` / `JWT_SECRET` is required

| Deployment | Required? |
|---|---|
| VPC — `docker-compose up` | **No** — `setup-vpc.sh` leaves it blank and the backend starts fine |
| VPC — Helm | Set via `secrets.jwtSecret` in `values.yaml` — only needed if you attach your own frontend |
| SaaS (self-hosted with Supabase auth) | **Yes** — must match your Supabase project's JWT secret |

---

## VPC bootstrap flow (how the first key is created)

`setup-vpc.sh` handles this automatically:

1. Starts postgres + redis + api via `docker-compose up`
2. Waits for `GET /health` → `200`
3. Calls `POST /keys/bootstrap` with `x-vpc-bootstrap: <GATEWAY_SECRET>`
4. The backend creates an org, an owner membership, and one `codios_sk_*` key
5. Prints the key — **copy it now, it is shown only once**

If you missed it or need a new key:

```bash
# Re-run bootstrap if no keys exist yet
curl -X POST http://localhost:8080/keys/bootstrap \
  -H "x-vpc-bootstrap: $(grep GATEWAY_SECRET .env | cut -d= -f2)"

# Or create a key once you already have one
curl -X POST http://localhost:8080/keys \
  -H "Authorization: Bearer codios_sk_<existing>" \
  -H "Content-Type: application/json" \
  -d '{"name": "new-key"}'
```

---

## Summary for VPC users

```
setup-vpc.sh
    └─ writes .env (JWT_SECRET, GATEWAY_SECRET, keys…)
    └─ docker-compose up
    └─ POST /keys/bootstrap  →  codios_sk_xxxx  ← your API key

Everything else:
    Authorization: Bearer codios_sk_xxxx
    (JWT_SECRET / SUPABASE_JWT_SECRET is never touched)
```
