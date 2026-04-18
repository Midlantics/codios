# codios-sdk

Python SDK for [Codios](https://codios.midlantics.com) — A2A Agent Security Layer.

## Installation

```bash
pip install codios-sdk

# With FastAPI middleware
pip install "codios-sdk[fastapi]"
```

## Quick start

### Verify a contract (in your agent)

```python
import os
from codios import verify_contract

CODIOS_PUBLIC_KEY = os.environ["CODIOS_PUBLIC_KEY"]

# contract dict comes from the X-Codios-Contract header sent by the caller
result = verify_contract(contract, CODIOS_PUBLIC_KEY, requested_action="summarize")

if not result.valid:
    raise PermissionError(f"Rejected: {result.reason}")
    # reason: contract_expired | invalid_signature | action_not_permitted | action_forbidden
```

### FastAPI middleware

```python
import os
from fastapi import FastAPI, Depends
from codios.middleware.fastapi import require_contract, ContractClaims

app = FastAPI()

# Set CODIOS_PUBLIC_KEY in your environment (from Codios dashboard)

@app.post("/summarize")
async def summarize(
    body: dict,
    claims: ContractClaims = Depends(require_contract("summarize")),
):
    # Contract is already verified at this point
    print(f"Caller: {claims.issuer_did}")
    return {"result": "..."}
```

The middleware reads `X-Codios-Contract` from the request header, verifies the Ed25519 signature offline (no network call), checks expiry, and validates the requested action is in `allowed_actions`.

### Generate a keypair (for registering a new agent)

```python
from codios import generate_keypair

kp = generate_keypair()
print(kp.did)         # did:key:z6Mk...
print(kp.public_key)  # base64 — register this with Codios
print(kp.private_key) # base64 — store securely, never share
```

## How it works

1. **Agent A** wants to call **Agent B**. It requests a signed contract from Codios API (`POST /contracts`).
2. Codios signs the contract with its Ed25519 platform key and returns it.
3. Agent A sends the contract in the `X-Codios-Contract` header when calling Agent B.
4. Agent B's SDK verifies the signature **locally** — zero network latency, no single point of failure.
5. If valid, the call proceeds. The result is logged to the Codios audit trail.

## Environment variables

| Variable | Description |
|---|---|
| `CODIOS_PUBLIC_KEY` | Base64 Ed25519 public key — from Codios dashboard Settings |
