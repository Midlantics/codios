#!/usr/bin/env bash
# Codios VPC setup — generates keys and starts services.
# Usage: 
#   ./setup-vpc.sh              # full setup + start
#   ./setup-vpc.sh --keys-only  # generate keys and print, don't start

set -euo pipefail

KEYS_ONLY=false
[[ "${1:-}" == "--keys-only" ]] && KEYS_ONLY=true

echo "╔══════════════════════════════════════════╗"
echo "║        Codios VPC Setup                  ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── Check deps ────────────────────────────────────────────────────────────────
for cmd in docker python3 openssl; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "✗ Missing dependency: $cmd" && exit 1
  fi
done

# ── Generate Ed25519 platform keys ────────────────────────────────────────────
echo "▸ Generating Ed25519 platform keys..."

KEYS_JSON=$(python3 - <<'PYEOF'
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
try:
    from services.crypto import generate_keypair
    import json
    print(json.dumps(generate_keypair()))
except ImportError:
    # Fallback: generate via openssl if deps not installed locally
    import subprocess, base64, hashlib, json
    raw = subprocess.check_output(["openssl", "genpkey", "-algorithm", "ed25519", "-outform", "DER"])
    # Extract 32-byte private key seed (last 32 bytes of PKCS8 DER)
    seed = raw[-32:]
    # Derive public key
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub_bytes = priv.public_key().public_bytes_raw()
    prefix = bytes([0xed, 0x01])
    import base58
    did = "did:key:z" + base58.b58encode(prefix + pub_bytes).decode()
    print(json.dumps({
        "private_key": base64.b64encode(seed).decode(),
        "public_key":  base64.b64encode(pub_bytes).decode(),
        "did":         did,
    }))
PYEOF
)

PRIVATE_KEY=$(echo "$KEYS_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['private_key'])")
PUBLIC_KEY=$(echo "$KEYS_JSON"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['public_key'])")
DID=$(echo "$KEYS_JSON"         | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['did'])")

echo "  DID:        $DID"
echo "  Public key: ${PUBLIC_KEY:0:20}..."

if $KEYS_ONLY; then
  echo ""
  echo "CODIOS_PRIVATE_KEY=$PRIVATE_KEY"
  echo "CODIOS_PUBLIC_KEY=$PUBLIC_KEY"
  echo "CODIOS_DID=$DID"
  exit 0
fi

# ── Generate secrets ──────────────────────────────────────────────────────────
POSTGRES_PASSWORD=$(openssl rand -hex 24)
REDIS_PASSWORD=$(openssl rand -hex 16)
JWT_SECRET=$(openssl rand -hex 32)
GATEWAY_SECRET=$(openssl rand -hex 32)

# ── Write .env ────────────────────────────────────────────────────────────────
if [[ -f .env ]]; then
  echo ""
  echo "▸ .env already exists — skipping (delete it to regenerate)"
else
  cat > .env <<EOF
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
REDIS_PASSWORD=$REDIS_PASSWORD
CODIOS_PRIVATE_KEY=$PRIVATE_KEY
CODIOS_PUBLIC_KEY=$PUBLIC_KEY
CODIOS_DID=$DID
JWT_SECRET=$JWT_SECRET
GATEWAY_SECRET=$GATEWAY_SECRET
PORT=8080
APP_URL=http://localhost:8080
ALLOWED_ORIGINS=*
RESEND_API_KEY=
RESEND_FROM=Codios Alerts <alerts@example.com>
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
EOF
  echo "▸ Written .env"
fi

# ── Start services ────────────────────────────────────────────────────────────
echo ""
echo "▸ Building and starting services..."
docker compose up --build -d

echo ""
echo "▸ Waiting for API to be ready..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:${PORT:-8080}/health >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

# ── Bootstrap: create initial API key ─────────────────────────────────────────
echo ""
echo "▸ Creating initial API key..."
INIT_KEY=$(curl -sf -X POST "http://localhost:${PORT:-8080}/keys" \
  -H "Content-Type: application/json" \
  -H "x-vpc-bootstrap: $GATEWAY_SECRET" \
  -d '{"name":"default"}' 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('key',''))" 2>/dev/null || echo "")

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Codios VPC is running                              ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  API URL:    http://localhost:${PORT:-8080}                   ║"
echo "║  Docs:       http://localhost:${PORT:-8080}/docs              ║"
if [[ -n "$INIT_KEY" ]]; then
echo "║  API Key:    $INIT_KEY  ║"
fi
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Platform public key (share with your agents):      ║"
echo "║  $PUBLIC_KEY"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  Set CODIOS_PUBLIC_KEY=$PUBLIC_KEY in your agent environments."
echo "  Use the API key above in Authorization: Bearer <key> headers."
echo ""
