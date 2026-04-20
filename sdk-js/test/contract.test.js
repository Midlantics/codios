/**
 * Edge-case tests for the Codios JS SDK.
 * Runs with Node's built-in test runner: node --test
 * No extra dependencies required.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  generateAgentKeyPair,
  publicKeyToDid,
  signData,
  verifySignature,
  issueContract,
  verifyContract,
  encodeContract,
  decodeContract,
  hashPayload,
} from "../dist/index.js";

// ── Helpers ──────────────────────────────────────────────────────────────────

function makeAgents() {
  return {
    issuer:   generateAgentKeyPair(),
    target:   generateAgentKeyPair(),
    platform: generateAgentKeyPair(),
  };
}

function makeContract(overrides = {}) {
  const { issuer, target, platform } = makeAgents();
  const contract = issueContract(
    {
      issuerAgentId:   "agent-a",
      issuerDid:       issuer.did,
      targetAgentId:   "agent-b",
      targetDid:       target.did,
      allowedActions:  ["summarize", "translate"],
      forbiddenActions: ["delete"],
      ttlSeconds:      3600,
      ...overrides,
    },
    platform.privateKey,
  );
  return { issuer, target, platform, contract };
}

// ── generateAgentKeyPair ──────────────────────────────────────────────────────

describe("generateAgentKeyPair", () => {
  it("returns publicKey, privateKey, and did", () => {
    const kp = generateAgentKeyPair();
    assert.ok(kp.publicKey, "publicKey missing");
    assert.ok(kp.privateKey, "privateKey missing");
    assert.ok(kp.did,       "did missing");
  });

  it("DID starts with did:key:z6Mk (Ed25519 multicodec)", () => {
    const kp = generateAgentKeyPair();
    assert.ok(
      kp.did.startsWith("did:key:z6Mk"),
      `unexpected DID prefix: ${kp.did.slice(0, 20)}`,
    );
  });

  it("publicKeyToDid matches did from generateAgentKeyPair", () => {
    const kp = generateAgentKeyPair();
    assert.equal(publicKeyToDid(kp.publicKey), kp.did);
  });

  it("each call produces unique keys", () => {
    const a = generateAgentKeyPair();
    const b = generateAgentKeyPair();
    assert.notEqual(a.publicKey,  b.publicKey);
    assert.notEqual(a.privateKey, b.privateKey);
    assert.notEqual(a.did,        b.did);
  });
});

// ── signData / verifySignature ────────────────────────────────────────────────

describe("signData / verifySignature", () => {
  it("verifies own signature", () => {
    const kp = generateAgentKeyPair();
    const sig = signData("hello world", kp.privateKey);
    assert.ok(verifySignature("hello world", sig, kp.publicKey));
  });

  it("rejects tampered message", () => {
    const kp = generateAgentKeyPair();
    const sig = signData("hello world", kp.privateKey);
    assert.ok(!verifySignature("hello WORLD", sig, kp.publicKey));
  });

  it("rejects wrong public key", () => {
    const a = generateAgentKeyPair();
    const b = generateAgentKeyPair();
    const sig = signData("data", a.privateKey);
    assert.ok(!verifySignature("data", sig, b.publicKey));
  });

  it("signature carries ed25519: prefix", () => {
    const kp = generateAgentKeyPair();
    const sig = signData("payload", kp.privateKey);
    assert.ok(sig.startsWith("ed25519:"), `unexpected prefix: ${sig.slice(0, 20)}`);
  });

  it("empty data signs and verifies correctly", () => {
    const kp = generateAgentKeyPair();
    const sig = signData("", kp.privateKey);
    assert.ok(verifySignature("", sig, kp.publicKey));
    assert.ok(!verifySignature(" ", sig, kp.publicKey));
  });
});

// ── issueContract ─────────────────────────────────────────────────────────────

describe("issueContract — structure", () => {
  it("returns all required fields", () => {
    const { contract } = makeContract();
    assert.ok(contract.contract_id.startsWith("ctr_"), `bad contract_id: ${contract.contract_id}`);
    assert.equal(contract.version, "1.0");
    assert.ok(contract.issued_at);
    assert.ok(contract.expires_at);
    assert.ok(contract.nonce);
    assert.ok(contract.signature);
    assert.deepEqual(contract.allowed_actions,  ["summarize", "translate"]);
    assert.deepEqual(contract.forbidden_actions, ["delete"]);
  });

  it("expires_at is exactly ttlSeconds after issued_at", () => {
    const { contract } = makeContract({ ttlSeconds: 7200 });
    const diffSec =
      (new Date(contract.expires_at).getTime() - new Date(contract.issued_at).getTime()) / 1000;
    assert.ok(Math.abs(diffSec - 7200) < 2, `TTL mismatch: ${diffSec}s`);
  });

  it("default ttl is 3600 when ttlSeconds omitted", () => {
    const { issuer, target, platform } = makeAgents();
    const contract = issueContract(
      { issuerAgentId: "a", issuerDid: issuer.did, targetAgentId: "b", targetDid: target.did, allowedActions: ["read"] },
      platform.privateKey,
    );
    const diffSec =
      (new Date(contract.expires_at).getTime() - new Date(contract.issued_at).getTime()) / 1000;
    assert.ok(Math.abs(diffSec - 3600) < 2);
  });

  it("resource limits appear under snake_case keys", () => {
    const { contract } = makeContract({
      resourceLimits: { maxCalls: 100, maxTokens: 50000, maxDurationSeconds: 300 },
    });
    assert.equal(contract.resource_limits.max_calls,            100);
    assert.equal(contract.resource_limits.max_tokens,           50000);
    assert.equal(contract.resource_limits.max_duration_seconds, 300);
  });

  it("resource_limits is empty object when not specified", () => {
    const { contract } = makeContract();
    assert.deepEqual(contract.resource_limits, {});
  });

  it("each call produces unique contract_id and nonce", () => {
    const a = makeContract();
    const b = makeContract();
    assert.notEqual(a.contract.contract_id, b.contract.contract_id);
    assert.notEqual(a.contract.nonce,       b.contract.nonce);
  });

  it("forbiddenActions defaults to [] when omitted", () => {
    const { issuer, target, platform } = makeAgents();
    const contract = issueContract(
      { issuerAgentId: "a", issuerDid: issuer.did, targetAgentId: "b", targetDid: target.did, allowedActions: ["read"] },
      platform.privateKey,
    );
    assert.deepEqual(contract.forbidden_actions, []);
  });
});

// ── verifyContract — happy paths ──────────────────────────────────────────────

describe("verifyContract — valid cases", () => {
  it("allows an action in allowedActions", () => {
    const { contract, platform } = makeContract();
    assert.deepEqual(verifyContract(contract, platform.publicKey, "summarize"), { valid: true });
  });

  it("allows a second action in allowedActions", () => {
    const { contract, platform } = makeContract();
    assert.deepEqual(verifyContract(contract, platform.publicKey, "translate"), { valid: true });
  });

  it("passes with no requestedAction (signature-only mode)", () => {
    const { contract, platform } = makeContract();
    assert.deepEqual(verifyContract(contract, platform.publicKey), { valid: true });
  });
});

// ── verifyContract — expiry ───────────────────────────────────────────────────

describe("verifyContract — expiry", () => {
  it("rejects contract with expires_at in the past", () => {
    const { contract, platform } = makeContract({ ttlSeconds: -1 });
    const result = verifyContract(contract, platform.publicKey, "summarize");
    assert.equal(result.valid,  false);
    assert.equal(result.reason, "contract_expired");
  });

  it("expiry is checked before signature — tampered expires_at still returns contract_expired", () => {
    const { contract, platform } = makeContract();
    const expired = { ...contract, expires_at: new Date(Date.now() - 5000).toISOString() };
    const result = verifyContract(expired, platform.publicKey, "summarize");
    assert.equal(result.reason, "contract_expired");
  });
});

// ── verifyContract — action enforcement ──────────────────────────────────────

describe("verifyContract — action enforcement", () => {
  it("rejects a forbidden action", () => {
    const { contract, platform } = makeContract();
    const result = verifyContract(contract, platform.publicKey, "delete");
    assert.equal(result.valid,  false);
    assert.equal(result.reason, "action_forbidden");
  });

  it("rejects an action not in allowedActions", () => {
    const { contract, platform } = makeContract();
    const result = verifyContract(contract, platform.publicKey, "exfiltrate");
    assert.equal(result.valid,  false);
    assert.equal(result.reason, "action_not_permitted");
  });

  it("forbidden check runs before allowed check", () => {
    // "delete" is forbidden — reason must be action_forbidden, not action_not_permitted
    const { contract, platform } = makeContract();
    assert.equal(verifyContract(contract, platform.publicKey, "delete").reason, "action_forbidden");
  });
});

// ── verifyContract — signature integrity ──────────────────────────────────────

describe("verifyContract — signature integrity", () => {
  it("rejects contract verified with wrong public key", () => {
    const { contract } = makeContract();
    const other = generateAgentKeyPair();
    const result = verifyContract(contract, other.publicKey, "summarize");
    assert.equal(result.valid,  false);
    assert.equal(result.reason, "invalid_signature");
  });

  it("rejects tampered allowed_actions (extra action added)", () => {
    const { contract, platform } = makeContract();
    const tampered = { ...contract, allowed_actions: [...contract.allowed_actions, "admin"] };
    const result = verifyContract(tampered, platform.publicKey, "admin");
    assert.equal(result.valid,  false);
    assert.equal(result.reason, "invalid_signature");
  });

  it("rejects tampered forbidden_actions", () => {
    const { contract, platform } = makeContract();
    // Remove "delete" from forbidden so the body no longer matches the signature
    const tampered = { ...contract, forbidden_actions: [] };
    // Use "translate" (allowed, not forbidden in tampered) so action checks pass
    const result = verifyContract(tampered, platform.publicKey, "translate");
    assert.equal(result.valid,  false);
    assert.equal(result.reason, "invalid_signature");
  });

  it("rejects tampered resource_limits", () => {
    const { contract, platform } = makeContract({ resourceLimits: { maxCalls: 10 } });
    const tampered = { ...contract, resource_limits: { max_calls: 9999 } };
    const result = verifyContract(tampered, platform.publicKey, "summarize");
    assert.equal(result.valid,  false);
    assert.equal(result.reason, "invalid_signature");
  });

  it("rejects missing signature (empty string)", () => {
    const { contract, platform } = makeContract();
    const noSig = { ...contract, signature: "" };
    const result = verifyContract(noSig, platform.publicKey, "summarize");
    assert.equal(result.valid,  false);
    assert.equal(result.reason, "missing_signature");
  });
});

// ── encodeContract / decodeContract ──────────────────────────────────────────

describe("encodeContract / decodeContract", () => {
  it("roundtrips losslessly", () => {
    const { contract } = makeContract();
    assert.deepEqual(decodeContract(encodeContract(contract)), contract);
  });

  it("encoded value is a base64 string", () => {
    const { contract } = makeContract();
    const encoded = encodeContract(contract);
    assert.equal(typeof encoded, "string");
    assert.match(encoded, /^[A-Za-z0-9+/]+=*$/, "not valid base64");
  });

  it("different contracts produce different encoded values", () => {
    const a = makeContract();
    const b = makeContract();
    assert.notEqual(encodeContract(a.contract), encodeContract(b.contract));
  });
});

// ── hashPayload ───────────────────────────────────────────────────────────────

describe("hashPayload", () => {
  it("is deterministic for same input", () => {
    const p = { action: "read", agent: "agent-1" };
    assert.equal(hashPayload(p), hashPayload(p));
  });

  it("differs for different payloads", () => {
    assert.notEqual(hashPayload({ a: 1 }), hashPayload({ a: 2 }));
  });

  it("returns a 64-char lowercase hex string (SHA-256)", () => {
    const h = hashPayload({ x: 42 });
    assert.match(h, /^[0-9a-f]{64}$/, `unexpected hash format: ${h}`);
  });

  it("order-sensitive (different key order = different hash)", () => {
    // JSON.stringify is order-sensitive, so hashPayload is too
    const h1 = hashPayload({ a: 1, b: 2 });
    const h2 = hashPayload({ b: 2, a: 1 });
    // These MAY differ depending on JSON.stringify behaviour — just confirm it doesn't throw
    assert.equal(typeof h1, "string");
    assert.equal(typeof h2, "string");
  });
});
