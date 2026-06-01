/**
 * Codios signed capability contracts.
 *
 * Contracts are signed with the Codios platform Ed25519 key and verified
 * offline — no network call required on the hot path. 
 */
import { createHash, randomBytes } from "node:crypto";
import { signData, verifySignature } from "./keys.js";

export interface ContractOptions {
  issuerAgentId: string;
  issuerDid: string;
  targetAgentId: string;
  targetDid: string;
  allowedActions: string[];
  forbiddenActions?: string[];
  resourceLimits?: {
    maxCalls?: number;
    maxTokens?: number;
    maxDurationSeconds?: number;
  };
  /** Contract lifetime in seconds. Default: 3600 (1 hour) */
  ttlSeconds?: number;
}

export interface SignedContract {
  contract_id: string;
  version: "1.0";
  issued_at: string;
  expires_at: string;
  issuer: { agent_id: string; did: string };
  target: { agent_id: string; did: string };
  allowed_actions: string[];
  forbidden_actions: string[];
  resource_limits: Record<string, number>;
  nonce: string;
  signature: string;
}

export type DenyReason =
  | "contract_expired"
  | "invalid_signature"
  | "action_not_permitted"
  | "action_forbidden"
  | "missing_signature";

export interface VerifyResult {
  valid: boolean;
  reason?: DenyReason;
}

/** RFC 8785 canonical JSON — sort keys recursively, no whitespace */
function canonicalize(obj: object): string {
  return JSON.stringify(obj, (_key, value: unknown) => {
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      return Object.fromEntries(
        Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
          a < b ? -1 : a > b ? 1 : 0,
        ),
      );
    }
    return value;
  });
}

/**
 * Issue and sign a capability contract.
 * Call this on the Codios platform (server side) — requires the private key.
 */
export function issueContract(
  options: ContractOptions,
  codiosPrivateKey: string,
): SignedContract {
  const now = new Date();
  const ttl = options.ttlSeconds ?? 3600;
  const expires = new Date(now.getTime() + ttl * 1000);

  const limits: Record<string, number> = {};
  if (options.resourceLimits?.maxCalls != null) limits.max_calls = options.resourceLimits.maxCalls;
  if (options.resourceLimits?.maxTokens != null) limits.max_tokens = options.resourceLimits.maxTokens;
  if (options.resourceLimits?.maxDurationSeconds != null) limits.max_duration_seconds = options.resourceLimits.maxDurationSeconds;

  const body = {
    contract_id: "ctr_" + randomBytes(16).toString("hex"),
    version: "1.0" as const,
    issued_at: now.toISOString(),
    expires_at: expires.toISOString(),
    issuer: { agent_id: options.issuerAgentId, did: options.issuerDid },
    target: { agent_id: options.targetAgentId, did: options.targetDid },
    allowed_actions: options.allowedActions,
    forbidden_actions: options.forbiddenActions ?? [],
    resource_limits: limits,
    nonce: randomBytes(32).toString("hex"),
  };

  return { ...body, signature: signData(canonicalize(body), codiosPrivateKey) };
}

/**
 * Verify a signed contract offline (no network call).
 * Order: expiry → action scope → signature (fail-fast).
 */
export function verifyContract(
  contract: SignedContract,
  codiosPublicKey: string,
  requestedAction?: string,
): VerifyResult {
  if (new Date(contract.expires_at) < new Date()) {
    return { valid: false, reason: "contract_expired" };
  }

  if (requestedAction) {
    if (contract.forbidden_actions.includes(requestedAction)) {
      return { valid: false, reason: "action_forbidden" };
    }
    if (!contract.allowed_actions.includes(requestedAction)) {
      return { valid: false, reason: "action_not_permitted" };
    }
  }

  if (!contract.signature) {
    return { valid: false, reason: "missing_signature" };
  }

  const { signature, ...body } = contract;
  if (!verifySignature(canonicalize(body), signature, codiosPublicKey)) {
    return { valid: false, reason: "invalid_signature" };
  }

  return { valid: true };
}

export function hashPayload(payload: unknown): string {
  return createHash("sha256").update(JSON.stringify(payload)).digest("hex");
}

export function encodeContract(contract: SignedContract): string {
  return Buffer.from(JSON.stringify(contract)).toString("base64");
}

export function decodeContract(encoded: string): SignedContract {
  return JSON.parse(Buffer.from(encoded, "base64").toString("utf8")) as SignedContract;
}
