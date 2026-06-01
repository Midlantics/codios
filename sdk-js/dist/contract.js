/**
 * Codios signed capability contracts.
 *
 * Contracts are signed with the Codios platform Ed25519 key and verified
 * offline — no network call required on the hot path.
 */
import { createHash, randomBytes } from "node:crypto";
import { signData, verifySignature } from "./keys.js";
/** RFC 8785 canonical JSON — sort keys recursively, no whitespace */
function canonicalize(obj) {
    return JSON.stringify(obj, (_key, value) => {
        if (value !== null && typeof value === "object" && !Array.isArray(value)) {
            return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0));
        }
        return value;
    });
}
/**
 * Issue and sign a capability contract.
 * Call this on the Codios platform (server side) — requires the private key.
 */
export function issueContract(options, codiosPrivateKey) {
    const now = new Date();
    const ttl = options.ttlSeconds ?? 3600;
    const expires = new Date(now.getTime() + ttl * 1000);
    const limits = {};
    if (options.resourceLimits?.maxCalls != null)
        limits.max_calls = options.resourceLimits.maxCalls;
    if (options.resourceLimits?.maxTokens != null)
        limits.max_tokens = options.resourceLimits.maxTokens;
    if (options.resourceLimits?.maxDurationSeconds != null)
        limits.max_duration_seconds = options.resourceLimits.maxDurationSeconds;
    const body = {
        contract_id: "ctr_" + randomBytes(16).toString("hex"),
        version: "1.0",
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
export function verifyContract(contract, codiosPublicKey, requestedAction) {
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
export function hashPayload(payload) {
    return createHash("sha256").update(JSON.stringify(payload)).digest("hex");
}
export function encodeContract(contract) {
    return Buffer.from(JSON.stringify(contract)).toString("base64");
}
export function decodeContract(encoded) {
    return JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
}
//# sourceMappingURL=contract.js.map