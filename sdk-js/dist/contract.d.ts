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
    issuer: {
        agent_id: string;
        did: string;
    };
    target: {
        agent_id: string;
        did: string;
    };
    allowed_actions: string[];
    forbidden_actions: string[];
    resource_limits: Record<string, number>;
    nonce: string;
    signature: string;
}
export type DenyReason = "contract_expired" | "invalid_signature" | "action_not_permitted" | "action_forbidden" | "missing_signature";
export interface VerifyResult {
    valid: boolean;
    reason?: DenyReason;
}
/**
 * Issue and sign a capability contract.
 * Call this on the Codios platform (server side) — requires the private key.
 */
export declare function issueContract(options: ContractOptions, codiosPrivateKey: string): SignedContract;
/**
 * Verify a signed contract offline (no network call).
 * Order: expiry → action scope → signature (fail-fast).
 */
export declare function verifyContract(contract: SignedContract, codiosPublicKey: string, requestedAction?: string): VerifyResult;
export declare function hashPayload(payload: unknown): string;
export declare function encodeContract(contract: SignedContract): string;
export declare function decodeContract(encoded: string): SignedContract;
//# sourceMappingURL=contract.d.ts.map