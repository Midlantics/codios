export interface AgentKeyPair {
    /** base64 raw Ed25519 public key (32 bytes) — store in registry */
    publicKey: string;
    /** base64 raw Ed25519 private key (32 bytes) — NEVER store, keep in agent env */
    privateKey: string;
    /** did:key:z6Mk... */
    did: string;
}
export declare function generateAgentKeyPair(): AgentKeyPair;
export declare function publicKeyToDid(publicKeyBase64: string): string;
export declare function signData(data: string, privateKeyBase64: string): string;
export declare function verifySignature(data: string, signature: string, publicKeyBase64: string): boolean;
//# sourceMappingURL=keys.d.ts.map