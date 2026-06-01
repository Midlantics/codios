/**
 * Ed25519 key generation and DID:key construction.
 *
 * DID:key spec: https://w3c-ccg.github.io/did-method-key/#ed25519-x25519
 * Uses @noble/curves — audited, zero-dependency, works in Node + browsers.
 */
import { ed25519 } from "@noble/curves/ed25519";
import bs58 from "bs58";
// Ed25519 multicodec prefix per DID:key spec (0xed 0x01)
const ED25519_PREFIX = new Uint8Array([0xed, 0x01]);
export function generateAgentKeyPair() {
    const privateKeyBytes = ed25519.utils.randomPrivateKey();
    const publicKeyBytes = ed25519.getPublicKey(privateKeyBytes);
    return {
        publicKey: Buffer.from(publicKeyBytes).toString("base64"),
        privateKey: Buffer.from(privateKeyBytes).toString("base64"),
        did: publicBytesToDid(publicKeyBytes),
    };
}
export function publicKeyToDid(publicKeyBase64) {
    return publicBytesToDid(Buffer.from(publicKeyBase64, "base64"));
}
function publicBytesToDid(publicBytes) {
    const prefixed = new Uint8Array(ED25519_PREFIX.length + publicBytes.length);
    prefixed.set(ED25519_PREFIX);
    prefixed.set(publicBytes, ED25519_PREFIX.length);
    return `did:key:z${bs58.encode(prefixed)}`;
}
export function signData(data, privateKeyBase64) {
    const privateKeyBytes = Buffer.from(privateKeyBase64, "base64");
    const msgBytes = Buffer.from(data, "utf8");
    const signature = ed25519.sign(msgBytes, privateKeyBytes);
    return "ed25519:" + Buffer.from(signature).toString("base64");
}
export function verifySignature(data, signature, publicKeyBase64) {
    try {
        const colonIdx = signature.indexOf(":");
        if (colonIdx === -1 || signature.slice(0, colonIdx) !== "ed25519")
            return false;
        const sigBase64 = signature.slice(colonIdx + 1);
        const msgBytes = Buffer.from(data, "utf8");
        const sigBytes = Buffer.from(sigBase64, "base64");
        const pubKeyBytes = Buffer.from(publicKeyBase64, "base64");
        return ed25519.verify(sigBytes, msgBytes, pubKeyBytes);
    }
    catch {
        return false;
    }
}
//# sourceMappingURL=keys.js.map