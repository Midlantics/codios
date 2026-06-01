/**
 * Fetch-based middleware for Codios contract enforcement.
 * Works with Next.js API routes, Cloudflare Workers, and any fetch-based handler.
 *
 * Usage (Next.js App Router):
 *   import { withCodios } from "@codios/sdk/middleware/fetch";
 *
 *   export const POST = withCodios(
 *     { codiosPublicKey: process.env.CODIOS_PUBLIC_KEY!, requiredAction: "summarize" },
 *     async (req, contract) => {
 *       return Response.json({ result: "done" });
 *     },
 *   );
 */
import { verifyContract, decodeContract } from "../contract.js";
export function withCodios(options, handler) {
    return async (req) => {
        const encoded = req.headers.get("x-codios-contract");
        const requestedAction = options.requiredAction ?? req.headers.get("x-a2a-action") ?? undefined;
        if (!encoded) {
            return Response.json({ error: "missing_contract", message: "No Codios contract provided. Obtain one at codios.midlantics.com" }, { status: 401 });
        }
        let contract;
        try {
            contract = decodeContract(encoded);
        }
        catch {
            return Response.json({ error: "malformed_contract" }, { status: 400 });
        }
        const { valid, reason } = verifyContract(contract, options.codiosPublicKey, requestedAction);
        if (!valid) {
            return Response.json({ error: "contract_invalid", reason }, { status: 403 });
        }
        if (options.gatewayUrl) {
            try {
                const nonceRes = await fetch(`${options.gatewayUrl}/nonces/consume`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        nonce: contract.nonce,
                        contract_id: contract.contract_id,
                        expires_at: contract.expires_at,
                    }),
                    signal: AbortSignal.timeout(2000),
                });
                if (!nonceRes.ok) {
                    const body = await nonceRes.json();
                    return Response.json({ error: "contract_invalid", reason: body.reason ?? "nonce_rejected" }, { status: 403 });
                }
            }
            catch {
                if (process.env.NODE_ENV === "production") {
                    return Response.json({ error: "enforcement_gateway_unreachable" }, { status: 503 });
                }
                console.warn("[codios] Nonce check skipped — gateway unreachable (dev mode)");
            }
        }
        return handler(req, contract);
    };
}
//# sourceMappingURL=fetch.js.map