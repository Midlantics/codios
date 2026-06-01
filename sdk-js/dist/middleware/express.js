import { verifyContract, decodeContract } from "../contract.js";
export function codiosGuard(options) {
    return async (req, res, next) => {
        const encoded = req.headers["x-codios-contract"];
        const requestedAction = options.requiredAction ?? req.headers["x-a2a-action"];
        if (!encoded) {
            res.status(401).json({
                error: "missing_contract",
                message: "No Codios contract provided. Obtain one at codios.midlantics.com",
            });
            return;
        }
        let contract;
        try {
            contract = decodeContract(encoded);
        }
        catch {
            res.status(400).json({ error: "malformed_contract" });
            return;
        }
        const { valid, reason } = verifyContract(contract, options.codiosPublicKey, requestedAction);
        if (!valid) {
            options.onDenied?.(req, reason, contract);
            res.status(403).json({ error: "contract_invalid", reason });
            return;
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
                    const nonceReason = body.reason ?? "nonce_rejected";
                    options.onDenied?.(req, nonceReason, contract);
                    res.status(403).json({ error: "contract_invalid", reason: nonceReason });
                    return;
                }
            }
            catch {
                if (process.env.NODE_ENV === "production") {
                    res.status(503).json({ error: "enforcement_gateway_unreachable" });
                    return;
                }
                console.warn("[codios] Nonce check skipped — gateway unreachable (dev mode)");
            }
        }
        req.codiosContract = contract;
        next();
    };
}
//# sourceMappingURL=express.js.map