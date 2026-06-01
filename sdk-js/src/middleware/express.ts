/**
 * Express middleware for Codios contract enforcement.
 *
 * Usage:
 *   import { codiosGuard } from "@codios/sdk/middleware/express";
 *
 *   app.use("/summarize", codiosGuard({
 *     codiosPublicKey: process.env.CODIOS_PUBLIC_KEY!,
 *     gatewayUrl: process.env.CODIOS_GATEWAY_URL,   // for nonce/replay check
 *     requiredAction: "summarize",
 *   })); 
 */
import type { Request, Response, NextFunction } from "express";
import { verifyContract, decodeContract, type SignedContract } from "../contract.js";

export interface CodiosGuardOptions {
  codiosPublicKey: string;
  /** Gateway URL for nonce consumption (replay defense). Omit to skip nonce check. */
  gatewayUrl?: string;
  /** Action the caller must have permission for. If omitted, only signature is checked. */
  requiredAction?: string;
  /** Called on every denial — useful for logging to your audit system. */
  onDenied?: (req: Request, reason: string, contract?: SignedContract) => void;
}

export function codiosGuard(options: CodiosGuardOptions) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const encoded = req.headers["x-codios-contract"] as string | undefined;
    const requestedAction = options.requiredAction ?? (req.headers["x-a2a-action"] as string | undefined);

    if (!encoded) {
      res.status(401).json({
        error: "missing_contract",
        message: "No Codios contract provided. Obtain one at codios.midlantics.com",
      });
      return;
    }

    let contract: SignedContract;
    try {
      contract = decodeContract(encoded);
    } catch {
      res.status(400).json({ error: "malformed_contract" });
      return;
    }

    const { valid, reason } = verifyContract(contract, options.codiosPublicKey, requestedAction);
    if (!valid) {
      options.onDenied?.(req, reason!, contract);
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
          const body = await nonceRes.json() as { reason?: string };
          const nonceReason = body.reason ?? "nonce_rejected";
          options.onDenied?.(req, nonceReason, contract);
          res.status(403).json({ error: "contract_invalid", reason: nonceReason });
          return;
        }
      } catch {
        if (process.env.NODE_ENV === "production") {
          res.status(503).json({ error: "enforcement_gateway_unreachable" });
          return;
        }
        console.warn("[codios] Nonce check skipped — gateway unreachable (dev mode)");
      }
    }

    (req as Request & { codiosContract: SignedContract }).codiosContract = contract;
    next();
  };
}
