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
import { type SignedContract } from "../contract.js";
export interface CodiosGuardOptions {
    codiosPublicKey: string;
    /** Gateway URL for nonce consumption (replay defense). Omit to skip nonce check. */
    gatewayUrl?: string;
    /** Action the caller must have permission for. If omitted, only signature is checked. */
    requiredAction?: string;
    /** Called on every denial — useful for logging to your audit system. */
    onDenied?: (req: Request, reason: string, contract?: SignedContract) => void;
}
export declare function codiosGuard(options: CodiosGuardOptions): (req: Request, res: Response, next: NextFunction) => Promise<void>;
//# sourceMappingURL=express.d.ts.map