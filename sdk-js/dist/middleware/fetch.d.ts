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
import { type SignedContract } from "../contract.js";
export interface FetchCodiosOptions {
    codiosPublicKey: string;
    gatewayUrl?: string;
    requiredAction?: string;
}
type FetchHandler = (req: Request, contract: SignedContract) => Promise<Response>;
export declare function withCodios(options: FetchCodiosOptions, handler: FetchHandler): (req: Request) => Promise<Response>;
export {};
//# sourceMappingURL=fetch.d.ts.map