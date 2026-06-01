/**
 * codios issue 
 *
 * Issue a signed capability contract between two registered agents.
 * Outputs the contract JSON and its base64-encoded form (for X-Codios-Contract header).
 */
import { Command } from "commander";
import pc from "picocolors";
import { encodeContract, type SignedContract } from "@codios/sdk";
import { resolveConfig, apiCall, ok, info } from "../lib.js";

export function issueCommand(): Command {
  return new Command("issue")
    .description("Issue a signed contract between two agents")
    .requiredOption("--issuer <agent_id>", "Issuer agent ID (agt_...)")
    .requiredOption("--target <agent_id>", "Target agent ID (agt_...)")
    .requiredOption("--actions <list>", "Comma-separated allowed actions (e.g. summarize,translate)")
    .option("--forbid <list>", "Comma-separated forbidden actions", "")
    .option("--max-calls <n>", "Maximum number of calls allowed", parseInt)
    .option("--max-tokens <n>", "Maximum tokens allowed", parseInt)
    .option("--ttl <seconds>", "Contract lifetime in seconds (default: 3600)", parseInt)
    .option("--api-key <key>", "Codios API key")
    .option("--api-url <url>", "Codios API URL")
    .option("--json", "Output raw JSON only (pipe-friendly)")
    .option("--header", "Output only the base64 X-Codios-Contract header value")
    .action(async (opts: {
      issuer: string;
      target: string;
      actions: string;
      forbid: string;
      maxCalls?: number;
      maxTokens?: number;
      ttl?: number;
      apiKey?: string;
      apiUrl?: string;
      json?: boolean;
      header?: boolean;
    }) => {
      const config = resolveConfig({ apiKey: opts.apiKey, apiUrl: opts.apiUrl });

      const allowedActions = opts.actions.split(",").map(s => s.trim()).filter(Boolean);
      const forbiddenActions = opts.forbid
        ? opts.forbid.split(",").map(s => s.trim()).filter(Boolean)
        : [];

      const resourceLimits: Record<string, number> = {};
      if (opts.maxCalls != null) resourceLimits.max_calls = opts.maxCalls;
      if (opts.maxTokens != null) resourceLimits.max_tokens = opts.maxTokens;

      const data = await apiCall(config, "POST", "/contracts", {
        issuer_agent_id: opts.issuer,
        target_agent_id: opts.target,
        allowed_actions: allowedActions,
        forbidden_actions: forbiddenActions,
        resource_limits: resourceLimits,
        ttl_seconds: opts.ttl ?? 3600,
      }) as { contract_id: string; contract: SignedContract };

      const contract = data.contract;
      const encoded = encodeContract(contract);

      if (opts.header) {
        process.stdout.write(encoded + "\n");
        return;
      }

      if (opts.json) {
        console.log(JSON.stringify(contract, null, 2));
        return;
      }

      console.log();
      ok(`Contract issued: ${pc.bold(data.contract_id)}`);
      console.log();
      info("Issuer", opts.issuer);
      info("Target", opts.target);
      info("Actions", allowedActions.join(", "));
      if (forbiddenActions.length) info("Forbidden", forbiddenActions.join(", "));
      if (opts.maxCalls != null) info("Max calls", String(opts.maxCalls));
      info("Expires", new Date(contract.expires_at).toLocaleString());
      info("Nonce", contract.nonce.slice(0, 16) + "...");
      console.log();
      console.log(pc.bold("X-Codios-Contract header value:"));
      console.log(pc.cyan(encoded));
      console.log();
      console.log(pc.dim("Verify with: ") + pc.cyan(`codios verify --contract "${encoded.slice(0, 40)}..." --action ${allowedActions[0]}`));
    });
}
