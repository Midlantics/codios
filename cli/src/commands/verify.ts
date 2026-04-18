/**
 * codios verify
 *
 * Verify a signed contract offline — no network call required.
 * Reads the contract from --contract (base64) or stdin.
 */
import { Command } from "commander";
import pc from "picocolors";
import { verifyContract, decodeContract } from "@codios/sdk";
import { resolveConfig, fatal, ok, info } from "../lib.js";

export function verifyCommand(): Command {
  return new Command("verify")
    .description("Verify a signed contract offline (no network call)")
    .option("-c, --contract <base64>", "Base64-encoded contract (X-Codios-Contract value)")
    .option("-a, --action <action>", "Action to check permission for")
    .option("-k, --public-key <base64>", "Codios platform public key. Defaults to CODIOS_PUBLIC_KEY env var")
    .option("--json", "Output raw JSON result")
    .action(async (opts: {
      contract?: string;
      action?: string;
      publicKey?: string;
      json?: boolean;
    }) => {
      const config = resolveConfig({ publicKey: opts.publicKey });
      const publicKey = opts.publicKey ?? config.publicKey;

      if (!publicKey) {
        fatal("No public key. Use --public-key or set CODIOS_PUBLIC_KEY");
      }

      // Accept contract from --contract flag or stdin
      let encoded = opts.contract;
      if (!encoded) {
        if (process.stdin.isTTY) {
          fatal("No contract provided. Use --contract <base64> or pipe via stdin");
        }
        encoded = await readStdin();
      }
      encoded = encoded.trim();

      let contract: ReturnType<typeof decodeContract>;
      try {
        contract = decodeContract(encoded);
      } catch {
        fatal("Could not decode contract — must be a valid base64-encoded Codios contract");
      }

      const result = verifyContract(contract, publicKey, opts.action);

      if (opts.json) {
        console.log(JSON.stringify({ ...result, contract_id: contract.contract_id }, null, 2));
        process.exit(result.valid ? 0 : 1);
      }

      console.log();

      if (result.valid) {
        ok(`Contract ${pc.bold(contract.contract_id)} is ${pc.green("valid")}`);
        console.log();
        info("Issuer agent", contract.issuer.agent_id);
        info("Target agent", contract.target.agent_id);
        info("Allowed", contract.allowed_actions.join(", ") || "(any)");
        if (contract.forbidden_actions.length) info("Forbidden", contract.forbidden_actions.join(", "));
        info("Expires", new Date(contract.expires_at).toLocaleString());
        if (opts.action) info("Action check", pc.green(`"${opts.action}" ✓ permitted`));
      } else {
        console.log(pc.red("✗") + ` Contract ${pc.bold(contract.contract_id ?? "unknown")} is ${pc.red("invalid")}`);
        console.log();
        info("Reason", pc.red(result.reason ?? "unknown"));
        if (result.reason === "contract_expired") {
          info("Expired at", new Date(contract.expires_at).toLocaleString());
        }
        if (opts.action && (result.reason === "action_not_permitted" || result.reason === "action_forbidden")) {
          info("Action", `"${opts.action}"`);
          info("Allowed", contract.allowed_actions.join(", ") || "(any)");
        }
        process.exit(1);
      }

      console.log();
    });
}

function readStdin(): Promise<string> {
  return new Promise(resolve => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", chunk => { data += chunk; });
    process.stdin.on("end", () => resolve(data));
  });
}
