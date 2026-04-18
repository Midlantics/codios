/**
 * codios register
 *
 * Register an agent in the Codios registry.
 * Requires CODIOS_API_KEY (or --api-key) and a public key.
 */
import { Command } from "commander";
import pc from "picocolors";
import { publicKeyToDid } from "@codios/sdk";
import { resolveConfig, apiCall, fatal, ok, info } from "../lib.js";

export function registerCommand(): Command {
  return new Command("register")
    .description("Register an agent in the Codios registry")
    .requiredOption("-n, --name <name>", "Agent name")
    .option("-d, --description <desc>", "Agent description", "")
    .option("-k, --public-key <base64>", "Ed25519 public key (base64). Defaults to CODIOS_PUBLIC_KEY env var")
    .option("-c, --capabilities <list>", "Comma-separated capability list (e.g. summarize,translate)", "")
    .option("--api-key <key>", "Codios API key. Defaults to CODIOS_API_KEY env var")
    .option("--api-url <url>", "Codios API URL. Defaults to CODIOS_API_URL env var")
    .option("--json", "Output raw JSON response")
    .action(async (opts: {
      name: string;
      description: string;
      publicKey?: string;
      capabilities: string;
      apiKey?: string;
      apiUrl?: string;
      json?: boolean;
    }) => {
      const config = resolveConfig({ apiKey: opts.apiKey, apiUrl: opts.apiUrl });
      const publicKey = opts.publicKey ?? config.publicKey;

      if (!publicKey) {
        fatal("No public key provided. Use --public-key or set CODIOS_PUBLIC_KEY");
      }

      let did: string;
      try {
        did = publicKeyToDid(publicKey);
      } catch {
        fatal("Invalid public key — must be a base64-encoded Ed25519 public key (32 bytes)");
      }

      const capabilities = opts.capabilities
        ? opts.capabilities.split(",").map(s => s.trim()).filter(Boolean)
        : [];

      const data = await apiCall(config, "POST", "/agents", {
        name: opts.name,
        description: opts.description,
        public_key: publicKey,
        capabilities,
        agent_card: {
          name: opts.name,
          description: opts.description,
          capabilities,
          did,
        },
      }) as { agent: { id: string; did: string } };

      if (opts.json) {
        console.log(JSON.stringify(data, null, 2));
        return;
      }

      console.log();
      ok(`Agent registered: ${pc.bold(opts.name)}`);
      console.log();
      info("Agent ID", data.agent.id);
      info("DID", data.agent.did);
      info("Public key", publicKey.slice(0, 24) + "...");
      console.log();
      console.log(pc.dim("Next: issue a contract with  ") + pc.cyan(`codios issue --issuer ${data.agent.id} --target <target_id> --actions <action>`));
    });
}
