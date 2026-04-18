/**
 * codios agents
 *
 * List registered agents.
 */
import { Command } from "commander";
import pc from "picocolors";
import { resolveConfig, apiCall } from "../lib.js";

interface Agent {
  id: string;
  name: string;
  description: string;
  did: string;
  status: string;
  capabilities: string[];
  created_at: string;
}

export function agentsCommand(): Command {
  return new Command("agents")
    .description("List registered agents")
    .option("--api-key <key>", "Codios API key")
    .option("--api-url <url>", "Codios API URL")
    .option("--json", "Output raw JSON")
    .action(async (opts: { apiKey?: string; apiUrl?: string; json?: boolean }) => {
      const config = resolveConfig({ apiKey: opts.apiKey, apiUrl: opts.apiUrl });
      const agents = await apiCall(config, "GET", "/agents") as Agent[];

      if (opts.json) {
        console.log(JSON.stringify(agents, null, 2));
        return;
      }

      if (agents.length === 0) {
        console.log(pc.dim("No agents registered. Run: codios register --name <name> --public-key <key>"));
        return;
      }

      console.log();
      for (const a of agents) {
        const statusColor = a.status === "active" ? pc.green : a.status === "suspended" ? pc.yellow : pc.red;
        console.log(
          pc.bold(a.name.padEnd(24)) +
          pc.dim(a.id.padEnd(36)) +
          statusColor(a.status.padEnd(12)) +
          pc.dim(a.capabilities.slice(0, 3).join(", ") || "no capabilities"),
        );
        console.log(pc.dim("  " + a.did));
        console.log();
      }
    });
}
