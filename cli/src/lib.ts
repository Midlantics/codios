/**
 * Shared helpers: config resolution, API client, output formatting.
 */
import pc from "picocolors";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

export interface CodiosConfig {
  apiUrl: string;
  apiKey: string;
  publicKey: string;
  privateKey: string;
  did: string;
}

export function resolveConfig(overrides: Partial<CodiosConfig> = {}): CodiosConfig {
  // Try loading a local .codios file for project-level config
  let fileConfig: Record<string, string> = {};
  try {
    const raw = readFileSync(resolve(process.cwd(), ".codios"), "utf8");
    for (const line of raw.split("\n")) {
      const [k, ...rest] = line.split("=");
      if (k && rest.length) fileConfig[k.trim()] = rest.join("=").trim();
    }
  } catch { /* no .codios file — fine */ }

  return {
    apiUrl:     overrides.apiUrl     ?? fileConfig.CODIOS_API_URL     ?? process.env.CODIOS_API_URL     ?? "https://codios-backend-production.up.railway.app",
    apiKey:     overrides.apiKey     ?? fileConfig.CODIOS_API_KEY     ?? process.env.CODIOS_API_KEY     ?? "",
    publicKey:  overrides.publicKey  ?? fileConfig.CODIOS_PUBLIC_KEY  ?? process.env.CODIOS_PUBLIC_KEY  ?? "",
    privateKey: overrides.privateKey ?? fileConfig.CODIOS_PRIVATE_KEY ?? process.env.CODIOS_PRIVATE_KEY ?? "",
    did:        overrides.did        ?? fileConfig.CODIOS_DID         ?? process.env.CODIOS_DID         ?? "",
  };
}

export async function apiCall(
  config: CodiosConfig,
  method: string,
  path: string,
  body?: unknown,
): Promise<unknown> {
  if (!config.apiKey) {
    fatal("No API key found. Set CODIOS_API_KEY or run: codios login");
  }

  const res = await fetch(`${config.apiUrl}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${config.apiKey}`,
    },
    body: body != null ? JSON.stringify(body) : undefined,
  });

  const text = await res.text();
  let data: unknown;
  try { data = JSON.parse(text); } catch { data = text; }

  if (!res.ok) {
    const msg = typeof data === "object" && data !== null && "detail" in data
      ? (data as { detail: string }).detail
      : text;
    fatal(`API error ${res.status}: ${msg}`);
  }

  return data;
}

export function fatal(msg: string): never {
  console.error(pc.red("✗") + " " + msg);
  process.exit(1);
}

export function ok(msg: string) {
  console.log(pc.green("✓") + " " + msg);
}

export function info(label: string, value: string) {
  console.log(pc.dim((label + ":").padEnd(20)) + value);
}

export function json(data: unknown) {
  console.log(JSON.stringify(data, null, 2));
}

export function printBox(lines: string[]) {
  const width = Math.max(...lines.map(l => l.length)) + 4;
  const bar = "─".repeat(width);
  console.log(pc.dim("┌" + bar + "┐"));
  for (const line of lines) {
    console.log(pc.dim("│") + "  " + line + " ".repeat(width - line.length - 2) + pc.dim("│"));
  }
  console.log(pc.dim("└" + bar + "┘"));
}
