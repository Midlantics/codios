/**
 * codios keygen
 *
 * Generate a new Ed25519 keypair for agent registration.
 * The private key is shown ONCE — store it immediately in your env vars.
 */
import { Command } from "commander";
import { writeFileSync, appendFileSync, existsSync } from "node:fs";
import pc from "picocolors";
import { generateAgentKeyPair } from "@codios/sdk";
import { ok, info, printBox } from "../lib.js";

export function keygenCommand(): Command {
  return new Command("keygen")
    .description("Generate a new Ed25519 keypair for an agent")
    .option("--save <file>", "Append keys to a file (e.g. .env)")
    .option("--json", "Output raw JSON")
    .action((opts: { save?: string; json?: boolean }) => {
      const kp = generateAgentKeyPair();

      if (opts.json) {
        console.log(JSON.stringify(kp, null, 2));
        return;
      }

      console.log();
      printBox([
        pc.bold("Codios — New Agent Keypair"),
        "",
        pc.dim("Public key  (share with registry)"),
        pc.cyan(kp.publicKey),
        "",
        pc.dim("DID:key"),
        pc.cyan(kp.did),
        "",
        pc.dim("Private key " + pc.red("⚠ shown once — store securely")),
        pc.yellow(kp.privateKey),
      ]);
      console.log();

      info("CODIOS_PUBLIC_KEY", kp.publicKey);
      info("CODIOS_PRIVATE_KEY", kp.privateKey);
      info("CODIOS_DID", kp.did);
      console.log();

      if (opts.save) {
        const lines = [
          `CODIOS_PUBLIC_KEY=${kp.publicKey}`,
          `CODIOS_PRIVATE_KEY=${kp.privateKey}`,
          `CODIOS_DID=${kp.did}`,
          "",
        ].join("\n");

        if (existsSync(opts.save)) {
          appendFileSync(opts.save, "\n" + lines);
        } else {
          writeFileSync(opts.save, lines);
        }
        ok(`Keys appended to ${opts.save}`);
      } else {
        console.log(pc.dim("Tip: run with --save .env to write directly to a file"));
      }
    });
}
