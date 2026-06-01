#!/usr/bin/env node
import { Command } from "commander";
import pc from "picocolors";
import { keygenCommand } from "./commands/keygen.js";
import { registerCommand } from "./commands/register.js";
import { issueCommand } from "./commands/issue.js";
import { verifyCommand } from "./commands/verify.js";
import { agentsCommand } from "./commands/agents.js";

const program = new Command();

program
  .name("codios")
  .description(
    pc.bold("Codios") + pc.dim(" — A2A Agent Security Layer\n") +
    pc.dim("  https://codios.midlantics.com"),
  )
  .version("0.1.0")
  .addCommand(keygenCommand())
  .addCommand(registerCommand())
  .addCommand(issueCommand())
  .addCommand(verifyCommand())
  .addCommand(agentsCommand());

program.parse();

