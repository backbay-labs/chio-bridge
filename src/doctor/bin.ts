#!/usr/bin/env node
/**
 * `chio-doctor` — environment & stack diagnostics.
 *
 * Ships as the `chio-doctor` bin entry of `@chio/bridge`. When a
 * `chio` Rust binary is on PATH, users can also invoke it as
 * `chio doctor`; the Rust side is expected to delegate to this script.
 */
import { runDoctor } from "./runner.js";
import { renderJson, renderTable } from "./render.js";
import type { DoctorOptions } from "./types.js";

function parseArgs(argv: string[]): { opts: DoctorOptions; help: boolean; err?: string } {
  const opts: DoctorOptions = { full: false, json: false, fix: false };
  let help = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") help = true;
    else if (a === "--full") opts.full = true;
    else if (a === "--json") opts.json = true;
    else if (a === "--fix") opts.fix = true;
    else if (a === "--plugin") {
      const v = argv[++i];
      if (!v) return { opts, help: false, err: "--plugin requires an argument" };
      opts.plugin = v;
    } else if (a && a.startsWith("--plugin=")) {
      opts.plugin = a.slice("--plugin=".length);
    } else {
      return { opts, help: false, err: `unknown flag: ${a}` };
    }
  }
  return { opts, help };
}

function printHelp(): void {
  const lines = [
    "chio-doctor — diagnose your chio install",
    "",
    "Usage: chio-doctor [--full] [--json] [--fix] [--plugin <name>]",
    "",
    "Flags:",
    "  --full           run expensive probes (harness start, endpoint hits, unit tests)",
    "  --json           emit a machine-readable JSON report instead of a table",
    "  --fix            attempt to auto-remediate known failures (bun add, harness start)",
    "  --plugin <name>  run plugin-specific checks only",
    "  -h, --help       show this help",
    "",
    "Exit codes: 0 = no failures (warnings allowed); 1 = at least one fail; 2 = usage error.",
  ];
  process.stdout.write(lines.join("\n") + "\n");
}

async function main(): Promise<void> {
  const { opts, help, err } = parseArgs(process.argv.slice(2));
  if (err) {
    process.stderr.write(`chio-doctor: ${err}\n`);
    printHelp();
    process.exit(2);
  }
  if (help) {
    printHelp();
    process.exit(0);
  }

  const report = await runDoctor(opts);
  if (opts.json) {
    process.stdout.write(renderJson(report) + "\n");
  } else {
    const useColor = Boolean((process.stdout as NodeJS.WriteStream).isTTY)
      && process.env.NO_COLOR === undefined;
    process.stdout.write(renderTable(report, useColor) + "\n");
  }
  process.exit(report.summary.fail > 0 ? 1 : 0);
}

main().catch((err) => {
  process.stderr.write(`chio-doctor: fatal: ${(err as Error).stack ?? String(err)}\n`);
  process.exit(2);
});
