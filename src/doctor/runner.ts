import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runEnvironmentChecks } from "./checks/environment.js";
import { runBridgeChecks } from "./checks/bridge.js";
import { runHarnessChecks, tearDownHarness } from "./checks/harness.js";
import { runPluginChecks } from "./checks/plugins.js";
import { runPolicyChecks } from "./checks/policy.js";
import { applyFixes } from "./fix.js";
import type {
  CheckSection,
  DoctorOptions,
  DoctorReport,
  RunContext,
} from "./types.js";

function doctorVersion(): string {
  const here = fileURLToPath(import.meta.url);
  let dir = dirname(here);
  for (let i = 0; i < 8; i++) {
    const candidate = resolve(dir, "package.json");
    if (existsSync(candidate)) {
      try {
        const pkg = JSON.parse(readFileSync(candidate, "utf8"));
        if (pkg.name === "@chio/bridge" && typeof pkg.version === "string") {
          return pkg.version;
        }
      } catch {
        // Keep walking; malformed package.json is not fatal.
      }
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return "0.0.0";
}

/**
 * Run every configured check and return a structured report. Separating
 * this from the CLI entrypoint keeps it easy to unit-test with a
 * synthetic RunContext.
 */
export async function runDoctor(opts: DoctorOptions): Promise<DoctorReport> {
  const startedAt = new Date().toISOString();
  const ctx: RunContext = {
    opts,
    cwd: opts.cwd ?? process.cwd(),
    home: opts.home ?? (process.env.HOME ?? ""),
    pathEnv: opts.pathEnv ?? (process.env.PATH ?? ""),
  };

  const sections: CheckSection[] = [];

  sections.push(await runEnvironmentChecks(ctx));
  sections.push(await runBridgeChecks(ctx));

  const { section: harnessSection, state: harnessState } =
    await runHarnessChecks(ctx);
  sections.push(harnessSection);

  try {
    sections.push(await runPluginChecks(ctx));
    sections.push(await runPolicyChecks(ctx));
  } finally {
    // Always tear the harness down, even if a later check threw, so
    // callers of `--full` don't leak daemon processes.
    await tearDownHarness(harnessState);
  }

  if (opts.fix) {
    await applyFixes(sections, ctx);
  }

  const summary = { ok: 0, warn: 0, fail: 0, skip: 0 };
  for (const s of sections) {
    for (const r of s.results) {
      summary[r.status]++;
    }
  }

  return {
    doctorVersion: doctorVersion(),
    startedAt,
    finishedAt: new Date().toISOString(),
    sections,
    summary,
  };
}
