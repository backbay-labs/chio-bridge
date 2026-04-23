import { resolve } from "node:path";
import type { CheckSection, RunContext } from "./types.js";
import { findOnPath, run } from "./util.js";

/**
 * Best-effort auto-remediation. We only implement fixes we can run with
 * zero blast radius: install a package, start the harness. Anything
 * that touches network secrets, policy files, or binaries stays manual.
 *
 * Each applied fix mutates the matching result status toward `ok` with
 * a trailing `[fixed]` note so `--json` consumers can audit what we did.
 */
export async function applyFixes(
  sections: CheckSection[],
  ctx: RunContext,
): Promise<void> {
  for (const section of sections) {
    for (const r of section.results) {
      if (r.status !== "fail" && r.status !== "warn") continue;

      if (r.id === "bridge.reachable") {
        const bun = findOnPath("bun", ctx.pathEnv);
        if (!bun) {
          r.message += " [fix skipped: no bun]";
          continue;
        }
        const res = await run(bun, ["add", "@chio/bridge"], {
          cwd: ctx.cwd,
          timeoutMs: 120_000,
        });
        if (res.exitCode === 0) {
          r.status = "ok";
          r.message = "installed via `bun add @chio/bridge` [fixed]";
        } else {
          r.message += ` [fix failed: exit ${res.exitCode}]`;
        }
        continue;
      }

      if (r.id === "harness.daemon") {
        const dir = (r.details?.dir as string | undefined)
          ?? process.env.CHIO_HARNESS_DIR;
        if (!dir) {
          r.message += " [fix skipped: harness dir unknown]";
          continue;
        }
        const start = resolve(dir, "bin/start.sh");
        const res = await run("bash", [start], {
          cwd: dir,
          timeoutMs: 45_000,
        });
        if (res.exitCode === 0) {
          r.status = "ok";
          r.message = "started via bin/start.sh [fixed]";
        } else {
          r.message += ` [fix failed: exit ${res.exitCode}]`;
        }
        continue;
      }
    }
  }
}
