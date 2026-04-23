import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { CheckResult, CheckSection, RunContext } from "../types.js";
import { findOnPath, run } from "../util.js";

/**
 * Load the doctor's *own* package.json (i.e. @chio/bridge's package.json)
 * using the compiled location of this module. Walks upward from the
 * emitted file until it finds package.json — robust to both the src/
 * and dist/ layouts.
 */
function loadDoctorPackage(): { path: string; version: string } | undefined {
  const here = fileURLToPath(import.meta.url);
  let dir = dirname(here);
  for (let i = 0; i < 8; i++) {
    const candidate = resolve(dir, "package.json");
    if (existsSync(candidate)) {
      try {
        const pkg = JSON.parse(readFileSync(candidate, "utf8"));
        if (pkg.name === "@chio/bridge") {
          return { path: candidate, version: pkg.version ?? "?" };
        }
      } catch {
        // Ignore malformed; keep walking.
      }
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return undefined;
}

export async function runBridgeChecks(ctx: RunContext): Promise<CheckSection> {
  const results: CheckResult[] = [];
  const doctorPkg = loadDoctorPackage();
  const doctorVersion = doctorPkg?.version ?? "?";

  // 5. @chio/bridge reachable
  let bridgePath: string | undefined;
  let bridgeVersion: string | undefined;
  try {
    // Use a require relative to the caller's cwd so this mirrors what a
    // user installing `@chio/bridge` would see.
    const req = createRequire(resolve(ctx.cwd, "package.json"));
    try {
      const pkgJsonPath = req.resolve("@chio/bridge/package.json");
      bridgePath = pkgJsonPath;
      const pkg = JSON.parse(readFileSync(pkgJsonPath, "utf8"));
      bridgeVersion = pkg.version ?? "?";
      results.push({
        id: "bridge.reachable",
        label: "@chio/bridge",
        status: "ok",
        message: `v${bridgeVersion} at ${pkgJsonPath}`,
        details: { path: pkgJsonPath, version: bridgeVersion ?? null },
      });
    } catch {
      // Fall back to the doctor's own package.json — this happens when
      // `chio-doctor` is run directly out of the chio-bridge checkout.
      if (doctorPkg) {
        bridgePath = doctorPkg.path;
        bridgeVersion = doctorPkg.version;
        results.push({
          id: "bridge.reachable",
          label: "@chio/bridge",
          status: "ok",
          message: `v${bridgeVersion} (self, at ${doctorPkg.path})`,
          details: { path: doctorPkg.path, version: bridgeVersion, self: true },
        });
      } else {
        throw new Error("resolve failed");
      }
    }
  } catch {
    results.push({
      id: "bridge.reachable",
      label: "@chio/bridge",
      status: "fail",
      message: "package not resolvable",
      remediation: "bun add @chio/bridge",
    });
  }

  // 6. Bridge version matches doctor version
  if (bridgeVersion && doctorVersion !== "?") {
    if (bridgeVersion === doctorVersion) {
      results.push({
        id: "bridge.version-match",
        label: "version match",
        status: "ok",
        message: `bridge v${bridgeVersion} == doctor v${doctorVersion}`,
      });
    } else {
      results.push({
        id: "bridge.version-match",
        label: "version match",
        status: "warn",
        message: `bridge v${bridgeVersion} != doctor v${doctorVersion}`,
        remediation: "bun upgrade @chio/bridge to match, or reinstall the doctor bin",
      });
    }
  } else {
    results.push({
      id: "bridge.version-match",
      label: "version match",
      status: "skip",
      message: "bridge or doctor version unknown",
    });
  }

  // 7. Bridge unit tests — expensive; --full only
  if (!ctx.opts.full) {
    results.push({
      id: "bridge.unit-tests",
      label: "unit tests",
      status: "skip",
      message: "skipped (use --full)",
      fullOnly: true,
    });
  } else {
    const bridgeDir = doctorPkg ? dirname(doctorPkg.path) : ctx.cwd;
    const bun = findOnPath("bun", ctx.pathEnv);
    const runner = bun ?? "npm";
    const runnerArgs = bun ? ["test"] : ["run", "test"];
    const res = await run(runner, runnerArgs, {
      cwd: bridgeDir,
      timeoutMs: 120_000,
    });
    if (res.spawnError) {
      results.push({
        id: "bridge.unit-tests",
        label: "unit tests",
        status: "warn",
        message: `could not spawn ${runner}`,
        remediation: "install bun (https://bun.sh) or ensure npm is on PATH",
      });
    } else if (res.exitCode === 0) {
      results.push({
        id: "bridge.unit-tests",
        label: "unit tests",
        status: "ok",
        message: `${runner} ${runnerArgs.join(" ")} passed`,
        details: { cwd: bridgeDir, runner },
      });
    } else {
      results.push({
        id: "bridge.unit-tests",
        label: "unit tests",
        status: "warn",
        message: `${runner} ${runnerArgs.join(" ")} exited ${res.exitCode}`,
        remediation: "run tests manually for details",
        details: { cwd: bridgeDir, stderr: res.stderr.slice(-400) },
      });
    }
  }

  return { title: "Bridge", results };
}
