import type { CheckResult, CheckSection, RunContext } from "../types.js";
import { compareSemver, extractVersion, findOnPath, run } from "../util.js";

const MIN_CHIO = "0.1.0";
const MIN_NODE = "20.0.0";

export async function runEnvironmentChecks(ctx: RunContext): Promise<CheckSection> {
  const results: CheckResult[] = [];

  // 1. chio binary on PATH
  const chioPath = findOnPath("chio", ctx.pathEnv) ?? findOnPath("arc", ctx.pathEnv);
  let chioVersion: string | undefined;
  if (!chioPath) {
    results.push({
      id: "env.chio-binary",
      label: "chio binary",
      status: "fail",
      message: "not found on PATH",
      remediation:
        "install from https://chio.world/releases or build from source at standalone/arc/",
    });
  } else {
    const res = await run(chioPath, ["--version"], { timeoutMs: 5_000 });
    if (res.spawnError || res.exitCode !== 0) {
      results.push({
        id: "env.chio-binary",
        label: "chio binary",
        status: "fail",
        message: `${chioPath} exists but \`--version\` failed (exit ${res.exitCode})`,
        remediation: "rebuild the chio binary: cargo build --release -p chio-cli",
        details: { path: chioPath, stderr: res.stderr.slice(0, 200) },
      });
    } else {
      chioVersion = extractVersion(res.stdout + " " + res.stderr);
      results.push({
        id: "env.chio-binary",
        label: "chio binary",
        status: "ok",
        message: `v${chioVersion ?? "?"} at ${chioPath}`,
        details: { path: chioPath, version: chioVersion ?? null },
      });
    }
  }

  // 2. chio version >= MIN_CHIO
  if (chioVersion === undefined) {
    results.push({
      id: "env.chio-version",
      label: "chio version",
      status: "skip",
      message: "chio binary not usable; cannot verify version",
    });
  } else if (!/^\d+\.\d+\.\d+/.test(chioVersion)) {
    results.push({
      id: "env.chio-version",
      label: "chio version",
      status: "warn",
      message: `unexpected version format: ${chioVersion}`,
      remediation: "upgrade chio; expected semver like 0.1.0",
    });
  } else if (compareSemver(chioVersion, MIN_CHIO) < 0) {
    results.push({
      id: "env.chio-version",
      label: "chio version",
      status: "fail",
      message: `v${chioVersion} < required v${MIN_CHIO}`,
      remediation: "upgrade the chio binary to at least v0.1.0",
    });
  } else {
    results.push({
      id: "env.chio-version",
      label: "chio version",
      status: "ok",
      message: `>= ${MIN_CHIO}`,
      details: { version: chioVersion, min: MIN_CHIO },
    });
  }

  // 3. Node >= 20
  const nodeVersionRaw = process.version; // e.g. "v22.14.0"
  const nodeVersion = extractVersion(nodeVersionRaw) ?? "0.0.0";
  if (compareSemver(nodeVersion, MIN_NODE) < 0) {
    results.push({
      id: "env.node",
      label: "node",
      status: "fail",
      message: `${nodeVersionRaw} < required v${MIN_NODE}`,
      remediation: "install Node 20+ from https://nodejs.org",
    });
  } else {
    results.push({
      id: "env.node",
      label: "node",
      status: "ok",
      message: nodeVersionRaw,
      details: { version: nodeVersion },
    });
  }

  // 4. Bun (optional)
  const bunPath = findOnPath("bun", ctx.pathEnv);
  if (!bunPath) {
    results.push({
      id: "env.bun",
      label: "bun",
      status: "warn",
      message: "not found",
      remediation: "some plugins ship Bun tooling (see https://bun.sh)",
    });
  } else {
    const res = await run(bunPath, ["--version"], { timeoutMs: 3_000 });
    const bunVersion = extractVersion(res.stdout);
    results.push({
      id: "env.bun",
      label: "bun",
      status: "ok",
      message: `v${bunVersion ?? "?"} at ${bunPath}`,
      details: { path: bunPath, version: bunVersion ?? null },
    });
  }

  return { title: "Environment", results };
}
