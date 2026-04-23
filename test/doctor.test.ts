import { test } from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { runDoctor } from "../dist/doctor/index.js";
import type { CheckResult, CheckStatus } from "../dist/doctor/types.js";

function makeTmpdir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), `chio-doctor-${prefix}-`));
}

/**
 * Writes a tiny shell script at <dir>/<name> that echoes the given
 * version string on --version and exits 0. We use this to mock the
 * `chio` and `bun` binaries against a clean, synthetic PATH.
 *
 * We use `#!/bin/bash` (absolute) so the script works even when our
 * synthetic PATH doesn't contain /usr/bin — otherwise `/usr/bin/env bash`
 * fails at shebang resolution and `run()` returns exit 127.
 */
function writeFakeBinary(dir: string, name: string, versionOutput: string): string {
  const path = join(dir, name);
  writeFileSync(path, `#!/bin/bash\necho "${versionOutput}"\n`, "utf8");
  chmodSync(path, 0o755);
  return path;
}

function getById(results: CheckResult[], id: string): CheckResult {
  const r = results.find((x) => x.id === id);
  assert.ok(r, `expected check ${id} in results`);
  return r;
}

function allIds(sections: { results: CheckResult[] }[]): CheckResult[] {
  return sections.flatMap((s) => s.results);
}

test("doctor reports ok when fake chio, node, bun all resolve", async () => {
  const binDir = makeTmpdir("bin-ok");
  writeFakeBinary(binDir, "chio", "chio-cli 0.2.0");
  writeFakeBinary(binDir, "bun", "1.3.3");
  const cwd = makeTmpdir("cwd-ok");
  const home = makeTmpdir("home-ok");

  const report = await runDoctor({
    full: false,
    json: false,
    fix: false,
    cwd,
    home,
    pathEnv: binDir,
  });

  const all = allIds(report.sections);
  const binary = getById(all, "env.chio-binary");
  assert.equal(binary.status satisfies CheckStatus, "ok");
  assert.match(binary.message, /v0\.2\.0/);

  const version = getById(all, "env.chio-version");
  assert.equal(version.status, "ok");

  const bun = getById(all, "env.bun");
  assert.equal(bun.status, "ok");

  // Node comes from the running process, which in CI is >= 20.
  const node = getById(all, "env.node");
  assert.equal(node.status, "ok");
});

test("doctor fails `env.chio-binary` when nothing matches on PATH", async () => {
  // An empty synthetic bin dir means chio, arc, and bun are all missing.
  const binDir = makeTmpdir("bin-empty");
  const cwd = makeTmpdir("cwd-fail");
  const home = makeTmpdir("home-fail");

  const report = await runDoctor({
    full: false,
    json: false,
    fix: false,
    cwd,
    home,
    pathEnv: binDir,
  });

  const all = allIds(report.sections);
  const binary = getById(all, "env.chio-binary");
  assert.equal(binary.status, "fail");
  assert.ok(binary.remediation, "fail should have a remediation");

  // Version check degrades to skip when the binary isn't usable.
  const version = getById(all, "env.chio-version");
  assert.equal(version.status, "skip");

  // Bun missing degrades to warn (not fail) per the contract.
  const bun = getById(all, "env.bun");
  assert.equal(bun.status, "warn");

  // Exit-code semantics: at least one fail.
  assert.ok(report.summary.fail >= 1);
});

test("doctor warns on plugin version match when bridge differs from doctor", async () => {
  const binDir = makeTmpdir("bin-vm");
  writeFakeBinary(binDir, "chio", "chio-cli 0.1.0");
  const cwd = makeTmpdir("cwd-vm");
  // Install a fake @chio/bridge in the synthetic cwd's node_modules with
  // a different version — this exercises the `require.resolve` path
  // and the version-mismatch branch.
  const modDir = join(cwd, "node_modules", "@chio", "bridge");
  mkdirSync(modDir, { recursive: true });
  writeFileSync(
    join(modDir, "package.json"),
    JSON.stringify({ name: "@chio/bridge", version: "9.9.9" }),
    "utf8",
  );
  writeFileSync(join(cwd, "package.json"), JSON.stringify({ name: "probe" }), "utf8");
  const home = makeTmpdir("home-vm");

  const report = await runDoctor({
    full: false,
    json: false,
    fix: false,
    cwd,
    home,
    pathEnv: binDir,
  });

  const all = allIds(report.sections);
  const reach = getById(all, "bridge.reachable");
  assert.equal(reach.status, "ok");
  const match = getById(all, "bridge.version-match");
  assert.equal(match.status, "warn");
  assert.match(match.message, /9\.9\.9/);
});

test("doctor detects a claude-code plugin under synthetic HOME", async () => {
  const binDir = makeTmpdir("bin-p");
  const cwd = makeTmpdir("cwd-p");
  const home = makeTmpdir("home-p");
  const pluginDir = join(home, ".claude", "plugins", "chio", ".claude-plugin");
  mkdirSync(pluginDir, { recursive: true });
  writeFileSync(
    join(pluginDir, "plugin.json"),
    JSON.stringify({ name: "chio", version: "0.2.0" }),
    "utf8",
  );

  const report = await runDoctor({
    full: false,
    json: false,
    fix: false,
    cwd,
    home,
    pathEnv: binDir,
  });

  const plugins = report.sections.find((s) => s.title.startsWith("Plugins"));
  assert.ok(plugins, "expected plugins section");
  assert.ok(plugins.results.some((r) => r.label === "chio"));
  const chio = plugins.results.find((r) => r.label === "chio");
  assert.ok(chio);
  assert.equal(chio!.status, "ok");
});

test("doctor lints an on-disk .chio/policy.yaml", async () => {
  const binDir = makeTmpdir("bin-pol");
  const cwd = makeTmpdir("cwd-pol");
  const home = makeTmpdir("home-pol");
  mkdirSync(join(cwd, ".chio"), { recursive: true });
  // Minimal valid HushSpec policy (shape cribbed from bridge fixtures).
  writeFileSync(
    join(cwd, ".chio", "policy.yaml"),
    [
      'hushspec: "0.1.0"',
      "name: doctor-probe",
      "rules:",
      "  tool_access:",
      "    enabled: true",
      "    default: block",
      "    allow:",
      "      - echo",
      "",
    ].join("\n"),
    "utf8",
  );

  const report = await runDoctor({
    full: false,
    json: false,
    fix: false,
    cwd,
    home,
    pathEnv: binDir,
  });

  const policy = report.sections.find((s) => s.title === "Policy");
  assert.ok(policy);
  const lint = policy!.results.find((r) => r.id === "policy.lint");
  assert.ok(lint, "expected policy.lint row");
  // `ok` or `warn` both acceptable; a `fail` means the policy schema
  // rejected our shape, which we want to know about.
  assert.notEqual(lint!.status, "fail");
});
