import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { lintPolicy, loadPolicy, parsePolicy } from "../dist/policy.js";
import { HUSHSPEC_SUPPORTED_VERSION } from "../dist/types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ARC_EXAMPLES = resolve(__dirname, "fixtures");

test("loadPolicy parses vendored canonical-hushspec.yaml", async () => {
  const p = resolve(ARC_EXAMPLES, "canonical-hushspec.yaml");
  const policy = await loadPolicy(p);
  assert.equal(policy.hushspec, HUSHSPEC_SUPPORTED_VERSION);
  assert.equal(policy.name, "canonical-code-agent");
  assert.ok(policy.rules?.tool_access);
});

test("loadPolicy parses tiny-hedge fixture", async () => {
  const p = resolve(__dirname, "fixtures/tiny-hedge.policy.yaml");
  const policy = await loadPolicy(p);
  assert.equal(policy.hushspec, "0.1.0");
  assert.equal(policy.name, "tiny-hedge");
  const report = await lintPolicy(policy);
  assert.deepEqual(report.errors, [], `unexpected lint errors: ${JSON.stringify(report.errors)}`);
});

test("parsePolicy rejects missing hushspec version", () => {
  assert.throws(() => parsePolicy("name: no-version\n"), /hushspec/);
});

test("parsePolicy rejects unsupported version", () => {
  assert.throws(() => parsePolicy("hushspec: \"9.9.9\"\n"), /unsupported hushspec/);
});

test("lintPolicy accepts velocity and human_in_loop as first-class rules", async () => {
  // Wave 1.6 of arc-policy promoted velocity and human_in_loop to first-class
  // `Rules` variants (see arc/crates/arc-policy/src/models.rs). The previous
  // bridge version flagged them as unknown keys and suggested moving them to
  // `extensions.chio.*`; that suggestion is now wrong.
  const yaml = `hushspec: "0.1.0"
rules:
  velocity:
    enabled: true
    max_invocations_per_window: 100
    window_secs: 3600
  human_in_loop:
    enabled: true
    require_confirmation: ["wire_transfer"]
    timeout_seconds: 300
    on_timeout: deny
extensions:
  chio:
    market_hours:
      tz: "America/New_York"
      open: "09:30"
      close: "16:00"
      days: [mon, tue, wed, thu, fri]
`;
  const parsed = parsePolicy(yaml);
  const report = await lintPolicy(parsed);
  assert.deepEqual(
    report.errors,
    [],
    `unexpected errors: ${JSON.stringify(report.errors)}`,
  );
  assert.deepEqual(
    report.warnings,
    [],
    `unexpected warnings: ${JSON.stringify(report.warnings)}`,
  );
});

test("lintPolicy still accepts velocity mirrored under extensions.chio", async () => {
  const yaml = `hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    default: block
    allow: [read_file]
extensions:
  chio:
    velocity:
      per_minute: 10
`;
  const report = await lintPolicy(parsePolicy(yaml));
  assert.deepEqual(report.errors, []);
});

test("lintPolicy flags truly-unknown rule keys", async () => {
  const yaml = `hushspec: "0.1.0"
rules:
  made_up_rule:
    enabled: true
`;
  const report = await lintPolicy(parsePolicy(yaml));
  const err = report.errors.find((e) => e.path === "rules.made_up_rule");
  assert.ok(err, "expected an error on rules.made_up_rule");
  assert.match(err!.message, /unknown rule key/);
});

test("lintPolicy warns on shadowed tool in allow+deny", async () => {
  const yaml = `hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    default: block
    allow: [read_file, write_file]
    deny: [write_file]
`;
  const report = await lintPolicy(parsePolicy(yaml));
  const shadow = report.warnings.find((w) =>
    w.path.includes("rules.tool_access.deny"),
  );
  assert.ok(shadow, "expected shadow warning");
});

test("lintPolicy warns on disabled rule block (dead capability)", async () => {
  const yaml = `hushspec: "0.1.0"
rules:
  forbidden_paths:
    enabled: false
    patterns: ["**/.env"]
`;
  const report = await lintPolicy(parsePolicy(yaml));
  const dead = report.warnings.find((w) => w.path === "rules.forbidden_paths");
  assert.ok(dead, "expected dead-capability warning");
});

test("lintPolicy warns on permissive egress (default allow with no allowlist)", async () => {
  const yaml = `hushspec: "0.1.0"
rules:
  egress:
    enabled: true
    default: allow
    allow: []
`;
  const report = await lintPolicy(parsePolicy(yaml));
  const leak = report.warnings.find((w) => w.path === "rules.egress");
  assert.ok(leak, "expected egress permissiveness warning");
});

test("lintPolicy flags unknown top-level key", async () => {
  const yaml = `hushspec: "0.1.0"
unexpected_top: 42
`;
  const report = await lintPolicy(parsePolicy(yaml));
  const unk = report.errors.find((e) => e.path === "unexpected_top");
  assert.ok(unk, "expected unknown-top-level error");
});
