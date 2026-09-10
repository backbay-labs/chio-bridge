import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const api = new URL("../dist/index.js", import.meta.url).href;
const gateway = fileURLToPath(new URL("../dist/gateway.js", import.meta.url));
const code = `const api = await import(${JSON.stringify(api)}); if(typeof api.ChioBridge !== 'function') throw new Error('API missing'); console.log('IMPORT_OK');`;

function imported(args: string[], input?: string, cwd?: string) {
  const result = spawnSync(process.execPath, args, { input, cwd, encoding: "utf8", timeout: 10000 });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "IMPORT_OK\n");
  assert.equal(result.stderr, "", "import must not start the gateway CLI");
}

test("bridge imports from explicit '-' stdin without treating it as a file", () => {
  imported(["--input-type=module", "-"], code);
});

test("bridge imports from implicit stdin and eval without a main filename", () => {
  imported(["--input-type=module"], code);
  imported(["--input-type=module", "--eval", code]);
});

test("eval arguments naming the actual gateway cannot accidentally start its CLI", () => {
  imported(["--input-type=module", "--eval", code, gateway]);
  imported(["--input-type=module", "-e", code, gateway]);
  imported(["--input-type=module", `--eval=${code}`, gateway]);
});

test("normal file imports and non-file argv entries do not execute the gateway", () => {
  const dir = mkdtempSync(join(tmpdir(), "chio-bridge-import-"));
  try {
    const script = join(dir, "import.mjs"); writeFileSync(script, code);
    imported([script]);
    for (const entry of [join(dir, "missing"), join(script, "not-a-directory")]) {
      writeFileSync(script, `process.argv[1] = ${JSON.stringify(entry)};\n${code}`);
      imported([script]);
    }
    writeFileSync(join(dir, "-"), "this is not the Node stdin entrypoint");
    imported(["--input-type=module", "-"], code, dir);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("actual gateway entrypoint still executes and reports invalid startup", () => {
  const result = spawnSync(process.execPath, [gateway], { encoding: "utf8", timeout: 10000 });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /gateway startup or persistence failed/);
});
