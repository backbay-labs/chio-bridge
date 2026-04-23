#!/usr/bin/env node
// prep-publish.mjs — rewrite `file:` workspace deps to real semver ranges.
//
// Run via `prepack`. Writes a copy of `package.json` to `package.json.bak`
// and rewrites selected deps so the tarball that `npm pack`/`npm publish`
// produces is publishable against the npm registry.
//
// Restore with `scripts/restore-publish.mjs` (run via `postpack`).
//
// Works purely in-tree: local `bun install` still uses the original
// `file:` links; only the tarball gets the transformed specs.

import { readFileSync, writeFileSync, copyFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

const pkgPath = resolve(process.cwd(), "package.json");
const bakPath = resolve(process.cwd(), "package.json.bak");

// Dep-name → publish-time semver range. Keep in sync with the
// target package's ^X.Y.Z as declared in its own package.json.
const REWRITES = {
  "@chio-protocol/sdk": "^1.0.0",
  "@chio/bridge": "^0.2.1",
};

if (existsSync(bakPath)) {
  // A previous run bailed before restoring. Keep the backup; do not
  // overwrite it with a possibly-rewritten package.json.
  console.error(
    "[prep-publish] package.json.bak already exists; refusing to clobber.",
  );
  process.exit(1);
}

const raw = readFileSync(pkgPath, "utf8");
const pkg = JSON.parse(raw);

copyFileSync(pkgPath, bakPath);

let rewrote = 0;
for (const group of ["dependencies", "peerDependencies"]) {
  const deps = pkg[group];
  if (!deps) continue;
  for (const [name, spec] of Object.entries(deps)) {
    if (typeof spec !== "string") continue;
    if (!spec.startsWith("file:")) continue;
    const target = REWRITES[name];
    if (!target) {
      console.error(
        `[prep-publish] dep ${name} has file: spec but no publish rewrite target`,
      );
      process.exit(2);
    }
    deps[name] = target;
    rewrote++;
  }
}

writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");
console.error(`[prep-publish] rewrote ${rewrote} file: dep(s) for publish.`);
