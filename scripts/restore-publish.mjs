#!/usr/bin/env node
// restore-publish.mjs — restore package.json from the backup created by
// prep-publish.mjs. Idempotent: no-op if the backup is missing.

import { existsSync, renameSync } from "node:fs";
import { resolve } from "node:path";

const pkgPath = resolve(process.cwd(), "package.json");
const bakPath = resolve(process.cwd(), "package.json.bak");

if (!existsSync(bakPath)) {
  console.error("[restore-publish] no backup; nothing to restore.");
  process.exit(0);
}

renameSync(bakPath, pkgPath);
console.error("[restore-publish] restored package.json from backup.");
