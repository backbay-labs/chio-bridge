#!/usr/bin/env node
// Build a self-contained candidate without mutating source package metadata.
import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const destination = resolve(process.argv[2] ?? join(root, "artifacts"));
const manifestPath = join(root, "package.json");
const original = readFileSync(manifestPath);
const manifest = JSON.parse(original);
const stage = mkdtempSync(join(tmpdir(), "chio-release-stage-"));
const nodeModules = join(root, "node_modules");
const production = Object.keys(manifest.dependencies ?? {});
function run(command, args, cwd, capture = false) {
  const result = spawnSync(command, args, { cwd, encoding: "utf8", stdio: capture ? ["ignore", "pipe", "pipe"] : "inherit" });
  if (result.status !== 0) throw new Error(`${command} ${args.join(" ")} failed: ${result.stderr ?? result.error ?? result.status}`);
  return result.stdout ?? "";
}
function contained(base, target) {
  const rel = relative(base, target);
  return rel === "" || (!rel.startsWith(`..${process.platform === "win32" ? "\\" : "/"}`) && rel !== ".." && !isAbsolute(rel));
}
function packageDirectory(from, name) {
  let dir = from;
  while (contained(root, dir)) {
    const candidate = join(dir, "node_modules", name);
    if (existsSync(join(candidate, "package.json"))) {
      const actual = realpathSync(candidate);
      if (!contained(realpathSync(nodeModules), actual)) throw new Error(`dependency ${name} resolves outside this checkout's node_modules`);
      return actual;
    }
    if (dir === root) break;
    dir = dirname(dir);
  }
  throw new Error(`missing installed production dependency ${name}; run npm ci`);
}
function bundlePackage(source, target, chain = []) {
  if (chain.includes(source)) throw new Error(`cyclic production dependency: ${source}`);
  cpSync(source, target, { recursive: true, dereference: true, filter: path => !relative(source, path).split(/[\\/]/).includes("node_modules") });
  const pkg = JSON.parse(readFileSync(join(source, "package.json"), "utf8"));
  const dependencies = Object.keys(pkg.dependencies ?? {});
  for (const name of dependencies) {
    const childSource = packageDirectory(source, name);
    const child = JSON.parse(readFileSync(join(childSource, "package.json"), "utf8"));
    bundlePackage(childSource, join(target, "node_modules", name), [...chain, source]);
    pkg.dependencies[name] = child.version;
  }
  if (dependencies.length) pkg.bundleDependencies = dependencies;
  delete pkg.bundledDependencies;
  delete pkg.devDependencies;
  delete pkg.scripts;
  writeFileSync(join(target, "package.json"), `${JSON.stringify(pkg, null, 2)}\n`);
}
try {
  if (!existsSync(nodeModules) || lstatSync(nodeModules).isSymbolicLink()) throw new Error("run npm ci in this checkout; shared node_modules symlinks are unsupported");
  run("npm", ["run", "build"], root);
  // Ask npm for the selected release files before adding stage-only dependencies.
  const listing = JSON.parse(run("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], root, true))[0];
  for (const file of listing.files) {
    const target = join(stage, file.path);
    if (!contained(stage, target) || file.path.startsWith("node_modules/")) throw new Error(`unexpected source pack entry ${file.path}`);
    mkdirSync(dirname(target), {recursive: true});
    cpSync(join(root, file.path), target, {recursive: true, dereference: true});
  }
  const staged = {...manifest};
  staged.dependencies = {...manifest.dependencies};
  for (const name of production) {
    const source = packageDirectory(root, name);
    const pkg = JSON.parse(readFileSync(join(source, "package.json"), "utf8"));
    bundlePackage(source, join(stage, "node_modules", name));
    staged.dependencies[name] = pkg.version;
  }
  staged.bundleDependencies = production;
  delete staged.bundledDependencies;
  delete staged.devDependencies;
  delete staged.scripts;
  writeFileSync(join(stage, "package.json"), `${JSON.stringify(staged, null, 2)}\n`);
  mkdirSync(destination, {recursive: true});
  const packed = JSON.parse(run("npm", ["pack", "--json", "--ignore-scripts", "--pack-destination", destination], stage, true))[0];
  const artifact = join(destination, basename(packed.filename));
  const sha256 = createHash("sha256").update(readFileSync(artifact)).digest("hex");
  writeFileSync(`${artifact}.sha256`, `${sha256}  ${basename(artifact)}\n`);
  process.stdout.write(`${JSON.stringify({name:manifest.name,version:manifest.version,artifact,sha256,bundled:production})}\n`);
} finally {
  rmSync(stage, {recursive:true,force:true});
  if (!readFileSync(manifestPath).equals(original)) throw new Error("source manifest changed while packaging");
}
