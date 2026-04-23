import { spawn, spawnSync, type SpawnOptions } from "node:child_process";
import { existsSync } from "node:fs";
import { CliError } from "../errors.js";

export interface CliResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
}

export interface CliRunOptions {
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
  cwd?: string;
  input?: string;
}

/**
 * Resolve the binary used for policy enforcement, preferring the renamed
 * `chio` binary over the legacy `arc` binary.
 *
 * Discovery order:
 *   1. Explicit argument (highest precedence).
 *   2. `CHIO_BIN` env var (set by the chio-test-harness env.sh).
 *   3. An absolute-path sibling `chio` binary next to a known `arc` pointer
 *      (`CHIO_ARC_BIN` legacy env, or `ARC_BIN`). Used when harness env
 *      still points at the pre-rename binary but a `chio` binary has been
 *      built in the same release directory.
 *   4. Plain `chio` on `$PATH`.
 *   5. Legacy fallback: `CHIO_ARC_BIN` / `ARC_BIN` (pre-Wave 5.0.1).
 *   6. Final fallback: plain `arc` on `$PATH`.
 *
 * Wave 5.0.1: the rename sweep produced a fresh `chio` binary. Prefer it
 * when available so downstream is not permanently pinned to the legacy
 * `arc` artifact.
 */
export function resolveChioBinary(explicit?: string): string {
  if (explicit && explicit.length > 0) {
    return explicit;
  }

  const envChio = process.env.CHIO_BIN;
  if (envChio && envChio.length > 0) {
    return envChio;
  }

  const legacyArc = process.env.CHIO_ARC_BIN ?? process.env.ARC_BIN;
  if (legacyArc && legacyArc.length > 0) {
    // If we can see a sibling `chio` binary next to the legacy `arc`
    // pointer (release builds land both in target/release/), prefer chio.
    const sibling = legacyArc.replace(/arc(?:\.exe)?$/, "chio");
    if (sibling !== legacyArc && existsSync(sibling)) {
      return sibling;
    }
  }

  // Probe $PATH for `chio` before falling back to the legacy name.
  if (hasOnPath("chio")) {
    return "chio";
  }

  if (legacyArc && legacyArc.length > 0) {
    return legacyArc;
  }

  return "arc";
}

function hasOnPath(name: string): boolean {
  try {
    const probe = spawnSync(name, ["--version"], { stdio: "ignore" });
    return probe.status !== null && probe.error === undefined;
  } catch {
    return false;
  }
}

export class ChioCli {
  readonly binary: string;

  constructor(binary?: string) {
    this.binary = resolveChioBinary(binary);
  }

  async run(args: string[], options: CliRunOptions = {}): Promise<CliResult> {
    return runCommand(this.binary, args, options);
  }

  async runJson<T = unknown>(args: string[], options: CliRunOptions = {}): Promise<T> {
    const withJsonFlag = args.includes("--format") || args.includes("--json")
      ? args
      : [...args, "--format", "json"];
    const result = await this.run(withJsonFlag, options);
    if (result.exitCode !== 0 && result.stdout.trim().length === 0) {
      throw new CliError(
        `chio ${args.join(" ")} exited ${result.exitCode}`,
        result.exitCode,
        result.stderr,
      );
    }
    const text = result.stdout.trim();
    if (text.length === 0) {
      throw new CliError(
        `chio ${args.join(" ")} produced no JSON output`,
        result.exitCode,
        result.stderr,
      );
    }
    try {
      return JSON.parse(extractLastJson(text)) as T;
    } catch (cause) {
      throw new CliError(
        `chio ${args.join(" ")} produced unparseable JSON`,
        result.exitCode,
        `${result.stderr}\nraw: ${text.slice(0, 500)}`,
      );
    }
  }
}

export function runCommand(
  binary: string,
  args: string[],
  options: CliRunOptions = {},
): Promise<CliResult> {
  return new Promise((resolve, reject) => {
    const spawnOptions: SpawnOptions = {
      stdio: ["pipe", "pipe", "pipe"],
      env: options.env ?? process.env,
    };
    if (options.cwd) spawnOptions.cwd = options.cwd;

    const child = spawn(binary, args, spawnOptions);
    let stdout = "";
    let stderr = "";
    let timer: NodeJS.Timeout | undefined;

    child.stdout?.setEncoding("utf8");
    child.stderr?.setEncoding("utf8");
    child.stdout?.on("data", (d: string) => {
      stdout += d;
    });
    child.stderr?.on("data", (d: string) => {
      stderr += d;
    });

    child.on("error", (err) => {
      if (timer) clearTimeout(timer);
      reject(new CliError(`failed to spawn ${binary}: ${err.message}`, null, stderr));
    });

    child.on("close", (code) => {
      if (timer) clearTimeout(timer);
      resolve({ stdout, stderr, exitCode: code });
    });

    if (options.timeoutMs !== undefined) {
      timer = setTimeout(() => {
        child.kill("SIGKILL");
        reject(new CliError(`command timed out after ${options.timeoutMs}ms`, null, stderr));
      }, options.timeoutMs);
    }

    if (options.input !== undefined) {
      child.stdin?.write(options.input);
      child.stdin?.end();
    } else {
      child.stdin?.end();
    }
  });
}

/**
 * Some chio subcommands emit a human-readable prefix before a JSON blob.
 * We accept either a full JSON body, or extract the last balanced JSON object.
 */
function extractLastJson(text: string): string {
  const trimmed = text.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) return trimmed;
  const lastOpen = Math.max(trimmed.lastIndexOf("\n{"), trimmed.lastIndexOf("\n["));
  if (lastOpen === -1) return trimmed;
  return trimmed.slice(lastOpen + 1);
}
