import { spawn, type SpawnOptions } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { delimiter, join } from "node:path";

export interface RunResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  /** True if the process could not even be spawned (ENOENT etc). */
  spawnError: boolean;
}

/**
 * Thin wrapper around child_process.spawn that captures stdout/stderr
 * into strings and always resolves (never rejects) so check code can
 * make status decisions based on exit code and spawnError alone.
 */
export function run(
  binary: string,
  args: string[],
  options: { timeoutMs?: number; env?: NodeJS.ProcessEnv; cwd?: string } = {},
): Promise<RunResult> {
  return new Promise((resolve) => {
    const spawnOptions: SpawnOptions = {
      stdio: ["ignore", "pipe", "pipe"],
      env: options.env ?? process.env,
    };
    if (options.cwd) spawnOptions.cwd = options.cwd;

    let child;
    try {
      child = spawn(binary, args, spawnOptions);
    } catch (err) {
      resolve({ stdout: "", stderr: String(err), exitCode: null, spawnError: true });
      return;
    }

    let stdout = "";
    let stderr = "";
    let timer: NodeJS.Timeout | undefined;
    let settled = false;

    child.stdout?.setEncoding("utf8");
    child.stderr?.setEncoding("utf8");
    child.stdout?.on("data", (d: string) => { stdout += d; });
    child.stderr?.on("data", (d: string) => { stderr += d; });

    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve({
        stdout,
        stderr: stderr || String(err),
        exitCode: null,
        spawnError: true,
      });
    });

    child.on("close", (code) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve({ stdout, stderr, exitCode: code, spawnError: false });
    });

    if (options.timeoutMs !== undefined) {
      timer = setTimeout(() => {
        try { child.kill("SIGKILL"); } catch {
          // Already exited; safe to ignore.
        }
      }, options.timeoutMs);
    }
  });
}

/**
 * Search the given PATH string for an executable file. Returns the
 * first match or undefined. Pure function — tests inject `pathEnv`.
 */
export function findOnPath(binary: string, pathEnv: string): string | undefined {
  if (!pathEnv) return undefined;
  for (const dir of pathEnv.split(delimiter)) {
    if (!dir) continue;
    const candidate = join(dir, binary);
    try {
      if (existsSync(candidate)) {
        const st = statSync(candidate);
        if (st.isFile()) return candidate;
      }
    } catch {
      // Skip unreadable directories.
    }
  }
  return undefined;
}

/** Compare two semver-ish strings; returns <0 / 0 / >0 like strcmp. */
export function compareSemver(a: string, b: string): number {
  const pa = a.replace(/^v/, "").split(/[.\-+]/).map((s) => parseInt(s, 10) || 0);
  const pb = b.replace(/^v/, "").split(/[.\-+]/).map((s) => parseInt(s, 10) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const av = pa[i] ?? 0;
    const bv = pb[i] ?? 0;
    if (av !== bv) return av - bv;
  }
  return 0;
}

/** Return a semver-ish match from a free-form version string. */
export function extractVersion(text: string): string | undefined {
  const m = text.match(/(\d+\.\d+\.\d+(?:-[\w.]+)?)/);
  return m?.[1];
}
