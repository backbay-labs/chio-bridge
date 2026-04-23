/**
 * Shared types for `chio-doctor`.
 *
 * Each check emits a `CheckResult` describing its status, a one-line
 * message, and (optionally) a remediation hint. The top-level runner
 * groups these into sections and aggregates counts for summary output.
 */

export type CheckStatus = "ok" | "warn" | "fail" | "skip";

export interface CheckResult {
  /** Stable, machine-readable identifier (e.g. "env.chio-binary"). */
  id: string;
  /** Short label for table output (e.g. "chio binary"). */
  label: string;
  status: CheckStatus;
  /** One-line summary message (e.g. "v0.1.0 at /usr/local/bin/chio"). */
  message: string;
  /** Remediation hint for warn/fail rows. */
  remediation?: string;
  /** Opaque structured data for `--json` consumers. */
  details?: Record<string, unknown>;
  /** If true, suggests --full will unlock this (used for skipped probes). */
  fullOnly?: boolean;
}

export interface CheckSection {
  /** Section title (e.g. "Environment"). */
  title: string;
  results: CheckResult[];
}

export interface DoctorReport {
  doctorVersion: string;
  startedAt: string;
  finishedAt: string;
  sections: CheckSection[];
  summary: {
    ok: number;
    warn: number;
    fail: number;
    skip: number;
  };
}

export interface DoctorOptions {
  /** Run expensive probes (harness start, endpoint hits, unit tests). */
  full: boolean;
  /** Emit JSON instead of the colored table. */
  json: boolean;
  /** Scope plugin checks to this plugin name only. */
  plugin?: string;
  /** Attempt `--fix` for warn/fail rows where we have a known recipe. */
  fix: boolean;
  /** cwd override for discovery (tests inject a tmpdir). */
  cwd?: string;
  /** HOME override (tests inject a tmpdir). */
  home?: string;
  /** PATH override (tests force-miss the chio binary). */
  pathEnv?: string;
}

export interface RunContext {
  opts: DoctorOptions;
  cwd: string;
  home: string;
  pathEnv: string;
}
