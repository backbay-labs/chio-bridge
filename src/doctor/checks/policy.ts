import { existsSync } from "node:fs";
import { join } from "node:path";
import { lintPolicy, loadPolicy } from "../../policy.js";
import type { CheckResult, CheckSection, RunContext } from "../types.js";

/** 15. default policy discoverable + lintable. */
export async function runPolicyChecks(ctx: RunContext): Promise<CheckSection> {
  const results: CheckResult[] = [];
  const policyPath = join(ctx.cwd, ".chio", "policy.yaml");
  if (!existsSync(policyPath)) {
    results.push({
      id: "policy.discoverable",
      label: "policy",
      status: "skip",
      message: `no .chio/policy.yaml in ${ctx.cwd}`,
    });
    return { title: "Policy", results };
  }
  try {
    const policy = await loadPolicy(policyPath);
    const report = await lintPolicy(policy);
    if (report.errors.length > 0) {
      results.push({
        id: "policy.lint",
        label: "policy lint",
        status: "fail",
        message: `${report.errors.length} error(s) in ${policyPath}`,
        remediation: report.errors.slice(0, 2).map((e) => `${e.path}: ${e.message}`).join("; "),
        details: { errors: report.errors, warnings: report.warnings },
      });
    } else if (report.warnings.length > 0) {
      results.push({
        id: "policy.lint",
        label: "policy lint",
        status: "warn",
        message: `${report.warnings.length} warning(s) in ${policyPath}`,
        details: { warnings: report.warnings },
      });
    } else {
      results.push({
        id: "policy.lint",
        label: "policy lint",
        status: "ok",
        message: `clean at ${policyPath}`,
      });
    }
  } catch (err) {
    results.push({
      id: "policy.lint",
      label: "policy lint",
      status: "fail",
      message: `parse failed: ${(err as Error).message}`,
      remediation: `fix YAML at ${policyPath} or re-generate it`,
    });
  }
  return { title: "Policy", results };
}
