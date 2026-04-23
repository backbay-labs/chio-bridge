import { readFile } from "node:fs/promises";
import YAML from "yaml";
import { PolicyParseError } from "./errors.js";
import {
  EXTENSION_KEYS,
  HUSHSPEC_SUPPORTED_VERSION,
  RULE_KEYS,
  type HushSpec,
  type LintIssue,
  type LintReport,
  type RuleKey,
} from "./types.js";

const RULE_KEY_SET = new Set<string>(RULE_KEYS);
const EXTENSION_KEY_SET = new Set<string>(EXTENSION_KEYS);

const TOP_LEVEL_KEYS = new Set([
  "hushspec",
  "name",
  "description",
  "extends",
  "merge_strategy",
  "rules",
  "extensions",
  "metadata",
]);

const MERGE_STRATEGIES = new Set(["replace", "merge", "deep_merge"]);

/**
 * Keys that older policies occasionally place under `rules:` that still
 * don't exist as first-class HushSpec rules in chio-policy. We retain a
 * small fallback map so the lint suggestion remains actionable — but note
 * that `velocity` and `human_in_loop` are now first-class rules (Wave 1.6)
 * so they're no longer mapped here.
 */
const KNOWN_EXTENSION_FALLBACKS: Record<string, string> = {
  approval: "extensions.chio.approval",
  budget: "extensions.chio.budget",
};

export async function loadPolicy(path: string): Promise<HushSpec> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (cause) {
    throw new PolicyParseError(
      `failed to read policy at ${path}: ${(cause as Error).message}`,
      path,
      cause,
    );
  }
  return parsePolicy(text, path);
}

export function parsePolicy(text: string, path?: string): HushSpec {
  let doc: unknown;
  try {
    doc = YAML.parse(text);
  } catch (cause) {
    throw new PolicyParseError(
      `YAML parse error: ${(cause as Error).message}`,
      path,
      cause,
    );
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    throw new PolicyParseError("policy root must be a YAML mapping", path);
  }
  const obj = doc as Record<string, unknown>;
  const version = obj.hushspec;
  if (typeof version !== "string") {
    throw new PolicyParseError(
      "policy is missing required `hushspec` version field",
      path,
    );
  }
  if (version !== HUSHSPEC_SUPPORTED_VERSION) {
    throw new PolicyParseError(
      `unsupported hushspec version "${version}" (expected "${HUSHSPEC_SUPPORTED_VERSION}")`,
      path,
    );
  }
  return obj as unknown as HushSpec;
}

export async function lintPolicy(input: HushSpec | string): Promise<LintReport> {
  const policy: HushSpec =
    typeof input === "string" ? await loadPolicy(input) : input;
  const errors: LintIssue[] = [];
  const warnings: LintIssue[] = [];

  if (policy.hushspec !== HUSHSPEC_SUPPORTED_VERSION) {
    errors.push({
      path: "hushspec",
      message: `unsupported hushspec version "${policy.hushspec}"`,
      severity: "error",
      suggestion: `set hushspec: "${HUSHSPEC_SUPPORTED_VERSION}"`,
    });
  }

  const policyObj = policy as unknown as Record<string, unknown>;
  for (const key of Object.keys(policyObj)) {
    if (!TOP_LEVEL_KEYS.has(key)) {
      errors.push({
        path: key,
        message: `unknown top-level key "${key}"`,
        severity: "error",
        suggestion:
          "HushSpec 0.1.0 permits only: hushspec, name, description, extends, merge_strategy, rules, extensions, metadata",
      });
    }
  }

  if (policy.merge_strategy && !MERGE_STRATEGIES.has(policy.merge_strategy)) {
    errors.push({
      path: "merge_strategy",
      message: `invalid merge_strategy "${policy.merge_strategy}"`,
      severity: "error",
      suggestion: "one of: replace, merge, deep_merge",
    });
  }

  const rules = policy.rules;
  if (rules && typeof rules === "object" && !Array.isArray(rules)) {
    const rulesObj = rules as Record<string, unknown>;
    for (const key of Object.keys(rulesObj)) {
      if (!RULE_KEY_SET.has(key)) {
        const fallback = KNOWN_EXTENSION_FALLBACKS[key];
        errors.push({
          path: `rules.${key}`,
          message: `unknown rule key "${key}" (not in HushSpec 0.1.0 closed schema)`,
          severity: "error",
          suggestion: fallback
            ? `move to \`${fallback}\` until it lands as a first-class rule`
            : `valid rule keys: ${RULE_KEYS.join(", ")}`,
        });
      }
    }

    checkToolAccessShadow(rulesObj, warnings);
    checkEgressLeak(rulesObj, warnings);
    checkDeadCapability(rulesObj, warnings);
  } else if (rules !== undefined) {
    errors.push({
      path: "rules",
      message: "rules must be a mapping",
      severity: "error",
    });
  }

  const extensions = policy.extensions;
  if (extensions && typeof extensions === "object" && !Array.isArray(extensions)) {
    const extObj = extensions as Record<string, unknown>;
    for (const key of Object.keys(extObj)) {
      if (!EXTENSION_KEY_SET.has(key)) {
        errors.push({
          path: `extensions.${key}`,
          message: `unknown extension "${key}" (not in chio-policy Extensions schema)`,
          severity: "error",
          suggestion: `valid extensions: ${EXTENSION_KEYS.join(", ")}`,
        });
      }
    }
  } else if (extensions !== undefined) {
    errors.push({
      path: "extensions",
      message: "extensions must be a mapping",
      severity: "error",
    });
  }

  return { errors, warnings };
}

function checkToolAccessShadow(
  rules: Record<string, unknown>,
  warnings: LintIssue[],
): void {
  const ta = rules.tool_access;
  if (!ta || typeof ta !== "object" || Array.isArray(ta)) return;
  const tao = ta as Record<string, unknown>;
  const allow = Array.isArray(tao.allow) ? (tao.allow as unknown[]) : [];
  const deny = Array.isArray(tao.deny) ? (tao.deny as unknown[]) : [];
  const allowSet = new Set(allow.filter((v): v is string => typeof v === "string"));
  for (const d of deny) {
    if (typeof d === "string" && allowSet.has(d)) {
      warnings.push({
        path: `rules.tool_access.deny[${d}]`,
        message: `tool "${d}" appears in both allow and deny; deny wins (shadowed rule)`,
        severity: "warning",
        suggestion: "remove from one list",
      });
    }
  }
  if (tao.default === "allow" && allow.length > 0 && deny.length === 0) {
    warnings.push({
      path: "rules.tool_access",
      message: "`allow` list has no effect when default is allow and deny is empty",
      severity: "warning",
      suggestion: "set default: block for a deny-by-default allowlist",
    });
  }
}

function checkEgressLeak(
  rules: Record<string, unknown>,
  warnings: LintIssue[],
): void {
  const eg = rules.egress;
  if (!eg || typeof eg !== "object" || Array.isArray(eg)) {
    const hasPathRules = Boolean(rules.path_allowlist ?? rules.forbidden_paths);
    if (hasPathRules) {
      warnings.push({
        path: "rules.egress",
        message:
          "policy defines filesystem rules but no egress policy; network calls default to kernel default",
        severity: "warning",
        suggestion: "add `rules.egress: { enabled: true, default: block, allow: [] }` for explicit network control",
      });
    }
    return;
  }
  const ego = eg as Record<string, unknown>;
  const allow = Array.isArray(ego.allow) ? (ego.allow as unknown[]) : [];
  if (ego.default === "allow" && allow.length === 0) {
    warnings.push({
      path: "rules.egress",
      message: "egress defaults to allow with no allowlist — effectively wide-open",
      severity: "warning",
      suggestion: "either set default: block, or enumerate allow: [...]",
    });
  }
}

function checkDeadCapability(
  rules: Record<string, unknown>,
  warnings: LintIssue[],
): void {
  for (const [key, value] of Object.entries(rules)) {
    if (!RULE_KEY_SET.has(key)) continue;
    if (!value || typeof value !== "object" || Array.isArray(value)) continue;
    const ruleObj = value as Record<string, unknown>;
    if ("enabled" in ruleObj && ruleObj.enabled === false) {
      warnings.push({
        path: `rules.${key}`,
        message: `rule "${key}" is disabled (enabled: false) — it will not be enforced`,
        severity: "warning",
        suggestion: "remove the block or set enabled: true",
      });
    }
  }
}

export function ruleKeys(): readonly RuleKey[] {
  return RULE_KEYS;
}
