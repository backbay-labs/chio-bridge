import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import type { CheckResult, CheckSection, RunContext } from "../types.js";

interface PluginFinding {
  name: string;
  version?: string;
  source: string;
  kind: "claude-code" | "codex" | "cursor" | "opencode" | "workspace";
  manifestPath?: string;
  manifest?: Record<string, unknown>;
}

/**
 * Discover and validate chio plugin installs across common agent shells.
 * Everything here is read-only — we never modify plugin files.
 */
export async function runPluginChecks(ctx: RunContext): Promise<CheckSection> {
  const results: CheckResult[] = [];
  const findings = discoverPlugins(ctx);

  const filtered = ctx.opts.plugin
    ? findings.filter((f) => f.name.includes(ctx.opts.plugin as string))
    : findings;

  if (filtered.length === 0) {
    results.push({
      id: "plugins.none",
      label: "plugins",
      status: "skip",
      message: ctx.opts.plugin
        ? `no plugin matched --plugin ${ctx.opts.plugin}`
        : "no chio plugins detected",
    });
    return { title: `Plugins (0 found)`, results };
  }

  for (const f of filtered) {
    const v = validate(f);
    results.push({
      id: `plugins.${f.kind}.${f.name}`,
      label: f.name,
      status: v.status,
      message: `${v.status === "ok" ? "v" + (f.version ?? "?") + " " : ""}${v.detail} (${f.source})`,
      remediation: v.remediation,
      details: {
        kind: f.kind,
        version: f.version ?? null,
        source: f.source,
        manifestPath: f.manifestPath ?? null,
      },
    });
  }

  return { title: `Plugins (${filtered.length} found)`, results };
}

function discoverPlugins(ctx: RunContext): PluginFinding[] {
  const found: PluginFinding[] = [];

  // Claude Code: ~/.claude/plugins/**/.claude-plugin/plugin.json
  const claudeRoot = join(ctx.home, ".claude", "plugins");
  scanPluginsRoot(claudeRoot, "claude-code", found);

  // Codex: ~/.codex/plugins/**
  const codexRoot = join(ctx.home, ".codex", "plugins");
  scanPluginsRoot(codexRoot, "codex", found);

  // Opencode: ~/.opencode/plugins/**
  const opencodeRoot = join(ctx.home, ".opencode", "plugins");
  scanOpencodeRoot(opencodeRoot, found);

  // Cursor: .cursor/hooks.json in cwd
  const cursorHooks = join(ctx.cwd, ".cursor", "hooks.json");
  if (existsSync(cursorHooks)) {
    try {
      const text = readFileSync(cursorHooks, "utf8");
      if (text.includes("chio") || text.includes(".chio/")) {
        found.push({
          name: "chio-cursor-plugin",
          source: cursorHooks,
          kind: "cursor",
          manifestPath: cursorHooks,
          manifest: JSON.parse(text),
        });
      }
    } catch {
      // Treat unparseable files as still-detected but lint-failing.
      found.push({
        name: "chio-cursor-plugin",
        source: cursorHooks,
        kind: "cursor",
        manifestPath: cursorHooks,
      });
    }
  }

  // Workspace: .chio/ in cwd
  const chioWorkspace = join(ctx.cwd, ".chio");
  if (existsSync(chioWorkspace) && statSync(chioWorkspace).isDirectory()) {
    found.push({
      name: ".chio workspace",
      source: chioWorkspace,
      kind: "workspace",
    });
  }

  return found;
}

function scanPluginsRoot(
  root: string,
  kind: "claude-code" | "codex",
  out: PluginFinding[],
): void {
  if (!existsSync(root)) return;
  let entries: string[] = [];
  try { entries = readdirSync(root); } catch { return; }
  for (const name of entries) {
    const pluginDir = join(root, name);
    const manifestRel = kind === "claude-code"
      ? join(".claude-plugin", "plugin.json")
      : join(".codex-plugin", "plugin.json");
    const manifestPath = join(pluginDir, manifestRel);
    if (existsSync(manifestPath)) {
      let manifest: Record<string, unknown> | undefined;
      let version: string | undefined;
      try {
        const raw = JSON.parse(readFileSync(manifestPath, "utf8"));
        manifest = raw;
        version = typeof raw.version === "string" ? raw.version : undefined;
      } catch {
        // Leave undefined; validator will flag invalid JSON.
      }
      out.push({
        name: (manifest?.name as string | undefined) ?? name,
        version,
        source: pluginDir,
        kind,
        manifestPath,
        manifest,
      });
    }
  }
}

function scanOpencodeRoot(root: string, out: PluginFinding[]): void {
  if (!existsSync(root)) return;
  let entries: string[] = [];
  try { entries = readdirSync(root); } catch { return; }
  for (const name of entries) {
    const pluginDir = join(root, name);
    const manifestPath = join(pluginDir, "opencode.json");
    if (existsSync(manifestPath)) {
      try {
        const raw = JSON.parse(readFileSync(manifestPath, "utf8"));
        const version = typeof raw.version === "string" ? raw.version : undefined;
        out.push({
          name: (raw.name as string | undefined) ?? name,
          version,
          source: pluginDir,
          kind: "opencode",
          manifestPath,
          manifest: raw,
        });
      } catch {
        out.push({
          name,
          source: pluginDir,
          kind: "opencode",
          manifestPath,
        });
      }
    }
  }
}

function validate(f: PluginFinding): {
  status: "ok" | "warn" | "fail";
  detail: string;
  remediation?: string;
} {
  if (f.kind === "workspace") {
    return { status: "ok", detail: `workspace at ${f.source}` };
  }
  if (!f.manifest) {
    return {
      status: "warn",
      detail: "manifest unreadable",
      remediation: `inspect ${f.manifestPath ?? f.source}`,
    };
  }
  // Each plugin kind has a minimal schema we validate against. We
  // intentionally don't depend on the plugin's own type defs so the
  // doctor keeps working across versions.
  if (f.kind === "claude-code") {
    const m = f.manifest as Record<string, unknown>;
    if (typeof m.name !== "string" || typeof m.version !== "string") {
      return {
        status: "fail",
        detail: "missing name/version in plugin.json",
        remediation: "add top-level `name` and `version` strings",
      };
    }
    return { status: "ok", detail: `at ${f.source}` };
  }
  if (f.kind === "codex") {
    const m = f.manifest as Record<string, unknown>;
    if (typeof m.name !== "string" || typeof m.version !== "string") {
      return {
        status: "fail",
        detail: "missing name/version in .codex-plugin/plugin.json",
        remediation: "add top-level `name` and `version` strings",
      };
    }
    const hooksRef = (m.hooks as string | undefined) ?? "./hooks.json";
    const resolved = resolve(f.source, hooksRef);
    if (!existsSync(resolved)) {
      return {
        status: "warn",
        detail: `hooks.json referenced but missing: ${hooksRef}`,
        remediation: `create ${hooksRef} in ${f.source}`,
      };
    }
    return { status: "ok", detail: `at ${f.source}` };
  }
  if (f.kind === "cursor") {
    const m = f.manifest as Record<string, unknown>;
    if (typeof m.version !== "number" || !m.hooks || typeof m.hooks !== "object") {
      return {
        status: "fail",
        detail: "hooks.json missing `version` or `hooks`",
        remediation: "reinstall chio-cursor-plugin to regenerate .cursor/hooks.json",
      };
    }
    return { status: "ok", detail: `via ${f.source}` };
  }
  if (f.kind === "opencode") {
    const m = f.manifest as Record<string, unknown>;
    const plugins = (m.plugins as unknown[] | undefined) ?? [];
    const hasChio = Array.isArray(plugins)
      && plugins.some((p) => typeof p === "string" && p.includes("chio"));
    if (!hasChio) {
      return {
        status: "warn",
        detail: "opencode.json does not list a chio plugin",
        remediation: "add chio entry to opencode.json `plugins`",
      };
    }
    return { status: "ok", detail: `at ${f.source}` };
  }
  return { status: "warn", detail: "unknown plugin kind" };
}
