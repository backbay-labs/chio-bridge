import type { CheckStatus, DoctorReport } from "./types.js";

const RESET = "\x1b[0m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const RED = "\x1b[31m";
const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";

function color(useColor: boolean, code: string, text: string): string {
  return useColor ? `${code}${text}${RESET}` : text;
}

function glyph(status: CheckStatus, useColor: boolean): string {
  switch (status) {
    case "ok":   return color(useColor, GREEN,  "\u2713"); // ✓
    case "warn": return color(useColor, YELLOW, "\u26A0"); // ⚠
    case "fail": return color(useColor, RED,    "\u2717"); // ✗
    case "skip": return color(useColor, DIM,    "\u2298"); // ⊘
  }
}

/**
 * Produce the default colored, aligned terminal table. If
 * `process.stdout.isTTY` is false the caller should pass useColor=false.
 */
export function renderTable(report: DoctorReport, useColor: boolean): string {
  const lines: string[] = [];
  lines.push(color(useColor, BOLD, `chio doctor ${report.doctorVersion}`));
  lines.push("");

  // Column width: align the label column across all sections so the
  // message column starts at a consistent x-position.
  let labelWidth = 10;
  for (const s of report.sections) {
    for (const r of s.results) {
      if (r.label.length > labelWidth) labelWidth = r.label.length;
    }
  }
  labelWidth = Math.min(labelWidth, 30);

  for (const section of report.sections) {
    lines.push(section.title);
    for (const r of section.results) {
      const padded = r.label.padEnd(labelWidth, " ");
      const msg = r.status === "warn" && r.remediation
        ? `${r.message} \u00B7 ${r.remediation}`
        : r.message;
      lines.push(`  ${glyph(r.status, useColor)} ${padded}  ${msg}`);
      if (r.status === "fail" && r.remediation) {
        lines.push(`    ${color(useColor, DIM, "\u2192 " + r.remediation)}`);
      }
    }
    lines.push("");
  }

  const { ok, warn, fail, skip } = report.summary;
  lines.push(
    `Summary: ${color(useColor, GREEN, `${ok} ok`)} \u00B7 ` +
    `${color(useColor, YELLOW, `${warn} warn`)} \u00B7 ` +
    `${color(useColor, RED, `${fail} fail`)} \u00B7 ` +
    `${skip} skipped`,
  );
  if (skip > 0) {
    lines.push(color(useColor, DIM, "Run `chio doctor --full` to execute skipped checks."));
  }
  return lines.join("\n");
}

export function renderJson(report: DoctorReport): string {
  return JSON.stringify(report, null, 2);
}
