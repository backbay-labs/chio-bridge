/**
 * Library entrypoint for the `@chio/bridge/doctor` subpath. The actual
 * bin shim lives in `./bin.ts` so that importing the runner from unit
 * tests doesn't accidentally execute `main()`.
 */
export { runDoctor } from "./runner.js";
export { renderJson, renderTable } from "./render.js";
export type {
  CheckResult,
  CheckSection,
  CheckStatus,
  DoctorOptions,
  DoctorReport,
} from "./types.js";
