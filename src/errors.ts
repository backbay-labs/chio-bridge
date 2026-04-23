export class ChioBridgeError extends Error {
  readonly code: string;
  readonly detail?: unknown;
  constructor(code: string, message: string, detail?: unknown) {
    super(message);
    this.name = "ChioBridgeError";
    this.code = code;
    this.detail = detail;
  }
}

export class NotInitializedError extends ChioBridgeError {
  constructor(message = "bridge not initialized in daemon mode") {
    super("not_initialized", message);
    this.name = "NotInitializedError";
  }
}

export class PolicyParseError extends ChioBridgeError {
  readonly path?: string;
  constructor(message: string, path?: string, detail?: unknown) {
    super("policy_parse", message, detail);
    this.name = "PolicyParseError";
    this.path = path;
  }
}

export class CapabilityDeniedError extends ChioBridgeError {
  readonly guard?: string;
  constructor(message: string, guard?: string, detail?: unknown) {
    super("capability_denied", message, detail);
    this.name = "CapabilityDeniedError";
    this.guard = guard;
  }
}

export class DaemonUnreachableError extends ChioBridgeError {
  readonly url?: string;
  constructor(message: string, url?: string, detail?: unknown) {
    super("daemon_unreachable", message, detail);
    this.name = "DaemonUnreachableError";
    this.url = url;
  }
}

export class SignatureInvalidError extends ChioBridgeError {
  constructor(message = "signature verification failed", detail?: unknown) {
    super("signature_invalid", message, detail);
    this.name = "SignatureInvalidError";
  }
}

export class CliError extends ChioBridgeError {
  readonly stderr?: string;
  readonly exitCode: number | null;
  constructor(message: string, exitCode: number | null, stderr?: string) {
    super("cli_error", message, { stderr, exitCode });
    this.name = "CliError";
    this.exitCode = exitCode;
    this.stderr = stderr;
  }
}
