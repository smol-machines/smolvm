/**
 * Error classes for smolvm-embedded.
 */

/**
 * Base error class for all smolvm embedded SDK errors.
 */
export class SmolvmError extends Error {
  readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = "SmolvmError";
    this.code = code;
  }
}

/** VM or resource not found. */
export class NotFoundError extends SmolvmError {
  constructor(message: string) {
    super(message, "NOT_FOUND");
    this.name = "NotFoundError";
  }
}

/** Invalid VM state for the requested operation. */
export class InvalidStateError extends SmolvmError {
  constructor(message: string) {
    super(message, "INVALID_STATE");
    this.name = "InvalidStateError";
  }
}

/** Hypervisor not available on this system. */
export class HypervisorUnavailableError extends SmolvmError {
  constructor(message: string) {
    super(message, "HYPERVISOR_UNAVAILABLE");
    this.name = "HypervisorUnavailableError";
  }
}

/** Resource conflict (e.g., sandbox already exists). */
export class ConflictError extends SmolvmError {
  constructor(message: string) {
    super(message, "CONFLICT");
    this.name = "ConflictError";
  }
}

/**
 * Parse a NAPI error into a typed SmolvmError.
 *
 * NAPI errors from the Rust side are formatted as `[CODE] message`.
 */
export function parseNativeError(err: Error): SmolvmError {
  const match = err.message.match(/^\[(\w+)\]\s*(.*)/s);
  if (!match) {
    return new SmolvmError(err.message, "SMOLVM_ERROR");
  }

  const [, code, message] = match;

  switch (code) {
    case "NOT_FOUND":
      return new NotFoundError(message);
    case "INVALID_STATE":
      return new InvalidStateError(message);
    case "HYPERVISOR_UNAVAILABLE":
      return new HypervisorUnavailableError(message);
    case "CONFLICT":
      return new ConflictError(message);
    default:
      return new SmolvmError(message, code);
  }
}
