/**
 * smolvm-embedded — Embedded Node.js SDK for smolvm.
 *
 * Embed microVMs directly in your Node.js process via NAPI-RS.
 * No daemon required.
 *
 * @example
 * ```ts
 * import { quickExec, withSandbox, Sandbox } from "smolvm-embedded";
 *
 * // One-liner
 * const result = await quickExec(["echo", "hello"]);
 *
 * // Managed lifecycle
 * await withSandbox({ name: "my-sandbox" }, async (sb) => {
 *   const r = await sb.exec(["date"]);
 *   console.log(r.stdout);
 * });
 *
 * // Full control
 * const sb = await Sandbox.create({ name: "my-vm" });
 * const r = await sb.run("alpine:latest", ["cat", "/etc/os-release"]);
 * console.log(r.stdout);
 * await sb.delete();
 * ```
 */

// Core classes
export { Sandbox, withSandbox, quickExec, quickRun } from "./sandbox.js";
export { MicroVM, withMicroVM } from "./microvm.js";
export { ExecResult, ExecutionError } from "./execution.js";

// Presets
export { PythonSandbox } from "./presets/python.js";
export { NodeSandbox } from "./presets/node.js";

// Error classes
export {
  SmolvmError,
  NotFoundError,
  InvalidStateError,
  HypervisorUnavailableError,
  ConflictError,
  parseNativeError,
} from "./errors.js";

// Types
export type {
  SandboxConfig,
  MicroVMConfig,
  MountSpec,
  PortSpec,
  ResourceSpec,
  ExecOptions,
  CodeOptions,
  ImageInfo,
} from "./types.js";
