/**
 * smolvm-embedded — Embedded Node.js SDK for smolvm.
 *
 * Embed microVMs directly in your Node.js process via NAPI-RS.
 * No daemon required.
 *
 * @example
 * ```ts
 * import { quickExec, withMachine, Machine } from "smolvm-embedded";
 *
 * // One-liner
 * const result = await quickExec(["echo", "hello"]);
 *
 * // Managed lifecycle
 * await withMachine({ name: "my-machine" }, async (sb) => {
 *   const r = await sb.exec(["date"]);
 *   console.log(r.stdout);
 * });
 *
 * // Full control
 * const sb = await Machine.create({ name: "my-vm" });
 * const r = await sb.run("alpine:latest", ["cat", "/etc/os-release"]);
 * console.log(r.stdout);
 * await sb.delete();
 * ```
 */

// Core classes
export { Machine, withMachine, quickExec, quickRun } from "./machine.js";
export { ExecResult, ExecutionError } from "./execution.js";

// Presets
export { PythonMachine } from "./presets/python.js";
export { NodeMachine } from "./presets/node.js";

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
  MachineConfig,
  MountSpec,
  PortSpec,
  ResourceSpec,
  ExecOptions,
  CodeOptions,
  ImageInfo,
} from "./types.js";
