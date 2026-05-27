/**
 * Type definitions for smolvm-embedded.
 *
 * These types mirror the existing smolvm-node SDK API shape
 * but operate in-process via NAPI-RS (no daemon required).
 */

// ============================================================================
// Configuration Types
// ============================================================================

/**
 * Configuration for creating a machine.
 */
export interface MachineConfig {
  /** Unique name for the machine. Used as the VM identifier. */
  name: string;
  /** Host directories to mount into the VM. */
  mounts?: MountSpec[];
  /** Port mappings from host to guest. */
  ports?: PortSpec[];
  /** VM resource configuration. */
  resources?: ResourceSpec;
  /** If true, create() does NOT auto-start — call start() explicitly. Storage persists across stop/start. */
  persistent?: boolean;
}

/**
 * A host directory mount specification.
 */
export interface MountSpec {
  /** Absolute path on the host. */
  source: string;
  /** Absolute path inside the guest. */
  target: string;
  /** Mount as read-only (default: true). */
  readOnly?: boolean;
}

/**
 * A port mapping from host to guest.
 */
export interface PortSpec {
  /** Port on the host. */
  host: number;
  /** Port inside the guest. */
  guest: number;
}

/**
 * VM resource allocation.
 */
export interface ResourceSpec {
  /** Number of vCPUs (default: 4). */
  cpus?: number;
  /** Memory in MiB (default: 8192). */
  memoryMb?: number;
  /** Enable outbound network access (default: false). */
  network?: boolean;
  /** Storage disk size in GiB (default: 20). */
  storageGib?: number;
  /** Overlay disk size in GiB (default: 10). */
  overlayGib?: number;
}

// ============================================================================
// Execution Types
// ============================================================================

/**
 * Options for command execution.
 */
export interface ExecOptions {
  /** Environment variables as key-value pairs. */
  env?: Record<string, string>;
  /** Working directory for the command. */
  workdir?: string;
  /** Timeout in seconds. */
  timeout?: number;
}

/**
 * Options for writing a file into the VM.
 */
export interface FileWriteOptions {
  /** Optional octal file mode, for example `0o644`. */
  mode?: number;
}

/**
 * Options for code execution (extends ExecOptions).
 */
export interface CodeOptions extends ExecOptions {
  /** Override default image. */
  image?: string;
}

// ============================================================================
// Response Types
// ============================================================================

/**
 * Information about an OCI image.
 */
export interface ImageInfo {
  /** Image reference (e.g., "alpine:latest"). */
  reference: string;
  /** Image digest (sha256:...). */
  digest: string;
  /** Image size in bytes. */
  size: number;
  /** Platform architecture (e.g., "arm64"). */
  architecture: string;
  /** Platform OS (e.g., "linux"). */
  os: string;
}

/**
 * Event emitted by a streaming exec session.
 */
export interface ExecStreamEvent {
  /** Event kind. */
  kind: "stdout" | "stderr" | "exit" | "error";
  /** Text payload for stdout/stderr events. */
  data?: string;
  /** Exit code for exit events. */
  exitCode?: number;
  /** Error message for error events. */
  message?: string;
}
