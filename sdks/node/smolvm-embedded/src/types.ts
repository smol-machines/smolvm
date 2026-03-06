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
 * Configuration for creating a sandbox.
 */
export interface SandboxConfig {
  /** Unique name for the sandbox. Used as the VM identifier. */
  name: string;
  /** Host directories to mount into the VM. */
  mounts?: MountSpec[];
  /** Port mappings from host to guest. */
  ports?: PortSpec[];
  /** VM resource configuration. */
  resources?: ResourceSpec;
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
  /** Number of vCPUs (default: 1). */
  cpus?: number;
  /** Memory in MiB (default: 512). */
  memoryMb?: number;
  /** Enable outbound network access (default: false). */
  network?: boolean;
  /** Storage disk size in GiB (default: 20). */
  storageGb?: number;
  /** Overlay disk size in GiB (default: 2). */
  overlayGb?: number;
}

/**
 * Configuration for creating a MicroVM.
 *
 * Same shape as SandboxConfig — MicroVMs are persistent named VMs
 * that survive across process invocations and support reconnection.
 */
export interface MicroVMConfig {
  /** Unique name for the MicroVM. Used as the VM identifier. */
  name: string;
  /** Host directories to mount into the VM. */
  mounts?: MountSpec[];
  /** Port mappings from host to guest. */
  ports?: PortSpec[];
  /** VM resource configuration. */
  resources?: ResourceSpec;
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
