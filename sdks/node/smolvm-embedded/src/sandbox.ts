/**
 * Sandbox — high-level wrapper around NapiSandbox.
 *
 * Provides the same ergonomic API as @smolvm/node but runs entirely
 * in-process via native bindings (no daemon required).
 */

import { ExecResult } from "./execution.js";
import { parseNativeError } from "./errors.js";
import { loadNativeBinding } from "./native-binding.js";
import type {
  SandboxConfig,
  ExecOptions,
  ImageInfo,
  MountSpec,
  PortSpec,
  ResourceSpec,
} from "./types.js";

const { NapiSandbox } = loadNativeBinding();

/**
 * Convert SDK ExecOptions to the NAPI format.
 */
function toNapiExecOptions(
  options?: ExecOptions
): { env?: Array<{ key: string; value: string }>; workdir?: string; timeoutSecs?: number } | undefined {
  if (!options) return undefined;
  return {
    env: options.env
      ? Object.entries(options.env).map(([key, value]) => ({ key, value }))
      : undefined,
    workdir: options.workdir,
    timeoutSecs: options.timeout,
  };
}

/**
 * Convert SDK config to NAPI format.
 */
function toNapiConfig(config: SandboxConfig) {
  return {
    name: config.name,
    mounts: config.mounts?.map((m: MountSpec) => ({
      source: m.source,
      target: m.target,
      readOnly: m.readOnly,
    })),
    ports: config.ports?.map((p: PortSpec) => ({
      host: p.host,
      guest: p.guest,
    })),
    resources: config.resources
      ? {
          cpus: config.resources.cpus,
          memoryMb: config.resources.memoryMb,
          network: config.resources.network,
          storageGb: config.resources.storageGb,
          overlayGb: config.resources.overlayGb,
        }
      : undefined,
  };
}

/**
 * Wrap a native call with error translation.
 */
async function wrapNative<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    throw parseNativeError(err as Error);
  }
}

/**
 * A sandbox wrapping a microVM with native bindings.
 *
 * No daemon required — the VM runs directly in the Node.js process
 * via libkrun (Hypervisor.framework on macOS, KVM on Linux).
 */
export class Sandbox {
  readonly name: string;
  private native: InstanceType<typeof NapiSandbox>;
  private started = false;

  protected constructor(config: SandboxConfig) {
    this.name = config.name;
    this.native = new NapiSandbox(toNapiConfig(config));
  }

  /**
   * Create and start a new sandbox.
   */
  static async create(config: SandboxConfig): Promise<Sandbox> {
    const sandbox = new Sandbox(config);
    await sandbox.start();
    return sandbox;
  }

  /**
   * Start the sandbox VM.
   *
   * Boots a microVM via fork + libkrun, waits for the agent to be ready,
   * then establishes a vsock connection. If the VM is already running
   * with matching config, this is a no-op.
   */
  async start(): Promise<void> {
    await wrapNative(() => this.native.start());
    this.started = true;
  }

  /** Whether the sandbox has been started. */
  get isStarted(): boolean {
    return this.started;
  }

  /** Get the current VM state: "stopped", "starting", "running", or "stopping". */
  get state(): string {
    return this.native.state();
  }

  /**
   * Execute a command directly in the VM.
   *
   * @param command - Command and arguments (e.g., ["echo", "hello"])
   * @param options - Execution options (env, workdir, timeout)
   */
  async exec(command: string[], options?: ExecOptions): Promise<ExecResult> {
    const result = await wrapNative<{ exitCode: number; stdout: string; stderr: string }>(() =>
      this.native.exec(command, toNapiExecOptions(options))
    );
    return new ExecResult(result.exitCode, result.stdout, result.stderr);
  }

  /**
   * Pull an OCI image and run a command inside it.
   *
   * @param image - OCI image reference (e.g., "alpine:latest")
   * @param command - Command and arguments
   * @param options - Execution options
   */
  async run(
    image: string,
    command: string[],
    options?: ExecOptions
  ): Promise<ExecResult> {
    const result = await wrapNative<{ exitCode: number; stdout: string; stderr: string }>(() =>
      this.native.run(image, command, toNapiExecOptions(options))
    );
    return new ExecResult(result.exitCode, result.stdout, result.stderr);
  }

  /**
   * Pull an OCI image into the sandbox's storage.
   */
  async pullImage(image: string): Promise<ImageInfo> {
    return wrapNative(() => this.native.pullImage(image));
  }

  /**
   * List all cached OCI images.
   */
  async listImages(): Promise<ImageInfo[]> {
    return wrapNative(() => this.native.listImages());
  }

  /**
   * Stop the sandbox VM gracefully.
   */
  async stop(): Promise<void> {
    await wrapNative(() => this.native.stop());
    this.started = false;
  }

  /**
   * Stop the sandbox and delete all associated storage.
   */
  async delete(): Promise<void> {
    await wrapNative(() => this.native.delete());
    this.started = false;
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Create a sandbox, run a function with it, then clean up.
 *
 * @example
 * ```ts
 * const result = await withSandbox({ name: "my-task" }, async (sb) => {
 *   return await sb.exec(["echo", "hello"]);
 * });
 * ```
 */
export async function withSandbox<T>(
  config: SandboxConfig,
  fn: (sandbox: Sandbox) => Promise<T>
): Promise<T> {
  const sandbox = await Sandbox.create(config);
  try {
    return await fn(sandbox);
  } finally {
    await sandbox.delete().catch(() => {
      // Best-effort cleanup
    });
  }
}

/**
 * Quick one-shot command execution in a temporary sandbox.
 *
 * Creates a sandbox, runs the command, cleans up, and returns the result.
 *
 * @example
 * ```ts
 * const result = await quickExec(["echo", "hello"]);
 * console.log(result.stdout); // "hello\n"
 * ```
 */
export async function quickExec(
  command: string[],
  options?: SandboxConfig & ExecOptions
): Promise<ExecResult> {
  const name = options?.name ?? `quick-${Date.now().toString(36)}`;
  return withSandbox({ ...options, name }, (sb) =>
    sb.exec(command, options)
  );
}

/**
 * Quick one-shot command execution in a container image.
 *
 * Creates a sandbox, pulls the image, runs the command, cleans up.
 *
 * @example
 * ```ts
 * const result = await quickRun("alpine:latest", ["cat", "/etc/os-release"]);
 * console.log(result.stdout);
 * ```
 */
export async function quickRun(
  image: string,
  command: string[],
  options?: SandboxConfig & ExecOptions
): Promise<ExecResult> {
  const name = options?.name ?? `quick-${Date.now().toString(36)}`;
  return withSandbox({ ...options, name }, (sb) =>
    sb.run(image, command, options)
  );
}
