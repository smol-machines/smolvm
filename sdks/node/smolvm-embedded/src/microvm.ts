/**
 * MicroVM — persistent named VM that survives across process invocations.
 *
 * Unlike Sandbox (which auto-starts on create and deletes storage on cleanup),
 * MicroVM provides explicit lifecycle control and supports reconnection to
 * already-running VMs. No container support (no run/pullImage/listImages).
 */

import { ExecResult } from "./execution.js";
import { parseNativeError } from "./errors.js";
import { loadNativeBinding } from "./native-binding.js";
import type { MicroVMConfig, ExecOptions, MountSpec, PortSpec } from "./types.js";

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
 * Convert MicroVMConfig to NAPI format.
 */
function toNapiConfig(config: MicroVMConfig) {
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
 * A persistent named MicroVM.
 *
 * MicroVMs differ from Sandboxes:
 * - `create()` does NOT auto-start — call `start()` explicitly
 * - `connect()` reconnects to an already-running VM by name
 * - No container support (`run()`, `pullImage()`, `listImages()`)
 * - Storage persists across stop/start cycles (use `delete()` to remove)
 * - Exposes `pid` and `isRunning` for process inspection
 */
export class MicroVM {
  readonly name: string;
  private native: InstanceType<typeof NapiSandbox>;

  private constructor(name: string, native: InstanceType<typeof NapiSandbox>) {
    this.name = name;
    this.native = native;
  }

  /**
   * Create a new MicroVM (does NOT start it — call `start()` explicitly).
   */
  static async create(config: MicroVMConfig): Promise<MicroVM> {
    const native = new NapiSandbox(toNapiConfig(config));
    return new MicroVM(config.name, native);
  }

  /**
   * Connect to an already-running MicroVM by name.
   *
   * Throws NotFoundError if no running VM exists with the given name.
   */
  static async connect(name: string): Promise<MicroVM> {
    try {
      const native = NapiSandbox.connect(name);
      return new MicroVM(name, native);
    } catch (err) {
      throw parseNativeError(err as Error);
    }
  }

  /**
   * Start the MicroVM.
   *
   * Boots a microVM via fork + libkrun, waits for the agent to be ready,
   * then establishes a vsock connection. If the VM is already running
   * with matching config, this is a no-op.
   */
  async start(): Promise<void> {
    await wrapNative(() => this.native.start());
  }

  /**
   * Stop the MicroVM gracefully. Storage is preserved.
   */
  async stop(): Promise<void> {
    await wrapNative(() => this.native.stop());
  }

  /**
   * Stop the MicroVM and delete all associated storage.
   */
  async delete(): Promise<void> {
    await wrapNative(() => this.native.delete());
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

  /** Get the current VM state: "stopped", "starting", "running", or "stopping". */
  get state(): string {
    return this.native.state();
  }

  /** Whether the VM process is currently running. */
  get isRunning(): boolean {
    return this.native.isRunning;
  }

  /** The child PID of the VM process, or null if not running. */
  get pid(): number | null {
    return this.native.pid ?? null;
  }
}

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Create a MicroVM, start it, run a function, then stop it.
 *
 * Unlike `withSandbox`, this stops (not deletes) the VM — storage is preserved.
 *
 * @example
 * ```ts
 * const result = await withMicroVM({ name: "my-vm" }, async (vm) => {
 *   return await vm.exec(["echo", "hello"]);
 * });
 * ```
 */
export async function withMicroVM<T>(
  config: MicroVMConfig,
  fn: (vm: MicroVM) => Promise<T>
): Promise<T> {
  const vm = await MicroVM.create(config);
  await vm.start();
  try {
    return await fn(vm);
  } finally {
    await vm.stop().catch(() => {
      // Best-effort cleanup
    });
  }
}
