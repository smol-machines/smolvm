/**
 * PythonSandbox — pre-configured sandbox for running Python code.
 */

import { Sandbox } from "../sandbox.js";
import { ExecResult } from "../execution.js";
import type { SandboxConfig, ExecOptions, CodeOptions } from "../types.js";

export class PythonSandbox extends Sandbox {
  static readonly DEFAULT_IMAGE = "python:3.12-alpine";

  static async create(config: SandboxConfig): Promise<PythonSandbox> {
    const sandbox = new PythonSandbox(config);
    await sandbox.start();
    // Pre-pull the Python image
    await sandbox.pullImage(PythonSandbox.DEFAULT_IMAGE);
    return sandbox;
  }

  private constructor(config: SandboxConfig) {
    super(config);
  }

  /** Run Python code. */
  async runCode(code: string, options?: CodeOptions): Promise<ExecResult> {
    const image = options?.image ?? PythonSandbox.DEFAULT_IMAGE;
    return this.run(image, ["python3", "-c", code], options);
  }

  /** Run a Python file (must be in a mounted directory). */
  async runFile(path: string, options?: CodeOptions): Promise<ExecResult> {
    const image = options?.image ?? PythonSandbox.DEFAULT_IMAGE;
    return this.run(image, ["python3", path], options);
  }

  /** Run setup code, then main code. */
  async runWithSetup(
    setupCode: string,
    mainCode: string,
    options?: CodeOptions
  ): Promise<ExecResult> {
    const combined = `${setupCode}\n${mainCode}`;
    return this.runCode(combined, options);
  }

  /** Install pip packages. */
  async pip(
    packages: string[],
    options?: ExecOptions
  ): Promise<ExecResult> {
    return this.run(
      PythonSandbox.DEFAULT_IMAGE,
      ["pip", "install", ...packages],
      options
    );
  }

  /** List installed packages. */
  async listPackages(options?: ExecOptions): Promise<string[]> {
    const result = await this.run(
      PythonSandbox.DEFAULT_IMAGE,
      ["pip", "list", "--format=freeze"],
      options
    );
    return result.stdout.trim().split("\n").filter(Boolean);
  }

  /** Get Python version. */
  async version(options?: CodeOptions): Promise<string> {
    const image = options?.image ?? PythonSandbox.DEFAULT_IMAGE;
    const result = await this.run(image, ["python3", "--version"], options);
    return result.stdout.trim();
  }
}
