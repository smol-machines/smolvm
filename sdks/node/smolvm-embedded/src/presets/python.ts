/**
 * PythonMachine — pre-configured machine for running Python code.
 */

import { Machine } from "../machine.js";
import { ExecResult } from "../execution.js";
import type { MachineConfig, ExecOptions, CodeOptions } from "../types.js";

export class PythonMachine extends Machine {
  static readonly DEFAULT_IMAGE = "python:3.12-alpine";

  static async create(config: MachineConfig): Promise<PythonMachine> {
    const machine = new PythonMachine(config);
    await machine.start();
    // Pre-pull the Python image
    await machine.pullImage(PythonMachine.DEFAULT_IMAGE);
    return machine;
  }

  private constructor(config: MachineConfig) {
    super(config);
  }

  /** Run Python code. */
  async runCode(code: string, options?: CodeOptions): Promise<ExecResult> {
    const image = options?.image ?? PythonMachine.DEFAULT_IMAGE;
    return this.run(image, ["python3", "-c", code], options);
  }

  /** Run a Python file (must be in a mounted directory). */
  async runFile(path: string, options?: CodeOptions): Promise<ExecResult> {
    const image = options?.image ?? PythonMachine.DEFAULT_IMAGE;
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
      PythonMachine.DEFAULT_IMAGE,
      ["pip", "install", ...packages],
      options
    );
  }

  /** List installed packages. */
  async listPackages(options?: ExecOptions): Promise<string[]> {
    const result = await this.run(
      PythonMachine.DEFAULT_IMAGE,
      ["pip", "list", "--format=freeze"],
      options
    );
    return result.stdout.trim().split("\n").filter(Boolean);
  }

  /** Get Python version. */
  async version(options?: CodeOptions): Promise<string> {
    const image = options?.image ?? PythonMachine.DEFAULT_IMAGE;
    const result = await this.run(image, ["python3", "--version"], options);
    return result.stdout.trim();
  }
}
