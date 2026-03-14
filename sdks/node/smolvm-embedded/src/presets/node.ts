/**
 * NodeSandbox — pre-configured sandbox for running Node.js code.
 */

import { Sandbox } from "../sandbox.js";
import { ExecResult } from "../execution.js";
import type { SandboxConfig, ExecOptions, CodeOptions } from "../types.js";

export class NodeSandbox extends Sandbox {
  static readonly DEFAULT_IMAGE = "node:22-alpine";

  static async create(config: SandboxConfig): Promise<NodeSandbox> {
    const sandbox = new NodeSandbox(config);
    await sandbox.start();
    // Pre-pull the Node image
    await sandbox.pullImage(NodeSandbox.DEFAULT_IMAGE);
    return sandbox;
  }

  private constructor(config: SandboxConfig) {
    super(config);
  }

  /** Run JavaScript code. */
  async runCode(code: string, options?: CodeOptions): Promise<ExecResult> {
    const image = options?.image ?? NodeSandbox.DEFAULT_IMAGE;
    return this.run(image, ["node", "-e", code], options);
  }

  /** Run a JavaScript file (must be in a mounted directory). */
  async runFile(path: string, options?: CodeOptions): Promise<ExecResult> {
    const image = options?.image ?? NodeSandbox.DEFAULT_IMAGE;
    return this.run(image, ["node", path], options);
  }

  /** Run ESM code. */
  async runESM(code: string, options?: CodeOptions): Promise<ExecResult> {
    const image = options?.image ?? NodeSandbox.DEFAULT_IMAGE;
    return this.run(
      image,
      ["node", "--input-type=module", "-e", code],
      options
    );
  }

  /** Evaluate a JavaScript expression and return the result. */
  async evaluate(
    expression: string,
    options?: CodeOptions
  ): Promise<ExecResult> {
    const code = `console.log(JSON.stringify(${expression}))`;
    return this.runCode(code, options);
  }

  /** Run npm commands. */
  async npm(args: string[], options?: ExecOptions): Promise<ExecResult> {
    return this.run(NodeSandbox.DEFAULT_IMAGE, ["npm", ...args], options);
  }

  /** Install npm packages. */
  async npmInstall(
    packages: string[],
    options?: ExecOptions
  ): Promise<ExecResult> {
    return this.npm(["install", ...packages], options);
  }

  /** Run npx commands. */
  async npx(args: string[], options?: ExecOptions): Promise<ExecResult> {
    return this.run(NodeSandbox.DEFAULT_IMAGE, ["npx", ...args], options);
  }

  /** Get Node.js version. */
  async version(options?: CodeOptions): Promise<string> {
    const image = options?.image ?? NodeSandbox.DEFAULT_IMAGE;
    const result = await this.run(image, ["node", "--version"], options);
    return result.stdout.trim();
  }
}
