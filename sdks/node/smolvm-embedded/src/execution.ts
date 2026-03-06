/**
 * Execution result types for smolvm-embedded.
 */

/**
 * Error thrown when assertSuccess() is called on a failed execution.
 */
export class ExecutionError extends Error {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;

  constructor(exitCode: number, stdout: string, stderr: string) {
    super(`Command failed with exit code ${exitCode}`);
    this.name = "ExecutionError";
    this.exitCode = exitCode;
    this.stdout = stdout;
    this.stderr = stderr;
  }
}

/**
 * Rich result object from command execution.
 */
export class ExecResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;

  constructor(exitCode: number, stdout: string, stderr: string) {
    this.exitCode = exitCode;
    this.stdout = stdout;
    this.stderr = stderr;
  }

  /** Whether the command exited successfully (exit code 0). */
  get success(): boolean {
    return this.exitCode === 0;
  }

  /** Combined stdout and stderr output. */
  get output(): string {
    if (this.stdout && this.stderr) {
      return `${this.stdout}\n${this.stderr}`;
    }
    return this.stdout || this.stderr;
  }

  /**
   * Assert that the command succeeded (exit code 0).
   * Throws ExecutionError if the command failed.
   * Returns this for method chaining.
   */
  assertSuccess(): this {
    if (!this.success) {
      throw new ExecutionError(this.exitCode, this.stdout, this.stderr);
    }
    return this;
  }
}
