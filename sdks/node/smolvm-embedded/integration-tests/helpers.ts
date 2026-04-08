import { createServer } from "node:net";
import * as http from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

export function uniqueName(prefix: string): string {
  const safePrefix = prefix.replace(/[^a-z0-9-]/gi, "").slice(0, 10) || "sdk";
  return [
    safePrefix,
    process.pid.toString(36),
    Date.now().toString(36),
    Math.random().toString(36).slice(2, 6),
  ].join("-");
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function makeTempDir(prefix: string): Promise<string> {
  return mkdtemp(join(tmpdir(), `${prefix}-`));
}

export async function removeTempDir(path: string): Promise<void> {
  await rm(path, { recursive: true, force: true });
}

export async function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();

    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close(() => reject(new Error("Failed to allocate a TCP port")));
        return;
      }

      const { port } = address;
      server.close((err) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(port);
      });
    });
  });
}

export async function httpGetText(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = http.get(url, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        body += chunk;
      });
      res.on("end", () => {
        if ((res.statusCode ?? 0) >= 400) {
          reject(new Error(`HTTP ${res.statusCode}: ${body}`));
          return;
        }
        resolve(body);
      });
    });

    req.once("error", reject);
  });
}

export async function waitForHttpText(
  url: string,
  attempts = 20,
  intervalMs = 500
): Promise<string> {
  let lastError: unknown;

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await httpGetText(url);
    } catch (error) {
      lastError = error;
      await sleep(intervalMs);
    }
  }

  throw lastError instanceof Error
    ? lastError
    : new Error(`Timed out waiting for ${url}`);
}

export function collectExecStream(events: Array<{
  kind: string;
  data?: string;
  exitCode?: number;
  message?: string;
}>): {
  stdout: string;
  stderr: string;
  exitCode: number | undefined;
  errors: string[];
} {
  let stdout = "";
  let stderr = "";
  let exitCode: number | undefined;
  const errors: string[] = [];

  for (const event of events) {
    switch (event.kind) {
      case "stdout":
        stdout += event.data ?? "";
        break;
      case "stderr":
        stderr += event.data ?? "";
        break;
      case "exit":
        exitCode = event.exitCode;
        break;
      case "error":
        if (event.message) {
          errors.push(event.message);
        }
        break;
      default:
        errors.push(`unknown event kind: ${event.kind}`);
        break;
    }
  }

  return { stdout, stderr, exitCode, errors };
}
