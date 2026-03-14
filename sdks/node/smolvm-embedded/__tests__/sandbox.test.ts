/**
 * Integration tests for smolvm-embedded.
 *
 * Requirements:
 * - macOS with Hypervisor.framework or Linux with KVM
 * - repo-local or packaged libkrun/libkrunfw build outputs available
 * - smolvm agent rootfs at the default path:
 *   - macOS: ~/Library/Application Support/smolvm/agent-rootfs
 *   - Linux: ~/.local/share/smolvm/agent-rootfs
 * - The current platform package must be built first: `cd sdks/node && npm run build`
 */

import { describe, it, expect, afterAll } from "vitest";
import {
  Sandbox,
  withSandbox,
  quickExec,
  quickRun,
  ExecResult,
} from "../src/index";

describe("Sandbox lifecycle", () => {
  it("should create, exec, and delete a sandbox", async () => {
    const sb = await Sandbox.create({ name: "test-lifecycle" });
    try {
      expect(sb.state).toBe("running");

      const result = await sb.exec(["echo", "hello from smolvm"]);
      expect(result).toBeInstanceOf(ExecResult);
      expect(result.exitCode).toBe(0);
      expect(result.stdout.trim()).toBe("hello from smolvm");
      expect(result.success).toBe(true);
    } finally {
      await sb.delete();
    }
  });

  it("should handle non-zero exit codes", async () => {
    await withSandbox({ name: "test-exit-code" }, async (sb) => {
      const result = await sb.exec(["sh", "-c", "exit 42"]);
      expect(result.exitCode).toBe(42);
      expect(result.success).toBe(false);
    });
  });

  it("should capture stderr", async () => {
    await withSandbox({ name: "test-stderr" }, async (sb) => {
      const result = await sb.exec([
        "sh",
        "-c",
        'echo "out" && echo "err" >&2',
      ]);
      expect(result.stdout.trim()).toBe("out");
      expect(result.stderr.trim()).toBe("err");
    });
  });

  it("should pass environment variables", async () => {
    await withSandbox({ name: "test-env" }, async (sb) => {
      const result = await sb.exec(["sh", "-c", "echo $MY_VAR"], {
        env: { MY_VAR: "hello-env" },
      });
      expect(result.stdout.trim()).toBe("hello-env");
    });
  });
});

describe("quickExec", () => {
  it("should execute a command in a temporary sandbox", async () => {
    const result = await quickExec(["echo", "quick"]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout.trim()).toBe("quick");
  });

  it("should execute multiple commands", async () => {
    const result = await quickExec([
      "sh",
      "-c",
      "uname -s && echo done",
    ]);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("done");
  });
});

describe("Container image execution", () => {
  it("should run a command in an Alpine container", async () => {
    const result = await quickRun("alpine:latest", [
      "cat",
      "/etc/os-release",
    ], {
      resources: { network: true },
    });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("Alpine");
  });

  it("should pull and list images", async () => {
    await withSandbox({
      name: "test-images",
      resources: { network: true },
    }, async (sb) => {
      const info = await sb.pullImage("alpine:latest");
      expect(info.reference).toContain("alpine");
      expect(info.digest).toMatch(/^sha256:/);
      expect(info.size).toBeGreaterThan(0);

      const images = await sb.listImages();
      expect(images.length).toBeGreaterThanOrEqual(1);
      expect(images.some((img) => img.reference.includes("alpine"))).toBe(
        true
      );
    });
  });
});

describe("withSandbox", () => {
  it("should clean up on success", async () => {
    const result = await withSandbox(
      { name: "test-cleanup-success" },
      async (sb) => {
        return sb.exec(["echo", "ok"]);
      }
    );
    expect(result.exitCode).toBe(0);
  });

  it("should clean up on error", async () => {
    await expect(
      withSandbox({ name: "test-cleanup-error" }, async () => {
        throw new Error("test error");
      })
    ).rejects.toThrow("test error");
  });
});

describe("ExecResult", () => {
  it("assertSuccess should pass for exit code 0", async () => {
    const result = await quickExec(["true"]);
    expect(() => result.assertSuccess()).not.toThrow();
  });

  it("assertSuccess should throw for non-zero exit code", async () => {
    const result = await quickExec(["false"]);
    expect(() => result.assertSuccess()).toThrow("Command failed");
  });
});

describe("Sandbox with resources", () => {
  it("should create a sandbox with custom resources", async () => {
    await withSandbox(
      {
        name: "test-resources",
        resources: {
          cpus: 2,
          memoryMb: 1024,
          network: true,
        },
      },
      async (sb) => {
        // Verify CPU count visible in guest
        const result = await sb.exec(["nproc"]);
        expect(result.exitCode).toBe(0);
        expect(parseInt(result.stdout.trim())).toBe(2);
      }
    );
  });
});
