import { describe, expect, it } from "vitest";

import { withMachine } from "../src/index.js";

import { collectExecStream, uniqueName } from "./helpers.js";

describe("embedded sdk exec and file io", () => {
  it("supports exec env, workdir, stderr, and non-zero exit codes", async () => {
    await withMachine({ name: uniqueName("exec") }, async (machine) => {
      const result = await machine.exec(
        ["sh", "-lc", 'echo "$GREETING"; pwd; echo "warn" >&2; exit 7'],
        {
          env: { GREETING: "hello-sdk" },
          workdir: "/tmp",
        }
      );

      expect(result.exitCode).toBe(7);
      expect(result.stdout).toContain("hello-sdk");
      expect(result.stdout).toContain("/tmp");
      expect(result.stderr).toContain("warn");
    });
  });

  it("collects stdout, stderr, and exit events from streaming exec", async () => {
    await withMachine({ name: uniqueName("stream") }, async (machine) => {
      const events = await machine.execStreaming([
        "sh",
        "-lc",
        "echo line-1 && echo line-2 >&2 && echo line-3",
      ]);

      const result = collectExecStream(events);
      expect(result.stdout).toContain("line-1");
      expect(result.stdout).toContain("line-3");
      expect(result.stderr).toContain("line-2");
      expect(result.exitCode).toBe(0);
      expect(result.errors).toEqual([]);
    });
  });

  it("supports file upload and download", async () => {
    await withMachine({ name: uniqueName("files") }, async (machine) => {
      const upload = `hello-from-host-${Date.now().toString(36)}`;

      await machine.writeFile("/tmp/uploaded.txt", upload, { mode: 0o640 });

      const uploadCheck = await machine.exec(["cat", "/tmp/uploaded.txt"]);
      expect(uploadCheck.exitCode).toBe(0);
      expect(uploadCheck.stdout.trim()).toBe(upload);

      await machine.exec([
        "sh",
        "-lc",
        "echo 'hello from vm' > /tmp/from-vm.txt",
      ]);

      const downloaded = await machine.readFile("/tmp/from-vm.txt");
      expect(downloaded.toString("utf8").trim()).toBe("hello from vm");
    });
  });
});
