import { writeFile, readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import { withMachine } from "../src/index.js";

import {
  getFreePort,
  makeTempDir,
  removeTempDir,
  sleep,
  uniqueName,
  waitForHttpText,
} from "./helpers.js";

describe("embedded sdk networking, mounts, and ports", () => {
  it("keeps outbound network disabled by default", async () => {
    await withMachine({ name: uniqueName("no-net") }, async (machine) => {
      const result = await machine.exec(["nslookup", "cloudflare.com"]);
      expect(result.exitCode).not.toBe(0);
    });
  });

  it("supports DNS lookups when network is enabled", async () => {
    await withMachine(
      {
        name: uniqueName("dns"),
        resources: { network: true },
      },
      async (machine) => {
        const result = await machine.exec([
          "sh",
          "-lc",
          "nslookup cloudflare.com && nslookup github.com",
        ]);

        expect(result.exitCode).toBe(0);
        expect(result.output).toContain("Address");
      }
    );
  });

  it("supports read-only and read-write host mounts", async () => {
    const readWriteDir = await makeTempDir("smolvm-rw");
    const readOnlyDir = await makeTempDir("smolvm-ro");

    try {
      await writeFile(`${readWriteDir}/input.txt`, "rw-data\n", "utf8");
      await writeFile(`${readOnlyDir}/readonly.txt`, "ro-data\n", "utf8");

      await withMachine(
        {
          name: uniqueName("mounts"),
          mounts: [
            { source: readWriteDir, target: "/mnt/rw", readOnly: false },
            { source: readOnlyDir, target: "/mnt/ro", readOnly: true },
          ],
        },
        async (machine) => {
          const readResult = await machine.exec([
            "sh",
            "-lc",
            "cat /mnt/rw/input.txt && cat /mnt/ro/readonly.txt",
          ]);

          expect(readResult.exitCode).toBe(0);
          expect(readResult.stdout).toContain("rw-data");
          expect(readResult.stdout).toContain("ro-data");

          const writeResult = await machine.exec([
            "sh",
            "-lc",
            "echo written-from-vm > /mnt/rw/output.txt",
          ]);
          expect(writeResult.exitCode).toBe(0);

          const blockedWrite = await machine.exec([
            "sh",
            "-lc",
            "echo blocked > /mnt/ro/blocked.txt",
          ]);
          expect(blockedWrite.exitCode).not.toBe(0);
        }
      );

      const written = await readFile(`${readWriteDir}/output.txt`, "utf8");
      expect(written.trim()).toBe("written-from-vm");
    } finally {
      await removeTempDir(readWriteDir);
      await removeTempDir(readOnlyDir);
    }
  });

  it("supports host-to-guest port mappings", async () => {
    const hostPort = await getFreePort();

    await withMachine(
      {
        name: uniqueName("ports"),
        ports: [{ host: hostPort, guest: 8080 }],
        resources: { network: true },
      },
      async (machine) => {
        const serverPromise = machine.exec([
          "sh",
          "-lc",
          "printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\n\\r\\nok' | nc -l -p 8080 -w 15",
        ]);

        await sleep(1000);

        const body = await waitForHttpText(`http://127.0.0.1:${hostPort}/`);
        expect(body).toBe("ok");

        const serverResult = await serverPromise;
        expect(serverResult.exitCode).toBe(0);
      }
    );
  });
});
