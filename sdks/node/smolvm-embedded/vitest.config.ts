import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Daemonless VM startup is reliable under process workers but not thread workers.
    pool: "forks",
    testTimeout: 120_000, // 2 minutes — VM boot + image pull can be slow
    hookTimeout: 60_000,
    include: ["__tests__/**/*.test.ts"],
  },
});
