/**
 * Runtime environment setup for bundled native libraries.
 *
 * The embedded SDK runs inside `node`, so Rust-side `current_exe()` points
 * at the Node executable rather than this package. Expose an explicit library
 * directory so smolvm can find bundled libkrun/libkrunfw assets reliably.
 */

import { existsSync } from "node:fs";
import { delimiter, resolve } from "node:path";

import { getPlatformPackageRoot } from "./platform-package.js";

function prependEnvPath(name: string, entry: string): void {
  const current = process.env[name];
  if (!current) {
    process.env[name] = entry;
    return;
  }

  const parts = current.split(delimiter);
  if (!parts.includes(entry)) {
    process.env[name] = `${entry}${delimiter}${current}`;
  }
}

export function prepareNativeRuntime(): void {
  const bundledLibDir = resolve(getPlatformPackageRoot(), "lib");
  if (!existsSync(bundledLibDir)) {
    return;
  }

  if (!process.env.SMOLVM_LIB_DIR) {
    process.env.SMOLVM_LIB_DIR = bundledLibDir;
  }

  if (process.platform === "darwin") {
    prependEnvPath("DYLD_LIBRARY_PATH", bundledLibDir);
  } else if (process.platform === "linux") {
    prependEnvPath("LD_LIBRARY_PATH", bundledLibDir);
  }
}
