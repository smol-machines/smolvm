import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

function currentPlatformKey(): string {
  return `${process.platform}:${process.arch}`;
}

function currentPackageRoot(): string {
  if (typeof __dirname === "string") {
    return resolve(__dirname, "..");
  }

  return resolve(dirname(fileURLToPath(import.meta.url)), "..");
}

export function getPlatformPackageName(): string {
  switch (currentPlatformKey()) {
    case "darwin:arm64":
      return "smolvm-embedded-darwin-arm64";
    case "darwin:x64":
      return "smolvm-embedded-darwin-x64";
    case "linux:arm64":
      return "smolvm-embedded-linux-arm64-gnu";
    case "linux:x64":
      return "smolvm-embedded-linux-x64-gnu";
    default:
      throw new Error(
        `Unsupported smolvm-embedded platform: ${process.platform}/${process.arch}`
      );
  }
}

export function getPlatformPackageRoot(): string {
  const packageName = getPlatformPackageName();
  const packageRoot = currentPackageRoot();
  const siblingPackageRoot = resolve(packageRoot, "..", packageName);
  const siblingPackageJson = resolve(siblingPackageRoot, "package.json");

  if (existsSync(siblingPackageJson)) {
    return siblingPackageRoot;
  }

  try {
    return dirname(require.resolve(`${packageName}/package.json`));
  } catch {
    throw new Error(
      `Missing internal platform package '${packageName}' for smolvm-embedded. ` +
        "Build the current platform package from sdks/node first."
    );
  }
}
