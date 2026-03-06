import { dirname } from "node:path";

function currentPlatformKey(): string {
  return `${process.platform}:${process.arch}`;
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

  try {
    return dirname(require.resolve(`${packageName}/package.json`));
  } catch {
    throw new Error(
      `Missing internal platform package '${packageName}' for smolvm-embedded. ` +
        "Install workspace dependencies and build the current platform package."
    );
  }
}
