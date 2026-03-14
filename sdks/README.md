# SmolVM Embedded SDKs

## Overview

This directory holds language bindings that embed `smolvm` directly into the
host process instead of talking to the API server.

Layout convention:

- `sdks/scripts/` contains shared helpers used by all embedded SDKs.
- `sdks/node/` contains the Node.js embedded SDK and its internal platform
  packages.
- future embedded SDKs should live in sibling directories such as
  `sdks/python/`, `sdks/go/`, and `sdks/c/`.

Bundled native library rule:

- Embedded SDKs ship package-local copies of `libkrun` and `libkrunfw`.
- Those libraries are always staged from the `smolvm` repo's bundled `./lib`
  directory, not from Homebrew or other system locations.
- Shared helpers in `sdks/scripts/` should be used to copy the current host's
  libraries into each SDK package's `lib/` directory.

Current status:

- **The embedded sdk currently create sandbox without involving the DB storage. This means sandboxes created via embedded sdk is not visible via the smolvm CLI. This is a bug and we are actively working on a fix**
- `sdks/node/` is the first embedded SDK implementation.


## Development

### Build

Install the Node workspace dependencies, then run the repo-level embedded SDK
build. That flow compiles `smolvm-napi`, stages the bundled `libkrun` and
`libkrunfw` libraries into the current-host platform package, and builds the
public `smolvm-embedded` package.

```bash
cd sdks/node
npm install

cd ../..
./scripts/build-embedded-node.sh
```

If you are already inside `sdks/node`, `npm run build` rebuilds the current-host
platform package plus the public package without leaving the workspace.

### Test

Use the Node workspace for the main verification flow:

```bash
cd sdks/node
npm test
npm run smoke
npm exec --workspace smolvm-embedded tsx examples/basic.ts
```

- `npm test` rebuilds the current platform package and runs the
  `smolvm-embedded` Vitest suite.
- `npm run smoke` performs the fresh-install validation from the PR by packing
  the public package plus the host platform package, installing them into a
  temporary project, and checking that the native binding loads correctly.
- `npm exec --workspace smolvm-embedded tsx examples/basic.ts` runs the local
  integration example that exercises `quickExec`, container execution, managed
  sandbox lifecycle, and explicit sandbox cleanup.

### Manual Fresh-Install Check

If you want to test from a freshly installed
`smolvm-embedded` Node SDK" flow by hand, pack both the public package and the
current-host platform package, then install them into a throwaway project.

Supported platform package directories:

- `smolvm-embedded-darwin-arm64`
- `smolvm-embedded-darwin-x64`
- `smolvm-embedded-linux-arm64-gnu`
- `smolvm-embedded-linux-x64-gnu`

Example using the current-host package name in `PLATFORM_PKG`:

```bash
TMP_PACK_DIR="$(mktemp -d /tmp/smolvm-embedded-pack.XXXXXX)"
TMP_PROJECT_DIR="$(mktemp -d /tmp/smolvm-embedded-project.XXXXXX)"
PLATFORM_PKG="smolvm-embedded-darwin-arm64"

cd sdks/node/"$PLATFORM_PKG"
npm pack --pack-destination "$TMP_PACK_DIR"

cd ../smolvm-embedded
npm pack --pack-destination "$TMP_PACK_DIR"

cd "$TMP_PROJECT_DIR"
npm init -y
npm install typescript tsx @types/node
npm install \
  "$TMP_PACK_DIR"/smolvm-embedded-0.1.0.tgz \
  "$TMP_PACK_DIR"/"$PLATFORM_PKG"-0.1.0.tgz
```

Create `index.ts` in the temporary project:

```ts
import { quickExec, withSandbox } from "smolvm-embedded";

async function main() {
  const hello = await quickExec(["echo", "hello from smolvm-embedded"]);
  console.log("quickExec stdout:", hello.stdout.trim());
  console.log("quickExec exitCode:", hello.exitCode);

  await withSandbox({ name: "demo-sandbox" }, async (sb) => {
    const result = await sb.exec(["uname", "-a"]);
    console.log("sandbox uname:", result.stdout.trim());
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
```

Run the smoke program:

```bash
cd "$TMP_PROJECT_DIR"
npx tsx index.ts
```
